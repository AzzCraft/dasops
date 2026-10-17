from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Callable, Mapping

from dasops.tasks import index_rows_by_id, parse_tasks_index, update_tasks_md_text

from .canonical import semantic_digest, with_self_digest
from .claim import (
    ProtectedClaimError,
    _decode_token,
    _replace_worker_lock,
    _timestamp,
    _token_b64,
    _token_hash,
    _validate_worker_lock_path,
    _write_new_worker_lock,
    read_worker_lock,
    verify_challenge_response,
)
from .git_canonical import BareCanonicalRepo
from .state_store import ProtectedStateStore


IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")


class ProtectedLifecycleError(ProtectedClaimError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _operation_id(kind: str, idempotency_key: str) -> str:
    if not IDEMPOTENCY_RE.fullmatch(idempotency_key):
        raise ProtectedLifecycleError(
            "idempotency key must contain 8 to 128 safe identifier characters"
        )
    return f"{kind}-" + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32]


def _response_digest(response: bytes) -> str:
    return semantic_digest({"responseSha256": hashlib.sha256(response).hexdigest()})


def _wal_value(subject: dict[str, Any], phase: str, **updates: Any) -> dict[str, Any]:
    value = dict(subject)
    value.pop("recordDigest", None)
    value.update(updates)
    value["schema"] = "protected-lifecycle-wal/v1"
    value["phase"] = phase
    return with_self_digest(value)


def _state_update(state: dict[str, Any], **updates: Any) -> dict[str, Any]:
    value = dict(state)
    value.pop("recordDigest")
    value.update(updates)
    return with_self_digest(value)


def _unlink_owner_file(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
        raise ProtectedLifecycleError("refusing to remove a non-owner worker-lock object")
    os.unlink(path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _validate_intent(
    intent: dict[str, Any],
    *,
    operation: str,
    idempotency_key: str,
    change_id: str,
    task_id: str,
    owner: str,
    challenge_digest: str,
    response_digest: str,
) -> None:
    expected = {
        "operation": operation,
        "idempotencyKey": idempotency_key,
        "changeId": change_id,
        "taskId": task_id,
        "owner": owner,
        "authorizationChallengeDigest": challenge_digest,
        "authorizationResponseDigest": response_digest,
    }
    for field, value in expected.items():
        if intent[field] != value:
            raise ProtectedLifecycleError(f"lifecycle retry subject drift: {field}")


def _finish_lifecycle_readback(store, result, *, operation, idempotency_key, change_id,
                               task_id, owner, worker_lock_path, challenge_digest, response_digest):
    """Finish only the original receipt's missing WAL tail, never replay its action."""
    operation_id = _operation_id(operation, idempotency_key)
    intent = store.wal(operation_id, "intent")
    prepared = store.wal(operation_id, "candidate_prepared")
    kind = "renewal" if operation == "renew" else operation
    if (intent is None or prepared is None or intent["schema"] != "protected-lifecycle-wal/v1"
            or prepared["schema"] != "protected-lifecycle-wal/v1" or intent["phase"] != "intent"
            or prepared["phase"] != "candidate_prepared" or result["schema"] != f"protected-{kind}-result/v1"
            or result["operationId"] != operation_id or intent["operationId"] != operation_id
            or intent["workerLockPath"] != str(worker_lock_path.expanduser().parent.resolve()/worker_lock_path.name)):
        raise ProtectedLifecycleError("lifecycle receipt lacks its exact original history")
    _validate_intent(intent, operation=operation, idempotency_key=idempotency_key, change_id=change_id,
        task_id=task_id, owner=owner, challenge_digest=challenge_digest, response_digest=response_digest)
    if (any(result[k] != intent[k] for k in ("changeId", "taskId", "claimOperationId"))
            or result["priorOwner" if operation == "reclaim" else "owner"] != owner
            or any(prepared[k] != v for k, v in intent.items()
                   if k not in {"phase", "recordDigest", "candidateCommit", "newTokenHash", "newLeaseGeneration", "leaseExpiresAt"})
            or result["canonicalCommit" if operation == "renew" else "candidateCommit"] != prepared["candidateCommit"]):
        raise ProtectedLifecycleError("lifecycle receipt differs from original intent/candidate")
    expected = _wal_value(prepared, "readback_complete")
    complete = store.wal(operation_id, "readback_complete")
    if complete is not None:
        if complete != expected:
            raise ProtectedLifecycleError("lifecycle final WAL differs from original receipt")
        return result
    if operation not in store.policy()["allowedOperations"]:
        raise ProtectedLifecycleError("protected policy does not authorize lifecycle recovery")
    state = store.read_state(change_id, task_id)
    if (state is None or state["operationId"] != intent["claimOperationId"]
            or state["owner"] != owner or state["canonicalCommit"] != prepared["candidateCommit"]
            or store.repo.head() != prepared["candidateCommit"]):
        raise ProtectedLifecycleError("lifecycle receipt tail conflicts with current state")
    if operation == "renew":
        lock = read_worker_lock(worker_lock_path, store)
        if (state["status"] != "renewal_pending" or lock["status"] != "renewal_pending"
                or result["newLeaseGeneration"] != intent["priorLeaseGeneration"]+1
                or result["priorTokenHash"] != intent["priorTokenHash"]
                or result["priorLeaseGeneration"] != intent["priorLeaseGeneration"]
                or result["workerLockSha256"] != hashlib.sha256(worker_lock_path.read_bytes()).hexdigest()
                or any(result[a] != prepared[a] or result[a] != state[b] or state[b] != lock[b]
                       for a, b in (("newTokenHash", "tokenHash"), ("newLeaseGeneration", "leaseGeneration"),
                                    ("leaseExpiresAt", "leaseExpiresAt")))):
            raise ProtectedLifecycleError("renewal receipt tail differs from original token/state")
    elif (state["status"] != ("released" if operation == "release" else "reclaimed")
            or any(result[k] != state[k] for k in ("tokenHash", "claimGeneration", "leaseGeneration"))
            or result["baseCommit"] != intent["baseCommit"]):
        raise ProtectedLifecycleError("terminal lifecycle receipt tail differs from original state")
    store.append_wal(expected)
    return result


def renew_claim(
    *,
    store: ProtectedStateStore,
    change_id: str,
    task_id: str,
    owner: str,
    worker_lock_path: Path,
    challenge_id: str,
    response: bytes,
    idempotency_key: str,
    lease_seconds: int | None = None,
) -> dict[str, Any]:
    """Rotate a lease token and fence work until fresh new-token activation."""
    operation_id = _operation_id("renew", idempotency_key)
    challenge = store.read_challenge(challenge_id)
    challenge_digest = challenge["recordDigest"]
    response_digest = _response_digest(response)
    with store.change_lock(change_id):
        existing = store.read_receipt(operation_id, "renewal-result")
        if existing is not None:
            return _finish_lifecycle_readback(store, existing, operation="renew", idempotency_key=idempotency_key,
                change_id=change_id, task_id=task_id, owner=owner, worker_lock_path=worker_lock_path,
                challenge_digest=challenge_digest, response_digest=response_digest)
        policy = store.policy()
        if "renew" not in policy["allowedOperations"]:
            raise ProtectedLifecycleError("protected policy does not authorize renew")
        requested_lease = lease_seconds if lease_seconds is not None else policy["leaseSecondsMax"]
        if requested_lease < policy["leaseSecondsMin"] or requested_lease > policy["leaseSecondsMax"]:
            raise ProtectedLifecycleError("requested lease is outside protected policy bounds")
        state = store.read_state(change_id, task_id)
        if state is None:
            raise ProtectedLifecycleError("protected task state not found")
        worker_lock = _validate_worker_lock_path(worker_lock_path, store.repo)
        pending_path = worker_lock.with_name(f".{worker_lock.name}.{operation_id}.pending")
        intent = store.wal(operation_id, "intent")
        if intent is None:
            worker_lock, current_lock, challenge = verify_challenge_response(
                store=store,
                state=state,
                owner=owner,
                worker_lock_path=worker_lock,
                challenge_id=challenge_id,
                response=response,
                expected_operation="renewal_authorization",
                expected_status="active",
            )
            created_at = _timestamp(_now())
            subject = {
                "operationId": operation_id,
                "idempotencyKey": idempotency_key,
                "operation": "renew",
                "claimOperationId": state["operationId"],
                "changeId": change_id,
                "taskId": task_id,
                "owner": owner,
                "priorStateDigest": state["recordDigest"],
                "priorTokenHash": state["tokenHash"],
                "priorLeaseGeneration": state["leaseGeneration"],
                "newTokenHash": None,
                "newLeaseGeneration": None,
                "leaseExpiresAt": None,
                "baseCommit": state["canonicalCommit"],
                "candidateCommit": None,
                "workerLockPath": str(worker_lock),
                "pendingWorkerLockPath": str(pending_path),
                "authorizationChallengeDigest": challenge_digest,
                "authorizationResponseDigest": response_digest,
                "createdAt": created_at,
            }
            store.append_wal(_wal_value(subject, "intent"))
            intent = store.wal(operation_id, "intent")
            assert intent is not None
        else:
            _validate_intent(
                intent,
                operation="renew",
                idempotency_key=idempotency_key,
                change_id=change_id,
                task_id=task_id,
                owner=owner,
                challenge_digest=challenge_digest,
                response_digest=response_digest,
            )
            current_lock = None

        candidate_wal = store.wal(operation_id, "candidate_prepared")
        if candidate_wal is None:
            if state["recordDigest"] != intent["priorStateDigest"] or state["status"] != "active":
                raise ProtectedLifecycleError("renewal intent exists but prior active state drifted")
            if current_lock is None:
                current_lock = read_worker_lock(worker_lock, store)
            if pending_path.exists():
                pending_lock = read_worker_lock(pending_path, store)
            else:
                token = secrets.token_bytes(32)
                expires_at = _timestamp(_now() + timedelta(seconds=requested_lease))
                pending_lock = dict(current_lock)
                pending_lock.update(
                    {
                        "status": "renewal_pending",
                        "tokenBase64": _token_b64(token),
                        "tokenHash": _token_hash(token),
                        "leaseGeneration": state["leaseGeneration"] + 1,
                        "leaseExpiresAt": expires_at,
                        "updatedAt": _timestamp(_now()),
                    }
                )
                _write_new_worker_lock(pending_path, pending_lock, store)
            candidate_wal = _wal_value(
                intent,
                "candidate_prepared",
                newTokenHash=pending_lock["tokenHash"],
                newLeaseGeneration=pending_lock["leaseGeneration"],
                leaseExpiresAt=pending_lock["leaseExpiresAt"],
                candidateCommit=state["canonicalCommit"],
            )
            store.append_wal(candidate_wal)
        else:
            if pending_path.exists():
                pending_lock = read_worker_lock(pending_path, store)
            else:
                pending_lock = read_worker_lock(worker_lock, store)
            for field, wal_field in (
                ("tokenHash", "newTokenHash"),
                ("leaseGeneration", "newLeaseGeneration"),
                ("leaseExpiresAt", "leaseExpiresAt"),
            ):
                if pending_lock[field] != candidate_wal[wal_field]:
                    raise ProtectedLifecycleError(f"renewal candidate/lock drift: {field}")

        primary_lock = read_worker_lock(worker_lock, store)
        if primary_lock["tokenHash"] == intent["priorTokenHash"]:
            _replace_worker_lock(worker_lock, pending_lock, store)
        elif primary_lock["tokenHash"] != candidate_wal["newTokenHash"]:
            raise ProtectedLifecycleError("worker lock is neither prior nor prepared renewal generation")
        store.append_wal(_wal_value(candidate_wal, "lock_replaced"))

        state = store.read_state(change_id, task_id)
        assert state is not None
        if state["recordDigest"] == intent["priorStateDigest"] and state["status"] == "active":
            state = _state_update(
                state,
                status="renewal_pending",
                tokenHash=candidate_wal["newTokenHash"],
                leaseGeneration=candidate_wal["newLeaseGeneration"],
                leaseExpiresAt=candidate_wal["leaseExpiresAt"],
                updatedAt=_timestamp(_now()),
            )
            store.write_state(state)
        elif not (
            state["status"] == "renewal_pending"
            and state["tokenHash"] == candidate_wal["newTokenHash"]
            and state["leaseGeneration"] == candidate_wal["newLeaseGeneration"]
        ):
            raise ProtectedLifecycleError("renewal state recovery found an incompatible generation")
        store.append_wal(_wal_value(candidate_wal, "state_committed"))
        _unlink_owner_file(pending_path)
        final_lock = read_worker_lock(worker_lock, store)
        result = with_self_digest(
            {
                "schema": "protected-renewal-result/v1",
                "operationId": operation_id,
                "claimOperationId": intent["claimOperationId"],
                "changeId": change_id,
                "taskId": task_id,
                "owner": owner,
                "outcome": "renewal_pending_activation",
                "priorTokenHash": intent["priorTokenHash"],
                "newTokenHash": candidate_wal["newTokenHash"],
                "priorLeaseGeneration": intent["priorLeaseGeneration"],
                "newLeaseGeneration": candidate_wal["newLeaseGeneration"],
                "leaseExpiresAt": candidate_wal["leaseExpiresAt"],
                "canonicalCommit": candidate_wal["candidateCommit"],
                "workerLockSha256": hashlib.sha256(worker_lock.read_bytes()).hexdigest(),
                "authorizationChallengeDigest": challenge_digest,
                "authorizationResponseDigest": response_digest,
            }
        )
        if final_lock["status"] != "renewal_pending":
            raise ProtectedLifecycleError("renewed worker lock is not pending activation")
        store.write_receipt(operation_id, "renewal-result", result)
        store.append_wal(_wal_value(candidate_wal, "readback_complete"))
        return result


def release_claim(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    change_id: str,
    task_id: str,
    owner: str,
    worker_lock_path: Path,
    challenge_id: str,
    response: bytes,
    idempotency_key: str,
) -> dict[str, Any]:
    """Return an active task to unassigned TODO through an exact-base CAS."""
    operation_id = _operation_id("release", idempotency_key)
    challenge = store.read_challenge(challenge_id)
    challenge_digest = challenge["recordDigest"]
    response_digest = _response_digest(response)
    with store.change_lock(change_id):
        existing = store.read_receipt(operation_id, "release-result")
        state = store.read_state(change_id, task_id)
        if existing is not None:
            return _finish_lifecycle_readback(store, existing, operation="release", idempotency_key=idempotency_key,
                change_id=change_id, task_id=task_id, owner=owner, worker_lock_path=worker_lock_path,
                challenge_digest=challenge_digest, response_digest=response_digest)
        policy = store.policy()
        if "release" not in policy["allowedOperations"]:
            raise ProtectedLifecycleError("protected policy does not authorize release")
        if state is None:
            raise ProtectedLifecycleError("protected task state not found")
        worker_lock = _validate_worker_lock_path(worker_lock_path, repo)
        intent = store.wal(operation_id, "intent")
        if intent is None:
            worker_lock, current_lock, challenge = verify_challenge_response(
                store=store,
                state=state,
                owner=owner,
                worker_lock_path=worker_lock,
                challenge_id=challenge_id,
                response=response,
                expected_operation="release_authorization",
                expected_status="active",
            )
            created_at = _timestamp(_now())
            subject = {
                "operationId": operation_id,
                "idempotencyKey": idempotency_key,
                "operation": "release",
                "claimOperationId": state["operationId"],
                "changeId": change_id,
                "taskId": task_id,
                "owner": owner,
                "priorStateDigest": state["recordDigest"],
                "priorTokenHash": state["tokenHash"],
                "priorLeaseGeneration": state["leaseGeneration"],
                "newTokenHash": None,
                "newLeaseGeneration": None,
                "leaseExpiresAt": state["leaseExpiresAt"],
                "baseCommit": repo.head(),
                "candidateCommit": None,
                "workerLockPath": str(worker_lock),
                "pendingWorkerLockPath": None,
                "authorizationChallengeDigest": challenge_digest,
                "authorizationResponseDigest": response_digest,
                "createdAt": created_at,
            }
            store.append_wal(_wal_value(subject, "intent"))
            intent = store.wal(operation_id, "intent")
            assert intent is not None
        else:
            _validate_intent(
                intent,
                operation="release",
                idempotency_key=idempotency_key,
                change_id=change_id,
                task_id=task_id,
                owner=owner,
                challenge_digest=challenge_digest,
                response_digest=response_digest,
            )
            current_lock = None

        candidate_wal = store.wal(operation_id, "candidate_prepared")
        tasks_path = f"openspec/changes/{change_id}/tasks.md"
        if candidate_wal is None:
            tasks_bytes = repo.read_path(intent["baseCommit"], tasks_path)
            try:
                tasks_text = tasks_bytes.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ProtectedLifecycleError("tasks.md is not strict UTF-8") from exc
            row = index_rows_by_id(parse_tasks_index(tasks_text)).get(task_id)
            if row is None or row.status != "IN_PROGRESS" or row.owner != owner:
                raise ProtectedLifecycleError("canonical task is not active for the releasing owner")
            updated_text, changed = update_tasks_md_text(tasks_text, task_id, "-", "TODO")
            if not changed:
                raise ProtectedLifecycleError("release could not update canonical task")
            candidate, _tree = repo.build_single_path_commit(
                base_commit=intent["baseCommit"],
                path=tasks_path,
                content=updated_text.encode("utf-8"),
                message=f"chore(tasks): protected release {task_id}\n\nOperation: {operation_id}",
                timestamp=intent["createdAt"],
                scratch_root=store.scratch_root,
            )
            candidate_wal = _wal_value(intent, "candidate_prepared", candidateCommit=candidate)
            store.append_wal(candidate_wal)

        state = store.read_state(change_id, task_id)
        assert state is not None
        if state["recordDigest"] == intent["priorStateDigest"] and state["status"] == "active":
            if current_lock is None:
                current_lock = read_worker_lock(worker_lock, store)
            pending_lock = dict(current_lock)
            pending_lock.update({"status": "release_pending", "updatedAt": _timestamp(_now())})
            _replace_worker_lock(worker_lock, pending_lock, store)
            state = _state_update(state, status="release_pending", updatedAt=_timestamp(_now()))
            store.write_state(state)
        elif state["status"] not in {"release_pending", "released"}:
            raise ProtectedLifecycleError("release recovery found incompatible protected state")
        store.append_wal(_wal_value(candidate_wal, "state_committed"))
        store.append_wal(_wal_value(candidate_wal, "cas_pending"))
        head = repo.head()
        if head == intent["baseCommit"]:
            repo.cas(old_commit=intent["baseCommit"], new_commit=candidate_wal["candidateCommit"])
        elif head != candidate_wal["candidateCommit"]:
            raise ProtectedLifecycleError("release CAS is fenced by canonical ref drift")
        if repo.head() != candidate_wal["candidateCommit"]:
            raise ProtectedLifecycleError("release canonical readback mismatch")
        store.append_wal(_wal_value(candidate_wal, "cas_applied"))

        state = store.read_state(change_id, task_id)
        assert state is not None
        if state["status"] == "release_pending":
            state = _state_update(
                state,
                status="released",
                canonicalCommit=candidate_wal["candidateCommit"],
                updatedAt=_timestamp(_now()),
            )
            store.write_state(state)
        elif not (
            state["status"] == "released"
            and state["canonicalCommit"] == candidate_wal["candidateCommit"]
        ):
            raise ProtectedLifecycleError("release terminal state does not match published candidate")
        _unlink_owner_file(worker_lock)
        store.append_wal(_wal_value(candidate_wal, "worker_lock_deleted"))
        released_at = _timestamp(_now())
        result = with_self_digest(
            {
                "schema": "protected-release-result/v1",
                "operationId": operation_id,
                "claimOperationId": intent["claimOperationId"],
                "changeId": change_id,
                "taskId": task_id,
                "owner": owner,
                "outcome": "released",
                "tokenHash": intent["priorTokenHash"],
                "claimGeneration": state["claimGeneration"],
                "leaseGeneration": state["leaseGeneration"],
                "baseCommit": intent["baseCommit"],
                "candidateCommit": candidate_wal["candidateCommit"],
                "releasedAt": released_at,
                "workerLockDisposition": "deleted_with_filesystem_residuals_unclaimed",
                "authorizationChallengeDigest": challenge_digest,
                "authorizationResponseDigest": response_digest,
            }
        )
        store.write_receipt(operation_id, "release-result", result)
        store.append_wal(_wal_value(candidate_wal, "readback_complete"))
        return result


def reclaim_expired_claim(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    change_id: str,
    task_id: str,
    prior_owner: str,
    worker_lock_path: Path,
    authorization: dict[str, Any],
    authorization_verifier: Callable[[dict[str, Any], dict[str, Any]], Mapping[str, str]] | None,
    idempotency_key: str,
) -> dict[str, Any]:
    """Reclaim an expired lease only after an external three-role verification.

    The verifier is deliberately injected: this package does not invent a trust root
    or treat an unsigned local JSON file as approval.
    """
    operation_id = _operation_id("reclaim", idempotency_key)
    store.registry.validate(authorization)
    authorization_digest = authorization["recordDigest"]
    with store.change_lock(change_id):
        existing = store.read_receipt(operation_id, "reclaim-result")
        state = store.read_state(change_id, task_id)
        if existing is not None:
            intent = store.wal(operation_id, "intent")
            if intent is None:
                raise ProtectedLifecycleError("reclaim receipt lacks its original intent")
            role_digest = intent["authorizationResponseDigest"]
            if store.wal(operation_id, "readback_complete") is None:
                if authorization_verifier is None:
                    raise ProtectedLifecycleError("an independent reclaim authorization verifier is required")
                original_subject = {k: authorization[k] for k in ("changeId", "taskId", "expectedOwner", "claimGeneration",
                    "leaseGeneration", "canonicalCommit", "priorStateDigest", "reason")}
                role_bindings = authorization_verifier(authorization, original_subject)
                if (not isinstance(role_bindings, Mapping) or set(role_bindings) != {"anchor_owner", "task_governance", "verifier"}
                        or any(not isinstance(v, str) or not v for v in role_bindings.values())
                        or len(set(role_bindings.values())) != 3):
                    raise ProtectedLifecycleError("reclaim recovery requires distinct verified roles")
                role_digest = semantic_digest({"roleBindings": dict(sorted(role_bindings.items()))})
            return _finish_lifecycle_readback(store, existing, operation="reclaim", idempotency_key=idempotency_key,
                change_id=change_id, task_id=task_id, owner=prior_owner, worker_lock_path=worker_lock_path,
                challenge_digest=authorization_digest, response_digest=role_digest)
        policy = store.policy()
        if "reclaim" not in policy["allowedOperations"]:
            raise ProtectedLifecycleError("protected policy does not authorize reclaim")
        if state is None:
            raise ProtectedLifecycleError("protected task state not found")
        worker_lock = _validate_worker_lock_path(worker_lock_path, repo)
        intent = store.wal(operation_id, "intent")
        expected_subject = {
            "changeId": change_id,
            "taskId": task_id,
            "expectedOwner": prior_owner,
            "claimGeneration": state["claimGeneration"],
            "leaseGeneration": state["leaseGeneration"],
            "canonicalCommit": state["canonicalCommit"],
            "priorStateDigest": state["recordDigest"],
            "reason": "lease_expired",
        }
        if intent is None:
            if state["status"] not in {"active", "renewal_pending", "claimed_pending_activation"} or state["owner"] != prior_owner:
                raise ProtectedLifecycleError("task is not reclaimable for the expected prior owner")
            lease_expiry = datetime.fromisoformat(state["leaseExpiresAt"].replace("Z", "+00:00"))
            if _now() <= lease_expiry:
                raise ProtectedLifecycleError("lease has not expired")
            if state["status"] == "claimed_pending_activation":
                # Finish the original claim first. Reclaim never invents its
                # missing token/result or activates an already expired lease.
                original = store.wal(state["operationId"], "readback_complete")
                claimed = store.read_receipt(state["operationId"], "claim-result")
                lock = read_worker_lock(worker_lock, store)
                if (original is None or claimed is None or original["candidateCommit"] != state["canonicalCommit"]
                        or claimed["candidateCommit"] != state["canonicalCommit"]
                        or any(claimed[k] != state[k] for k in ("operationId", "changeId", "taskId", "owner", "tokenHash", "claimGeneration", "leaseGeneration"))
                        or hashlib.sha256(worker_lock.read_bytes()).hexdigest() != claimed["workerLockSha256"]
                        or repo.head() != state["canonicalCommit"] or str(worker_lock) != state["workerLockPath"]
                        or lock["candidateCommit"] != state["canonicalCommit"]
                        or any(lock[k] != state[k] for k in ("operationId", "changeId", "taskId", "owner", "status",
                            "tokenHash", "claimGeneration", "leaseGeneration", "leaseExpiresAt"))
                        or _token_hash(_decode_token(lock["tokenBase64"])) != state["tokenHash"]):
                    raise ProtectedLifecycleError("expired unactivated claim lacks its exact original readback/lock")
            issued = datetime.fromisoformat(authorization["issuedAt"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(authorization["expiresAt"].replace("Z", "+00:00"))
            if issued > _now() or _now() > expires:
                raise ProtectedLifecycleError("reclaim authorization is not currently valid")
            for field, value in expected_subject.items():
                if authorization[field] != value:
                    raise ProtectedLifecycleError(f"reclaim authorization subject mismatch: {field}")
            required_roles = {"anchor_owner", "task_governance", "verifier"}
            if set(authorization["requiredRoles"]) != required_roles:
                raise ProtectedLifecycleError("reclaim authorization does not require the exact three roles")
            if authorization_verifier is None:
                raise ProtectedLifecycleError("an independent reclaim authorization verifier is required")
            role_bindings = authorization_verifier(authorization, expected_subject)
            if not isinstance(role_bindings, Mapping) or set(role_bindings) != required_roles:
                raise ProtectedLifecycleError("reclaim verifier did not validate all required roles")
            identities = list(role_bindings.values())
            if any(not isinstance(value, str) or not value for value in identities):
                raise ProtectedLifecycleError("reclaim verifier returned an invalid signer identity")
            if len(set(identities)) != len(required_roles):
                raise ProtectedLifecycleError("reclaim roles must be held by distinct verified identities")
            role_digest = semantic_digest({"roleBindings": dict(sorted(role_bindings.items()))})
            created_at = _timestamp(_now())
            subject = {
                "operationId": operation_id,
                "idempotencyKey": idempotency_key,
                "operation": "reclaim",
                "claimOperationId": state["operationId"],
                "changeId": change_id,
                "taskId": task_id,
                "owner": prior_owner,
                "priorStateDigest": state["recordDigest"],
                "priorTokenHash": state["tokenHash"],
                "priorLeaseGeneration": state["leaseGeneration"],
                "newTokenHash": None,
                "newLeaseGeneration": None,
                "leaseExpiresAt": state["leaseExpiresAt"],
                "baseCommit": repo.head(),
                "candidateCommit": None,
                "workerLockPath": str(worker_lock),
                "pendingWorkerLockPath": None,
                "authorizationChallengeDigest": authorization_digest,
                "authorizationResponseDigest": role_digest,
                "createdAt": created_at,
            }
            store.append_wal(_wal_value(subject, "intent"))
            intent = store.wal(operation_id, "intent")
            assert intent is not None
        else:
            if intent["operation"] != "reclaim" or intent["authorizationChallengeDigest"] != authorization_digest:
                raise ProtectedLifecycleError("reclaim retry authorization drift")
            if authorization_verifier is None:
                raise ProtectedLifecycleError("an independent reclaim authorization verifier is required")
            original_subject = {
                "changeId": intent["changeId"],
                "taskId": intent["taskId"],
                "expectedOwner": intent["owner"],
                "claimGeneration": authorization["claimGeneration"],
                "leaseGeneration": intent["priorLeaseGeneration"],
                "canonicalCommit": authorization["canonicalCommit"],
                "priorStateDigest": intent["priorStateDigest"],
                "reason": "lease_expired",
            }
            role_bindings = authorization_verifier(authorization, original_subject)
            role_digest = semantic_digest({"roleBindings": dict(sorted(role_bindings.items()))})
            if role_digest != intent["authorizationResponseDigest"]:
                raise ProtectedLifecycleError("reclaim retry verified-role drift")

        candidate_wal = store.wal(operation_id, "candidate_prepared")
        tasks_path = f"openspec/changes/{change_id}/tasks.md"
        if candidate_wal is None:
            tasks_bytes = repo.read_path(intent["baseCommit"], tasks_path)
            try:
                tasks_text = tasks_bytes.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ProtectedLifecycleError("tasks.md is not strict UTF-8") from exc
            row = index_rows_by_id(parse_tasks_index(tasks_text)).get(task_id)
            if row is None or row.status != "IN_PROGRESS" or row.owner != prior_owner:
                raise ProtectedLifecycleError("canonical task is not held by the prior owner")
            updated_text, changed = update_tasks_md_text(tasks_text, task_id, "-", "TODO")
            if not changed:
                raise ProtectedLifecycleError("reclaim could not update canonical task")
            candidate, _tree = repo.build_single_path_commit(
                base_commit=intent["baseCommit"],
                path=tasks_path,
                content=updated_text.encode("utf-8"),
                message=f"chore(tasks): protected reclaim {task_id}\n\nOperation: {operation_id}",
                timestamp=intent["createdAt"],
                scratch_root=store.scratch_root,
            )
            candidate_wal = _wal_value(intent, "candidate_prepared", candidateCommit=candidate)
            store.append_wal(candidate_wal)

        state = store.read_state(change_id, task_id)
        assert state is not None
        if state["recordDigest"] == intent["priorStateDigest"]:
            lock = read_worker_lock(worker_lock, store)
            pending_lock = dict(lock)
            pending_lock.update({"status": "reclaim_pending", "updatedAt": _timestamp(_now())})
            _replace_worker_lock(worker_lock, pending_lock, store)
            state = _state_update(state, status="reclaim_pending", updatedAt=_timestamp(_now()))
            store.write_state(state)
        elif state["status"] not in {"reclaim_pending", "reclaimed"}:
            raise ProtectedLifecycleError("reclaim recovery found incompatible protected state")
        store.append_wal(_wal_value(candidate_wal, "state_committed"))
        store.append_wal(_wal_value(candidate_wal, "cas_pending"))
        head = repo.head()
        if head == intent["baseCommit"]:
            repo.cas(old_commit=intent["baseCommit"], new_commit=candidate_wal["candidateCommit"])
        elif head != candidate_wal["candidateCommit"]:
            raise ProtectedLifecycleError("reclaim CAS is fenced by canonical ref drift")
        if repo.head() != candidate_wal["candidateCommit"]:
            raise ProtectedLifecycleError("reclaim canonical readback mismatch")
        store.append_wal(_wal_value(candidate_wal, "cas_applied"))

        state = store.read_state(change_id, task_id)
        assert state is not None
        if state["status"] == "reclaim_pending":
            state = _state_update(
                state,
                status="reclaimed",
                canonicalCommit=candidate_wal["candidateCommit"],
                updatedAt=_timestamp(_now()),
            )
            store.write_state(state)
        elif state["status"] != "reclaimed":
            raise ProtectedLifecycleError("reclaim terminal state mismatch")
        _unlink_owner_file(worker_lock)
        store.append_wal(_wal_value(candidate_wal, "worker_lock_deleted"))
        result = with_self_digest(
            {
                "schema": "protected-reclaim-result/v1",
                "operationId": operation_id,
                "claimOperationId": intent["claimOperationId"],
                "changeId": change_id,
                "taskId": task_id,
                "priorOwner": prior_owner,
                "outcome": "reclaimed",
                "tokenHash": intent["priorTokenHash"],
                "claimGeneration": state["claimGeneration"],
                "leaseGeneration": state["leaseGeneration"],
                "baseCommit": intent["baseCommit"],
                "candidateCommit": candidate_wal["candidateCommit"],
                "reclaimedAt": _timestamp(_now()),
                "authorizationDigest": authorization_digest,
                "verifiedRoleBindingsDigest": intent["authorizationResponseDigest"],
                "workerLockDisposition": "deleted_with_filesystem_residuals_unclaimed",
            }
        )
        store.write_receipt(operation_id, "reclaim-result", result)
        store.append_wal(_wal_value(candidate_wal, "readback_complete"))
        return result
