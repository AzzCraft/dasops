from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
from typing import Any

from dasops.tasks import (
    index_rows_by_id,
    is_unassigned_owner,
    parse_tasks_index,
    split_deps,
    update_tasks_md_text,
)

from .canonical import canonical_bytes, load_canonical_json, semantic_digest, with_self_digest
from .encoding import strict_urlsafe_b64decode
from .git_canonical import BareCanonicalRepo, CanonicalRepoError
from .state_store import ProtectedStateStore, StateStoreError, atomic_write


class ProtectedClaimError(RuntimeError):
    pass


class NoReadyTask(ProtectedClaimError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _token_b64(token: bytes) -> str:
    return base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")


def _decode_token(value: str) -> bytes:
    try:
        return strict_urlsafe_b64decode(value, expected_size=32)
    except Exception as exc:
        raise ProtectedClaimError("worker lock contains an invalid token encoding") from exc


def _token_hash(token: bytes) -> str:
    return "sha256:" + hashlib.sha256(token).hexdigest()


def _operation_id(idempotency_key: str) -> str:
    if len(idempotency_key) < 8 or len(idempotency_key) > 256:
        raise ProtectedClaimError("idempotency key must contain 8 to 256 characters")
    return "claim-" + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32]


def _worker_lock_bytes(value: dict[str, Any], store: ProtectedStateStore) -> bytes:
    store.registry.validate(value, verify_digest=False)
    return canonical_bytes(value)


def _validate_worker_lock_path(path: Path, repo: BareCanonicalRepo) -> Path:
    resolved_parent = path.expanduser().parent.resolve()
    resolved = resolved_parent / path.name
    try:
        resolved.relative_to(repo.path)
    except ValueError:
        pass
    else:
        raise ProtectedClaimError("raw-token worker lock cannot live inside canonical/shared state")
    resolved_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(resolved_parent, stat.S_IMODE(os.stat(resolved_parent).st_mode) & ~0o077)
    if resolved_parent.is_symlink() or os.stat(resolved_parent).st_uid != os.getuid():
        raise ProtectedClaimError("worker-lock parent is not owner controlled")
    return resolved


def _write_new_worker_lock(path: Path, value: dict[str, Any], store: ProtectedStateStore) -> None:
    if path.exists() or path.is_symlink():
        raise ProtectedClaimError(f"worker lock already exists: {path}")
    atomic_write(path, _worker_lock_bytes(value, store), mode=0o600, create_only=True)


def _replace_worker_lock(path: Path, value: dict[str, Any], store: ProtectedStateStore) -> None:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid():
        raise ProtectedClaimError("worker lock is not an owner-controlled mode-0600 regular file")
    atomic_write(path, _worker_lock_bytes(value, store), mode=0o600)


def read_worker_lock(path: Path, store: ProtectedStateStore) -> dict[str, Any]:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid():
        raise ProtectedClaimError("worker lock is not an owner-controlled mode-0600 regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        data = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                raise ProtectedClaimError("worker lock exceeds 65536 bytes")
    finally:
        os.close(fd)
    value = load_canonical_json(data)
    store.registry.validate(value, verify_digest=False)
    return value


def _wal_value(
    *,
    operation_id: str,
    idempotency_key: str,
    phase: str,
    base_commit: str,
    candidate_commit: str | None,
    created_at: str,
    change_id: str,
    task_id: str,
    owner: str,
    token_hash: str,
    worker_lock: Path,
) -> dict[str, Any]:
    return with_self_digest(
        {
            "schema": "protected-operation-wal/v1",
            "operationId": operation_id,
            "idempotencyKey": idempotency_key,
            "operation": "claim",
            "phase": phase,
            "baseCommit": base_commit,
            "candidateCommit": candidate_commit,
            "createdAt": created_at,
            "changeId": change_id,
            "taskId": task_id,
            "owner": owner,
            "tokenHash": token_hash,
            "workerLockPath": str(worker_lock),
        }
    )


def _state_value(
    *,
    operation_id: str,
    change_id: str,
    task_id: str,
    owner: str,
    status: str,
    token_hash: str,
    canonical_commit: str,
    updated_at: str,
    worker_lock: Path,
    lease_expires_at: str,
    claim_generation: int,
    lease_generation: int,
) -> dict[str, Any]:
    return with_self_digest(
        {
            "schema": "protected-task-state/v1",
            "operationId": operation_id,
            "changeId": change_id,
            "taskId": task_id,
            "owner": owner,
            "status": status,
            "tokenHash": token_hash,
            "claimGeneration": claim_generation,
            "leaseGeneration": lease_generation,
            "canonicalCommit": canonical_commit,
            "updatedAt": updated_at,
            "workerLockPath": str(worker_lock),
            "leaseExpiresAt": lease_expires_at,
        }
    )


def _claim_phase(intent: dict[str, Any], phase: str, candidate: str) -> dict[str, Any]:
    return with_self_digest({**{k: v for k, v in intent.items() if k != "recordDigest"},
                             "phase": phase, "candidateCommit": candidate})


def _finish_claim(repo, store, worker_lock, intent, receipt):
    """Resume only this original claim; missing private token is unrecoverable."""
    if "claim" not in store.policy()["allowedOperations"]:
        raise ProtectedClaimError("protected policy does not authorize claim recovery")
    if repo.path != store.repo.path:
        raise ProtectedClaimError("claim store differs from canonical repository")
    try:
        lock = read_worker_lock(worker_lock, store)
    except FileNotFoundError as exc:
        raise ProtectedClaimError("original private claim token is missing; recovery refused") from exc
    if (lock["schema"] != "protected-worker-lock/v1"
            or lock["status"] not in {"claim_pending", "claimed_pending_activation"}
            or any(lock[k] != intent[k] for k in
                   ("operationId", "changeId", "taskId", "owner", "tokenHash", "baseCommit"))
            or _token_hash(_decode_token(lock["tokenBase64"])) != intent["tokenHash"]):
        raise ProtectedClaimError("claim worker lock differs from original intent")
    created = datetime.fromisoformat(intent["createdAt"].replace("Z", "+00:00"))
    updated = datetime.fromisoformat(lock["updatedAt"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(lock["leaseExpiresAt"].replace("Z", "+00:00"))
    if not created <= updated <= _now() or expires <= created:
        raise ProtectedClaimError("claim original timestamps are inconsistent")
    if set(lock) != {"schema", "operationId", "changeId", "taskId", "owner", "status", "tokenBase64",
                     "tokenHash", "claimGeneration", "leaseGeneration", "baseCommit", "candidateCommit", "updatedAt", "leaseExpiresAt"}:
        raise ProtectedClaimError("claim original lock contains a different operation")
    if lock["status"] == "claim_pending" and (lock["candidateCommit"] is not None or updated != created):
        raise ProtectedClaimError("pending claim lock differs from original preparation")
    tasks_path = f"openspec/changes/{intent['changeId']}/tasks.md"
    text = repo.read_path(intent["baseCommit"], tasks_path).decode("utf-8", "strict")
    rows = parse_tasks_index(text); by_id = index_rows_by_id(rows)
    selected = next((r for r in rows if r.status == "TODO" and is_unassigned_owner(r.owner)
                     and all(d in by_id and by_id[d].status == "DONE" for d in split_deps(r.depends_on, by_id))), None)
    if selected is None or selected.task_id != intent["taskId"]:
        raise ProtectedClaimError("original claim Task was not dependency-ready")
    content, changed = update_tasks_md_text(text, intent["taskId"], intent["owner"], "IN_PROGRESS")
    if not changed:
        raise ProtectedClaimError("original claim Task cannot be updated")
    prepared = store.wal(intent["operationId"], "candidate_prepared")
    if prepared is not None and (prepared["schema"] != "protected-operation-wal/v1"
            or prepared.get("operation") != "claim" or not prepared.get("candidateCommit")):
        raise ProtectedClaimError("claim candidate WAL has the wrong original type/outcome")
    candidate = prepared["candidateCommit"] if prepared is not None else None
    for phase in ("candidate_prepared", "cas_pending", "cas_applied", "readback_complete"):
        value = store.wal(intent["operationId"], phase)
        if value is not None and (candidate is None or value != _claim_phase(intent, phase, candidate)):
            raise ProtectedClaimError("claim WAL differs from original intent/candidate")
    if any(p.stem not in {"intent", "candidate_prepared", "cas_pending", "cas_applied", "readback_complete"}
           for p in store.operation_dir(intent["operationId"]).glob("*.json")):
        raise ProtectedClaimError("unsupported original claim phase")
    head = repo.head()
    if head not in {intent["baseCommit"], candidate}:
        raise ProtectedClaimError("claim recovery is fenced by canonical ref drift")
    if candidate is not None:
        parents = repo._run("rev-list", "--parents", "-n", "1", candidate).stdout.decode().split()
        paths = repo._run("diff", "--name-only", "-z", intent["baseCommit"], candidate).stdout.split(b"\0")
        old_entry = repo._run("ls-tree", intent["baseCommit"], "--", tasks_path).stdout.split()[0:2]
        new_entry = repo._run("ls-tree", candidate, "--", tasks_path).stdout.split()[0:2]
        if (parents != [candidate, intent["baseCommit"]] or paths != [tasks_path.encode(), b""]
                or old_entry != new_entry or old_entry[1:] != [b"blob"]
                or repo.read_path(candidate, tasks_path) != content.encode("utf-8")):
            raise ProtectedClaimError("claim candidate differs from original exact Task transition")
    if lock["status"] == "claimed_pending_activation" and lock["candidateCommit"] != candidate:
        raise ProtectedClaimError("claim final lock differs from original candidate")
    state = store.read_state(intent["changeId"], intent["taskId"])
    pending = _state_value(operation_id=intent["operationId"], change_id=intent["changeId"],
        task_id=intent["taskId"], owner=intent["owner"], status="claim_pending", token_hash=intent["tokenHash"],
        canonical_commit=intent["baseCommit"], updated_at=intent["createdAt"], worker_lock=worker_lock,
        lease_expires_at=lock["leaseExpiresAt"], claim_generation=lock["claimGeneration"], lease_generation=lock["leaseGeneration"])
    final = with_self_digest({**{k: v for k, v in pending.items() if k != "recordDigest"},
                              "status": "claimed_pending_activation", "canonicalCommit": candidate,
                              "updatedAt": lock["updatedAt"]}) if candidate else None
    if state is None or state["operationId"] != intent["operationId"]:
        if (head != intent["baseCommit"] or lock["status"] != "claim_pending" or receipt is not None
                or (state is None and (lock["claimGeneration"], lock["leaseGeneration"]) != (1, 1))
                or (state is not None and (state["status"] not in {"released", "reclaimed"}
                    or (lock["claimGeneration"], lock["leaseGeneration"]) !=
                       (state["claimGeneration"]+1, state["leaseGeneration"]+1)))):
            raise ProtectedClaimError("claim prior state/generations differ from original preparation")
    elif state != pending and not (lock["status"] == "claimed_pending_activation" and state == final):
        raise ProtectedClaimError("claim state differs from original pre/postimage")
    if head == intent["baseCommit"] and (lock["status"] != "claim_pending" or (final is not None and state == final) or receipt is not None):
        raise ProtectedClaimError("claim canonical ref contradicts published state")
    if receipt is not None:
        expected = with_self_digest(dict(schema="protected-claim-result/v1", operationId=intent["operationId"],
            outcome="claimed_pending_activation", changeId=intent["changeId"], taskId=intent["taskId"],
            owner=intent["owner"], claimGeneration=lock["claimGeneration"], leaseGeneration=lock["leaseGeneration"],
            tokenHash=intent["tokenHash"], baseCommit=intent["baseCommit"], candidateCommit=candidate,
            workerLockSha256=hashlib.sha256(worker_lock.read_bytes()).hexdigest()))
        if head != candidate or lock["status"] != "claimed_pending_activation" or state != final or receipt != expected:
            raise ProtectedClaimError("claim receipt differs from exact published state")
        store.append_wal(_claim_phase(intent, "readback_complete", candidate))
        return receipt
    if candidate is None:
        candidate, _ = repo.build_single_path_commit(base_commit=intent["baseCommit"], path=tasks_path,
            content=content.encode("utf-8"), message=f"chore(tasks): protected claim {intent['taskId']}\n\nOperation: {intent['operationId']}",
            timestamp=intent["createdAt"], scratch_root=store.scratch_root)
        store.append_wal(_claim_phase(intent, "candidate_prepared", candidate))
    if state is None or state["operationId"] != intent["operationId"]:
        store.write_state(pending)
    store.append_wal(_claim_phase(intent, "cas_pending", candidate))
    if head == intent["baseCommit"]:
        repo.cas(old_commit=intent["baseCommit"], new_commit=candidate)
    if repo.head() != candidate:
        raise ProtectedClaimError("claim canonical readback differs from original candidate")
    store.append_wal(_claim_phase(intent, "cas_applied", candidate))
    if lock["status"] == "claim_pending":
        lock = {**lock, "status": "claimed_pending_activation", "candidateCommit": candidate,
                "updatedAt": intent["createdAt"]}
        _replace_worker_lock(worker_lock, lock, store)
    final = with_self_digest({**{k: v for k, v in pending.items() if k != "recordDigest"},
                              "status": "claimed_pending_activation", "canonicalCommit": candidate,
                              "updatedAt": lock["updatedAt"]})
    if state != final:
        store.write_state(final)
    result = with_self_digest(dict(schema="protected-claim-result/v1", operationId=intent["operationId"],
        outcome="claimed_pending_activation", changeId=intent["changeId"], taskId=intent["taskId"],
        owner=intent["owner"], claimGeneration=lock["claimGeneration"], leaseGeneration=lock["leaseGeneration"],
        tokenHash=intent["tokenHash"], baseCommit=intent["baseCommit"], candidateCommit=candidate,
        workerLockSha256=hashlib.sha256(worker_lock.read_bytes()).hexdigest()))
    store.write_receipt(intent["operationId"], "claim-result", result)
    store.append_wal(_claim_phase(intent, "readback_complete", candidate))
    return result


def claim_ready(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    change_id: str,
    owner: str,
    worker_lock_path: Path,
    idempotency_key: str,
) -> dict[str, Any]:
    operation_id = _operation_id(idempotency_key)
    if repo.path != store.repo.path:
        raise ProtectedClaimError("claim store differs from canonical repository")
    worker_lock = _validate_worker_lock_path(worker_lock_path, repo)
    with store.change_lock(change_id):
        existing = store.read_receipt(operation_id, "claim-result")
        intent = store.wal(operation_id, "intent")
        if intent is not None:
            if (intent["schema"] != "protected-operation-wal/v1" or intent["operation"] != "claim"
                    or intent["phase"] != "intent" or intent["candidateCommit"] is not None
                    or any(intent[k] != v for k, v in {
                        "operationId": operation_id, "idempotencyKey": idempotency_key,
                        "changeId": change_id, "owner": owner, "workerLockPath": str(worker_lock),
                    }.items())):
                raise ProtectedClaimError("claim retry differs from original intent")
            if existing is not None:
                if (existing["schema"] != "protected-claim-result/v1"
                        or existing["outcome"] != "claimed_pending_activation"
                        or any(existing[k] != intent[k] for k in
                               ("operationId", "changeId", "taskId", "owner", "tokenHash", "baseCommit"))):
                    raise ProtectedClaimError("claim receipt differs from original intent")
                complete = store.wal(operation_id, "readback_complete")
                expected = _claim_phase(intent, "readback_complete", existing["candidateCommit"])
                if complete is not None:
                    if complete != expected:
                        raise ProtectedClaimError("claim readback differs from original intent")
                    return existing
            return _finish_claim(repo, store, worker_lock, intent, existing)
        if existing is not None or store.operation_dir(operation_id).exists():
            raise ProtectedClaimError("claim history lacks its original intent")
        policy = store.policy()
        if "claim" not in policy["allowedOperations"]:
            raise ProtectedClaimError("protected policy does not authorize claim")
        base = repo.head()
        tasks_path = f"openspec/changes/{change_id}/tasks.md"
        tasks_bytes = repo.read_path(base, tasks_path)
        try:
            tasks_text = tasks_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ProtectedClaimError("tasks.md is not strict UTF-8") from exc
        rows = parse_tasks_index(tasks_text)
        if not rows:
            raise ProtectedClaimError("canonical tasks.md has no parseable task index")
        by_id = index_rows_by_id(rows)
        selected = None
        for row in rows:
            if row.status != "TODO" or not is_unassigned_owner(row.owner):
                continue
            dependencies = split_deps(row.depends_on, by_id)
            if all(dep in by_id and by_id[dep].status == "DONE" for dep in dependencies):
                selected = row
                break
        if selected is None:
            raise NoReadyTask("no dependency-ready unassigned TODO task")
        prior_state = store.read_state(change_id, selected.task_id)
        if prior_state is None:
            claim_generation = 1
            lease_generation = 1
        else:
            if prior_state["status"] not in {"released", "reclaimed"}:
                raise ProtectedClaimError(
                    "canonical TODO task has nonterminal protected state; refusing generation reset"
                )
            claim_generation = prior_state["claimGeneration"] + 1
            lease_generation = prior_state["leaseGeneration"] + 1
        token = secrets.token_bytes(32)
        token_hash = _token_hash(token)
        created_at = _timestamp(_now())
        lease_expires_at = _timestamp(
            datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            + timedelta(seconds=policy["leaseSecondsMax"])
        )
        pending_lock = {
            "schema": "protected-worker-lock/v1",
            "operationId": operation_id,
            "changeId": change_id,
            "taskId": selected.task_id,
            "owner": owner,
            "status": "claim_pending",
            "tokenBase64": _token_b64(token),
            "tokenHash": token_hash,
            "claimGeneration": claim_generation,
            "leaseGeneration": lease_generation,
            "baseCommit": base,
            "candidateCommit": None,
            "updatedAt": created_at,
            "leaseExpiresAt": lease_expires_at,
        }
        store.append_wal(
            _wal_value(
                operation_id=operation_id,
                idempotency_key=idempotency_key,
                phase="intent",
                base_commit=base,
                candidate_commit=None,
                created_at=created_at,
                change_id=change_id,
                task_id=selected.task_id,
                owner=owner,
                token_hash=token_hash,
                worker_lock=worker_lock,
            )
        )
        _write_new_worker_lock(worker_lock, pending_lock, store)
        return _finish_claim(repo, store, worker_lock, store.wal(operation_id, "intent"), None)


def issue_activation_challenge(
    *,
    store: ProtectedStateStore,
    change_id: str,
    task_id: str,
    owner: str,
    operation: str = "claim_activation",
    lifetime_seconds: int = 300,
) -> dict[str, Any]:
    if lifetime_seconds < 30 or lifetime_seconds > 600:
        raise ProtectedClaimError("activation challenge lifetime must be 30 to 600 seconds")
    with store.change_lock(change_id):
        state = store.read_state(change_id, task_id)
        expected_status = {
            "claim_activation": "claimed_pending_activation",
            "renewal_authorization": "active",
            "renewal_activation": "renewal_pending",
            "release_authorization": "active",
            "completion_authorization": "active",
        }.get(operation)
        if expected_status is None:
            raise ProtectedClaimError(f"unsupported challenge operation: {operation}")
        policy_operation = {
            "claim_activation": "activate",
            "renewal_authorization": "renew",
            "renewal_activation": "renew",
            "release_authorization": "release",
            "completion_authorization": "complete",
        }[operation]
        policy = store.policy()
        if policy_operation not in policy["allowedOperations"]:
            raise ProtectedClaimError(f"protected policy does not authorize {policy_operation}")
        if state is None or state["status"] != expected_status or state["owner"] != owner:
            raise ProtectedClaimError(f"task is not {expected_status} for this owner")
        lease_expiry = datetime.fromisoformat(state["leaseExpiresAt"].replace("Z", "+00:00"))
        if _now() > lease_expiry:
            raise ProtectedClaimError("task lease expired before challenge issuance")
        issued = _now()
        challenge = secrets.token_bytes(32)
        value = with_self_digest(
            {
                "schema": "protected-activation-challenge/v1",
                "challengeId": secrets.token_hex(16),
                "challengeBase64": _token_b64(challenge),
                "taskId": task_id,
                "owner": owner,
                "claimGeneration": state["claimGeneration"],
                "leaseGeneration": state["leaseGeneration"],
                "operation": operation,
                "canonicalCommit": state["canonicalCommit"],
                "issuedAt": _timestamp(issued),
                "expiresAt": _timestamp(issued + timedelta(seconds=lifetime_seconds)),
            }
        )
        store.write_challenge(value)
        return value


def activation_response(token: bytes, challenge: dict[str, Any]) -> bytes:
    challenge_bytes = _decode_token(challenge["challengeBase64"])
    subject = b"protected-task-challenge/v1\0" + challenge_bytes + canonical_bytes(
        {
            "challengeId": challenge["challengeId"],
            "operation": challenge["operation"],
            "owner": challenge["owner"],
            "taskId": challenge["taskId"],
            "claimGeneration": challenge["claimGeneration"],
            "leaseGeneration": challenge["leaseGeneration"],
            "canonicalCommit": challenge["canonicalCommit"],
        }
    )
    return hmac.new(token, subject, hashlib.sha256).digest()


def verify_challenge_response(
    *,
    store: ProtectedStateStore,
    state: dict[str, Any],
    owner: str,
    worker_lock_path: Path,
    challenge_id: str,
    response: bytes,
    expected_operation: str,
    expected_status: str,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Verify a fresh proof of possession while the caller holds the change lock."""
    if state["status"] != expected_status or state["owner"] != owner:
        raise ProtectedClaimError(f"task is not {expected_status} for this owner")
    worker_lock = _validate_worker_lock_path(worker_lock_path, store.repo)
    if str(worker_lock) != state["workerLockPath"]:
        raise ProtectedClaimError("worker lock path does not match protected state")
    lock = read_worker_lock(worker_lock, store)
    for field in (
        "operationId",
        "taskId",
        "owner",
        "tokenHash",
        "claimGeneration",
        "leaseGeneration",
        "leaseExpiresAt",
    ):
        if lock[field] != state[field]:
            raise ProtectedClaimError(f"worker lock/state mismatch: {field}")
    if lock["candidateCommit"] != state["canonicalCommit"]:
        raise ProtectedClaimError("worker lock/state mismatch: canonicalCommit")
    token = _decode_token(lock["tokenBase64"])
    if len(token) != 32 or _token_hash(token) != state["tokenHash"]:
        raise ProtectedClaimError("worker lock token hash mismatch")
    challenge = store.read_challenge(challenge_id)
    if challenge["operation"] != expected_operation:
        raise ProtectedClaimError("challenge operation mismatch")
    for field in (
        "taskId",
        "owner",
        "claimGeneration",
        "leaseGeneration",
        "canonicalCommit",
    ):
        if challenge[field] != state[field]:
            raise ProtectedClaimError(f"challenge/state mismatch: {field}")
    expires = datetime.fromisoformat(challenge["expiresAt"].replace("Z", "+00:00"))
    if _now() > expires:
        raise ProtectedClaimError("activation challenge expired")
    lease_expiry = datetime.fromisoformat(state["leaseExpiresAt"].replace("Z", "+00:00"))
    if _now() > lease_expiry:
        raise ProtectedClaimError("task lease expired")
    expected_response = activation_response(token, challenge)
    if len(response) != 32 or not hmac.compare_digest(response, expected_response):
        raise ProtectedClaimError("activation response mismatch")
    return worker_lock, lock, challenge


def activate_claim(
    *,
    store: ProtectedStateStore,
    change_id: str,
    task_id: str,
    owner: str,
    worker_lock_path: Path,
    challenge_id: str,
    response: bytes,
) -> dict[str, Any]:
    with store.change_lock(change_id):
        state = store.read_state(change_id, task_id)
        if state is None:
            raise ProtectedClaimError("protected task state not found")
        receipt_kind = f"activation-{challenge_id}"
        existing = store.read_receipt(state["operationId"], receipt_kind)
        if existing is not None:
            return existing
        challenge = store.read_challenge(challenge_id)
        transition = {
            "claim_activation": "claimed_pending_activation",
            "renewal_activation": "renewal_pending",
        }
        expected_status = transition.get(challenge["operation"])
        if expected_status is None:
            raise ProtectedClaimError("challenge does not authorize activation")
        worker_lock, lock, challenge = verify_challenge_response(
            store=store,
            state=state,
            owner=owner,
            worker_lock_path=worker_lock_path,
            challenge_id=challenge_id,
            response=response,
            expected_operation=challenge["operation"],
            expected_status=expected_status,
        )
        activated_at = _timestamp(_now())
        active_lock = dict(lock)
        active_lock.update({"status": "active", "updatedAt": activated_at})
        _replace_worker_lock(worker_lock, active_lock, store)
        active_state_subject = dict(state)
        active_state_subject.pop("recordDigest")
        active_state_subject.update({"status": "active", "updatedAt": activated_at})
        active_state = with_self_digest(active_state_subject)
        store.write_state(active_state)
        receipt = with_self_digest(
            {
                "schema": "protected-activation-receipt/v1",
                "operationId": state["operationId"],
                "taskId": task_id,
                "owner": owner,
                "outcome": "matched",
                "tokenHash": state["tokenHash"],
                "claimGeneration": state["claimGeneration"],
                "leaseGeneration": state["leaseGeneration"],
                "canonicalCommit": state["canonicalCommit"],
                "challengeDigest": challenge["recordDigest"],
                "responseDigest": semantic_digest({"responseSha256": hashlib.sha256(response).hexdigest()}),
                "activatedAt": activated_at,
                "activationKind": challenge["operation"],
            }
        )
        store.write_receipt(state["operationId"], receipt_kind, receipt)
        return receipt
