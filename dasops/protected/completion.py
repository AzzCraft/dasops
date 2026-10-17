from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from dasops.tasks import index_rows_by_id, parse_tasks_index, update_tasks_md_text

from .canonical import semantic_digest, with_self_digest
from .claim import (
    ProtectedClaimError,
    _replace_worker_lock,
    _timestamp,
    _validate_worker_lock_path,
    read_worker_lock,
    verify_challenge_response,
)
from .git_canonical import BareCanonicalRepo
from .lifecycle import _operation_id, _state_update, _unlink_owner_file
from .state_store import ProtectedStateStore


class ProtectedCompletionError(ProtectedClaimError):
    pass


ApprovalVerifier = Callable[[dict[str, Any], dict[str, Any]], Mapping[str, str]]


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _input_manifest(changes: Mapping[str, tuple[bytes | None, str | None]]) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    for path, (content, mode) in sorted(changes.items()):
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not path or "\x00" in path:
            raise ProtectedCompletionError(f"unsafe completion path: {path!r}")
        if path == ".git" or path.startswith(".git/") or path.startswith("das-task-state/"):
            raise ProtectedCompletionError(f"forbidden completion path: {path}")
        if path.startswith("openspec/changes/") and (
            path.endswith("/tasks.md") or "/task_locks/" in path
        ):
            raise ProtectedCompletionError(f"completion cannot directly mutate task governance: {path}")
        if mode not in {None, "100644", "100755"}:
            raise ProtectedCompletionError(f"unsupported completion mode for {path}: {mode}")
        manifest.append(
            {
                "path": path,
                "mode": mode,
                "deleted": content is None,
                "contentSha256": None if content is None else hashlib.sha256(content).hexdigest(),
            }
        )
    return manifest


def _set_pending_state(
    *,
    store: ProtectedStateStore,
    request: dict[str, Any],
    worker_lock_path: Path,
) -> None:
    state = store.read_state(request["changeId"], request["taskId"])
    if state is None:
        raise ProtectedCompletionError("protected task state not found")
    worker_lock = _validate_worker_lock_path(worker_lock_path, store.repo)
    if str(worker_lock) != state["workerLockPath"]:
        raise ProtectedCompletionError("worker lock path does not match protected state")
    lock = read_worker_lock(worker_lock, store)
    if state["status"] == "active":
        for field in ("operationId", "owner", "tokenHash", "claimGeneration", "leaseGeneration"):
            if state[field] != request[field if field != "operationId" else "claimOperationId"]:
                raise ProtectedCompletionError(f"completion request/state mismatch: {field}")
        pending_fields = {
            "status": "completion_pending",
            "pendingOperationId": request["operationId"],
            "pendingCandidateCommit": request["candidateCommit"],
            "completionRequestDigest": request["recordDigest"],
            "updatedAt": _timestamp(_now()),
        }
        pending_lock = dict(lock)
        pending_lock.update(pending_fields)
        _replace_worker_lock(worker_lock, pending_lock, store)
        store.write_state(_state_update(state, **pending_fields))
        return
    if not (
        state["status"] == "completion_pending"
        and state.get("pendingOperationId") == request["operationId"]
        and state.get("pendingCandidateCommit") == request["candidateCommit"]
        and state.get("completionRequestDigest") == request["recordDigest"]
        and lock["status"] == "completion_pending"
    ):
        raise ProtectedCompletionError("a different completion is already pending")


def prepare_completion(
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
    changes: Mapping[str, tuple[bytes | None, str | None]],
    package_lifetime_seconds: int = 3600,
) -> dict[str, Any]:
    operation_id = _operation_id("completion", idempotency_key)
    if package_lifetime_seconds < 300 or package_lifetime_seconds > 86400:
        raise ProtectedCompletionError("completion package lifetime must be 300 to 86400 seconds")
    manifest = _input_manifest(changes)
    input_digest = semantic_digest({"changes": manifest})
    challenge = store.read_challenge(challenge_id)
    response_digest = semantic_digest({"responseSha256": hashlib.sha256(response).hexdigest()})
    with store.change_lock(change_id):
        existing = store.read_receipt(operation_id, "completion-request")
        if existing is not None:
            if existing["inputDigest"] != input_digest:
                raise ProtectedCompletionError("completion retry input drift")
            for field, value in (("changeId", change_id), ("taskId", task_id), ("owner", owner)):
                if existing[field] != value:
                    raise ProtectedCompletionError(f"completion retry subject drift: {field}")
            _set_pending_state(store=store, request=existing, worker_lock_path=worker_lock_path)
            return existing
        policy = store.policy()
        if "complete" not in policy["allowedOperations"]:
            raise ProtectedCompletionError("protected policy does not authorize complete")
        state = store.read_state(change_id, task_id)
        if state is None:
            raise ProtectedCompletionError("protected task state not found")
        consumption_kind = f"challenge-{challenge_id}"
        consumption = store.read_receipt(state["operationId"], consumption_kind)
        if consumption is not None:
            if (
                consumption["operationId"] != operation_id
                or consumption["inputDigest"] != input_digest
                or consumption["challengeDigest"] != challenge["recordDigest"]
            ):
                raise ProtectedCompletionError("completion authorization challenge was already consumed")
            response_digest = consumption["authorizationResponseDigest"]
            if state["status"] != "active" or state["owner"] != owner:
                raise ProtectedCompletionError("consumed completion request no longer has its active claim")
            worker_lock = _validate_worker_lock_path(worker_lock_path, repo)
        else:
            worker_lock, _lock, challenge = verify_challenge_response(
                store=store,
                state=state,
                owner=owner,
                worker_lock_path=worker_lock_path,
                challenge_id=challenge_id,
                response=response,
                expected_operation="completion_authorization",
                expected_status="active",
            )
            consumption = with_self_digest(
                {
                    "schema": "protected-challenge-consumption/v1",
                    "challengeId": challenge_id,
                    "challengeDigest": challenge["recordDigest"],
                    "authorizationResponseDigest": response_digest,
                    "operationId": operation_id,
                    "purpose": "completion_prepare",
                    "inputDigest": input_digest,
                    "consumedAt": _timestamp(_now()),
                }
            )
            store.write_receipt(state["operationId"], consumption_kind, consumption)
        base = repo.head()
        tasks_path = f"openspec/changes/{change_id}/tasks.md"
        tasks_text = repo.read_path(base, tasks_path).decode("utf-8", "strict")
        row = index_rows_by_id(parse_tasks_index(tasks_text)).get(task_id)
        if row is None or row.status != "IN_PROGRESS" or row.owner != owner:
            raise ProtectedCompletionError("canonical task is not active for the completing owner")
        updated_tasks, changed = update_tasks_md_text(tasks_text, task_id, owner, "DONE")
        if not changed:
            raise ProtectedCompletionError("completion could not update canonical task")
        candidate_changes = dict(changes)
        if tasks_path in candidate_changes:
            raise ProtectedCompletionError("completion input must not contain its canonical tasks.md")
        candidate_changes[tasks_path] = (updated_tasks.encode("utf-8"), None)
        prepared_at = _timestamp(_now())
        candidate, _tree = repo.build_path_changes_commit(
            base_commit=base,
            changes=candidate_changes,
            message=f"feat: protected completion {task_id}\n\nOperation: {operation_id}",
            timestamp=prepared_at,
            scratch_root=store.scratch_root,
        )
        request = with_self_digest(
            {
                "schema": "protected-completion-request/v1",
                "operationId": operation_id,
                "claimOperationId": state["operationId"],
                "changeId": change_id,
                "taskId": task_id,
                "taskPath": tasks_path,
                "owner": owner,
                "tokenHash": state["tokenHash"],
                "claimGeneration": state["claimGeneration"],
                "leaseGeneration": state["leaseGeneration"],
                "baseCommit": base,
                "candidateCommit": candidate,
                "changedPaths": sorted(candidate_changes),
                "inputDigest": input_digest,
                "authorizationChallengeDigest": challenge["recordDigest"],
                "authorizationResponseDigest": response_digest,
                "preparedAt": prepared_at,
                "expiresAt": _timestamp(_now() + timedelta(seconds=package_lifetime_seconds)),
            }
        )
        store.write_receipt(operation_id, "completion-request", request)
        _set_pending_state(store=store, request=request, worker_lock_path=worker_lock)
        return request


def _verify_approval(
    *,
    store: ProtectedStateStore,
    request: dict[str, Any],
    approval: dict[str, Any],
    action: str,
    canonical_head: str,
    verification_digest: str | None,
    approval_verifier: ApprovalVerifier | None,
) -> str:
    store.registry.validate(approval)
    expected = {
        "action": action,
        "requestDigest": request["recordDigest"],
        "candidateCommit": request["candidateCommit"],
        "canonicalHead": canonical_head,
        "verificationDigest": verification_digest,
    }
    for field, value in expected.items():
        if approval[field] != value:
            raise ProtectedCompletionError(f"completion approval subject mismatch: {field}")
    issued = datetime.fromisoformat(approval["issuedAt"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(approval["expiresAt"].replace("Z", "+00:00"))
    if issued > _now() or _now() > expires:
        raise ProtectedCompletionError("completion approval is not currently valid")
    required = {"reviewer", "task_governance", "verifier"}
    if set(approval["requiredRoles"]) != required:
        raise ProtectedCompletionError("completion approval does not require the exact review roles")
    if approval_verifier is None:
        raise ProtectedCompletionError("an independent completion approval verifier is required")
    role_bindings = approval_verifier(approval, expected)
    if not isinstance(role_bindings, Mapping) or set(role_bindings) != required:
        raise ProtectedCompletionError("completion verifier did not validate all required roles")
    identities = list(role_bindings.values())
    if any(not isinstance(value, str) or not value for value in identities) or len(set(identities)) != 3:
        raise ProtectedCompletionError("completion roles require three distinct verified identities")
    return semantic_digest({"roleBindings": dict(sorted(role_bindings.items()))})


def _accept_decision(
    *,
    store: ProtectedStateStore,
    request: dict[str, Any],
    approval: dict[str, Any],
    action: str,
    canonical_head: str,
    verification_digest: str | None,
    approval_verifier: ApprovalVerifier | None,
) -> str:
    kind = f"completion-decision-{action}"
    competing_kind = "completion-decision-abort" if action == "publish" else "completion-decision-publish"
    competing = store.read_receipt(request["operationId"], competing_kind)
    if competing is not None and action == "publish":
        raise ProtectedCompletionError("a competing completion decision was already accepted")
    superseded_digest = competing["recordDigest"] if competing is not None else None
    existing = store.read_receipt(request["operationId"], kind)
    if existing is not None:
        store.registry.validate(approval)
        expected = {
            "requestDigest": request["recordDigest"],
            "action": action,
            "canonicalHead": canonical_head,
            "approvalDigest": approval["recordDigest"],
            "verificationDigest": verification_digest,
        }
        for field, value in expected.items():
            if existing[field] != value:
                raise ProtectedCompletionError(f"accepted completion decision drift: {field}")
        return existing["verifiedRoleBindingsDigest"]
    if action == "publish" and _now() > datetime.fromisoformat(request["expiresAt"].replace("Z", "+00:00")):
        raise ProtectedCompletionError("completion package expired before publication decision")
    role_digest = _verify_approval(
        store=store,
        request=request,
        approval=approval,
        action=action,
        canonical_head=canonical_head,
        verification_digest=verification_digest,
        approval_verifier=approval_verifier,
    )
    intent = with_self_digest(
        {
            "schema": "protected-completion-decision-intent/v1",
            "operationId": request["operationId"],
            "requestDigest": request["recordDigest"],
            "action": action,
            "canonicalHead": canonical_head,
            "approvalDigest": approval["recordDigest"],
            "verificationDigest": verification_digest,
            "verifiedRoleBindingsDigest": role_digest,
            "supersededDecisionDigest": superseded_digest,
            "acceptedAt": _timestamp(_now()),
        }
    )
    store.write_receipt(request["operationId"], kind, intent)
    return role_digest


def publish_completion(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    operation_id: str,
    approval: dict[str, Any],
    verification: dict[str, Any],
    approval_verifier: ApprovalVerifier | None,
) -> dict[str, Any]:
    request = store.read_receipt(operation_id, "completion-request")
    if request is None:
        raise ProtectedCompletionError("completion request not found")
    store.registry.validate(verification)
    if verification["requestDigest"] != request["recordDigest"]:
        raise ProtectedCompletionError("completion verification request mismatch")
    if verification["candidateCommit"] != request["candidateCommit"]:
        raise ProtectedCompletionError("completion verification candidate mismatch")
    verification_digest = verification["recordDigest"]
    with store.change_lock(request["changeId"]):
        existing = store.read_receipt(operation_id, "completion-result")
        if existing is not None:
            return existing
        state = store.read_state(request["changeId"], request["taskId"])
        if state is None:
            raise ProtectedCompletionError("protected task state not found")
        if state["status"] not in {"completion_pending", "completed"}:
            raise ProtectedCompletionError("task is not pending this completion")
        head = repo.head()
        if head not in {request["baseCommit"], request["candidateCommit"]}:
            raise ProtectedCompletionError("completion publication is fenced by canonical ref drift")
        role_digest = _accept_decision(
            store=store,
            request=request,
            approval=approval,
            action="publish",
            canonical_head=request["baseCommit"],
            verification_digest=verification_digest,
            approval_verifier=approval_verifier,
        )
        if head == request["baseCommit"]:
            repo.cas(old_commit=request["baseCommit"], new_commit=request["candidateCommit"])
        if repo.head() != request["candidateCommit"]:
            raise ProtectedCompletionError("completion canonical readback mismatch")
        completed_at = state["updatedAt"] if state["status"] == "completed" else _timestamp(_now())
        if state["status"] == "completion_pending":
            state = dict(state)
            state.pop("recordDigest")
            state.pop("pendingOperationId", None)
            state.pop("pendingCandidateCommit", None)
            state.pop("completionRequestDigest", None)
            state.update(
                {
                    "status": "completed",
                    "canonicalCommit": request["candidateCommit"],
                    "updatedAt": completed_at,
                }
            )
            state = with_self_digest(state)
            store.write_state(state)
        _unlink_owner_file(Path(state["workerLockPath"]))
        result = with_self_digest(
            {
                "schema": "protected-completion-result/v1",
                "operationId": operation_id,
                "requestDigest": request["recordDigest"],
                "outcome": "published",
                "baseCommit": request["baseCommit"],
                "candidateCommit": request["candidateCommit"],
                "canonicalReadback": repo.head(),
                "approvalDigest": approval["recordDigest"],
                "verificationDigest": verification_digest,
                "verifiedRoleBindingsDigest": role_digest,
                "workerLockDisposition": "deleted_with_filesystem_residuals_unclaimed",
                "completedAt": completed_at,
            }
        )
        store.write_receipt(operation_id, "completion-result", result)
        return result


def abort_completion(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    operation_id: str,
    approval: dict[str, Any],
    approval_verifier: ApprovalVerifier | None,
) -> dict[str, Any]:
    request = store.read_receipt(operation_id, "completion-request")
    if request is None:
        raise ProtectedCompletionError("completion request not found")
    with store.change_lock(request["changeId"]):
        existing = store.read_receipt(operation_id, "completion-result")
        if existing is not None:
            return existing
        head = repo.head()
        if head == request["candidateCommit"]:
            raise ProtectedCompletionError("completion candidate is already canonical; publish recovery is required")
        state = store.read_state(request["changeId"], request["taskId"])
        if state is None or state["status"] not in {"completion_pending", "active"}:
            raise ProtectedCompletionError("task is not pending this completion")
        role_digest = _accept_decision(
            store=store,
            request=request,
            approval=approval,
            action="abort",
            canonical_head=head,
            verification_digest=None,
            approval_verifier=approval_verifier,
        )
        worker_lock = Path(state["workerLockPath"])
        lock = read_worker_lock(worker_lock, store)
        completed_at = state["updatedAt"] if state["status"] == "active" else _timestamp(_now())
        if state["status"] == "completion_pending":
            state.pop("recordDigest", None)
            for value in (state, lock):
                value.pop("pendingOperationId", None)
                value.pop("pendingCandidateCommit", None)
                value.pop("completionRequestDigest", None)
                value.update({"status": "active", "updatedAt": completed_at})
            state["canonicalCommit"] = head
            lock["candidateCommit"] = head
            _replace_worker_lock(worker_lock, lock, store)
            store.write_state(with_self_digest(state))
        result = with_self_digest(
            {
                "schema": "protected-completion-result/v1",
                "operationId": operation_id,
                "requestDigest": request["recordDigest"],
                "outcome": "aborted_pre_cas",
                "baseCommit": request["baseCommit"],
                "candidateCommit": request["candidateCommit"],
                "canonicalReadback": head,
                "approvalDigest": approval["recordDigest"],
                "verificationDigest": None,
                "verifiedRoleBindingsDigest": role_digest,
                "workerLockDisposition": "retained_active",
                "completedAt": completed_at,
            }
        )
        store.write_receipt(operation_id, "completion-result", result)
        return result
