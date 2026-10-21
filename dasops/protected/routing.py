from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from dasops.tasks import (
    index_rows_by_id,
    is_unassigned_owner,
    parse_tasks_index,
    split_deps,
    update_tasks_md_text,
)

from .canonical import semantic_digest, verify_self_digest, with_self_digest
from .claim import _timestamp
from .git_canonical import BareCanonicalRepo
from .state_store import ProtectedStateStore


class ProtectedRouteError(RuntimeError):
    pass


RouteApprovalVerifier = Callable[[dict[str, Any], dict[str, Any]], Mapping[str, str]]


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _validate_sorted_unique(rows: list[dict[str, Any]], kind: str) -> list[str]:
    ids = [row["taskId"] for row in rows]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise ProtectedRouteError(f"{kind} must be sorted by taskId and unique")
    return ids


def prepare_route(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    request: dict[str, Any],
    source_receipts: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    store.registry.validate(request)
    request_id = request["requestId"]
    change_id = request["changeId"]
    with store.change_lock(change_id):
        existing_request = store.read_receipt(request_id, "route-request")
        existing_result = store.read_receipt(request_id, "route-prepared")
        if existing_request is not None:
            if existing_request["recordDigest"] != request["recordDigest"]:
                raise ProtectedRouteError("route request idempotency drift")
            if existing_result is not None:
                return existing_result
        policy = store.policy()
        if "route_prepare" not in policy["allowedOperations"]:
            raise ProtectedRouteError("protected policy does not authorize route_prepare")
        if repo.head() != request["baseCommit"]:
            raise ProtectedRouteError("route base does not match canonical main")
        source_ids = _validate_sorted_unique(request["sourceResults"], "sourceResults")
        target_ids = _validate_sorted_unique(request["targetTransitions"], "targetTransitions")
        if set(source_ids) & set(target_ids):
            raise ProtectedRouteError("route sources and targets must be disjoint")
        if set(source_receipts) != set(source_ids):
            raise ProtectedRouteError("source receipt set does not equal the request denominator")
        requested_digests = {row["taskId"]: row["resultDigest"] for row in request["sourceResults"]}
        for task_id in source_ids:
            receipt = source_receipts[task_id]
            try:
                digest = verify_self_digest(receipt)
            except Exception as exc:
                raise ProtectedRouteError(f"invalid source receipt for {task_id}: {exc}") from exc
            if digest != requested_digests[task_id]:
                raise ProtectedRouteError(f"source result digest mismatch: {task_id}")

        tasks_path = f"openspec/changes/{change_id}/tasks.md"
        try:
            tasks_text = repo.read_path(request["baseCommit"], tasks_path).decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ProtectedRouteError("tasks.md is not strict UTF-8") from exc
        rows = parse_tasks_index(tasks_text)
        by_id = index_rows_by_id(rows)
        expected_sources: set[str] = set()
        for target in request["targetTransitions"]:
            row = by_id.get(target["taskId"])
            if row is None:
                raise ProtectedRouteError(f"route target is absent: {target['taskId']}")
            if row.status != "BLOCKED" or not is_unassigned_owner(row.owner):
                raise ProtectedRouteError(f"route target is not unassigned BLOCKED: {row.task_id}")
            expected_sources.update(split_deps(row.depends_on, by_id))
        if set(source_ids) != expected_sources:
            raise ProtectedRouteError("sourceResults are not the exact dependency denominator")
        for source_id in source_ids:
            row = by_id.get(source_id)
            if row is None or row.status != "DONE":
                raise ProtectedRouteError(f"route source is not DONE: {source_id}")

        updated = tasks_text
        for task_id in target_ids:
            updated, changed = update_tasks_md_text(updated, task_id, "-", "TODO")
            if not changed:
                raise ProtectedRouteError(f"route target could not be promoted: {task_id}")
        prepare_intent = store.read_receipt(request_id, "route-prepare-intent")
        if prepare_intent is None:
            prepare_intent = with_self_digest(
                {
                    "schema": "protected-route-prepare-intent/v1",
                    "requestId": request_id,
                    "requestDigest": request["recordDigest"],
                    "baseCommit": request["baseCommit"],
                    "taskPath": tasks_path,
                    "preparedAt": _timestamp(_now()),
                }
            )
            store.write_receipt(request_id, "route-prepare-intent", prepare_intent)
        elif prepare_intent["requestDigest"] != request["recordDigest"]:
            raise ProtectedRouteError("route prepare intent drift")
        prepared_at = prepare_intent["preparedAt"]
        candidate, _tree = repo.build_single_path_commit(
            base_commit=request["baseCommit"],
            path=tasks_path,
            content=updated.encode("utf-8"),
            message=f"chore(tasks): protected route {request_id}",
            timestamp=prepared_at,
            scratch_root=store.scratch_root,
        )
        result = with_self_digest(
            {
                "schema": "protected-route-result/v1",
                "requestId": request_id,
                "requestDigest": request["recordDigest"],
                "outcome": "prepared",
                "baseCommit": request["baseCommit"],
                "candidateCommit": candidate,
                "canonicalReadback": repo.head(),
                "approvalDigest": None,
                "verifiedRoleBindingsDigest": None,
                "completedAt": prepared_at,
            }
        )
        store.write_receipt(request_id, "route-request", request)
        store.write_receipt(request_id, "route-prepared", result)
        return result


def _accept_route_decision(
    *,
    store: ProtectedStateStore,
    request: dict[str, Any],
    prepared: dict[str, Any],
    approval: dict[str, Any],
    action: str,
    canonical_head: str,
    approval_verifier: RouteApprovalVerifier | None,
) -> str:
    store.registry.validate(approval)
    kind = f"route-decision-{action}"
    competing_kind = "route-decision-abort" if action == "publish" else "route-decision-publish"
    competing = store.read_receipt(request["requestId"], competing_kind)
    if competing is not None and action == "publish":
        raise ProtectedRouteError("a competing route abort was already accepted")
    existing = store.read_receipt(request["requestId"], kind)
    expected = {
        "action": action,
        "requestDigest": request["recordDigest"],
        "candidateCommit": prepared["candidateCommit"],
        "canonicalHead": canonical_head,
    }
    for field, value in expected.items():
        if approval[field] != value:
            raise ProtectedRouteError(f"route approval subject mismatch: {field}")
    if existing is not None:
        if existing["approvalDigest"] != approval["recordDigest"]:
            raise ProtectedRouteError("accepted route approval drift")
        return existing["verifiedRoleBindingsDigest"]
    issued = datetime.fromisoformat(approval["issuedAt"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(approval["expiresAt"].replace("Z", "+00:00"))
    if issued > _now() or _now() > expires:
        raise ProtectedRouteError("route approval is not currently valid")
    required = {"task_governance", "verifier"}
    if set(approval["requiredRoles"]) != required:
        raise ProtectedRouteError("route approval does not require the exact roles")
    if approval_verifier is None:
        raise ProtectedRouteError("an independent route approval verifier is required")
    bindings = approval_verifier(approval, expected)
    if not isinstance(bindings, Mapping) or set(bindings) != required:
        raise ProtectedRouteError("route verifier did not validate all required roles")
    identities = list(bindings.values())
    if any(not isinstance(value, str) or not value for value in identities) or len(set(identities)) != 2:
        raise ProtectedRouteError("route roles require distinct verified identities")
    role_digest = semantic_digest({"roleBindings": dict(sorted(bindings.items()))})
    intent = with_self_digest(
        {
            "schema": "protected-route-decision-intent/v1",
            "requestId": request["requestId"],
            "requestDigest": request["recordDigest"],
            "candidateCommit": prepared["candidateCommit"],
            "action": action,
            "canonicalHead": canonical_head,
            "approvalDigest": approval["recordDigest"],
            "verifiedRoleBindingsDigest": role_digest,
            "supersededDecisionDigest": competing["recordDigest"] if competing is not None else None,
            "acceptedAt": _timestamp(_now()),
        }
    )
    store.write_receipt(request["requestId"], kind, intent)
    return role_digest


def publish_route(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    request_id: str,
    approval: dict[str, Any],
    approval_verifier: RouteApprovalVerifier | None,
) -> dict[str, Any]:
    request = store.read_receipt(request_id, "route-request")
    prepared = store.read_receipt(request_id, "route-prepared")
    if request is None or prepared is None:
        raise ProtectedRouteError("prepared route not found")
    with store.change_lock(request["changeId"]):
        existing = store.read_receipt(request_id, "route-result")
        if existing is not None:
            return existing
        if "route_publish" not in store.policy()["allowedOperations"]:
            raise ProtectedRouteError("protected policy does not authorize route_publish")
        head = repo.head()
        if head not in {request["baseCommit"], prepared["candidateCommit"]}:
            raise ProtectedRouteError("route publication is fenced by canonical ref drift")
        role_digest = _accept_route_decision(
            store=store,
            request=request,
            prepared=prepared,
            approval=approval,
            action="publish",
            canonical_head=request["baseCommit"],
            approval_verifier=approval_verifier,
        )
        if head == request["baseCommit"]:
            repo.cas(old_commit=request["baseCommit"], new_commit=prepared["candidateCommit"])
        if repo.head() != prepared["candidateCommit"]:
            raise ProtectedRouteError("route canonical readback mismatch")
        result = with_self_digest(
            {
                "schema": "protected-route-result/v1",
                "requestId": request_id,
                "requestDigest": request["recordDigest"],
                "outcome": "published",
                "baseCommit": request["baseCommit"],
                "candidateCommit": prepared["candidateCommit"],
                "canonicalReadback": repo.head(),
                "approvalDigest": approval["recordDigest"],
                "verifiedRoleBindingsDigest": role_digest,
                "completedAt": _timestamp(_now()),
            }
        )
        store.write_receipt(request_id, "route-result", result)
        return result


def abort_route(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    request_id: str,
    approval: dict[str, Any],
    approval_verifier: RouteApprovalVerifier | None,
) -> dict[str, Any]:
    request = store.read_receipt(request_id, "route-request")
    prepared = store.read_receipt(request_id, "route-prepared")
    if request is None or prepared is None:
        raise ProtectedRouteError("prepared route not found")
    with store.change_lock(request["changeId"]):
        existing = store.read_receipt(request_id, "route-result")
        if existing is not None:
            return existing
        if "route_abort" not in store.policy()["allowedOperations"]:
            raise ProtectedRouteError("protected policy does not authorize route_abort")
        head = repo.head()
        if head == prepared["candidateCommit"]:
            raise ProtectedRouteError("route candidate is already canonical; publish recovery is required")
        role_digest = _accept_route_decision(
            store=store,
            request=request,
            prepared=prepared,
            approval=approval,
            action="abort",
            canonical_head=head,
            approval_verifier=approval_verifier,
        )
        result = with_self_digest(
            {
                "schema": "protected-route-result/v1",
                "requestId": request_id,
                "requestDigest": request["recordDigest"],
                "outcome": "aborted_pre_cas",
                "baseCommit": request["baseCommit"],
                "candidateCommit": prepared["candidateCommit"],
                "canonicalReadback": head,
                "approvalDigest": approval["recordDigest"],
                "verifiedRoleBindingsDigest": role_digest,
                "completedAt": _timestamp(_now()),
            }
        )
        store.write_receipt(request_id, "route-result", result)
        return result
