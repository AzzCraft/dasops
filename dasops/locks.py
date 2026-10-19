from __future__ import annotations

import os
import uuid
import re
import shlex
import subprocess
from . import legacy_task_state as state
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from .tasks import (
    extract_task_owner_status,
    index_rows_by_id,
    is_unassigned_owner,
    parse_tasks_index,
    split_deps,
    task_hints_from_text,
    update_tasks_md_text,
)


DEFAULT_LEASE_SECONDS = 3600


def _validate_id(name: str, value: str) -> None:
    """Reject ids containing path separators or parent-directory escapes."""
    if not value or value in {".", ".."} or any(ord(c) < 32 for c in value) or "/" in value or "\\" in value:
        raise SystemExit(f"Invalid {name}: {value!r} (must not contain path separators or '..')")


def _validate_owner(owner: str) -> None:
    if (not isinstance(owner, str) or not owner or owner != owner.strip()
            or is_unassigned_owner(owner) or "|" in owner
            or any(ord(c) < 32 or ord(c) == 127 for c in owner)):
        raise state.StateError("invalid_owner")


@dataclass(frozen=True)
class TaskLock:
    version: int
    task_id: str
    owner: str
    status: str
    claimed_at: str
    updated_at: str
    heartbeat_at: str
    lease_seconds: int
    lock_token: str
    audit_history: list[dict[str, object]] = field(default_factory=list)


def task_locks_dir(change_dir: Path) -> Path:
    return change_dir / "task_locks"


def lock_path_for(change_dir: Path, task_id: str) -> Path:
    _validate_id("task_id", task_id)
    return task_locks_dir(change_dir) / f"{task_id}.lock"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError("duplicate lock field")
        result[key] = loader.construct_object(value_node)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _read_lock_file(lock_path: Path) -> Optional[TaskLock]:
    raw = state.read_bytes(lock_path)
    if raw is None:
        return None
    try:
        data = yaml.load(raw, Loader=_UniqueLoader)
        required = {"version", "taskId", "owner", "status", "claimedAt", "updatedAt", "heartbeatAt", "leaseSeconds", "lockToken"}
        if not isinstance(data, dict) or not required.issubset(data) or set(data) - required - {"auditHistory"}:
            raise ValueError("invalid lock fields")
        if any(not isinstance(data[k], str) or not data[k].strip() for k in required - {"version", "leaseSeconds"}):
            raise ValueError("invalid lock strings")
        if any(type(data[k]) is not int or data[k] < 1 for k in ("version", "leaseSeconds")):
            raise ValueError("invalid lock counters")
        if data["taskId"] != lock_path.stem or data["status"] not in {"IN_PROGRESS", "DONE", "TODO", "BLOCKED", "PROPOSED"}:
            raise ValueError("invalid lock identity/status")
        history = data.get("auditHistory", [])
        if not isinstance(history, list) or not all(isinstance(x, dict) for x in history):
            raise ValueError("invalid lock history")
        times = [datetime.fromisoformat(data[k]) for k in ("claimedAt", "updatedAt", "heartbeatAt")]
        times = [x.replace(tzinfo=timezone.utc) if x.tzinfo is None else x for x in times]
        if times[1] < times[0] or times[2] < times[0]:
            raise ValueError("invalid lock times")
        return TaskLock(data["version"], data["taskId"], data["owner"], data["status"], data["claimedAt"], data["updatedAt"], data["heartbeatAt"], data["leaseSeconds"], data["lockToken"], history)
    except (ValueError, TypeError, KeyError, yaml.YAMLError, UnicodeError) as exc:
        raise state.StateError("invalid_lock") from exc


def _lock_bytes(lock: TaskLock) -> bytes:
    payload = {"version": lock.version, "taskId": lock.task_id, "owner": lock.owner, "status": lock.status,
               "claimedAt": lock.claimed_at, "updatedAt": lock.updated_at, "heartbeatAt": lock.heartbeat_at,
               "leaseSeconds": lock.lease_seconds, "lockToken": lock.lock_token}
    if lock.audit_history:
        payload["auditHistory"] = lock.audit_history
    return yaml.safe_dump(payload, sort_keys=False).encode("utf-8")


def write_lock(lock_path: Path, lock: TaskLock, *, must_create: bool = False) -> None:
    """Serialize fixtures; a managed change always uses its pair protocol."""
    change = lock_path.parent.parent
    if (change / "tasks.md").exists():
        with state.guard(change, write=True):
            text, rows, locks = _snapshot(change)
            row = rows.get(lock.task_id)
            if row is None or (row.owner, row.status) != (lock.owner, lock.status) or (must_create and lock.task_id in locks):
                raise state.StateError("invalid_lock_transition")
            state.commit(change, lock.task_id, text, _lock_bytes(lock), "write-lock")
        return
    if must_create and lock_path.exists():
        raise state.StateError("claim_conflict")
    state._install(lock_path, _lock_bytes(lock))


def _change(repo_root: Path, change_id: str, task_id: str | None = None) -> Path:
    _validate_id("change_id", change_id)
    if task_id is not None:
        _validate_id("task_id", task_id)
    return repo_root / "openspec" / "changes" / change_id


def _snapshot(change: Path):
    raw = state.read_bytes(change / "tasks.md")
    if raw is None:
        raise state.StateError("missing_tasks")
    text = raw.decode("utf-8")
    rows = parse_tasks_index(text)
    by_id = {r.task_id: r for r in rows}
    if len(by_id) != len(rows):
        raise state.StateError("duplicate_task")
    locks = {}
    lock_dir = task_locks_dir(change)
    if lock_dir.is_symlink():
        raise state.StateError("invalid_lock_directory")
    for path in sorted(lock_dir.glob("*.lock")):
        lock = _read_lock_file(path)
        row = by_id.get(lock.task_id)
        if row is None or row.owner != lock.owner or row.status != lock.status:
            raise state.StateError("inconsistent_task_state")
        locks[lock.task_id] = lock
    for row in rows:
        if row.status == "IN_PROGRESS" and row.task_id not in locks:
            raise state.StateError("inconsistent_task_state")
    return text, by_id, locks


def read_lock(lock_path: Path) -> Optional[TaskLock]:
    change = lock_path.parent.parent
    if not (change / "tasks.md").exists():
        return _read_lock_file(lock_path)  # standalone format parsing only
    with state.guard(change):
        _, _, locks = _snapshot(change)
        return locks.get(lock_path.stem)


def inspect_lock(*, repo_root: Path, change_id: str, task_id: str, expect_owner: str | None = None) -> dict[str, object]:
    change = _change(repo_root, change_id, task_id)
    path = lock_path_for(change, task_id)
    payload = {"changeId": change_id, "taskId": task_id, "path": str(path), "exists": os.path.lexists(path), "valid": False, "ownerMatches": False, "lock": None}
    try:
        with state.guard(change):
            payload["exists"] = os.path.lexists(path)
            _, _, locks = _snapshot(change)
            lock = locks.get(task_id)
            payload["valid"] = True
            if lock:
                payload["ownerMatches"] = bool(expect_owner and lock.owner == expect_owner)
                payload["lock"] = yaml.safe_load(_lock_bytes(lock))
    except state.StateError as exc:
        payload["error"] = exc.reason
    return payload


def _claim(change: Path, text: str, rows: dict, locks: dict, task_id: str, owner: str, force: bool):
    _validate_owner(owner)
    row = rows.get(task_id)
    if row is None or not owner.strip():
        raise state.StateError("missing_task_or_owner")
    existing = locks.get(task_id)
    if row.status == "DONE":
        raise state.StateError("completed_task_not_ready")
    if ((row.owner and not is_unassigned_owner(row.owner) and row.owner != owner) or (existing and existing.owner != owner)) and not force:
        raise state.StateError("owner_mismatch")
    now = _utc_now()
    changed_owner = bool(existing and existing.owner != owner)
    history = list(existing.audit_history) if existing else []
    if changed_owner:
        history.append({"operation": "forced-claim", "at": now, "fromOwner": existing.owner, "toOwner": owner, "oldToken": existing.lock_token})
    lock = TaskLock(existing.version + int(changed_owner) if existing else 2, task_id, owner, "IN_PROGRESS", existing.claimed_at if existing and not changed_owner else now, now, now,
                    existing.lease_seconds if existing else DEFAULT_LEASE_SECONDS,
                    existing.lock_token if existing and not changed_owner else uuid.uuid4().hex, history)
    updated, _ = update_tasks_md_text(text, task_id, owner, "IN_PROGRESS")
    state.commit(change, task_id, updated, _lock_bytes(lock), "claim")
    return lock_path_for(change, task_id), task_hints_from_text(updated, change / "tasks.md", task_id)


def claim_task(*, repo_root: Path, change_id: str, task_id: str, owner: str, status: str = "IN_PROGRESS", force: bool = False) -> Path:
    return claim_task_with_result(repo_root=repo_root, change_id=change_id, task_id=task_id,
                                  owner=owner, status=status, force=force)[0]


def claim_task_with_result(*, repo_root: Path, change_id: str, task_id: str, owner: str, status: str = "IN_PROGRESS", force: bool = False):
    change = _change(repo_root, change_id, task_id)
    if status != "IN_PROGRESS":
        raise state.StateError("claim_requires_in_progress; use complete-task for DONE")
    with state.guard(change, write=True):
        return _claim(change, *_snapshot(change), task_id, owner, force)


def claim_ready_task(*, repo_root: Path, change_id: str, owner: str, status: str = "IN_PROGRESS", allow_preassigned: bool = False) -> Optional[Path]:
    result = claim_ready_task_with_result(repo_root=repo_root, change_id=change_id, owner=owner,
                                          status=status, allow_preassigned=allow_preassigned)
    return result[0] if result is not None else None


def claim_ready_task_with_result(*, repo_root: Path, change_id: str, owner: str, status: str = "IN_PROGRESS", allow_preassigned: bool = False):
    change = _change(repo_root, change_id)
    if status != "IN_PROGRESS":
        raise state.StateError("claim_requires_in_progress")
    with state.guard(change, write=True):
        text, rows, locks = _snapshot(change)
        for row in rows.values():
            if row.status != "TODO" or row.task_id in locks:
                continue
            if not is_unassigned_owner(row.owner) and (not allow_preassigned or row.owner != owner):
                continue
            if any(dep not in rows or rows[dep].status != "DONE" for dep in split_deps(row.depends_on)):
                continue
            return _claim(change, text, rows, locks, row.task_id, owner, False)
    return None


def release_task(*, repo_root: Path, change_id: str, task_id: str, owner: str, status: str = "TODO", clear_owner: bool = False, force: bool = False) -> Path:
    change = _change(repo_root, change_id, task_id)
    if status not in {"TODO", "BLOCKED", "PROPOSED"}:
        raise state.StateError("invalid_release_status; use complete-task for DONE")
    with state.guard(change, write=True):
        text, rows, locks = _snapshot(change)
        lock = locks.get(task_id)
        if lock is None or (lock.owner != owner and not force):
            raise state.StateError("missing_lock_or_owner_mismatch")
        updated, _ = update_tasks_md_text(text, task_id, "-" if clear_owner else rows[task_id].owner, status)
        state.commit(change, task_id, updated, None, "release")
    return lock_path_for(change, task_id)


def is_stale(lock: TaskLock) -> bool:
    if lock.status == "DONE":
        return False
    try:
        heartbeat = datetime.fromisoformat(lock.heartbeat_at)
    except (ValueError, TypeError):
        return True
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - heartbeat).total_seconds() > lock.lease_seconds


def renew_lock(*, repo_root: Path, change_id: str, task_id: str, owner: str, lock_token: str) -> Path:
    change = _change(repo_root, change_id, task_id)
    with state.guard(change, write=True):
        text, _, locks = _snapshot(change)
        lock = locks.get(task_id)
        if lock is None or lock.status != "IN_PROGRESS" or is_stale(lock) or lock.owner != owner or lock.lock_token != lock_token:
            raise state.StateError("renewal_identity_mismatch")
        now = _utc_now()
        renewed = replace(lock, updated_at=now, heartbeat_at=now)
        state.commit(change, task_id, text, _lock_bytes(renewed), "renew")
    return lock_path_for(change, task_id)


def reclaim_lock_with_result(*, repo_root: Path, change_id: str, task_id: str, new_owner: str, reason: str, force: bool = False):
    _validate_owner(new_owner)
    change = _change(repo_root, change_id, task_id)
    if not reason.strip() or not new_owner.strip():
        raise state.StateError("reclaim_requires_owner_and_reason")
    with state.guard(change, write=True):
        text, _, locks = _snapshot(change)
        lock = locks.get(task_id)
        if lock is None or lock.status != "IN_PROGRESS" or (not force and not is_stale(lock)):
            raise state.StateError("lock_not_reclaimable")
        now = _utc_now()
        history = list(lock.audit_history) + [{"task": "OPS-003", "at": now, "reason": reason, "fromOwner": lock.owner, "toOwner": new_owner, "oldToken": lock.lock_token}]
        reclaimed = replace(lock, version=lock.version+1, owner=new_owner, claimed_at=now, updated_at=now, heartbeat_at=now, lock_token=uuid.uuid4().hex, audit_history=history)
        updated, _ = update_tasks_md_text(text, task_id, new_owner, "IN_PROGRESS")
        state.commit(change, task_id, updated, _lock_bytes(reclaimed), "reclaim")
        return lock_path_for(change, task_id), lock, reclaimed


def reclaim_lock(**kwargs) -> Path:
    return reclaim_lock_with_result(**kwargs)[0]


def _completion_subject(change: Path, task_id: str, owner: str, force: bool):
    _validate_owner(owner)
    text, rows, locks = _snapshot(change)
    row, lock = rows.get(task_id), locks.get(task_id)
    if row is None or row.status == "DONE":
        raise state.StateError("missing_or_completed_task")
    if not owner.strip() or (not is_unassigned_owner(row.owner) and row.owner != owner and not force):
        raise state.StateError("completion_owner_mismatch")
    if lock and (lock.status != "IN_PROGRESS" or is_stale(lock) or (lock.owner != owner and not force)):
        raise state.StateError("completion_requires_current_lease")
    if any(dep not in rows or rows[dep].status != "DONE" for dep in split_deps(row.depends_on)):
        raise state.StateError("completion_dependency_not_done")
    return text, row, lock


def complete_task(*, repo_root: Path, change_id: str, task_id: str, owner: str, force: bool = False, record_only: bool = False, reason: str = "") -> Path:
    change = _change(repo_root, change_id, task_id)
    with state.guard(change, write=True):
        _, row, lock = _completion_subject(change, task_id, owner, force)
        subject = (row, lock.lock_token if lock else None)
        if record_only:
            if not reason.strip():
                raise state.StateError("record_only_requires_reason")
            command, argv = "", []
        else:
            command = row.verify_gate.strip()
            if command.startswith("`") and command.endswith("`"):
                command = command[1:-1].strip()
            try:
                argv = shlex.split(command)
            except ValueError as exc:
                raise state.StateError("invalid_verify_gate") from exc
            if not argv or any(x in {"|", "||", "&&", ";", ">", ">>", "<"} for x in argv):
                raise state.StateError("invalid_verify_gate")
    # The gate can heartbeat and update other tasks. Never run it under guard.
    if not record_only:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            result = subprocess.run(argv, cwd=repo_root, env=env, capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise state.StateError("verification_execution_failed") from exc
        if result.returncode:
            raise state.StateError(f"verification_failed_exit_{result.returncode}")
    with state.guard(change, write=True):
        text, current_row, current = _completion_subject(change, task_id, owner, force)
        if (current_row, current.lock_token if current else None) != subject:
            raise state.StateError("completion_subject_changed")
        now = _utc_now()
        history = list(current.audit_history) if current else []
        history.append({"operation": "complete", "at": now, "verification": "not_run" if record_only else "pass", "command": command, "reason": reason if record_only else "", "exitCode": None if record_only else 0})
        completed = TaskLock(current.version if current else 2, task_id, owner, "DONE", current.claimed_at if current else now, now, now,
                             current.lease_seconds if current else DEFAULT_LEASE_SECONDS, current.lock_token if current else uuid.uuid4().hex, history)
        updated, _ = update_tasks_md_text(text, task_id, owner, "DONE")
        state.commit(change, task_id, updated, _lock_bytes(completed), "complete")
    return lock_path_for(change, task_id)
