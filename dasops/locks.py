from __future__ import annotations

import os
import tempfile
import uuid
from dataclasses import dataclass, field
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
    update_tasks_md_text,
)


DEFAULT_LEASE_SECONDS = 3600


def _validate_id(name: str, value: str) -> None:
    """Reject ids containing path separators or parent-directory escapes."""
    if not value or ".." in value.split("/") or "/" in value or "\\" in value:
        raise SystemExit(f"Invalid {name}: {value!r} (must not contain path separators or '..')")


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
    return task_locks_dir(change_dir) / f"{task_id}.lock"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_lock(lock_path: Path) -> Optional[TaskLock]:
    if not lock_path.exists():
        return None
    try:
        data = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    required = {
        "version",
        "taskId",
        "owner",
        "status",
        "claimedAt",
        "updatedAt",
        "heartbeatAt",
        "leaseSeconds",
        "lockToken",
    }
    if not required.issubset(data):
        return None

    try:
        lock = TaskLock(
            version=int(data["version"]),
            task_id=str(data["taskId"]),
            owner=str(data["owner"]),
            status=str(data["status"]),
            claimed_at=str(data["claimedAt"]),
            updated_at=str(data["updatedAt"]),
            heartbeat_at=str(data["heartbeatAt"]),
            lease_seconds=int(data["leaseSeconds"]),
            lock_token=str(data["lockToken"]),
            audit_history=list(data.get("auditHistory") or []),
        )
        if lock.version < 1:
            return None
        if not lock.task_id.strip() or not lock.owner.strip() or not lock.lock_token.strip():
            return None
        if lock.lease_seconds <= 0:
            return None
        allowed_statuses = {"IN_PROGRESS", "DONE", "TODO", "BLOCKED", "PROPOSED"}
        if lock.status not in allowed_statuses:
            return None

        claimed = datetime.fromisoformat(lock.claimed_at)
        updated = datetime.fromisoformat(lock.updated_at)
        heartbeat = datetime.fromisoformat(lock.heartbeat_at)
        if claimed.tzinfo is None:
            claimed = claimed.replace(tzinfo=timezone.utc)
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        if updated < claimed:
            return None
        if heartbeat < claimed:
            return None
        return lock
    except Exception:
        return None


def write_lock(lock_path: Path, lock: TaskLock, *, must_create: bool = False) -> None:
    payload = {
        "version": lock.version,
        "taskId": lock.task_id,
        "owner": lock.owner,
        "status": lock.status,
        "claimedAt": lock.claimed_at,
        "updatedAt": lock.updated_at,
        "heartbeatAt": lock.heartbeat_at,
        "leaseSeconds": lock.lease_seconds,
        "lockToken": lock.lock_token,
    }
    if lock.audit_history:
        payload["auditHistory"] = lock.audit_history
    content = yaml.safe_dump(payload, sort_keys=False)
    if must_create:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            raise SystemExit(
                f"Lock file already exists (concurrent claim): {lock_path}\n"
                "Another worker may have just claimed this task."
            )
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
    else:
        _atomic_write_text(lock_path, content)


def _atomic_write_text(path: Path, content: str) -> None:
    """Replace a text file atomically within its existing filesystem."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def inspect_lock(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    expect_owner: str | None = None,
) -> dict[str, object]:
    _validate_id("change_id", change_id)
    _validate_id("task_id", task_id)
    change_dir = repo_root / "openspec" / "changes" / change_id
    lock_path = lock_path_for(change_dir, task_id)
    lock = read_lock(lock_path)
    return {
        "changeId": change_id,
        "taskId": task_id,
        "path": str(lock_path),
        "exists": lock is not None,
        "ownerMatches": bool(lock and expect_owner and lock.owner == expect_owner),
        "lock": {
            "version": lock.version,
            "taskId": lock.task_id,
            "owner": lock.owner,
            "status": lock.status,
            "claimedAt": lock.claimed_at,
            "updatedAt": lock.updated_at,
            "heartbeatAt": lock.heartbeat_at,
            "leaseSeconds": lock.lease_seconds,
            "lockToken": lock.lock_token,
        }
        if lock
        else None,
    }


def claim_task(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    owner: str,
    status: str = "IN_PROGRESS",
    force: bool = False,
) -> Path:
    _validate_id("change_id", change_id)
    _validate_id("task_id", task_id)
    change_dir = repo_root / "openspec" / "changes" / change_id
    if not change_dir.exists():
        raise SystemExit(f"Change folder not found: {change_dir}")

    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    lock_dir = task_locks_dir(change_dir)
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_path_for(change_dir, task_id)

    existing_lock = read_lock(lock_path)
    if existing_lock and existing_lock.owner != owner and not force:
        raise SystemExit(
            f"Task {task_id} is already claimed by '{existing_lock.owner}'.\n"
            f"Lock file: {lock_path}\n"
            "If this is a mistake, ask the Orchestrator to re-assign, or re-run with --force."
        )

    now = _utc_now()
    lock = TaskLock(
        version=2,
        task_id=task_id,
        owner=owner,
        status=status,
        claimed_at=existing_lock.claimed_at if existing_lock else now,
        updated_at=now,
        heartbeat_at=now,
        lease_seconds=existing_lock.lease_seconds if existing_lock else DEFAULT_LEASE_SECONDS,
        lock_token=existing_lock.lock_token if existing_lock else uuid.uuid4().hex,
        audit_history=existing_lock.audit_history if existing_lock else [],
    )

    created_lock = existing_lock is None
    if created_lock:
        # The O_EXCL claim is the linearization point.  Do it before changing
        # tasks.md so a losing worker cannot overwrite the winning owner.
        write_lock(lock_path, lock, must_create=True)

    try:
        # Re-read after acquiring a new lock: a different actor may have
        # changed the task while this claimant was waiting for the lock.
        tasks_md = tasks_path.read_text(encoding="utf-8")
        current_owner, _current_status = extract_task_owner_status(tasks_md, task_id)
        if current_owner and not is_unassigned_owner(current_owner) and current_owner != owner and not force:
            raise SystemExit(
                f"Task {task_id} owner mismatch.\n"
                f"- tasks.md owner: '{current_owner}'\n"
                f"- you requested:  '{owner}'\n"
                "Refusing to claim. Ask Orchestrator to re-assign, or re-run with --force (Orchestrator only)."
            )
        updated, changed = update_tasks_md_text(tasks_md, task_id, owner, status)
        if not changed:
            raise SystemExit(
                f"Task ID '{task_id}' not found in {tasks_path}.\n"
                "Refusing to claim. Orchestrator should add the task first."
            )
        _atomic_write_text(tasks_path, updated)
        if not created_lock:
            write_lock(lock_path, lock)
    except BaseException:
        if created_lock:
            acquired = read_lock(lock_path)
            if acquired is not None and acquired.lock_token == lock.lock_token:
                lock_path.unlink(missing_ok=True)
        raise
    return lock_path


def complete_task(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    owner: str,
    force: bool = False,
) -> Path:
    return claim_task(
        repo_root=repo_root,
        change_id=change_id,
        task_id=task_id,
        owner=owner,
        status="DONE",
        force=force,
    )


def release_task(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    owner: str,
    status: str = "TODO",
    clear_owner: bool = False,
    force: bool = False,
) -> Path:
    _validate_id("change_id", change_id)
    _validate_id("task_id", task_id)
    change_dir = repo_root / "openspec" / "changes" / change_id
    if not change_dir.exists():
        raise SystemExit(f"Change folder not found: {change_dir}")

    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    lock_path = lock_path_for(change_dir, task_id)
    lock = read_lock(lock_path)
    if lock is None:
        raise SystemExit(f"Lock not found (task is not claimed): {lock_path}")
    if lock.owner != owner and not force:
        raise SystemExit(
            f"Refusing to release {task_id}: lock is owned by '{lock.owner}', not '{owner}'.\n"
            f"Lock file: {lock_path}\n"
            "Use --force only if you are the Orchestrator and you intend to re-assign."
        )

    tasks_md = tasks_path.read_text(encoding="utf-8")
    current_owner, _current_status = extract_task_owner_status(tasks_md, task_id)
    desired_owner = "-" if clear_owner else (current_owner if current_owner else owner)
    updated, changed = update_tasks_md_text(tasks_md, task_id, desired_owner, status)
    if not changed:
        raise SystemExit(f"Task ID '{task_id}' not found in {tasks_path}.")
    tasks_path.write_text(updated, encoding="utf-8")
    lock_path.unlink()
    return lock_path


def claim_ready_task(
    *,
    repo_root: Path,
    change_id: str,
    owner: str,
    status: str = "IN_PROGRESS",
    allow_preassigned: bool = False,
) -> Optional[Path]:
    _validate_id("change_id", change_id)
    change_dir = repo_root / "openspec" / "changes" / change_id
    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    tasks_md = tasks_path.read_text(encoding="utf-8")
    rows = parse_tasks_index(tasks_md)
    by_id = index_rows_by_id(rows)

    for row in rows:
        if (row.status or "").strip().upper() != "TODO":
            continue
        if not allow_preassigned and row.owner and not is_unassigned_owner(row.owner):
            continue
        if read_lock(lock_path_for(change_dir, row.task_id)) is not None:
            continue

        blocked = False
        for dep in split_deps(row.depends_on):
            dep_row = by_id.get(dep)
            if dep_row is None or (dep_row.status or "").strip().upper() != "DONE":
                blocked = True
                break
        if blocked:
            continue

        try:
            return claim_task(
                repo_root=repo_root,
                change_id=change_id,
                task_id=row.task_id,
                owner=owner,
                status=status,
                force=False,
            )
        except SystemExit:
            continue
    return None


# ---------------------------------------------------------------------------
# Lock lifecycle: stale detection, renew, reclaim
# ---------------------------------------------------------------------------


def is_stale(lock: TaskLock) -> bool:
    """Return True if the lock's heartbeat is older than its lease window."""
    try:
        heartbeat = datetime.fromisoformat(lock.heartbeat_at)
    except (ValueError, TypeError):
        return True
    now = datetime.now(timezone.utc)
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    elapsed = (now - heartbeat).total_seconds()
    return elapsed > lock.lease_seconds


def renew_lock(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    owner: str,
    lock_token: str,
) -> Path:
    """Renew the heartbeat of an existing lock. Owner and token must match."""
    change_dir = repo_root / "openspec" / "changes" / change_id
    lock_file = lock_path_for(change_dir, task_id)
    lock = read_lock(lock_file)
    if lock is None:
        raise SystemExit(f"Lock not found for task {task_id}.")
    if lock.owner != owner:
        raise SystemExit(
            f"Owner mismatch: lock owned by '{lock.owner}', renewal requested by '{owner}'."
        )
    if lock.lock_token != lock_token:
        raise SystemExit("Lock token mismatch. Cannot renew.")

    now = _utc_now()
    renewed = TaskLock(
        version=lock.version,
        task_id=lock.task_id,
        owner=lock.owner,
        status=lock.status,
        claimed_at=lock.claimed_at,
        updated_at=now,
        heartbeat_at=now,
        lease_seconds=lock.lease_seconds,
        lock_token=lock.lock_token,
    )
    write_lock(lock_file, renewed)
    return lock_file


def reclaim_lock(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    new_owner: str,
    reason: str,
    force: bool = False,
) -> Path:
    """Reclaim a stale (or force-overridden) lock for a new owner."""
    change_dir = repo_root / "openspec" / "changes" / change_id
    if not change_dir.exists():
        raise SystemExit(f"Change folder not found: {change_dir}")

    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    lock_file = lock_path_for(change_dir, task_id)
    lock = read_lock(lock_file)
    if lock is None:
        raise SystemExit(f"Lock not found for task {task_id}. Nothing to reclaim.")

    if not force and not is_stale(lock):
        raise SystemExit(
            f"Lock for {task_id} is NOT stale (heartbeat: {lock.heartbeat_at}, "
            f"lease: {lock.lease_seconds}s). Use --force to override."
        )

    now = _utc_now()
    audit_history = list(lock.audit_history)
    audit_history.append(
        {
            "task": "OPS-003",
            "at": now,
            "reason": reason,
            "fromOwner": lock.owner,
            "toOwner": new_owner,
            "oldToken": lock.lock_token,
        }
    )
    reclaimed = TaskLock(
        version=lock.version + 1,
        task_id=lock.task_id,
        owner=new_owner,
        status="IN_PROGRESS",
        claimed_at=now,
        updated_at=now,
        heartbeat_at=now,
        lease_seconds=lock.lease_seconds,
        lock_token=uuid.uuid4().hex,
        audit_history=audit_history,
    )

    tasks_md = tasks_path.read_text(encoding="utf-8")
    updated, _ = update_tasks_md_text(tasks_md, task_id, new_owner, "IN_PROGRESS")
    tasks_path.write_text(updated, encoding="utf-8")
    write_lock(lock_file, reclaimed)
    return lock_file
