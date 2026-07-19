"""DAS-03-009 dasops task lock with heartbeat / lease / stale recovery.

Hermetic, stdlib only. Filesystem-backed: each task lock lives at
``<root>/<taskId>.lock.json`` and stores ``{lockToken, leaseSeconds,
acquiredAt, heartbeatAt, owner}``. Stale locks (heartbeatAt + leaseSeconds
in the past) are automatically reclaimable.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_LEASE_SECONDS = 300


@dataclass
class Lock:
    taskId: str
    lockToken: str
    owner: str
    leaseSeconds: int
    acquiredAt: float
    heartbeatAt: float

    def is_stale(self, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        return (self.heartbeatAt + self.leaseSeconds) < now


class LockConflict(RuntimeError):
    """Another live owner already holds the lock."""


class InvalidToken(RuntimeError):
    """Caller provided a token that doesn't match the current lock."""


def _path(root: Path, task_id: str) -> Path:
    return root / f"{task_id}.lock.json"


def _read(path: Path) -> Lock | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text("utf-8"))
    except json.JSONDecodeError:
        return None
    return Lock(**data)


def _write(path: Path, lock: Lock) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(asdict(lock), indent=2), encoding="utf-8")
    os.replace(tmp, path)


def acquire(
    root: Path,
    task_id: str,
    owner: str,
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    now: float | None = None,
) -> Lock:
    """Acquire a lock; reclaims if existing lock is stale."""
    now = now if now is not None else time.time()
    path = _path(root, task_id)
    existing = _read(path)
    if existing and not existing.is_stale(now):
        raise LockConflict(
            f"task {task_id!r} held by {existing.owner!r} until "
            f"{existing.heartbeatAt + existing.leaseSeconds:.0f}"
        )
    lock = Lock(
        taskId=task_id,
        lockToken=secrets.token_hex(16),
        owner=owner,
        leaseSeconds=lease_seconds,
        acquiredAt=now,
        heartbeatAt=now,
    )
    _write(path, lock)
    return lock


def heartbeat(root: Path, task_id: str, lock_token: str, *, now: float | None = None) -> Lock:
    """Refresh the heartbeat timestamp; raises if token doesn't match."""
    now = now if now is not None else time.time()
    path = _path(root, task_id)
    existing = _read(path)
    if existing is None:
        raise InvalidToken(f"no lock for {task_id!r}")
    if existing.lockToken != lock_token:
        raise InvalidToken(f"wrong lockToken for {task_id!r}")
    existing.heartbeatAt = now
    _write(path, existing)
    return existing


def release(root: Path, task_id: str, lock_token: str) -> None:
    path = _path(root, task_id)
    existing = _read(path)
    if existing is None:
        return
    if existing.lockToken != lock_token:
        raise InvalidToken(f"wrong lockToken for {task_id!r}")
    path.unlink()


def reclaim_stale(root: Path, *, now: float | None = None) -> list[str]:
    """Remove stale lock files; returns list of reclaimed task IDs."""
    now = now if now is not None else time.time()
    reclaimed: list[str] = []
    if not root.is_dir():
        return reclaimed
    for path in root.glob("*.lock.json"):
        lock = _read(path)
        if lock and lock.is_stale(now):
            path.unlink()
            reclaimed.append(lock.taskId)
    return reclaimed
