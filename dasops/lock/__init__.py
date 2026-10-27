"""DAS-03-009 dasops task lock with heartbeat / lease / stale recovery.

Hermetic, stdlib only. Filesystem-backed: each task lock lives at
``<root>/<taskId>.lock.json`` and stores ``{lockToken, leaseSeconds,
acquiredAt, heartbeatAt, owner}``. Stale locks (heartbeatAt + leaseSeconds
in the past) are automatically reclaimable.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from ..identities import validate_id

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
        now = _timestamp(now if now is not None else time.time())
        return (self.heartbeatAt + self.leaseSeconds) < now


class LockConflict(RuntimeError):
    """Another live owner already holds the lock."""


class InvalidToken(RuntimeError):
    """Caller provided a token that doesn't match the current lock."""


def _path(root: Path, task_id: str) -> Path:
    validate_id('task_id', task_id)
    return root / f"{task_id}.lock.json"


def _timestamp(value):
    try:
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError('invalid timestamp')
    except OverflowError as exc:
        raise ValueError('invalid timestamp') from exc
    return value


def _validated(data, path):
    fields = {"taskId", "lockToken", "owner", "leaseSeconds", "acquiredAt", "heartbeatAt"}
    if not isinstance(data, dict) or set(data) != fields:
        raise ValueError("invalid fields")
    if any(not isinstance(data[k], str) or not data[k].strip() for k in ("taskId", "lockToken", "owner")):
        raise ValueError("invalid identity")
    validate_id('task_id', data['taskId'])
    if path.name != data["taskId"] + ".lock.json":
        raise ValueError("taskId does not match record filename")
    if type(data["leaseSeconds"]) is not int or data["leaseSeconds"] <= 0:
        raise ValueError("invalid lease")
    for key in ("acquiredAt", "heartbeatAt"):
        _timestamp(data[key])
    return Lock(**data)


def _read(path: Path) -> Lock | None:
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"invalid lock record: {path}")
    try:
        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate field: {key}")
                result[key] = value
            return result
        data = json.loads(path.read_text("utf-8"), object_pairs_hook=unique_fields)
        return _validated(data, path)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid lock record {path}: {exc}") from exc


def _write(path: Path, lock: Lock) -> None:
    _validated(asdict(lock), path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.dasops-lock-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(json.dumps(asdict(lock), indent=2, allow_nan=False))
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def acquire(
    root: Path,
    task_id: str,
    owner: str,
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    now: float | None = None,
) -> Lock:
    """Acquire a lock; reclaims if existing lock is stale."""
    now = _timestamp(now if now is not None else time.time())
    path = _path(root, task_id)
    lock = Lock(
        taskId=task_id,
        lockToken=secrets.token_hex(16),
        owner=owner,
        leaseSeconds=lease_seconds,
        acquiredAt=now,
        heartbeatAt=now,
    )
    _validated(asdict(lock), path)
    existing = _read(path)
    if existing and not existing.is_stale(now):
        raise LockConflict(
            f"task {task_id!r} held by {existing.owner!r} until "
            f"{existing.heartbeatAt + existing.leaseSeconds:.0f}"
        )
    _write(path, lock)
    return lock


def heartbeat(root: Path, task_id: str, lock_token: str, *, now: float | None = None) -> Lock:
    """Refresh the heartbeat timestamp; raises if token doesn't match."""
    now = _timestamp(now if now is not None else time.time())
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
    now = _timestamp(now if now is not None else time.time())
    reclaimed: list[str] = []
    if not root.is_dir():
        return reclaimed
    for path in root.glob("*.lock.json"):
        lock = _read(path)
        if lock and lock.is_stale(now):
            path.unlink()
            reclaimed.append(lock.taskId)
    return reclaimed
