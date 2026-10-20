"""Local cooperative task coordination; fixed Markdown/YAML pair recovery.

This is not an authorization boundary and does not coordinate separate clones.
Readers never recover writes. A durable pending record is rolled forward exactly.
"""
from __future__ import annotations

import base64
try:
    import fcntl
except ImportError:  # Other CLI operations still work on unsupported platforms.
    fcntl = None
import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path


class StateError(SystemExit):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"task_state: {reason}")


MAX_STATE_BYTES = 16 * 1024 * 1024


def read_bytes(path: Path) -> bytes | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATE_BYTES:
        raise StateError("invalid_state_file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise StateError("invalid_state_file")
        data = stream.read(MAX_STATE_BYTES + 1)
    if len(data) > MAX_STATE_BYTES:
        raise StateError("state_size_limit")
    return data


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir(path: Path, mode: int = 0o700) -> None:
    if path.is_symlink():
        raise StateError("symlink_state_directory")
    if not path.exists():
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            pass
        _sync_dir(path.parent)
    if not path.is_dir():
        raise StateError("invalid_state_directory")


def _install(path: Path, data: bytes | None) -> None:
    _mkdir(path.parent)
    if data is None:
        path.unlink(missing_ok=True)
        _sync_dir(path.parent)
        return
    fd, name = tempfile.mkstemp(prefix=".task-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        _sync_dir(path.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def _image(data: bytes | None, *, payload: bool = False) -> dict:
    value = {"present": data is not None, "sha256": hashlib.sha256(data).hexdigest() if data is not None else None}
    if payload:
        value["data"] = base64.b64encode(data).decode("ascii") if data is not None else None
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate recovery field")
        result[key] = value
    return result


def _targets(change: Path, task_id: str) -> tuple[Path, Path]:
    if not isinstance(task_id, str) or not task_id or task_id in {".", ".."} or any(c in task_id for c in "/\\\x00"):
        raise StateError("invalid_recovery_task")
    return change / "tasks.md", change / "task_locks" / f"{task_id}.lock"


def recover(change: Path) -> bool:
    pending = change / ".dasops-local" / "pending.json"
    raw = read_bytes(pending)
    if raw is None:
        return False
    try:
        record = json.loads(raw, object_pairs_hook=_unique_object)
        if set(record) != {"version", "taskId", "transactionId", "operation", "targets"} or record["version"] != 1:
            raise ValueError("invalid recovery record")
        targets = _targets(change, record["taskId"])
        if not isinstance(record["targets"], list) or len(record["targets"]) != 2:
            raise ValueError("invalid fixed target pair")
        decoded = []
        for target, item in zip(targets, record["targets"]):
            if set(item) != {"before", "after"} or set(item["before"]) != {"present", "sha256"} or set(item["after"]) != {"present", "sha256", "data"}:
                raise ValueError("invalid recovery image")
            after = item["after"]
            data = base64.b64decode(after["data"], validate=True) if after["present"] is True else None
            if _image(data, payload=True) != after:
                raise ValueError("invalid recovery digest")
            current = _image(read_bytes(target))
            if current != item["before"] and current != _image(data):
                raise StateError("recovery_conflict")
            decoded.append((target, data))
        # Both images are validated. Re-establish the journal durability barrier
        # even on retry after a failed rename-directory fsync or pre-created meta.
        fd = os.open(pending, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _sync_dir(pending.parent)
        _sync_dir(change)
        # No target may change until the pending record and its parents are synced.
        for target, data in decoded:
            if read_bytes(target) != data:
                _install(target, data)
            else:
                if data is not None:
                    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                _sync_dir(target.parent)
        pending.unlink()
        _sync_dir(pending.parent)
        return True
    except StateError:
        raise
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise StateError("recovery_required") from exc


@contextmanager
def guard(change: Path, *, write: bool = False):
    if fcntl is None:
        raise StateError("unsupported_task_coordination_platform")
    if not change.is_dir() or change.is_symlink():
        raise StateError("missing_or_invalid_change")
    meta = change / ".dasops-local"
    _mkdir(meta)
    fd = os.open(meta / "coordination.guard", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise StateError("invalid_coordination_guard")
        fcntl.flock(fd, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
        if write:
            recover(change)
        elif read_bytes(meta / "pending.json") is not None:
            raise StateError("recovery_required")
        yield
    finally:
        os.close(fd)


def commit(change: Path, task_id: str, tasks: str, lock: bytes | None, operation: str) -> None:
    """Caller holds exclusive guard and has validated the latest snapshot."""
    import uuid

    paths = _targets(change, task_id)
    after = (tasks.encode("utf-8"), lock)
    record = {"version": 1, "taskId": task_id, "transactionId": uuid.uuid4().hex, "operation": operation,
              "targets": [{"before": _image(read_bytes(path)), "after": _image(data, payload=True)} for path, data in zip(paths, after)]}
    pending = change / ".dasops-local" / "pending.json"
    encoded = json.dumps(record, sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise StateError("recovery_record_size_limit")
    try:
        _install(pending, encoded)
        recover(change)
    except (OSError, StateError) as exc:
        if os.path.lexists(pending):
            raise StateError("recovery_required") from exc
        raise
