from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
import re
import stat
from functools import wraps
from typing import Any, Iterator

from .canonical import canonical_bytes, load_canonical_json
from .git_canonical import BareCanonicalRepo
from .schema_registry import SchemaRegistry, SchemaValidationError


SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class StateStoreError(RuntimeError):
    pass


def _legacy_writer(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with self.writer_guard():
            return method(self, *args, **kwargs)
    return guarded


def _safe_id(kind: str, value: str) -> str:
    if not SAFE_ID_RE.fullmatch(value):
        raise StateStoreError(f"unsafe {kind}: {value!r}")
    return value


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600, create_only: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise StateStoreError(f"refusing symlinked state directory: {path.parent}")
    temp = path.parent / f".{path.name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if create_only and path.exists():
        temp.unlink(missing_ok=True)
        raise StateStoreError(f"immutable state object already exists: {path}")
    os.replace(temp, path)
    os.chmod(path, mode)
    _fsync_directory(path.parent)


class ProtectedStateStore:
    def __init__(self, repo: BareCanonicalRepo) -> None:
        self.repo = repo
        self.root = repo.path / "das-task-state"
        self.registry = SchemaRegistry()

    def initialize(self, policy: dict[str, Any]) -> None:
        if os.path.lexists(self.root / "migration.json"):
            raise StateStoreError("legacy authority is permanently fenced for migration")
        self.registry.validate(policy, verify_digest=False)
        if Path(policy["canonicalRepoPath"]).expanduser().resolve() != self.repo.path:
            raise StateStoreError("policy canonicalRepoPath does not match the bare repository")
        if policy["canonicalRef"] != self.repo.canonical_ref:
            raise StateStoreError("policy canonicalRef mismatch")
        operations = policy["allowedOperations"]
        if operations != sorted(set(operations)):
            raise StateStoreError("policy allowedOperations must be sorted and unique")
        if policy["leaseSecondsMin"] > policy["leaseSecondsMax"]:
            raise StateStoreError("policy lease bounds are inverted")
        self.root.mkdir(mode=0o700, parents=False, exist_ok=True)
        os.chmod(self.root, 0o700)
        if os.stat(self.root).st_uid != os.getuid():
            raise StateStoreError("task-state root is not owner controlled")
        policy_path = self.root / "policy.json"
        encoded = canonical_bytes(policy)
        if policy_path.exists():
            if policy_path.read_bytes() != encoded:
                raise StateStoreError("protected policy is immutable and already differs")
        else:
            atomic_write(policy_path, encoded, create_only=True)
        for name in ("locks", "operations", "states", "receipts", "challenges", "scratch"):
            directory = self.root / name
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        _fsync_directory(self.root)

    def policy(self) -> dict[str, Any]:
        path = self.root / "policy.json"
        if not path.is_file() or stat.S_IMODE(os.stat(path).st_mode) != 0o600:
            raise StateStoreError("protected policy is absent or not mode 0600")
        value = load_canonical_json(path.read_bytes())
        self.registry.validate(value, verify_digest=False)
        return value

    @contextlib.contextmanager
    def writer_guard(self, *, migration: bool = False) -> Iterator[None]:
        """Shared old-entry barrier; exclusive migration never waits on a writer.

        Installation must also stop old binaries/raw Git or filesystem writers.
        This cooperating library guard cannot revoke their OS capabilities.
        """
        path = self.root / "locks" / ".migration.lock"
        if self.root.resolve() != self.root or path.parent.resolve() != path.parent:
            raise StateStoreError("legacy authority directories must not be aliases")
        for directory in (self.root, path.parent):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise StateStoreError("legacy authority directories must be private")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
                raise StateStoreError("legacy migration barrier must be private and owner controlled")
            try:
                fcntl.flock(fd, (fcntl.LOCK_EX if migration else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise StateStoreError("legacy writer busy; retry the entire migration") from exc
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise StateStoreError("legacy migration barrier identity changed")
            if not migration and os.path.lexists(self.root / "migration.json"):
                raise StateStoreError("legacy authority is permanently fenced for migration")
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @contextlib.contextmanager
    def change_lock(self, change_id: str) -> Iterator[None]:
        with self.writer_guard():
            with self._change_lock(change_id):
                yield

    @contextlib.contextmanager
    def _change_lock(self, change_id: str) -> Iterator[None]:
        change = _safe_id("change id", change_id)
        path = self.root / "locks" / f"{change}.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def operation_dir(self, operation_id: str) -> Path:
        return self.root / "operations" / _safe_id("operation id", operation_id)

    @_legacy_writer
    def append_wal(self, value: dict[str, Any]) -> Path:
        self.registry.validate(value)
        operation_id = _safe_id("operation id", value["operationId"])
        phase = _safe_id("WAL phase", value["phase"])
        path = self.operation_dir(operation_id) / f"{phase}.json"
        encoded = canonical_bytes(value)
        if path.exists():
            if path.read_bytes() != encoded:
                raise StateStoreError(f"WAL phase drift for {operation_id}/{phase}")
            return path
        atomic_write(path, encoded, create_only=True)
        return path

    def wal(self, operation_id: str, phase: str) -> dict[str, Any] | None:
        path = self.operation_dir(operation_id) / f"{_safe_id('WAL phase', phase)}.json"
        if not path.exists():
            return None
        value = load_canonical_json(path.read_bytes())
        self.registry.validate(value)
        return value

    def state_path(self, change_id: str, task_id: str) -> Path:
        return self.root / "states" / _safe_id("change id", change_id) / f"{_safe_id('task id', task_id)}.json"

    @_legacy_writer
    def write_state(self, value: dict[str, Any]) -> Path:
        self.registry.validate(value)
        path = self.state_path(value["changeId"], value["taskId"])
        atomic_write(path, canonical_bytes(value))
        return path

    def read_state(self, change_id: str, task_id: str) -> dict[str, Any] | None:
        path = self.state_path(change_id, task_id)
        if not path.exists():
            return None
        value = load_canonical_json(path.read_bytes())
        self.registry.validate(value)
        return value

    def receipt_path(self, operation_id: str, kind: str) -> Path:
        return self.root / "receipts" / _safe_id("operation id", operation_id) / f"{_safe_id('receipt kind', kind)}.json"

    @_legacy_writer
    def write_receipt(self, operation_id: str, kind: str, value: dict[str, Any]) -> Path:
        self.registry.validate(value)
        path = self.receipt_path(operation_id, kind)
        encoded = canonical_bytes(value)
        if path.exists():
            if path.read_bytes() != encoded:
                raise StateStoreError(f"receipt drift for {operation_id}/{kind}")
            return path
        atomic_write(path, encoded, create_only=True)
        return path

    def read_receipt(self, operation_id: str, kind: str) -> dict[str, Any] | None:
        path = self.receipt_path(operation_id, kind)
        if not path.exists():
            return None
        value = load_canonical_json(path.read_bytes())
        self.registry.validate(value)
        return value

    def challenge_path(self, challenge_id: str) -> Path:
        return self.root / "challenges" / f"{_safe_id('challenge id', challenge_id)}.json"

    @_legacy_writer
    def write_challenge(self, value: dict[str, Any]) -> Path:
        self.registry.validate(value)
        path = self.challenge_path(value["challengeId"])
        atomic_write(path, canonical_bytes(value), create_only=True)
        return path

    def read_challenge(self, challenge_id: str) -> dict[str, Any]:
        path = self.challenge_path(challenge_id)
        if not path.is_file():
            raise StateStoreError("activation challenge not found")
        value = load_canonical_json(path.read_bytes())
        self.registry.validate(value)
        return value

    @property
    def scratch_root(self) -> Path:
        return self.root / "scratch"
