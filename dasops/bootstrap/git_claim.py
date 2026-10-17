from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
import re
import subprocess
from typing import Iterator

from dasops.protected.canonical import semantic_digest


OID = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


class GitClaimPublisherError(RuntimeError):
    pass


class GitCanonicalClaimPublisher:
    """Cooperative exact-base claim publisher for the old non-bare repository."""

    def __init__(self, repository: str | Path, *, authority_root: str | Path) -> None:
        supplied = Path(repository).expanduser()
        if not supplied.is_absolute() or supplied.is_symlink():
            raise GitClaimPublisherError("claim repository must be an absolute non-symlink path")
        self.path = supplied.resolve()
        if str(self.path) != str(supplied) or not self.path.is_dir() or os.stat(self.path).st_uid != os.getuid():
            raise GitClaimPublisherError("claim repository identity or ownership is invalid")
        top = self._git("rev-parse", "--show-toplevel", max_bytes=4096).decode().strip()
        bare = self._git("rev-parse", "--is-bare-repository", max_bytes=64).decode().strip()
        git_directory = Path(
            self._git("rev-parse", "--absolute-git-dir", max_bytes=4096).decode().strip()
        )
        expected_git_directory = self.path / ".git"
        if (
            top != str(self.path)
            or bare != "false"
            or git_directory != expected_git_directory
            or expected_git_directory.is_symlink()
            or not expected_git_directory.is_dir()
            or os.stat(expected_git_directory).st_uid != os.getuid()
        ):
            raise GitClaimPublisherError("claim repository is not the exact owner-controlled non-bare top level")
        self.object_format = self._git("rev-parse", "--show-object-format", max_bytes=64).decode().strip()
        if self.object_format not in {"sha1", "sha256"}:
            raise GitClaimPublisherError("claim repository object format is unsupported")
        authority = Path(authority_root).expanduser()
        if not authority.is_absolute() or authority.is_symlink() or str(authority.resolve(strict=False)) != str(authority):
            raise GitClaimPublisherError("claim publisher authority root must be normalized and absolute")
        authority.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(authority, 0o700)
        if os.stat(authority).st_uid != os.getuid():
            raise GitClaimPublisherError("claim publisher authority root is not owner controlled")
        self.authority_root = authority
        locks = authority / "locks"
        locks.mkdir(mode=0o700, exist_ok=True)
        os.chmod(locks, 0o700)
        self.repository_id = semantic_digest(
            {
                "schema": "canonical-claim-repository-identity/v1",
                "path": str(self.path),
                "gitDirectory": str(expected_git_directory),
                "objectFormat": self.object_format,
            }
        )

    def _git(self, *args: str, max_bytes: int = 1_048_576) -> bytes:
        process = subprocess.run(
            ["git", "-C", str(self.path), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        if process.returncode != 0:
            raise GitClaimPublisherError(f"claim Git operation failed: {args[0]}")
        if len(process.stdout) > max_bytes or len(process.stderr) > max_bytes:
            raise GitClaimPublisherError("claim Git operation exceeded its output budget")
        return process.stdout

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        path = self.authority_root / "locks" / f"{self.repository_id[7:]}.lock"
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _oid(self, value: str, label: str) -> str:
        expected_length = 40 if self.object_format == "sha1" else 64
        if not isinstance(value, str) or not OID.fullmatch(value) or len(value) != expected_length:
            raise GitClaimPublisherError(f"claim {label} is not a full {self.object_format} object ID")
        return value

    def head(self) -> str:
        return self._git("rev-parse", "--verify", "refs/heads/main", max_bytes=256).decode().strip()

    def cas(self, *, old_commit: str, new_commit: str) -> None:
        old = self._oid(old_commit, "old commit")
        new = self._oid(new_commit, "new commit")
        if old == new:
            raise GitClaimPublisherError("claim candidate must differ from its base")
        with self._lock():
            if self.head() != old:
                raise GitClaimPublisherError("claim main changed before exact-base CAS")
            lines = self._git("show", "-s", "--format=%T%n%P", new, max_bytes=1024).decode().splitlines()
            if len(lines) != 2 or lines[1].split() != [old]:
                raise GitClaimPublisherError("claim candidate is not a single-parent child of exact base")
            observed = self._git("rev-parse", "--verify", f"{new}^{{commit}}", max_bytes=256).decode().strip()
            if observed != new:
                raise GitClaimPublisherError("claim candidate commit identity readback failed")
            self._git("update-ref", "refs/heads/main", new, old, max_bytes=1024)
            if self.head() != new:
                raise GitClaimPublisherError("claim exact-base CAS readback failed")
