from __future__ import annotations

import contextlib
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Iterator

from dasops.protected.canonical import canonical_bytes, load_canonical_json, semantic_digest, with_self_digest
from dasops.protected.state_store import atomic_write

from .schema_registry import BootstrapSchemaRegistry


class GitAdoptionError(RuntimeError):
    pass


class GitAdoptionRepository:
    """Cooperative-profile real Git adapter for one adoption endpoint."""

    def __init__(
        self,
        repository: str | Path,
        *,
        role: str,
        authority_root: str | Path,
        effective_at: str,
        candidate_source: str | Path | None = None,
    ) -> None:
        if role not in {"old_bootstrap", "new_canonical"}:
            raise GitAdoptionError("Git adoption repository role is invalid")
        self.path = self._owned_path(repository, "repository")
        self.role = role
        self.effective_at = effective_at
        self.registry = BootstrapSchemaRegistry()
        authority = Path(authority_root).expanduser()
        if (
            not authority.is_absolute()
            or authority.is_symlink()
            or str(authority.resolve(strict=False)) != str(authority)
        ):
            raise GitAdoptionError("Git adoption authority root must be normalized and absolute")
        authority.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(authority, 0o700)
        if os.stat(authority).st_uid != os.getuid():
            raise GitAdoptionError("Git adoption authority root is not owner controlled")
        self.authority_root = authority
        for name in ("locks", "repository-state"):
            directory = authority / name
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        self.object_format = self._git("rev-parse", "--show-object-format", max_bytes=64).decode().strip()
        if self.object_format not in {"sha1", "sha256"}:
            raise GitAdoptionError("Git adoption repository object format is unsupported")
        self.repository_id = semantic_digest(
            {
                "schema": "canonical-repository-identity/v1",
                "path": str(self.path),
                "objectFormat": self.object_format,
            }
        )
        self.candidate_source = (
            None if candidate_source is None else self._owned_path(candidate_source, "candidate source")
        )
        if self.role == "old_bootstrap":
            top = self._git("rev-parse", "--show-toplevel", max_bytes=4096).decode().strip()
            if top != str(self.path):
                raise GitAdoptionError("old bootstrap repository is not its Git top level")
        else:
            bare = self._git("rev-parse", "--is-bare-repository", max_bytes=64).decode().strip()
            git_dir = Path(self._git("rev-parse", "--absolute-git-dir", max_bytes=4096).decode().strip())
            if bare != "true" or git_dir != self.path:
                raise GitAdoptionError("new canonical repository is not the exact bare Git directory")
            if self.candidate_source is None:
                raise GitAdoptionError("new canonical repository requires an explicit candidate source")
        self._lock_depth = 0

    @staticmethod
    def _owned_path(value: str | Path, label: str) -> Path:
        supplied = Path(value).expanduser()
        if not supplied.is_absolute() or supplied.is_symlink():
            raise GitAdoptionError(f"Git adoption {label} must be an absolute non-symlink path")
        resolved = supplied.resolve()
        if str(resolved) != str(supplied) or not resolved.is_dir() or os.stat(resolved).st_uid != os.getuid():
            raise GitAdoptionError(f"Git adoption {label} identity or ownership is invalid")
        return resolved

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
            raise GitAdoptionError(f"Git adoption operation failed: {args[0]}")
        if len(process.stdout) > max_bytes or len(process.stderr) > max_bytes:
            raise GitAdoptionError("Git adoption operation exceeded its output budget")
        return process.stdout

    @property
    def _state_path(self) -> Path:
        return self.authority_root / "repository-state" / f"{self.repository_id[7:]}.json"

    def _implicit_state(self) -> dict[str, Any]:
        return with_self_digest(
            {
                "schema": "git-adoption-repository-state/v1",
                "repositoryId": self.repository_id,
                "repositoryPath": str(self.path),
                "role": self.role,
                "generation": 0,
                "drained": False,
                "fenced": False,
                "fenceMode": "open",
                "updatedAt": None,
            }
        )

    def _state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return self._implicit_state()
        before = os.lstat(self._state_path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
        ):
            raise GitAdoptionError("Git adoption state is not owner-controlled mode 0600")
        value = load_canonical_json(self._state_path.read_bytes())
        self.registry.validate(value)
        if value["repositoryId"] != self.repository_id or value["role"] != self.role:
            raise GitAdoptionError("Git adoption state repository binding drift")
        return value

    def _write_state(self, current: dict[str, Any], **changes: Any) -> dict[str, Any]:
        subject = deepcopy(current)
        subject.pop("recordDigest")
        subject.update(changes)
        subject["generation"] = current["generation"] + 1
        subject["updatedAt"] = self.effective_at
        updated = with_self_digest(subject)
        self.registry.validate(updated)
        observed = self._state()
        if observed["recordDigest"] != current["recordDigest"]:
            raise GitAdoptionError("Git adoption state CAS failed")
        atomic_write(self._state_path, canonical_bytes(updated), mode=0o600)
        return updated

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        path = self.authority_root / "locks" / f"{self.repository_id[7:]}.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._lock_depth += 1
            yield
        finally:
            self._lock_depth -= 1
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _require_lock(self) -> None:
        if self._lock_depth != 1:
            raise GitAdoptionError("Git adoption mutation requires exactly one endpoint lock")

    def snapshot(self) -> dict[str, Any]:
        refs = self._git("for-each-ref", "--format=%(refname)", max_bytes=8_388_608).decode().splitlines()
        refs = sorted(set(ref for ref in refs if ref))
        main = None
        if "refs/heads/main" in refs:
            main = self._git("rev-parse", "--verify", "refs/heads/main", max_bytes=256).decode().strip()
        state = self._state()
        return {
            "path": str(self.path),
            "objectFormat": self.object_format,
            "main": main,
            "refs": refs,
            "drained": state["drained"],
            "fenced": state["fenced"],
            "fenceMode": state["fenceMode"],
        }

    def drain(self) -> None:
        self._require_lock()
        current = self._state()
        if not current["drained"]:
            self._write_state(current, drained=True)

    def prefence(self) -> None:
        self._require_lock()
        current = self._state()
        if not current["drained"]:
            raise GitAdoptionError("Git adoption pre-fence requires a drained repository")
        if current["fenceMode"] == "open":
            self._write_state(current, fenced=True, fenceMode="prefenced")

    def stage(self, ref: str, commit: str) -> None:
        self._require_lock()
        if self.role != "new_canonical" or not ref.startswith("refs/das-bootstrap/"):
            raise GitAdoptionError("Git adoption staging target is invalid")
        if self.snapshot()["main"] is not None:
            raise GitAdoptionError("Git adoption target main already exists")
        self._git("fetch", "--no-tags", str(self.candidate_source), f"{commit}:{ref}", max_bytes=8_388_608)
        observed = self._git("rev-parse", "--verify", ref, max_bytes=256).decode().strip()
        if observed != commit:
            raise GitAdoptionError("Git adoption staged ref readback mismatch")

    def candidate_identity(self, commit: str) -> dict[str, str]:
        self._require_lock()
        lines = self._git("show", "-s", "--format=%T%n%P", commit, max_bytes=1024).decode().splitlines()
        if len(lines) != 2 or len(lines[1].split()) != 1:
            raise GitAdoptionError("Git adoption candidate does not have exactly one parent")
        observed = self._git("rev-parse", "--verify", f"{commit}^{{commit}}", max_bytes=256).decode().strip()
        return {"commit": observed, "tree": lines[0], "parent": lines[1]}

    def create_main_from_absent(self, commit: str) -> None:
        self._require_lock()
        zero = "0" * (40 if self.object_format == "sha1" else 64)
        self._git("update-ref", "refs/heads/main", commit, zero, max_bytes=1024)
        if self.snapshot()["main"] != commit:
            raise GitAdoptionError("Git adoption zero-OID main CAS readback failed")

    def remove_staging(self, namespace: str) -> None:
        self._require_lock()
        if not namespace.startswith("refs/das-bootstrap/") or not namespace.endswith("/"):
            raise GitAdoptionError("Git adoption staging namespace is invalid")
        refs = self._git("for-each-ref", "--format=%(refname)", namespace, max_bytes=8_388_608).decode().splitlines()
        for ref in sorted(set(refs)):
            if ref:
                self._git("update-ref", "-d", ref, max_bytes=1024)

    def permanent_fence(self) -> None:
        self._require_lock()
        current = self._state()
        if not current["drained"] or current["fenceMode"] not in {"prefenced", "permanent"}:
            raise GitAdoptionError("Git adoption permanent fence requires the pre-fenced state")
        if current["fenceMode"] != "permanent":
            self._write_state(current, drained=True, fenced=True, fenceMode="permanent")

    def restore_access(self) -> None:
        self._require_lock()
        current = self._state()
        if current["fenceMode"] == "permanent":
            raise GitAdoptionError("Git adoption permanent fence cannot be reopened")
        if current["drained"] or current["fenced"]:
            self._write_state(current, drained=False, fenced=False, fenceMode="open")
