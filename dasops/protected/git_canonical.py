from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
from typing import Mapping


class CanonicalRepoError(RuntimeError):
    pass


def _safe_git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_ATTR_NOSYSTEM": "1",
    }
    if extra:
        env.update(extra)
    return env


class BareCanonicalRepo:
    """Validated bare Git repository with plumbing-only exact-base publication."""

    ACTIVE_HOOKS = (
        "pre-receive",
        "update",
        "post-receive",
        "reference-transaction",
        "proc-receive",
        "push-to-checkout",
    )
    FORBIDDEN_CONFIG_PREFIXES = (
        "alias.",
        "credential.",
        "filter.",
        "http.",
        "include.",
        "protocol.",
        "remote.",
        "url.",
    )

    def __init__(self, path: Path, *, canonical_ref: str = "refs/heads/main") -> None:
        self.path = path.expanduser().resolve()
        self.canonical_ref = canonical_ref
        self.validate()

    def _run(
        self,
        *args: str,
        input_bytes: bytes | None = None,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            ["/usr/bin/git", f"--git-dir={self.path}", *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_safe_git_env(extra_env),
            check=False,
        )
        if check and result.returncode != 0:
            raise CanonicalRepoError(
                f"Git command failed ({result.returncode}): {args!r}; "
                f"stderr={result.stderr.decode('utf-8', 'replace')}"
            )
        return result

    def validate(self) -> None:
        if not self.path.is_dir() or self.path.is_symlink():
            raise CanonicalRepoError(f"canonical repository is not a real directory: {self.path}")
        repo_stat = os.stat(self.path)
        if repo_stat.st_uid != os.getuid() or stat.S_IMODE(repo_stat.st_mode) & 0o022:
            raise CanonicalRepoError("canonical repository must be owner-controlled and not group/world writable")
        bare = self._run("rev-parse", "--is-bare-repository").stdout.decode().strip()
        if bare != "true":
            raise CanonicalRepoError("protected local mode requires a bare canonical repository")
        if self.canonical_ref != "refs/heads/main":
            raise CanonicalRepoError("protected v1 canonical ref must be refs/heads/main")
        alternates = self.path / "objects" / "info" / "alternates"
        if alternates.exists() and alternates.read_bytes().strip():
            raise CanonicalRepoError("Git object alternates are forbidden")
        if self._run("for-each-ref", "--format=%(refname)", "refs/replace").stdout.strip():
            raise CanonicalRepoError("Git replace refs are forbidden")
        hooks_path = self._run("config", "--local", "--path", "--get", "core.hooksPath", check=False)
        hooks_dir = Path(hooks_path.stdout.decode().strip()) if hooks_path.returncode == 0 else self.path / "hooks"
        if not hooks_dir.is_absolute():
            hooks_dir = self.path / hooks_dir
        active = [str(hooks_dir / name) for name in self.ACTIVE_HOOKS if (hooks_dir / name).exists() and os.access(hooks_dir / name, os.X_OK)]
        if active:
            raise CanonicalRepoError(f"active receive/ref hooks are forbidden: {active}")
        config_raw = self._run("config", "--local", "--name-only", "--list").stdout.decode().splitlines()
        for name in config_raw:
            lowered = name.strip().lower()
            if lowered == "core.hookspath" or lowered.startswith(self.FORBIDDEN_CONFIG_PREFIXES):
                raise CanonicalRepoError(f"forbidden local Git config: {name}")

    @property
    def object_hex_length(self) -> int:
        value = self._run("rev-parse", "--show-object-format").stdout.decode().strip()
        if value == "sha1":
            return 40
        if value == "sha256":
            return 64
        raise CanonicalRepoError(f"unsupported Git object format: {value}")

    def head(self) -> str:
        value = self._run("rev-parse", "--verify", self.canonical_ref).stdout.decode().strip()
        if len(value) != self.object_hex_length:
            raise CanonicalRepoError("canonical ref returned an invalid object id")
        return value

    def read_path(self, commit: str, path: str) -> bytes:
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not path:
            raise CanonicalRepoError(f"unsafe Git path: {path!r}")
        return self._run("cat-file", "blob", f"{commit}:{path}").stdout

    def build_single_path_commit(
        self,
        *,
        base_commit: str,
        path: str,
        content: bytes,
        message: str,
        timestamp: str,
        scratch_root: Path,
    ) -> tuple[str, str]:
        if self.head() != base_commit:
            raise CanonicalRepoError("canonical base drift before candidate construction")
        mode_line = self._run("ls-tree", base_commit, "--", path).stdout.decode().strip()
        if not mode_line or "\t" not in mode_line:
            raise CanonicalRepoError(f"candidate path does not exist at base: {path}")
        metadata, listed_path = mode_line.split("\t", 1)
        mode, kind, _old_oid = metadata.split(" ")
        if listed_path != path or kind != "blob" or mode not in {"100644", "100755"}:
            raise CanonicalRepoError(f"unsupported candidate path entry: {mode_line}")
        scratch_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="candidate-", dir=scratch_root) as temp_dir:
            index = Path(temp_dir) / "index"
            env = {"GIT_INDEX_FILE": str(index)}
            self._run("read-tree", base_commit, extra_env=env)
            blob = self._run("hash-object", "-w", "--stdin", input_bytes=content).stdout.decode().strip()
            self._run("update-index", "--cacheinfo", f"{mode},{blob},{path}", extra_env=env)
            tree = self._run("write-tree", extra_env=env).stdout.decode().strip()
        commit_env = {
            "GIT_AUTHOR_NAME": "DAS Protected Task Publisher",
            "GIT_AUTHOR_EMAIL": "protected-task-state@local",
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_NAME": "DAS Protected Task Publisher",
            "GIT_COMMITTER_EMAIL": "protected-task-state@local",
            "GIT_COMMITTER_DATE": timestamp,
        }
        commit = self._run(
            "commit-tree",
            tree,
            "-p",
            base_commit,
            input_bytes=(message.rstrip() + "\n").encode("utf-8"),
            extra_env=commit_env,
        ).stdout.decode().strip()
        parent = self._run("rev-parse", f"{commit}^").stdout.decode().strip()
        changed = [item for item in self._run("diff", "--name-only", "-z", base_commit, commit).stdout.split(b"\0") if item]
        if parent != base_commit or changed != [path.encode("utf-8")]:
            raise CanonicalRepoError("candidate graph or changed-path allowlist mismatch")
        hygiene = self._run("diff", "--check", base_commit, commit, check=False)
        if hygiene.returncode != 0:
            raise CanonicalRepoError("candidate patch hygiene failed")
        return commit, tree

    def build_path_changes_commit(
        self,
        *,
        base_commit: str,
        changes: Mapping[str, tuple[bytes | None, str | None]],
        message: str,
        timestamp: str,
        scratch_root: Path,
    ) -> tuple[str, str]:
        """Build a no-ref, single-parent commit for an exact path/content set."""
        if self.head() != base_commit:
            raise CanonicalRepoError("canonical base drift before candidate construction")
        if not changes:
            raise CanonicalRepoError("multi-path candidate has no changes")
        normalized: list[tuple[str, bytes | None, str | None]] = []
        for path, (content, requested_mode) in sorted(changes.items()):
            pure = PurePosixPath(path)
            if pure.is_absolute() or ".." in pure.parts or not path or "\x00" in path:
                raise CanonicalRepoError(f"unsafe Git path: {path!r}")
            if requested_mode not in {None, "100644", "100755"}:
                raise CanonicalRepoError(f"unsupported requested Git mode for {path}: {requested_mode}")
            normalized.append((path, content, requested_mode))
        scratch_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="candidate-", dir=scratch_root) as temp_dir:
            index = Path(temp_dir) / "index"
            env = {"GIT_INDEX_FILE": str(index)}
            self._run("read-tree", base_commit, extra_env=env)
            for path, content, requested_mode in normalized:
                mode_line = self._run("ls-tree", base_commit, "--", path).stdout.decode().strip()
                existing_mode: str | None = None
                if mode_line:
                    if "\t" not in mode_line:
                        raise CanonicalRepoError(f"malformed base tree entry: {mode_line}")
                    metadata, listed_path = mode_line.split("\t", 1)
                    existing_mode, kind, _old_oid = metadata.split(" ")
                    if listed_path != path or kind != "blob" or existing_mode not in {"100644", "100755"}:
                        raise CanonicalRepoError(f"unsupported base tree entry: {mode_line}")
                if content is None:
                    if existing_mode is None:
                        raise CanonicalRepoError(f"cannot delete absent candidate path: {path}")
                    self._run("update-index", "--force-remove", "--", path, extra_env=env)
                    continue
                mode = requested_mode or existing_mode or "100644"
                blob = self._run("hash-object", "-w", "--stdin", input_bytes=content).stdout.decode().strip()
                self._run("update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}", extra_env=env)
            tree = self._run("write-tree", extra_env=env).stdout.decode().strip()
        commit_env = {
            "GIT_AUTHOR_NAME": "DAS Protected Task Publisher",
            "GIT_AUTHOR_EMAIL": "protected-task-state@local",
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_NAME": "DAS Protected Task Publisher",
            "GIT_COMMITTER_EMAIL": "protected-task-state@local",
            "GIT_COMMITTER_DATE": timestamp,
        }
        commit = self._run(
            "commit-tree",
            tree,
            "-p",
            base_commit,
            input_bytes=(message.rstrip() + "\n").encode("utf-8"),
            extra_env=commit_env,
        ).stdout.decode().strip()
        parent = self._run("rev-parse", f"{commit}^").stdout.decode().strip()
        changed = sorted(
            item.decode("utf-8", "strict")
            for item in self._run("diff", "--name-only", "-z", base_commit, commit).stdout.split(b"\0")
            if item
        )
        expected = [path for path, _content, _mode in normalized]
        if parent != base_commit or changed != expected:
            raise CanonicalRepoError("candidate graph or changed-path allowlist mismatch")
        hygiene = self._run("diff", "--check", base_commit, commit, check=False)
        if hygiene.returncode != 0:
            raise CanonicalRepoError("candidate patch hygiene failed")
        return commit, tree

    def cas(self, *, old_commit: str, new_commit: str) -> None:
        if self.head() != old_commit:
            raise CanonicalRepoError("canonical base drift immediately before CAS")
        result = self._run("update-ref", self.canonical_ref, new_commit, old_commit, check=False)
        if result.returncode != 0:
            raise CanonicalRepoError("exact-base canonical CAS failed")
        if self.head() != new_commit:
            raise CanonicalRepoError("canonical readback mismatch after CAS")
