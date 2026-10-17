from __future__ import annotations

import hashlib
import os
import socket
import sys
from pathlib import Path
import stat
import subprocess

import pytest

from dasops.protected import canonical_bytes, with_self_digest
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.launcher import ProtectedLaunchError, launch_pinned
from dasops.protected.materializer import (
    ProtectedMaterializationError,
    build_materialization_request,
    materialize_no_ref,
)
from dasops.protected.state_store import ProtectedStateStore


SANDBOX_SCRIPT = b"""#!/bin/sh
set -eu
if printf 'forbidden' > should-not-write 2>/dev/null; then
  exit 91
fi
printf 'sandbox-ok\\n'
"""

FD_SCRIPT = b"""#!/usr/bin/python3
import hashlib
import os
import sys
value = os.read(int(sys.argv[1]), 4096)
print(hashlib.sha256(value).hexdigest())
"""

OUTPUT_SCRIPT = b"""#!/usr/bin/python3
print("x" * 4096)
"""

TIMEOUT_SCRIPT = b"""#!/bin/sh
/bin/sleep 5
"""


def require_trusted_bwrap() -> None:
    """Skip execution acceptance only when the host rewrites bwrap ownership."""
    sandbox_owner = Path("/usr/bin/bwrap").stat().st_uid
    if sandbox_owner not in {0, os.getuid()}:
        pytest.skip("host sandbox rewrites bwrap ownership; secure launcher acceptance runs on CI")


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def seeded(
    tmp_path: Path,
    *,
    executable: bytes = SANDBOX_SCRIPT,
    add_symlink: bool = False,
) -> tuple[BareCanonicalRepo, ProtectedStateStore]:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    source = tmp_path / "source"
    source.mkdir(parents=True)
    run("git", "init", "-b", "main", cwd=source)
    run("git", "config", "user.name", "Test", cwd=source)
    run("git", "config", "user.email", "test@example.invalid", cwd=source)
    tool = source / "verify-tool"
    tool.write_bytes(executable)
    tool.chmod(0o755)
    (source / "data.txt").write_text("candidate data\n", encoding="utf-8")
    (source / "not-selected.txt").write_text("excluded\n", encoding="utf-8")
    if add_symlink:
        (source / "unsafe-link").symlink_to("data.txt")
    run("git", "add", ".", cwd=source)
    run("git", "commit", "-m", "seed", cwd=source)
    bare = tmp_path / "canonical.git"
    run("git", "init", "--bare", str(bare))
    os.chmod(bare, 0o700)
    run("git", "push", str(bare), "main:main", cwd=source)
    run("git", f"--git-dir={bare}", "symbolic-ref", "HEAD", "refs/heads/main")
    repo = BareCanonicalRepo(bare)
    store = ProtectedStateStore(repo)
    store.initialize(
        {
            "schema": "protected-task-policy/v1",
            "policyId": "POLICY-LAUNCHER-001",
            "canonicalRepoPath": str(repo.path),
            "canonicalRef": "refs/heads/main",
            "allowedOperations": ["claim"],
            "leaseSecondsMin": 60,
            "leaseSecondsMax": 3600,
            "toolDigests": {"dasops": "sha256:" + "a" * 64},
        }
    )
    return repo, store


def materialized(
    tmp_path: Path,
    *,
    executable: bytes = SANDBOX_SCRIPT,
) -> tuple[BareCanonicalRepo, ProtectedStateStore, dict, dict]:
    repo, store = seeded(tmp_path, executable=executable)
    destination = tmp_path / "materialized"
    request = build_materialization_request(
        repo=repo,
        commit=repo.head(),
        destination=destination,
        include_paths=["data.txt", "verify-tool"],
    )
    receipt = materialize_no_ref(repo=repo, store=store, request=request)
    return repo, store, request, receipt


def descriptor_for(receipt: dict, executable: Path, argv: list[str], pass_fds: list[int]) -> dict:
    sandbox = Path("/usr/bin/bwrap")
    return with_self_digest(
        {
            "schema": "protected-launch-descriptor/v1",
            "materializationReceiptDigest": receipt["recordDigest"],
            "executablePath": str(executable),
            "executableSha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "sandboxExecutablePath": str(sandbox),
            "sandboxExecutableSha256": hashlib.sha256(sandbox.read_bytes()).hexdigest(),
            "sandboxProfile": "bwrap-readonly-workspace-v1",
            "workingDirectory": receipt["destination"],
            "argv": argv,
            "environment": {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            "passFds": pass_fds,
            "timeoutSeconds": 30,
            "maxOutputBytes": 1_048_576,
        }
    )


def test_no_ref_materializer_writes_exact_selection_without_mutating_refs(tmp_path: Path) -> None:
    repo, store = seeded(tmp_path)
    refs_before = repo._run("for-each-ref", "--format=%(refname) %(objectname)").stdout
    request = build_materialization_request(
        repo=repo,
        commit=repo.head(),
        destination=tmp_path / "materialized",
        include_paths=["data.txt", "verify-tool"],
    )
    receipt = materialize_no_ref(repo=repo, store=store, request=request)
    destination = Path(receipt["destination"])
    assert sorted(path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()) == [
        "data.txt",
        "verify-tool",
    ]
    assert not (destination / ".git").exists()
    assert not (destination / "not-selected.txt").exists()
    assert stat.S_IMODE((destination / "data.txt").stat().st_mode) == 0o600
    assert stat.S_IMODE((destination / "verify-tool").stat().st_mode) == 0o700
    assert repo._run("for-each-ref", "--format=%(refname) %(objectname)").stdout == refs_before
    assert receipt["inventoryDigest"]


def test_materializer_rejects_tree_substitution_symlinks_and_existing_destination(tmp_path: Path) -> None:
    repo, store = seeded(tmp_path / "normal")
    request = build_materialization_request(
        repo=repo,
        commit=repo.head(),
        destination=tmp_path / "normal" / "materialized",
        include_paths=["data.txt"],
    )
    subject = dict(request)
    subject.pop("recordDigest")
    subject["files"] = [dict(subject["files"][0])]
    subject["files"][0]["contentSha256"] = "0" * 64
    substituted = with_self_digest(subject)
    with pytest.raises(ProtectedMaterializationError, match="inventory mismatch"):
        materialize_no_ref(repo=repo, store=store, request=substituted)
    existing = Path(request["destination"])
    existing.mkdir()
    with pytest.raises(ProtectedMaterializationError, match="already exists"):
        materialize_no_ref(repo=repo, store=store, request=request)

    symlink_repo, _symlink_store = seeded(tmp_path / "symlink", add_symlink=True)
    with pytest.raises(ProtectedMaterializationError, match="non-regular"):
        build_materialization_request(
            repo=symlink_repo,
            commit=symlink_repo.head(),
            destination=tmp_path / "symlink" / "materialized",
        )


@pytest.fixture
def live_network_probe():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        with socket.create_connection(('127.0.0.1', port), timeout=1):
            peer, _ = listener.accept()
            peer.close()
        probe = ("import socket; s=socket.socket(); s.settimeout(1); "
                 f"rc=s.connect_ex(('127.0.0.1',{port})); s.close(); "
                 "raise SystemExit(92 if rc == 0 else 0)")
        yield probe


def test_network_probe_detects_an_unisolated_process(live_network_probe):
    result = subprocess.run([sys.executable, '-B', '-c', live_network_probe], timeout=5)
    assert result.returncode == 92, 'host control must expose reachable service'


def test_digest_pinned_launcher_enforces_readonly_workspace_and_network_namespace(tmp_path: Path, live_network_probe) -> None:
    require_trusted_bwrap()
    import shlex
    executable = SANDBOX_SCRIPT.replace(b"printf 'sandbox-ok", ("/usr/bin/python3 -c " + shlex.quote(live_network_probe) + "\n").encode() + b"printf 'sandbox-ok")
    _repo, store, _request, receipt = materialized(tmp_path, executable=executable)
    executable = Path(receipt["destination"]) / "verify-tool"
    descriptor = descriptor_for(receipt, executable, [], [])
    result = launch_pinned(
        store=store,
        descriptor=descriptor,
        materialization_receipt=receipt,
    )
    assert result.receipt["outcome"] == "exited"
    assert result.receipt["exitCode"] == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout == b"sandbox-ok\n"
    assert not (Path(receipt["destination"]) / "should-not-write").exists()


def test_launcher_rejects_executable_sandbox_and_environment_substitution(tmp_path: Path) -> None:
    require_trusted_bwrap()
    _repo, store, _request, receipt = materialized(tmp_path)
    executable = Path(receipt["destination"]) / "verify-tool"
    descriptor = descriptor_for(receipt, executable, [], [])
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    with pytest.raises(ProtectedLaunchError, match="digest mismatch"):
        launch_pinned(store=store, descriptor=descriptor, materialization_receipt=receipt)

    executable.write_bytes(SANDBOX_SCRIPT)
    bad_sandbox = dict(descriptor)
    bad_sandbox.pop("recordDigest")
    bad_sandbox["sandboxExecutableSha256"] = "0" * 64
    bad_sandbox = with_self_digest(bad_sandbox)
    with pytest.raises(ProtectedLaunchError, match="digest mismatch"):
        launch_pinned(store=store, descriptor=bad_sandbox, materialization_receipt=receipt)

    bad_environment = dict(descriptor)
    bad_environment.pop("recordDigest")
    bad_environment["environment"] = {**bad_environment["environment"], "SECRET": "not-allowed"}
    bad_environment = with_self_digest(bad_environment)
    with pytest.raises(Exception, match="Additional properties"):
        launch_pinned(store=store, descriptor=bad_environment, materialization_receipt=receipt)


def test_non_inheritable_fd_secret_is_not_serialized_or_returned(tmp_path: Path) -> None:
    require_trusted_bwrap()
    _repo, store, _request, receipt = materialized(tmp_path, executable=FD_SCRIPT)
    executable = Path(receipt["destination"]) / "verify-tool"
    read_fd, write_fd = os.pipe()
    secret = b"test-raw-secret-never-serialize"
    try:
        assert not os.get_inheritable(read_fd)
        os.write(write_fd, secret)
        os.close(write_fd)
        write_fd = -1
        descriptor = descriptor_for(receipt, executable, [str(read_fd)], [read_fd])
        result = launch_pinned(
            store=store,
            descriptor=descriptor,
            materialization_receipt=receipt,
            pass_fds=(read_fd,),
        )
        assert result.receipt["exitCode"] == 0, result.stderr.decode("utf-8", "replace")
        assert result.stdout.strip() == hashlib.sha256(secret).hexdigest().encode()
        assert secret not in canonical_bytes(descriptor)
        assert secret not in canonical_bytes(result.receipt)
        assert secret not in result.stdout + result.stderr
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_launcher_bounds_output_and_returns_timeout_receipt(tmp_path: Path) -> None:
    require_trusted_bwrap()
    _repo, store, _request, receipt = materialized(tmp_path / "output", executable=OUTPUT_SCRIPT)
    executable = Path(receipt["destination"]) / "verify-tool"
    descriptor = descriptor_for(receipt, executable, [], [])
    subject = dict(descriptor)
    subject.pop("recordDigest")
    subject["maxOutputBytes"] = 1024
    descriptor = with_self_digest(subject)
    with pytest.raises(ProtectedLaunchError, match="output exceeded"):
        launch_pinned(store=store, descriptor=descriptor, materialization_receipt=receipt)

    _repo2, store2, _request2, receipt2 = materialized(tmp_path / "timeout", executable=TIMEOUT_SCRIPT)
    executable2 = Path(receipt2["destination"]) / "verify-tool"
    timeout_descriptor = descriptor_for(receipt2, executable2, [], [])
    timeout_subject = dict(timeout_descriptor)
    timeout_subject.pop("recordDigest")
    timeout_subject["timeoutSeconds"] = 1
    timeout_descriptor = with_self_digest(timeout_subject)
    result = launch_pinned(
        store=store2,
        descriptor=timeout_descriptor,
        materialization_receipt=receipt2,
    )
    assert result.receipt["outcome"] == "timed_out"
    assert result.receipt["exitCode"] == -1
