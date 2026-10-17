from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import selectors
import stat
import subprocess
import time
from typing import Any, Iterable

from .canonical import with_self_digest
from .state_store import ProtectedStateStore


class ProtectedLaunchError(RuntimeError):
    pass


@dataclass(frozen=True)
class LaunchResult:
    receipt: dict[str, Any]
    stdout: bytes
    stderr: bytes


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_pinned(path_value: str, expected_sha256: str) -> bytes:
    requested = Path(path_value).expanduser()
    if not requested.is_absolute() or str(requested.resolve()) != path_value:
        raise ProtectedLaunchError(f"pinned executable path is not normalized: {path_value}")
    before = os.lstat(requested)
    if not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.getuid()}:
        raise ProtectedLaunchError("pinned executable is not a trusted regular file")
    if stat.S_IMODE(before.st_mode) & 0o022:
        raise ProtectedLaunchError("pinned executable is group/world writable")
    fd = os.open(requested, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ProtectedLaunchError("pinned executable changed during open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1_048_576)
            if not chunk:
                break
            total += len(chunk)
            if total > 134_217_728:
                raise ProtectedLaunchError("pinned executable exceeds 128 MiB")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise ProtectedLaunchError("pinned executable changed during hashing")
    finally:
        os.close(fd)
    content = b"".join(chunks)
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ProtectedLaunchError("pinned executable digest mismatch")
    return content


def _sealed_executable(name: str, content: bytes) -> int:
    if not hasattr(os, "memfd_create"):
        raise ProtectedLaunchError("sealed memfd execution is unavailable")
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fchmod(fd, 0o500)
        fcntl.fcntl(
            fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL,
        )
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except Exception:
        os.close(fd)
        raise


def _sandbox_command(bwrap_fd: int, tool_fd: int, descriptor: dict[str, Any]) -> list[str]:
    cwd = descriptor["workingDirectory"]
    command = [
        f"/proc/self/fd/{bwrap_fd}",
        "--die-with-parent",
        "--unshare-all",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    for system_path in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(system_path).exists():
            command.extend(("--ro-bind", system_path, system_path))
    for system_file in ("/etc/ld.so.cache", "/etc/alternatives"):
        if Path(system_file).exists():
            command.extend(("--ro-bind", system_file, system_file))
    command.extend(("--ro-bind", cwd, cwd, "--chdir", cwd))
    for name, value in sorted(descriptor["environment"].items()):
        command.extend(("--setenv", name, value))
    command.extend(("--", f"/proc/self/fd/{tool_fd}", *descriptor["argv"]))
    return command


def _run_bounded(
    command: list[str],
    *,
    environment: dict[str, str],
    pass_fds: tuple[int, ...],
    timeout_seconds: int,
    max_output_bytes: int,
) -> tuple[str, int, bytes, bytes]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        pass_fds=pass_fds,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    outcome = "exited"
    exceeded = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = "timed_out"
                process.kill()
                remaining = 1.0
            events = selector.select(timeout=min(max(remaining, 0.0), 0.25))
            if not events and outcome == "timed_out" and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = buffers[key.data]
                room = max_output_bytes + 1 - len(target)
                if room > 0:
                    target.extend(chunk[:room])
                if len(target) > max_output_bytes:
                    exceeded = True
                    process.kill()
            if exceeded and process.poll() is not None:
                # Continue draining both pipes without retaining additional bytes.
                continue
        exit_code = process.wait(timeout=1)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    if exceeded:
        raise ProtectedLaunchError("protected tool output exceeded the descriptor limit")
    return outcome, (-1 if outcome == "timed_out" else exit_code), bytes(buffers["stdout"]), bytes(buffers["stderr"])


def launch_pinned(
    *,
    store: ProtectedStateStore,
    descriptor: dict[str, Any],
    materialization_receipt: dict[str, Any],
    pass_fds: Iterable[int] = (),
) -> LaunchResult:
    store.registry.validate(descriptor)
    store.registry.validate(materialization_receipt)
    if descriptor["materializationReceiptDigest"] != materialization_receipt["recordDigest"]:
        raise ProtectedLaunchError("launch materialization receipt mismatch")
    cwd = Path(descriptor["workingDirectory"])
    if str(cwd) != materialization_receipt["destination"] or not cwd.is_dir() or cwd.is_symlink():
        raise ProtectedLaunchError("launch working directory does not match materialization")
    cwd_stat = os.stat(cwd)
    if cwd_stat.st_uid != os.getuid() or stat.S_IMODE(cwd_stat.st_mode) != 0o700:
        raise ProtectedLaunchError("launch working directory is not owner-controlled mode 0700")
    if any("\x00" in arg for arg in descriptor["argv"]):
        raise ProtectedLaunchError("launch argv contains NUL")
    provided_fds = tuple(pass_fds)
    if list(provided_fds) != descriptor["passFds"]:
        raise ProtectedLaunchError("launch pass-fd set does not match the descriptor")
    if list(provided_fds) != sorted(provided_fds):
        raise ProtectedLaunchError("launch pass descriptors must be sorted")
    for fd in provided_fds:
        try:
            os.fstat(fd)
        except OSError as exc:
            raise ProtectedLaunchError(f"launch pass fd is not open: {fd}") from exc
        if os.get_inheritable(fd):
            raise ProtectedLaunchError("raw-secret pass descriptors must be non-inheritable before launch")

    tool_content = _read_pinned(descriptor["executablePath"], descriptor["executableSha256"])
    sandbox_content = _read_pinned(
        descriptor["sandboxExecutablePath"], descriptor["sandboxExecutableSha256"]
    )
    tool_fd = _sealed_executable("das-protected-tool", tool_content)
    bwrap_fd = _sealed_executable("das-protected-bwrap", sandbox_content)
    command = _sandbox_command(bwrap_fd, tool_fd, descriptor)
    clean_env = dict(descriptor["environment"])
    try:
        outcome, exit_code, stdout, stderr = _run_bounded(
            command,
            environment=clean_env,
            pass_fds=(bwrap_fd, tool_fd, *provided_fds),
            timeout_seconds=descriptor["timeoutSeconds"],
            max_output_bytes=descriptor["maxOutputBytes"],
        )
    finally:
        os.close(tool_fd)
        os.close(bwrap_fd)
    receipt = with_self_digest(
        {
            "schema": "protected-launch-receipt/v1",
            "descriptorDigest": descriptor["recordDigest"],
            "outcome": outcome,
            "exitCode": exit_code,
            "sandboxProfile": descriptor["sandboxProfile"],
            "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
            "stdoutSize": len(stdout),
            "stderrSha256": hashlib.sha256(stderr).hexdigest(),
            "stderrSize": len(stderr),
            "finishedAt": _timestamp(),
        }
    )
    return LaunchResult(receipt=receipt, stdout=stdout, stderr=stderr)


def validate_bootstrap_launch(
    *,
    descriptor: dict[str, Any],
    verified_tool_release: Any,
    artifact_root: Path,
) -> None:
    """Bind a protected launch to the anchor-pinned launcher and release runtime.

    This validator is called by the independently pinned launcher process before
    ``launch_pinned``. Reading the launcher pin here is a substitution check, not
    a claim that an already-loaded Python module can attest itself.
    """
    anchor = verified_tool_release.authority.anchor
    launcher = anchor["trustedComponents"]["launcher"]
    _read_pinned(launcher["runtimePath"], launcher["packageDigest"].removeprefix("sha256:"))

    root = artifact_root.expanduser()
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProtectedLaunchError("tool artifact root must be an absolute non-symlink directory")
    root = root.resolve()
    runtime = verified_tool_release.release["runtime"]
    relative_runtime = Path(runtime["path"])
    if relative_runtime.is_absolute() or not relative_runtime.parts or ".." in relative_runtime.parts:
        raise ProtectedLaunchError("accepted runtime path is not a safe relative artifact path")
    candidate = root / relative_runtime
    cursor = root
    for part in relative_runtime.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ProtectedLaunchError("accepted runtime path contains a symlink")
    runtime_path = candidate.resolve()
    try:
        runtime_path.relative_to(root)
    except ValueError as exc:
        raise ProtectedLaunchError("accepted runtime path escapes the artifact root") from exc
    if str(runtime_path) != descriptor["executablePath"]:
        raise ProtectedLaunchError("launch executable is not the accepted tool runtime")
    content = _read_pinned(str(runtime_path), runtime["sha256"])
    if len(content) != runtime["size"] or descriptor["executableSha256"] != runtime["sha256"]:
        raise ProtectedLaunchError("accepted tool runtime size/digest binding failed")

    argv = descriptor["argv"]
    if not argv or argv[0] not in {"bootstrap-publisher", "adopt-bootstrap-claim"}:
        raise ProtectedLaunchError("accepted runtime launch is not a bootstrap command")
    if "--owner" not in argv or "--driver-fd" not in argv:
        raise ProtectedLaunchError("bootstrap launch requires explicit owner and authenticated driver FD")
    forbidden = {"--force", "--push", "--token", "--password", "--secret"}
    if any(item in forbidden for item in argv):
        raise ProtectedLaunchError("bootstrap launch contains a forbidden ambient/secret option")
    try:
        driver_fd = int(argv[argv.index("--driver-fd") + 1])
    except (ValueError, IndexError) as exc:
        raise ProtectedLaunchError("bootstrap driver FD argument is invalid") from exc
    if driver_fd < 3 or driver_fd not in descriptor["passFds"]:
        raise ProtectedLaunchError("bootstrap driver FD is not in the exact pass-FD set")


def launch_bootstrap_pinned(
    *,
    store: ProtectedStateStore,
    descriptor: dict[str, Any],
    materialization_receipt: dict[str, Any],
    verified_tool_release: Any,
    artifact_root: Path,
    pass_fds: Iterable[int] = (),
) -> LaunchResult:
    validate_bootstrap_launch(
        descriptor=descriptor,
        verified_tool_release=verified_tool_release,
        artifact_root=artifact_root,
    )
    return launch_pinned(
        store=store,
        descriptor=descriptor,
        materialization_receipt=materialization_receipt,
        pass_fds=pass_fds,
    )
