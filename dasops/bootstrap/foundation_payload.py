from __future__ import annotations

import hashlib
import fcntl
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, Mapping

from dasops.protected.canonical import canonical_bytes, load_canonical_json, semantic_digest, with_self_digest
from dasops.protected.state_store import atomic_write

from .schema_registry import BootstrapSchemaRegistry


class FoundationPayloadError(RuntimeError):
    pass


SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _repository(path_value: str | Path) -> Path:
    supplied = Path(path_value).expanduser()
    if not supplied.is_absolute() or supplied.is_symlink():
        raise FoundationPayloadError("worker repository must be an absolute non-symlink path")
    path = supplied.resolve()
    if str(path) != str(supplied) or not path.is_dir() or os.stat(path).st_uid != os.getuid():
        raise FoundationPayloadError("worker repository identity or ownership is invalid")
    return path


def _git(repo: Path, *args: str, max_bytes: int = 536_870_912) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    if process.returncode != 0:
        raise FoundationPayloadError(f"Git payload inspection failed for operation {args[0]}")
    if len(process.stdout) > max_bytes:
        raise FoundationPayloadError("Git payload inspection exceeded its byte budget")
    return process.stdout


def _safe_tree_path(value: bytes) -> str:
    try:
        path = value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise FoundationPayloadError("foundation payload path is not strict UTF-8") from exc
    pure = PurePosixPath(path)
    if (
        not path
        or path.startswith("/")
        or "\x00" in path
        or any(part in {"", ".", "..", ".git"} for part in pure.parts)
        or pure.as_posix() != path
    ):
        raise FoundationPayloadError("foundation payload contains an unsafe path")
    return path


def build_foundation_payload_manifest(
    *,
    worker_repository: str | Path,
    candidate_commit: str,
    expected_parent: str,
    manifest_id: str,
    created_at: str,
) -> dict[str, Any]:
    repo = _repository(worker_repository)
    top = _git(repo, "rev-parse", "--show-toplevel", max_bytes=4096).decode().strip()
    if top != str(repo):
        raise FoundationPayloadError("worker repository path is not its Git top level")
    object_format = _git(repo, "rev-parse", "--show-object-format", max_bytes=64).decode().strip()
    if object_format not in {"sha1", "sha256"}:
        raise FoundationPayloadError("worker repository object format is unsupported")
    commit = _git(repo, "rev-parse", "--verify", f"{candidate_commit}^{{commit}}", max_bytes=256).decode().strip()
    if commit != candidate_commit:
        raise FoundationPayloadError("candidate commit is not an exact full object ID")
    ancestry = _git(repo, "rev-list", "--parents", "-n", "1", commit, max_bytes=512).decode().split()
    if ancestry != [commit, expected_parent]:
        raise FoundationPayloadError("foundation candidate must have exactly the expected old main as parent")
    tree = _git(repo, "rev-parse", "--verify", f"{commit}^{{tree}}", max_bytes=256).decode().strip()
    raw_entries = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
    entries: list[dict[str, Any]] = []
    total = 0
    seen: set[str] = set()
    for raw in raw_entries:
        if not raw:
            continue
        try:
            header, path_bytes = raw.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii").split(" ")
        except (ValueError, UnicodeDecodeError) as exc:
            raise FoundationPayloadError("Git returned a malformed foundation tree entry") from exc
        path = _safe_tree_path(path_bytes)
        if path in seen or kind != "blob" or mode not in {"100644", "100755"}:
            raise FoundationPayloadError("foundation payload contains duplicate, symlink, submodule or special entries")
        seen.add(path)
        content = _git(repo, "cat-file", "blob", object_id)
        total += len(content)
        if total > 536_870_912:
            raise FoundationPayloadError("foundation payload exceeds 512 MiB")
        entries.append(
            {
                "path": path,
                "mode": mode,
                "gitObjectId": object_id,
                "size": len(content),
                "contentSha256": hashlib.sha256(content).hexdigest(),
                "classification": "tracked_candidate",
            }
        )
    if not entries or entries != sorted(entries, key=lambda item: item["path"]):
        raise FoundationPayloadError("foundation payload tree is empty or not deterministically ordered")
    manifest = with_self_digest(
        {
            "schema": "bootstrap-foundation-payload-manifest/v1",
            "manifestId": manifest_id,
            "workerRepositoryPath": str(repo),
            "objectFormat": object_format,
            "candidateCommit": commit,
            "candidateTree": tree,
            "candidateParent": expected_parent,
            "entries": entries,
            "entryCount": len(entries),
            "totalBytes": total,
            "inventoryDigest": semantic_digest(
                {"schema": "bootstrap-foundation-payload-inventory/v1", "entries": entries}
            ),
            "createdAt": created_at,
        }
    )
    BootstrapSchemaRegistry().validate(manifest)
    return manifest


def build_claim_adoption_request(
    *,
    request_id: str,
    package_id: str,
    root_digest: str,
    attempt_id: str,
    change_id: str,
    task_id: str,
    worker: str,
    old_repository: str,
    new_repository: str,
    payload_manifest: dict[str, Any],
    allowed_staging_namespace: str,
    requested_at: str,
) -> dict[str, Any]:
    BootstrapSchemaRegistry().validate(payload_manifest)
    old = str(_repository(old_repository))
    worker_path = payload_manifest["workerRepositoryPath"]
    new_supplied = Path(new_repository).expanduser()
    if not new_supplied.is_absolute() or new_supplied.is_symlink() or str(new_supplied.resolve(strict=False)) != str(new_supplied):
        raise FoundationPayloadError("new canonical repository path is not normalized and absolute")
    if len({old, worker_path, str(new_supplied)}) != 3:
        raise FoundationPayloadError("old, worker and new repository identities must be distinct")
    request = with_self_digest(
        {
            "schema": "bootstrap-claim-adoption-request/v1",
            "requestId": request_id,
            "packageId": package_id,
            "rootDigest": root_digest,
            "attemptId": attempt_id,
            "changeId": change_id,
            "taskId": task_id,
            "worker": worker,
            "oldRepositoryPath": old,
            "newRepositoryPath": str(new_supplied),
            "workerRepositoryPath": worker_path,
            "objectFormat": payload_manifest["objectFormat"],
            "expectedOldMain": payload_manifest["candidateParent"],
            "expectedNewMainAbsent": True,
            "candidateCommit": payload_manifest["candidateCommit"],
            "candidateTree": payload_manifest["candidateTree"],
            "candidateParent": payload_manifest["candidateParent"],
            "foundationPayloadManifestDigest": payload_manifest["recordDigest"],
            "allowedStagingNamespace": allowed_staging_namespace,
            "requestedAt": requested_at,
        }
    )
    BootstrapSchemaRegistry().validate(request)
    return request


def _write_prepared_package_unlocked(
    *,
    prepared_directory: str | Path,
    package_id: str,
    adoption_request: dict[str, Any],
    payload_manifest: dict[str, Any],
    records: Mapping[str, dict[str, Any]],
    manifest_id: str,
    created_at: str,
) -> dict[str, Any]:
    registry = BootstrapSchemaRegistry()
    registry.validate(adoption_request)
    registry.validate(payload_manifest)
    if (
        adoption_request["packageId"] != package_id
        or adoption_request["foundationPayloadManifestDigest"] != payload_manifest["recordDigest"]
    ):
        raise FoundationPayloadError("prepared package request/payload closure mismatch")
    root = Path(prepared_directory).expanduser()
    if not root.is_absolute() or root.is_symlink() or str(root.resolve(strict=False)) != str(root):
        raise FoundationPayloadError("prepared package path must be normalized, absolute and non-symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    if os.stat(root).st_uid != os.getuid() or stat.S_IMODE(os.stat(root).st_mode) != 0o700:
        raise FoundationPayloadError("prepared package directory is not owner-controlled mode 0700")
    mandatory = {"adoption-request.json", "foundation-payload.json"}
    if mandatory.intersection(records):
        raise FoundationPayloadError("prepared package record names collide with mandatory records")
    expected_records = {
        "adoption-request.json": adoption_request,
        "foundation-payload.json": payload_manifest,
        **records,
    }
    if any(not SAFE_FILE.fullmatch(name) or name == "package-manifest.json" for name in expected_records):
        raise FoundationPayloadError("prepared package record name is unsafe or reserved")
    allowed = {*expected_records, "package-manifest.json"}
    observed = {path.name for path in root.iterdir()}
    if not observed.issubset(allowed):
        raise FoundationPayloadError("prepared package contains an unexpected member")
    entries: list[dict[str, Any]] = []
    total = 0
    for name in sorted(expected_records):
        record = expected_records[name]
        registry.validate(record)
        encoded = canonical_bytes(record)
        path = root / name
        if path.exists():
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or path.read_bytes() != encoded:
                raise FoundationPayloadError("prepared package immutable member drift")
        else:
            atomic_write(path, encoded, mode=0o600, create_only=True)
        total += len(encoded)
        entries.append(
            {
                "path": name,
                "mode": "0600",
                "schema": record["schema"],
                "size": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
    manifest = with_self_digest(
        {
            "schema": "bootstrap-claim-adoption-package-manifest/v1",
            "manifestId": manifest_id,
            "packageId": package_id,
            "preparedDirectory": str(root),
            "adoptionRequestDigest": adoption_request["recordDigest"],
            "foundationPayloadManifestDigest": payload_manifest["recordDigest"],
            "entries": entries,
            "entryCount": len(entries),
            "totalBytes": total,
            "inventoryDigest": semantic_digest(
                {"schema": "bootstrap-claim-adoption-package-inventory/v1", "entries": entries}
            ),
            "manifestExcludedFromEntries": True,
            "createdAt": created_at,
        }
    )
    registry.validate(manifest)
    manifest_path = root / "package-manifest.json"
    encoded_manifest = canonical_bytes(manifest)
    if manifest_path.exists():
        before = os.lstat(manifest_path)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or manifest_path.read_bytes() != encoded_manifest:
            raise FoundationPayloadError("prepared package manifest drift")
    else:
        atomic_write(manifest_path, encoded_manifest, mode=0o600, create_only=True)
    if {path.name for path in root.iterdir()} != allowed:
        raise FoundationPayloadError("prepared package is not set-equal after publication")
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(os.lstat(path).st_mode) != 0o600:
            raise FoundationPayloadError("prepared package member type or mode is invalid")
    _fsync_directory(root)
    return manifest


def write_prepared_package(
    *,
    prepared_directory: str | Path,
    package_id: str,
    adoption_request: dict[str, Any],
    payload_manifest: dict[str, Any],
    records: Mapping[str, dict[str, Any]],
    manifest_id: str,
    created_at: str,
) -> dict[str, Any]:
    """Publish one immutable package while serializing retries on its directory."""

    root = Path(prepared_directory).expanduser()
    if (
        not root.is_absolute()
        or root == root.parent
        or root.is_symlink()
        or str(root.resolve(strict=False)) != str(root)
    ):
        raise FoundationPayloadError("prepared package path must be normalized, absolute and non-symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o700:
            raise FoundationPayloadError("prepared package directory is not owner-controlled mode 0700")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = os.stat(root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise FoundationPayloadError("prepared package directory identity changed before publication")
        result = _write_prepared_package_unlocked(
            prepared_directory=root,
            package_id=package_id,
            adoption_request=adoption_request,
            payload_manifest=payload_manifest,
            records=records,
            manifest_id=manifest_id,
            created_at=created_at,
        )
        current = os.stat(root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise FoundationPayloadError("prepared package directory identity changed during publication")
        return result
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def verify_prepared_package(
    *,
    package_manifest: dict[str, Any],
    adoption_request: dict[str, Any],
    payload_manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Read back an immutable package and prove its exact member closure."""

    registry = BootstrapSchemaRegistry()
    for record in (package_manifest, adoption_request, payload_manifest):
        registry.validate(record)
    if (
        package_manifest["packageId"] != adoption_request["packageId"]
        or package_manifest["adoptionRequestDigest"] != adoption_request["recordDigest"]
        or package_manifest["foundationPayloadManifestDigest"] != payload_manifest["recordDigest"]
        or adoption_request["foundationPayloadManifestDigest"] != payload_manifest["recordDigest"]
    ):
        raise FoundationPayloadError("prepared package manifest closure mismatch")
    root = Path(package_manifest["preparedDirectory"])
    if (
        not root.is_absolute()
        or root == root.parent
        or root.is_symlink()
        or str(root.resolve(strict=False)) != str(root)
    ):
        raise FoundationPayloadError("prepared package path must be normalized, absolute and non-symlink")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise FoundationPayloadError("prepared package directory is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o700:
            raise FoundationPayloadError("prepared package directory is not owner-controlled mode 0700")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        entries = package_manifest["entries"]
        names = [entry["path"] for entry in entries]
        if names != sorted(set(names)):
            raise FoundationPayloadError("prepared package manifest paths are not sorted and unique")
        expected = {*names, "package-manifest.json"}
        if {path.name for path in root.iterdir()} != expected:
            raise FoundationPayloadError("prepared package directory is not set-equal to its manifest")
        manifest_path = root / "package-manifest.json"
        if manifest_path.read_bytes() != canonical_bytes(package_manifest):
            raise FoundationPayloadError("prepared package manifest bytes drifted")
        records: dict[str, dict[str, Any]] = {}
        rebuilt_entries: list[dict[str, Any]] = []
        total = 0
        for entry in entries:
            path = root / entry["path"]
            before = os.lstat(path)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.getuid()
            ):
                raise FoundationPayloadError("prepared package member is not owner-controlled mode 0600")
            encoded = path.read_bytes()
            try:
                record = load_canonical_json(encoded)
                registry.validate(record)
            except Exception as exc:
                raise FoundationPayloadError("prepared package member is not a valid canonical record") from exc
            rebuilt = {
                "path": entry["path"],
                "mode": "0600",
                "schema": record["schema"],
                "size": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
            if rebuilt != entry:
                raise FoundationPayloadError("prepared package member does not match its inventory")
            after = os.lstat(path)
            if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
                raise FoundationPayloadError("prepared package member changed during readback")
            rebuilt_entries.append(rebuilt)
            records[entry["path"]] = record
            total += len(encoded)
        if (
            package_manifest["entryCount"] != len(rebuilt_entries)
            or package_manifest["totalBytes"] != total
            or package_manifest["inventoryDigest"]
            != semantic_digest(
                {"schema": "bootstrap-claim-adoption-package-inventory/v1", "entries": rebuilt_entries}
            )
            or records.get("adoption-request.json") != adoption_request
            or records.get("foundation-payload.json") != payload_manifest
        ):
            raise FoundationPayloadError("prepared package inventory closure mismatch")
        current = os.stat(root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise FoundationPayloadError("prepared package directory identity changed during readback")
        return records
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
