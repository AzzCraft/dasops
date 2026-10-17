from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
from typing import Any, Iterable

from .canonical import semantic_digest, with_self_digest
from .git_canonical import BareCanonicalRepo
from .state_store import ProtectedStateStore


class ProtectedMaterializationError(RuntimeError):
    pass


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _commit_inventory(repo: BareCanonicalRepo, commit: str) -> tuple[str, dict[str, dict[str, Any]]]:
    if len(commit) != repo.object_hex_length or any(char not in "0123456789abcdef" for char in commit):
        raise ProtectedMaterializationError("materialization requires an exact lowercase commit object id")
    commit_check = repo._run("cat-file", "-e", f"{commit}^{{commit}}", check=False)
    if commit_check.returncode != 0:
        raise ProtectedMaterializationError("materialization commit object is absent or not a commit")
    tree = repo._run("rev-parse", f"{commit}^{{tree}}").stdout.decode().strip()
    raw = repo._run("ls-tree", "-r", "-z", "--long", commit).stdout
    inventory: dict[str, dict[str, Any]] = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, raw_oid, raw_size = metadata.split()
            path = raw_path.decode("utf-8", "strict")
            oid = raw_oid.decode("ascii")
            size = int(raw_size)
        except Exception as exc:
            raise ProtectedMaterializationError("malformed or non-UTF-8 Git tree entry") from exc
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not path or "\x00" in path:
            raise ProtectedMaterializationError(f"unsafe Git tree path: {path!r}")
        decoded_mode = mode.decode("ascii")
        if kind != b"blob" or decoded_mode not in {"100644", "100755"}:
            raise ProtectedMaterializationError(f"unsupported non-regular Git entry: {path}")
        if path in inventory:
            raise ProtectedMaterializationError(f"duplicate Git tree path: {path}")
        content = repo._run("cat-file", "blob", oid).stdout
        if len(content) != size:
            raise ProtectedMaterializationError(f"Git blob size mismatch: {path}")
        inventory[path] = {
            "path": path,
            "mode": decoded_mode,
            "blobOid": oid,
            "size": size,
            "contentSha256": hashlib.sha256(content).hexdigest(),
        }
    if not inventory:
        raise ProtectedMaterializationError("commit has no regular files")
    return tree, inventory


def build_materialization_request(
    *,
    repo: BareCanonicalRepo,
    commit: str,
    destination: Path,
    include_paths: Iterable[str] | None = None,
    max_total_bytes: int = 536_870_912,
) -> dict[str, Any]:
    tree, inventory = _commit_inventory(repo, commit)
    if include_paths is None:
        selected = sorted(inventory)
    else:
        selected = list(include_paths)
        if selected != sorted(selected) or len(set(selected)) != len(selected):
            raise ProtectedMaterializationError("include paths must be sorted and unique")
        missing = [path for path in selected if path not in inventory]
        if missing:
            raise ProtectedMaterializationError(f"include paths are absent from commit: {missing}")
    if not selected:
        raise ProtectedMaterializationError("materialization selection is empty")
    files = [inventory[path] for path in selected]
    total = sum(item["size"] for item in files)
    if max_total_bytes < 1 or total > max_total_bytes:
        raise ProtectedMaterializationError("materialization exceeds the byte budget")
    dest = destination.expanduser()
    if not dest.is_absolute():
        raise ProtectedMaterializationError("materialization destination must be absolute")
    return with_self_digest(
        {
            "schema": "protected-materialization-request/v1",
            "sourceRepoPath": str(repo.path),
            "commit": commit,
            "tree": tree,
            "destination": str(dest),
            "files": files,
            "maxTotalBytes": max_total_bytes,
        }
    )


def _validate_destination(destination: str, repo: BareCanonicalRepo) -> Path:
    requested = Path(destination).expanduser()
    if not requested.is_absolute() or requested.name in {"", ".", ".."}:
        raise ProtectedMaterializationError("invalid absolute materialization destination")
    parent = requested.parent.resolve()
    dest = parent / requested.name
    if str(dest) != destination:
        raise ProtectedMaterializationError("materialization destination is not normalized")
    if requested.exists() or requested.is_symlink():
        raise ProtectedMaterializationError("materialization destination already exists")
    parent_stat = os.stat(parent)
    if parent.is_symlink() or parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ProtectedMaterializationError("materialization parent is not owner controlled")
    try:
        dest.relative_to(repo.path)
    except ValueError:
        pass
    else:
        raise ProtectedMaterializationError("materialization destination cannot be inside the source repository")
    return dest


def materialize_no_ref(
    *,
    repo: BareCanonicalRepo,
    store: ProtectedStateStore,
    request: dict[str, Any],
) -> dict[str, Any]:
    store.registry.validate(request)
    if request["sourceRepoPath"] != str(repo.path):
        raise ProtectedMaterializationError("materialization source repository mismatch")
    actual_tree, inventory = _commit_inventory(repo, request["commit"])
    if actual_tree != request["tree"]:
        raise ProtectedMaterializationError("materialization tree mismatch")
    paths = [item["path"] for item in request["files"]]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise ProtectedMaterializationError("materialization files must be sorted and unique")
    total = 0
    for expected in request["files"]:
        actual = inventory.get(expected["path"])
        if actual != expected:
            raise ProtectedMaterializationError(f"materialization inventory mismatch: {expected['path']}")
        total += expected["size"]
    if total > request["maxTotalBytes"]:
        raise ProtectedMaterializationError("materialization exceeds its declared byte budget")
    destination = _validate_destination(request["destination"], repo)
    destination.mkdir(mode=0o700)
    os.chmod(destination, 0o700)
    try:
        for item in request["files"]:
            target = destination.joinpath(*PurePosixPath(item["path"]).parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            cursor = target.parent
            while cursor != destination.parent:
                if cursor.is_symlink() or not cursor.is_dir() or os.stat(cursor).st_uid != os.getuid():
                    raise ProtectedMaterializationError(f"unsafe materialization directory: {cursor}")
                os.chmod(cursor, 0o700)
                if cursor == destination:
                    break
                cursor = cursor.parent
            content = repo._run("cat-file", "blob", item["blobOid"]).stdout
            if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["contentSha256"]:
                raise ProtectedMaterializationError(f"materialization blob readback mismatch: {item['path']}")
            local_mode = 0o700 if item["mode"] == "100755" else 0o600
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                local_mode,
            )
            try:
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(target, local_mode)
            readback = target.read_bytes()
            if hashlib.sha256(readback).hexdigest() != item["contentSha256"]:
                raise ProtectedMaterializationError(f"materialized file readback mismatch: {item['path']}")
        root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return with_self_digest(
        {
            "schema": "protected-materialization-receipt/v1",
            "requestDigest": request["recordDigest"],
            "outcome": "materialized",
            "commit": request["commit"],
            "tree": request["tree"],
            "destination": str(destination),
            "fileCount": len(request["files"]),
            "totalBytes": total,
            "inventoryDigest": semantic_digest({"files": request["files"]}),
            "materializedAt": _timestamp(),
        }
    )
