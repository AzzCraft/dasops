"""Pinned Cadence consumer. Proposals never become approved governance inputs."""
from __future__ import annotations

import hashlib
import fcntl
import base64
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .standards_contracts import exact_json as codec

MAX_BINARY_BYTES = 128 * 1024 * 1024


class CadenceDependencyError(ValueError):
    pass


def _hash_fd(fd):
    size = os.fstat(fd).st_size
    if not 0 < size <= MAX_BINARY_BYTES:
        raise CadenceDependencyError("Cadence executable size is unsupported")
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        data = os.pread(fd, min(1024 * 1024, size - offset), offset)
        if not data:
            raise CadenceDependencyError("Cadence executable changed while reading")
        digest.update(data)
        offset += len(data)
    return "sha256:" + digest.hexdigest()


def _run(fd, arguments, data, directory, timeout):
    # stdin is a bounded readonly descriptor, avoiding a pipe write/read deadlock.
    # No project scripts, PATH lookup, or inherited loader/runtime environment.
    with tempfile.TemporaryFile(dir=directory) as input_file:
        input_file.write(data)
        input_file.seek(0)
        proc = subprocess.Popen([f"/proc/self/fd/{fd}", *arguments], stdin=input_file,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=directory, env={"LANG": "C.UTF-8", "TZ": "UTC"},
                                pass_fds=(fd,), start_new_session=True)
        output = bytearray()
        error_size = 0
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
                selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CadenceDependencyError("Cadence dependency timed out")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif key.data == "stdout":
                            output.extend(chunk)
                            if len(output) > codec.MAX_BYTES:
                                raise CadenceDependencyError("Cadence output exceeds contract limit")
                        else:
                            error_size += len(chunk)
                            if error_size > 65536:
                                raise CadenceDependencyError("Cadence diagnostic limit exceeded")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CadenceDependencyError("Cadence dependency timed out")
                try:
                    code = proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired as exc:
                    raise CadenceDependencyError("Cadence dependency timed out") from exc
                if code != 0:
                    raise CadenceDependencyError("Cadence dependency rejected the proposal")
                return bytes(output)
        finally:
            # Preview cleanup is bounded. It does not certify a protected OS
            # boundary; that capability stays disabled pending reference probes.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
            proc.stdout.close()
            proc.stderr.close()


def resolve_preview(request, *, binary, binary_sha256, release_version, timeout=5.0):
    return _resolve(request, request, ["resolve", "--preview"], binary=binary,
                    binary_sha256=binary_sha256, release_version=release_version, timeout=timeout)


def resolve_facts_preview(request, *, binary, binary_sha256, release_version, timeout=5.0):
    """Check signed facts under supplied context, never grant protected authority.

    Public callers can supply their own keys/current state. This probe cannot
    authenticate an installed control plane or replace an approved Bundle.
    Native signature/current binding verification runs in the one pinned Go
    consumer; Python decodes the same payload solely to bind its response.
    """
    proposal, _, _ = facts_binding(request)
    return _resolve(proposal, request, ["resolve", "--check-approved-facts"], binary=binary,
                    binary_sha256=binary_sha256, release_version=release_version, timeout=timeout)


def facts_binding(request):
    """Decode original bytes only to bind a native check, without approving them."""
    if not isinstance(request, dict) or request.get("contractIdentity") != "das-approved-facts-preview-input/v1":
        raise CadenceDependencyError("an explicit signed-facts preview input is required")
    codec.closed_object(request, ["contractIdentity", "factsEnvelope", "controlContext", "catalog", "requirementsCatalog"])
    try:
        text = request["factsEnvelope"]["payload"]
        if not isinstance(text, str) or len(text) > (codec.MAX_BYTES + 2) // 3 * 4 or any(char.isspace() for char in text):
            raise ValueError("invalid payload encoding")
        if any(char in text for char in "+/") and any(char in text for char in "-_"):
            raise ValueError("mixed payload encoding")
        url = any(char in text for char in "-_")
        raw = base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_' if url else None, validate=True)
        canonical = (base64.urlsafe_b64encode(raw) if url else base64.b64encode(raw)).decode()
        if canonical.rstrip('=') != text.rstrip('='):
            raise ValueError("noncanonical payload encoding")
        payload = codec.parse(raw)
        proposal = dict(contractIdentity="das-bundle-preview-input/v3", scope=payload["scope"],
                        policyDigest=payload["policyRef"]["policyDigest"], facts=payload["facts"],
                        catalog=request["catalog"], requirementsCatalog=request["requirementsCatalog"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CadenceDependencyError("signed-facts payload cannot be bound") from exc
    return proposal, payload, raw


def _resolve(request, wire_request, arguments, *, binary, binary_sha256, release_version, timeout):
    if sys.platform != "linux":
        raise CadenceDependencyError("this pinned preview adapter supports Linux only")
    path = Path(binary)
    if not path.is_absolute() or not isinstance(binary_sha256, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", binary_sha256):
        raise CadenceDependencyError("an absolute Cadence executable and exact digest are required")
    if not isinstance(release_version, str) or not release_version or len(release_version) > 128:
        raise CadenceDependencyError("an exact Cadence release version is required")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
        raise CadenceDependencyError("invalid Cadence timeout")
    if not isinstance(request, dict) or request.get("contractIdentity") not in (
            "das-bundle-preview-input/v1", "das-bundle-preview-input/v2", "das-bundle-preview-input/v3"):
        raise CadenceDependencyError("only unapproved Bundle preview input is supported")
    v2 = request["contractIdentity"] in ("das-bundle-preview-input/v2", "das-bundle-preview-input/v3")
    codec.closed_object(request, ["contractIdentity", "scope", "policyDigest", "catalog", "facts"]
                        + (["requirementsCatalog"] if v2 else []))
    encoded = codec.canonical_catalog(wire_request) if v2 else codec.canonical(wire_request)
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if not stat.S_ISREG(os.fstat(fd).st_mode) or _hash_fd(fd) != binary_sha256:
            raise CadenceDependencyError("Cadence executable differs from its declared pin")
        with tempfile.TemporaryDirectory(prefix="das-bundle-preview-") as directory:
            identity = codec.parse(_run(fd, ["version", "--json"], b"", directory, timeout))
            codec.closed_object(identity, ["schemaVersion", "component", "releaseVersion", "binarySha256", "goVersion", "goos", "goarch", "sourceRevision", "sourceModified"])
            if identity["schemaVersion"] != "1.0.0" or identity["component"] != "cadence-oss" or identity["releaseVersion"] != release_version or identity["binarySha256"] != binary_sha256:
                raise CadenceDependencyError("Cadence runtime identity differs from the pin")
            if _hash_fd(fd) != binary_sha256:
                raise CadenceDependencyError("Cadence executable changed during identity check")
            result = codec.parse(_run(fd, arguments, encoded, directory, timeout))
            validate_preview_response(request, result)
            if _hash_fd(fd) != binary_sha256:
                raise CadenceDependencyError("Cadence executable changed during consumption")
            return result
    except CadenceDependencyError:
        raise
    except (OSError, ValueError, TypeError, KeyError, ValidationError, subprocess.SubprocessError) as exc:
        raise CadenceDependencyError("Cadence dependency or exact contract is unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def validate_preview_response(request, result):
    """One shared exact response/denominator check for both installed and preview consumers."""
    v2 = request["contractIdentity"] in ("das-bundle-preview-input/v2", "das-bundle-preview-input/v3")
    schema_name = {"das-bundle-preview-input/v1": "bundle_preview.schema.json",
                   "das-bundle-preview-input/v2": "bundle_preview_v2.schema.json",
                   "das-bundle-preview-input/v3": "bundle_preview_v3.schema.json"}[request["contractIdentity"]]
    schema = json.loads(files("dasops.standards_contracts").joinpath(schema_name).read_text())
    Draft202012Validator(schema).validate(result)
    normalized_facts = sorted(request["facts"], key=lambda fact: (fact["key"], fact["sourceRef"]))
    if result["scope"] != request["scope"] or result["policyDigest"] != request["policyDigest"] or result["standardVersion"] != request["catalog"]["standardVersion"] or result["catalogDigest"] != codec.digest(request["catalog"]) or result["factsDigest"] != codec.digest(normalized_facts):
        raise CadenceDependencyError("Cadence response belongs to another input")
    if v2:
        requirements = request["requirementsCatalog"]
        if result["requirementsCatalogDigest"] != codec.digest_catalog(requirements):
            raise CadenceDependencyError("Cadence response belongs to another requirement catalog")
        expected = {}
        for leaf in requirements["requirements"] + requirements["editionRequirements"]:
            if leaf["id"] in expected:
                raise CadenceDependencyError("duplicate requirement identity")
            expected[leaf["id"]] = (leaf["ownerModule"], leaf["parentClause"])
        trace = result["requirementTrace"]
        if [row["requirementId"] for row in trace] != sorted(expected):
            raise CadenceDependencyError("Cadence response omits, repeats or reorders requirements")
        if any((row["ownerModule"], row["parentClause"]) != expected[row["requirementId"]] for row in trace):
            raise CadenceDependencyError("Cadence response changed requirement ownership or parent")
    subject = dict(result)
    received = subject.pop("previewDigest")
    if received != codec.digest(subject):
        raise CadenceDependencyError("Cadence response integrity changed")
    return result


def pin_native(binary, binary_sha256, release_version, timeout):
    """Seal the existing fixed consumer once; the caller installs its trusted policy."""
    path = Path(binary)
    source = sealed = None
    try:
        source = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        if not stat.S_ISREG(os.fstat(source).st_mode) or _hash_fd(source)!=binary_sha256:
            raise CadenceDependencyError('native consumer executable differs from its installed pin')
        sealed = os.memfd_create('das-native-qualification',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        size = os.fstat(source).st_size
        offset=0
        while offset < size:
            data=os.pread(source,min(1024*1024,size-offset),offset)
            if not data:raise CadenceDependencyError('native consumer changed while pinning')
            position=0
            while position<len(data):
                written=os.write(sealed,data[position:])
                if written<=0:raise CadenceDependencyError('native pin write failed')
                position+=written
            offset+=len(data)
        os.fchmod(sealed,0o500)
        fcntl.fcntl(sealed,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        if _hash_fd(sealed)!=binary_sha256 or _hash_fd(source)!=binary_sha256:
            raise CadenceDependencyError('native consumer changed while pinning')
        # This identity call is before the writer transaction. No candidate
        # path/environment is used and the executable is already sealed.
        with tempfile.TemporaryDirectory(prefix='das-native-qualification-') as directory:
            identity=codec.parse(_run(sealed,['version','--json'],b'',directory,timeout))
        codec.closed_object(identity,['schemaVersion','component','releaseVersion','binarySha256','goVersion','goos','goarch','sourceRevision','sourceModified'])
        if (identity['schemaVersion']!='1.0.0' or identity['component']!='cadence-oss'
                or identity['releaseVersion']!=release_version or identity['binarySha256']!=binary_sha256):
            raise CadenceDependencyError('native release identity differs from installation')
        result=sealed;sealed=None
        return result
    except (OSError,ValueError,CadenceDependencyError) as exc:
        raise CadenceDependencyError('native consumer installation failed') from exc
    finally:
        for descriptor in (source,sealed):
            if descriptor is not None:os.close(descriptor)
