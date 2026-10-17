from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Callable, Iterator, Mapping

from dasops.protected.canonical import canonical_bytes, load_canonical_json, semantic_digest, with_self_digest
from dasops.protected.state_store import atomic_write

from .authority import ExternalVerificationRequest
from .schema_registry import BootstrapSchemaRegistry


class CryptographicVerificationError(RuntimeError):
    pass


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class ExternalPublicKey:
    identity: str
    roles: tuple[str, ...]
    public_key_path: Path


@dataclass(frozen=True)
class _LoadedPublicKey:
    specification: ExternalPublicKey
    pem: bytes


class OpenSslEd25519ExternalVerifier:
    """Raw Ed25519 verifier for non-circular SHA-256 subject-digest signatures."""

    def __init__(
        self,
        *,
        keys: Mapping[str, ExternalPublicKey],
        authority_ref: str,
        receipt_store: str | Path,
        clock: Callable[[], datetime],
        openssl_path: str = "/usr/bin/openssl",
    ) -> None:
        if not authority_ref.startswith("https://"):
            raise CryptographicVerificationError("cryptographic verifier authority reference must be HTTPS")
        if not callable(clock):
            raise CryptographicVerificationError("cryptographic verifier clock is mandatory")
        executable = Path(openssl_path)
        if not executable.is_absolute() or executable.is_symlink() or not executable.is_file():
            raise CryptographicVerificationError("OpenSSL executable path is not an absolute regular file")
        executable_metadata = os.stat(executable)
        if executable_metadata.st_uid != 0 or stat.S_IMODE(executable_metadata.st_mode) & 0o022:
            raise CryptographicVerificationError("OpenSSL executable is not root-owned and write-protected")
        root = Path(receipt_store).expanduser()
        if not root.is_absolute() or root.is_symlink() or str(root.resolve(strict=False)) != str(root):
            raise CryptographicVerificationError("cryptographic receipt store must be normalized and absolute")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        if os.stat(root).st_uid != os.getuid():
            raise CryptographicVerificationError("cryptographic receipt store is not owner controlled")
        for name in ("locks", "receipts", "scratch"):
            directory = root / name
            directory.mkdir(mode=0o700, exist_ok=True)
            metadata = os.lstat(directory)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise CryptographicVerificationError("cryptographic receipt-store member is not owner controlled")
            os.chmod(directory, 0o700)
        self.authority_ref = authority_ref
        self.receipt_store = root
        self.clock = clock
        self.openssl_path = str(executable)
        self.registry = BootstrapSchemaRegistry()
        loaded: dict[str, _LoadedPublicKey] = {}
        for fingerprint, specification in keys.items():
            if not isinstance(specification, ExternalPublicKey):
                raise CryptographicVerificationError("cryptographic key registry entry is invalid")
            if not specification.identity or specification.roles != tuple(sorted(set(specification.roles))):
                raise CryptographicVerificationError("cryptographic key identity/roles are invalid")
            pem = self._public_key_bytes(specification.public_key_path)
            observed = self.public_key_fingerprint(pem, openssl_path=self.openssl_path)
            if observed != fingerprint:
                raise CryptographicVerificationError("cryptographic public-key fingerprint mismatch")
            loaded[fingerprint] = _LoadedPublicKey(specification=specification, pem=pem)
        if not loaded:
            raise CryptographicVerificationError("cryptographic key registry is empty")
        self.keys = loaded

    @staticmethod
    def _public_key_bytes(path_value: Path) -> bytes:
        path = Path(path_value).expanduser()
        if not path.is_absolute() or path.is_symlink() or str(path.resolve()) != str(path):
            raise CryptographicVerificationError("cryptographic public key path is not normalized and absolute")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_size < 32
                or metadata.st_size > 65_536
            ):
                raise CryptographicVerificationError("cryptographic public key is not a trusted bounded regular file")
            value = bytearray()
            while len(value) <= 65_536:
                chunk = os.read(descriptor, min(65_537 - len(value), 16_384))
                if not chunk:
                    break
                value.extend(chunk)
            if len(value) != metadata.st_size or len(value) > 65_536:
                raise CryptographicVerificationError("cryptographic public key changed or exceeded its size bound")
            return bytes(value)
        finally:
            os.close(descriptor)

    @staticmethod
    def public_key_fingerprint(pem: bytes, *, openssl_path: str = "/usr/bin/openssl") -> str:
        try:
            process = subprocess.run(
                [openssl_path, "pkey", "-pubin", "-outform", "DER"],
                input=pem,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CryptographicVerificationError("OpenSSL public-key parsing failed closed") from exc
        if process.returncode != 0 or not process.stdout or len(process.stdout) > 65_536:
            raise CryptographicVerificationError("cryptographic public key is not a valid OpenSSL public key")
        return "sha256:" + hashlib.sha256(process.stdout).hexdigest()

    @contextlib.contextmanager
    def _lock(self, request_digest: str) -> Iterator[None]:
        path = self.receipt_store / "locks" / f"{request_digest[7:]}.lock"
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

    def _verify(self, key: _LoadedPublicKey, message: bytes, signature: bytes) -> bool:
        with tempfile.TemporaryDirectory(dir=self.receipt_store / "scratch") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            key_path = root / "public.pem"
            message_path = root / "subject.bin"
            signature_path = root / "signature.bin"
            for path, value in ((key_path, key.pem), (message_path, message), (signature_path, signature)):
                path.write_bytes(value)
                path.chmod(0o600)
            try:
                process = subprocess.run(
                    [
                        self.openssl_path,
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-inkey",
                        str(key_path),
                        "-rawin",
                        "-in",
                        str(message_path),
                        "-sigfile",
                        str(signature_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                    env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise CryptographicVerificationError("OpenSSL signature verification failed closed") from exc
            if len(process.stdout) > 65_536 or len(process.stderr) > 65_536:
                raise CryptographicVerificationError("OpenSSL verification exceeded its output budget")
            return process.returncode == 0

    def __call__(self, request: ExternalVerificationRequest) -> dict:
        if (
            not isinstance(request, ExternalVerificationRequest)
            or not 3 <= len(request.purpose) <= 128
            or not _DIGEST.fullmatch(request.subject_digest)
            or request.allowed_fingerprints != tuple(sorted(set(request.allowed_fingerprints)))
            or any(not _DIGEST.fullmatch(value) for value in request.allowed_fingerprints)
            or request.required_roles != tuple(sorted(set(request.required_roles)))
            or request.threshold < 1
            or request.threshold > len(request.allowed_fingerprints)
        ):
            raise CryptographicVerificationError("cryptographic verification request is malformed")
        request_digest = semantic_digest(
            {
                "schema": "external-cryptographic-verification-request/v1",
                "purpose": request.purpose,
                "subjectDigest": request.subject_digest,
                "signatures": list(request.signatures),
                "allowedFingerprints": list(request.allowed_fingerprints),
                "threshold": request.threshold,
                "requiredRoles": list(request.required_roles),
            }
        )
        verified = []
        for signature in request.signatures:
            if not isinstance(signature, dict):
                continue
            fingerprint = signature.get("keyFingerprint")
            key = self.keys.get(fingerprint)
            if fingerprint not in request.allowed_fingerprints or key is None:
                continue
            specification = key.specification
            if (
                signature.get("algorithm") != "ed25519"
                or signature.get("identity") != specification.identity
                or signature.get("role") not in specification.roles
            ):
                continue
            try:
                decoded = base64.b64decode(signature.get("signatureBase64", ""), validate=True)
            except (ValueError, TypeError):
                continue
            if len(decoded) != 64 or not self._verify(key, request.subject_digest.encode("ascii"), decoded):
                continue
            verified.append(
                {
                    "role": signature["role"],
                    "identity": signature["identity"],
                    "keyFingerprint": fingerprint,
                }
            )
        verified.sort(key=lambda item: (item["role"], item["identity"], item["keyFingerprint"]))
        receipt_path = self.receipt_store / "receipts" / f"{request_digest[7:]}.json"
        with self._lock(request_digest):
            if receipt_path.exists():
                descriptor = os.open(
                    receipt_path,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or metadata.st_size > 1_048_576
                    ):
                        raise CryptographicVerificationError("cryptographic verification receipt is not trusted")
                    encoded = bytearray()
                    while len(encoded) <= 1_048_576:
                        chunk = os.read(descriptor, min(1_048_577 - len(encoded), 65_536))
                        if not chunk:
                            break
                        encoded.extend(chunk)
                    if len(encoded) != metadata.st_size or len(encoded) > 1_048_576:
                        raise CryptographicVerificationError("cryptographic verification receipt changed or exceeded its size bound")
                finally:
                    os.close(descriptor)
                receipt = load_canonical_json(bytes(encoded))
                self.registry.validate(receipt)
                if (
                    receipt["requestDigest"] != request_digest
                    or receipt["purpose"] != request.purpose
                    or receipt["subjectDigest"] != request.subject_digest
                    or receipt["verifiedSigners"] != verified
                    or receipt["verifierAuthorityRef"] != self.authority_ref
                ):
                    raise CryptographicVerificationError("cryptographic verification receipt drift")
            else:
                now = self.clock()
                if now.tzinfo is None:
                    raise CryptographicVerificationError("cryptographic verifier clock is not timezone aware")
                receipt = with_self_digest(
                    {
                        "schema": "external-cryptographic-verification-receipt/v1",
                        "receiptId": f"crypto-{request_digest[-24:]}",
                        "requestDigest": request_digest,
                        "purpose": request.purpose,
                        "subjectDigest": request.subject_digest,
                        "verifiedSigners": verified,
                        "verifierAuthorityRef": self.authority_ref,
                        "verifiedAt": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    }
                )
                self.registry.validate(receipt)
                atomic_write(receipt_path, canonical_bytes(receipt), mode=0o600, create_only=True)
        return {
            "verifierAuthorityRef": self.authority_ref,
            "verifierReceiptDigest": receipt["recordDigest"],
            "verifiedSigners": verified,
        }
