from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
import subprocess

import pytest

from dasops.bootstrap.authority import ExternalVerificationRequest
from dasops.bootstrap.crypto_verifier import (
    CryptographicVerificationError,
    ExternalPublicKey,
    OpenSslEd25519ExternalVerifier,
)
from dasops.protected.canonical import canonical_bytes, load_canonical_json, with_self_digest

from .test_authority import digest


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def key_pair(tmp_path: Path, name: str):
    private = tmp_path / f"{name}.private.pem"
    public = tmp_path / f"{name}.public.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    private.chmod(0o600)
    public.chmod(0o644)
    fingerprint = OpenSslEd25519ExternalVerifier.public_key_fingerprint(public.read_bytes())
    return private, public.resolve(), fingerprint


def sign(private: Path, subject_digest: str, *, fingerprint: str, identity: str, role: str):
    subject_path = private.with_name(f"{private.stem}.{role}.subject")
    subject_path.write_bytes(subject_digest.encode("ascii"))
    subject_path.chmod(0o600)
    signature = subprocess.run(
        [
            "/usr/bin/openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private),
            "-rawin",
            "-in",
            str(subject_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
    assert len(signature) == 64
    return {
        "keyFingerprint": fingerprint,
        "identity": identity,
        "role": role,
        "algorithm": "ed25519",
        "signatureBase64": base64.b64encode(signature).decode(),
        "signedAt": "2026-07-16T11:59:00Z",
    }


def verifier_and_request(tmp_path: Path):
    private_a, public_a, fingerprint_a = key_pair(tmp_path, "a")
    private_b, public_b, fingerprint_b = key_pair(tmp_path, "b")
    subject = digest("a")
    signatures = (
        sign(
            private_a,
            subject,
            fingerprint=fingerprint_a,
            identity="owner-a",
            role="repository_owner",
        ),
        sign(
            private_b,
            subject,
            fingerprint=fingerprint_b,
            identity="reviewer-b",
            role="independent_verifier",
        ),
    )
    verifier = OpenSslEd25519ExternalVerifier(
        keys={
            fingerprint_a: ExternalPublicKey("owner-a", ("repository_owner",), public_a),
            fingerprint_b: ExternalPublicKey("reviewer-b", ("independent_verifier",), public_b),
        },
        authority_ref="https://authority.example/crypto/epoch-1",
        receipt_store=(tmp_path / "receipts").resolve(),
        clock=lambda: NOW,
    )
    request = ExternalVerificationRequest(
        purpose="bootstrap_operation_descriptor",
        subject_digest=subject,
        signatures=signatures,
        allowed_fingerprints=tuple(sorted((fingerprint_a, fingerprint_b))),
        threshold=2,
        required_roles=("independent_verifier", "repository_owner"),
    )
    return verifier, request


def test_real_ed25519_verifier_checks_keys_signatures_and_persists_stable_receipt(tmp_path: Path) -> None:
    verifier, request = verifier_and_request(tmp_path)
    first = verifier(request)
    second = verifier(request)
    assert first == second
    assert [item["role"] for item in first["verifiedSigners"]] == [
        "independent_verifier",
        "repository_owner",
    ]
    receipts = list((tmp_path / "receipts" / "receipts").glob("*.json"))
    assert len(receipts) == 1
    assert receipts[0].stat().st_mode & 0o777 == 0o600


def test_real_ed25519_verifier_excludes_tampered_or_misbound_signatures(tmp_path: Path) -> None:
    verifier, request = verifier_and_request(tmp_path)
    signatures = [dict(item) for item in request.signatures]
    signatures[0]["signatureBase64"] = base64.b64encode(b"x" * 64).decode()
    signatures[1]["identity"] = "substituted-identity"
    rejected = ExternalVerificationRequest(
        purpose=request.purpose,
        subject_digest=request.subject_digest,
        signatures=tuple(signatures),
        allowed_fingerprints=request.allowed_fingerprints,
        threshold=request.threshold,
        required_roles=request.required_roles,
    )
    assert verifier(rejected)["verifiedSigners"] == []


def test_real_ed25519_verifier_rejects_registry_fingerprint_mismatch(tmp_path: Path) -> None:
    _private_a, public_a, fingerprint_a = key_pair(tmp_path, "a")
    _private_b, public_b, _fingerprint_b = key_pair(tmp_path, "b")
    with pytest.raises(CryptographicVerificationError, match="fingerprint mismatch"):
        OpenSslEd25519ExternalVerifier(
            keys={fingerprint_a: ExternalPublicKey("owner-a", ("repository_owner",), public_b)},
            authority_ref="https://authority.example/crypto/epoch-1",
            receipt_store=(tmp_path / "receipts").resolve(),
            clock=lambda: NOW,
        )


def test_real_ed25519_verifier_rejects_existing_receipt_rebinding(tmp_path: Path) -> None:
    verifier, request = verifier_and_request(tmp_path)
    verifier(request)
    receipt_path = next((tmp_path / "receipts" / "receipts").glob("*.json"))
    receipt = load_canonical_json(receipt_path.read_bytes())
    receipt["verifierAuthorityRef"] = "https://substitute.example/crypto/epoch-1"
    receipt = with_self_digest({key: value for key, value in receipt.items() if key != "recordDigest"})
    receipt_path.write_bytes(canonical_bytes(receipt))
    receipt_path.chmod(0o600)
    with pytest.raises(CryptographicVerificationError, match="receipt drift"):
        verifier(request)
