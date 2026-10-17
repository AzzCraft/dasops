from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Callable, Iterable

from dasops.protected.canonical import semantic_digest, with_self_digest

from .schema_registry import BootstrapSchemaError, BootstrapSchemaRegistry


HEX_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:rc(0|[1-9][0-9]*))?$")


class AuthorityVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExternalVerificationRequest:
    purpose: str
    subject_digest: str
    signatures: tuple[dict[str, Any], ...]
    allowed_fingerprints: tuple[str, ...]
    threshold: int
    required_roles: tuple[str, ...]


ExternalVerifier = Callable[[ExternalVerificationRequest], dict[str, Any]]
RevocationVerifier = Callable[[str, str, int, datetime], dict[str, Any]]


@dataclass(frozen=True)
class VerifiedAuthority:
    anchor: dict[str, Any]
    root: dict[str, Any]
    root_verification: dict[str, Any]


@dataclass(frozen=True)
class VerifiedToolRelease:
    authority: VerifiedAuthority
    source_decision: dict[str, Any]
    release: dict[str, Any]
    source_verification: dict[str, Any]
    release_verification: dict[str, Any]


@dataclass(frozen=True)
class VerifiedOperation:
    tool_release: VerifiedToolRelease
    descriptor: dict[str, Any]
    descriptor_verification: dict[str, Any]


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityVerificationError(f"invalid RFC3339 time: {value}") from exc
    if parsed.tzinfo is None:
        raise AuthorityVerificationError("authority time must have an offset")
    return parsed.astimezone(timezone.utc)


def _now(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AuthorityVerificationError("verification time must be timezone aware")
    return value.astimezone(timezone.utc)


def _valid_window(record: dict[str, Any], now: datetime) -> None:
    start = _time(record["validFrom"])
    end = _time(record["validUntil"])
    if start >= end or now < start or now >= end:
        raise AuthorityVerificationError("authority record is outside its validity window")


def _semver(value: str) -> tuple[int, int, int, int, int]:
    match = SEMVER.fullmatch(value)
    if not match:
        raise AuthorityVerificationError(f"invalid semantic version: {value}")
    major, minor, patch, rc = match.groups()
    return int(major), int(minor), int(patch), (1 if rc is None else 0), int(rc or 0)


def _unique(values: Iterable[str], label: str) -> tuple[str, ...]:
    result = tuple(values)
    if tuple(sorted(result)) != result or len(set(result)) != len(result):
        raise AuthorityVerificationError(f"{label} must be sorted and unique")
    return result


def _signature_subject(record: dict[str, Any]) -> str:
    subject = dict(record)
    subject.pop("recordDigest", None)
    subject.pop("signatureSubjectDigest", None)
    subject.pop("signatures", None)
    return semantic_digest(subject)


def _validate_signature_subject(record: dict[str, Any]) -> None:
    if record["signatureSubjectDigest"] != _signature_subject(record):
        raise AuthorityVerificationError("non-circular signature subject digest mismatch")


class BootstrapAuthorityVerifier:
    def __init__(
        self,
        *,
        trusted_anchor_digest: str,
        external_verifier: ExternalVerifier,
        revocation_verifier: RevocationVerifier,
        registry: BootstrapSchemaRegistry | None = None,
    ) -> None:
        if not HEX_DIGEST.fullmatch(trusted_anchor_digest):
            raise AuthorityVerificationError("trusted anchor digest must be externally pinned SHA-256")
        if external_verifier is None or revocation_verifier is None:
            raise AuthorityVerificationError("independently controlled verification callbacks are mandatory")
        self.trusted_anchor_digest = trusted_anchor_digest
        self.external_verifier = external_verifier
        self.revocation_verifier = revocation_verifier
        self.registry = registry or BootstrapSchemaRegistry()

    def _schema(self, value: dict[str, Any]) -> None:
        try:
            self.registry.validate(value)
        except BootstrapSchemaError as exc:
            raise AuthorityVerificationError(str(exc)) from exc

    def _external(
        self,
        *,
        purpose: str,
        subject_digest: str,
        signatures: list[dict[str, Any]],
        allowed_fingerprints: Iterable[str],
        threshold: int,
        required_roles: Iterable[str],
        verified_at: datetime,
        fingerprint_roles: dict[str, tuple[str, ...]],
    ) -> dict[str, Any]:
        allowed = _unique(sorted(allowed_fingerprints), "allowed fingerprints")
        roles = _unique(sorted(required_roles), "required roles")
        if threshold < 1 or threshold > len(allowed):
            raise AuthorityVerificationError("signature threshold is outside the allowed signer set")
        request = ExternalVerificationRequest(
            purpose=purpose,
            subject_digest=subject_digest,
            signatures=tuple(signatures),
            allowed_fingerprints=allowed,
            threshold=threshold,
            required_roles=roles,
        )
        response = self.external_verifier(request)
        if not isinstance(response, dict):
            raise AuthorityVerificationError("external verifier returned no structured result")
        authority_ref = response.get("verifierAuthorityRef")
        receipt_digest = response.get("verifierReceiptDigest")
        signers = response.get("verifiedSigners")
        if not isinstance(authority_ref, str) or authority_ref.startswith("local:"):
            raise AuthorityVerificationError("external verifier authority is absent or local-only")
        if not isinstance(receipt_digest, str) or not HEX_DIGEST.fullmatch(receipt_digest):
            raise AuthorityVerificationError("external verifier receipt digest is invalid")
        if not isinstance(signers, list):
            raise AuthorityVerificationError("external verifier signer set is absent")
        fingerprints: list[str] = []
        identities: list[str] = []
        observed_roles: list[str] = []
        normalized: list[dict[str, str]] = []
        provided = {
            (item.get("role"), item.get("identity"), item.get("keyFingerprint"))
            for item in signatures
            if isinstance(item, dict)
        }
        for signer in signers:
            if not isinstance(signer, dict):
                raise AuthorityVerificationError("external signer result is malformed")
            fingerprint = signer.get("keyFingerprint")
            identity = signer.get("identity")
            role = signer.get("role")
            if fingerprint not in allowed or not isinstance(identity, str) or not identity or not isinstance(role, str):
                raise AuthorityVerificationError("external signer is outside the allowed identity/key/role set")
            if (role, identity, fingerprint) not in provided:
                raise AuthorityVerificationError("external signer result is not bound to an input signature")
            if role not in fingerprint_roles.get(fingerprint, ()):
                raise AuthorityVerificationError("external signer role is not authorized for its key")
            fingerprints.append(fingerprint)
            identities.append(identity)
            observed_roles.append(role)
            normalized.append({"role": role, "identity": identity, "keyFingerprint": fingerprint})
        if len(set(fingerprints)) < threshold:
            raise AuthorityVerificationError("external signature threshold was not met")
        if len(set(identities)) != len(identities):
            raise AuthorityVerificationError("one identity cannot occupy multiple verified signer slots")
        if not set(roles).issubset(observed_roles):
            raise AuthorityVerificationError("external verification omitted required roles")
        normalized.sort(key=lambda item: (item["role"], item["identity"], item["keyFingerprint"]))
        result = with_self_digest(
            {
                "schema": "external-role-verification/v1",
                "purpose": purpose,
                "subjectDigest": subject_digest,
                "requiredRoles": list(roles),
                "threshold": threshold,
                "verifiedSigners": normalized,
                "verifierAuthorityRef": authority_ref,
                "verifierReceiptDigest": receipt_digest,
                "verifiedAt": verified_at.isoformat().replace("+00:00", "Z"),
            }
        )
        self._schema(result)
        return result

    def verify_anchor_root(
        self,
        *,
        anchor: dict[str, Any],
        root: dict[str, Any],
        now: datetime,
    ) -> VerifiedAuthority:
        now = _now(now)
        self._schema(anchor)
        self._schema(root)
        _validate_signature_subject(root)
        if anchor["recordDigest"] != self.trusted_anchor_digest:
            raise AuthorityVerificationError("anchor does not match the out-of-band digest")
        if root["anchorId"] != anchor["anchorId"]:
            raise AuthorityVerificationError("root anchor identity mismatch")
        if root["rootId"] != anchor["expectedRootId"] or root["recordDigest"] != anchor["expectedRootDigest"]:
            raise AuthorityVerificationError("root identity or digest substitution")
        _valid_window(anchor, now)
        _valid_window(root, now)
        signing = _unique(anchor["rootSigningKeyFingerprints"], "anchor root signing fingerprints")
        recovery = _unique(anchor["recoveryKeyFingerprints"], "anchor recovery fingerprints")
        key_ids = [item["keyId"] for item in root["keys"]]
        key_fingerprints = [item["fingerprint"] for item in root["keys"]]
        if key_ids != sorted(key_ids) or len(set(key_ids)) != len(key_ids) or len(set(key_fingerprints)) != len(key_fingerprints):
            raise AuthorityVerificationError("root keys must be sorted by unique key ID with unique fingerprints")
        for item in root["keys"]:
            _unique(item["roles"], f"roles for {item['keyId']}")
        policy = root["toolPolicy"]
        _unique(policy["allowedSourceRepos"], "allowed source repositories")
        _unique(policy["requiredReviewRoles"], "required review roles")
        _unique(policy["requiredOperationRoles"], "required operation roles")
        _unique(policy["allowedOperations"], "allowed bootstrap operations")
        root_keys = {item["fingerprint"]: item for item in root["keys"]}
        if set(signing) != {key for key, item in root_keys.items() if "root_signer" in item["roles"]}:
            raise AuthorityVerificationError("root signing key set does not match the anchor")
        if set(recovery) != {key for key, item in root_keys.items() if "recovery" in item["roles"]}:
            raise AuthorityVerificationError("recovery key set does not match the anchor")
        if root["ordinaryThreshold"] != anchor["rootThreshold"] or root["recoveryThreshold"] != anchor["recoveryThreshold"]:
            raise AuthorityVerificationError("root thresholds do not match the anchor")
        if root["revocationEndpoint"] != anchor["revocationEndpoint"]:
            raise AuthorityVerificationError("root revocation endpoint does not match the anchor")
        revocation = self.revocation_verifier(anchor["revocationEndpoint"], root["rootId"], root["epoch"], now)
        if not isinstance(revocation, dict) or revocation.get("status") != "good":
            raise AuthorityVerificationError("root revocation status is not good")
        if revocation.get("rootDigest") != root["recordDigest"] or not HEX_DIGEST.fullmatch(str(revocation.get("receiptDigest", ""))):
            raise AuthorityVerificationError("revocation receipt does not bind the root")
        verification = self._external(
            purpose="bootstrap_root",
            subject_digest=root["signatureSubjectDigest"],
            signatures=root["signatures"],
            allowed_fingerprints=signing,
            threshold=anchor["rootThreshold"],
            required_roles=(),
            verified_at=now,
            fingerprint_roles={fingerprint: ("root_signer",) for fingerprint in signing},
        )
        return VerifiedAuthority(anchor=anchor, root=root, root_verification=verification)

    def verify_tool_release(
        self,
        *,
        authority: VerifiedAuthority,
        source_decision: dict[str, Any],
        release: dict[str, Any],
        now: datetime,
    ) -> VerifiedToolRelease:
        now = _now(now)
        self._schema(source_decision)
        self._schema(release)
        _validate_signature_subject(source_decision)
        _validate_signature_subject(release)
        root = authority.root
        for record in (source_decision, release):
            if record["rootId"] != root["rootId"] or record["rootEpoch"] != root["epoch"]:
                raise AuthorityVerificationError("tool record root identity/epoch mismatch")
            _valid_window(record, now)
        if source_decision["status"] != "accepted" or release["status"] != "accepted":
            raise AuthorityVerificationError("tool source and release must be externally accepted")
        if source_decision["upstreamRepo"] not in root["toolPolicy"]["allowedSourceRepos"]:
            raise AuthorityVerificationError("tool source repository is not allowed by the root")
        if release["sourceDecisionDigest"] != source_decision["recordDigest"]:
            raise AuthorityVerificationError("tool release source-decision mismatch")
        for field in ("sourceCommit", "sourceTree", "sourceSubtree"):
            if release[field] != source_decision[field]:
                raise AuthorityVerificationError(f"tool release {field} lineage mismatch")
        if _semver(release["version"]) < _semver(root["toolPolicy"]["minimumDasopsVersion"]):
            raise AuthorityVerificationError("tool release is below the root minimum version")
        if release["independentReviewStatus"] != "accepted" or release["signatureStatus"] != "signed":
            raise AuthorityVerificationError("tool release lacks independent review or signature acceptance")
        review_roles = root["toolPolicy"]["requiredReviewRoles"]
        allowed_by_role = {
            item["fingerprint"]
            for item in root["keys"]
            if set(item["roles"]).intersection(review_roles)
        }
        source_verification = self._external(
            purpose="tool_source_decision",
            subject_digest=source_decision["signatureSubjectDigest"],
            signatures=source_decision["signatures"],
            allowed_fingerprints=allowed_by_role,
            threshold=len(review_roles),
            required_roles=review_roles,
            verified_at=now,
            fingerprint_roles={fingerprint: tuple(root_key["roles"]) for fingerprint, root_key in {item["fingerprint"]: item for item in root["keys"]}.items()},
        )
        release_verification = self._external(
            purpose="tool_release",
            subject_digest=release["signatureSubjectDigest"],
            signatures=release["signatures"],
            allowed_fingerprints=allowed_by_role,
            threshold=len(review_roles),
            required_roles=review_roles,
            verified_at=now,
            fingerprint_roles={fingerprint: tuple(root_key["roles"]) for fingerprint, root_key in {item["fingerprint"]: item for item in root["keys"]}.items()},
        )
        return VerifiedToolRelease(
            authority=authority,
            source_decision=source_decision,
            release=release,
            source_verification=source_verification,
            release_verification=release_verification,
        )

    def verify_operation_descriptor(
        self,
        *,
        tool_release: VerifiedToolRelease,
        descriptor: dict[str, Any],
        expected_operation: str,
        change_id: str,
        task_id: str,
        now: datetime,
    ) -> VerifiedOperation:
        now = _now(now)
        self._schema(descriptor)
        _validate_signature_subject(descriptor)
        root = tool_release.authority.root
        _valid_window(descriptor, now)
        if descriptor["rootDigest"] != root["recordDigest"]:
            raise AuthorityVerificationError("operation descriptor root mismatch")
        if descriptor["toolReleaseDigest"] != tool_release.release["recordDigest"]:
            raise AuthorityVerificationError("operation descriptor tool release mismatch")
        if descriptor["operation"] != expected_operation or expected_operation not in root["toolPolicy"]["allowedOperations"]:
            raise AuthorityVerificationError("operation descriptor operation is not authorized")
        if descriptor["changeId"] != change_id or descriptor["taskId"] != task_id:
            raise AuthorityVerificationError("operation descriptor task subject mismatch")
        operation_roles = root["toolPolicy"]["requiredOperationRoles"]
        allowed = {
            item["fingerprint"]
            for item in root["keys"]
            if set(item["roles"]).intersection(operation_roles)
        }
        verification = self._external(
            purpose="bootstrap_operation_descriptor",
            subject_digest=descriptor["signatureSubjectDigest"],
            signatures=descriptor["signatures"],
            allowed_fingerprints=allowed,
            threshold=len(operation_roles),
            required_roles=operation_roles,
            verified_at=now,
            fingerprint_roles={fingerprint: tuple(root_key["roles"]) for fingerprint, root_key in {item["fingerprint"]: item for item in root["keys"]}.items()},
        )
        return VerifiedOperation(tool_release=tool_release, descriptor=descriptor, descriptor_verification=verification)
