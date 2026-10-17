from __future__ import annotations

import contextlib
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Iterator, Mapping, Protocol

from dasops.protected.canonical import (
    canonical_bytes,
    load_canonical_json,
    semantic_digest,
    with_self_digest,
)
from dasops.protected.state_store import atomic_write

from .schema_registry import BootstrapSchemaError, BootstrapSchemaRegistry


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECOVERY_ROLES = (
    "new_repository_owner",
    "old_repository_owner",
    "root_recovery",
    "security_recovery_owner",
)

RecoveryReceiptIssuer = Callable[[str, dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]]


@dataclass(frozen=True)
class RecoveryRootPolicy:
    root_digest: str
    root_epoch: int
    verifier_authority_ref: str
    controller_authority_ref: str
    root_recovery_threshold: int
    # role -> ((identity, key fingerprint), ...)
    role_signers: Mapping[str, tuple[tuple[str, str], ...]]


@dataclass(frozen=True)
class RecoveryVerificationRequest:
    purpose: str
    subject_digest: str
    signatures: tuple[dict[str, Any], ...]
    allowed_fingerprints: tuple[str, ...]
    threshold: int
    required_roles: tuple[str, ...]


RecoveryCryptographicVerifier = Callable[[RecoveryVerificationRequest], dict[str, Any]]


class RecoveryController(Protocol):
    authority_ref: str

    def apply_fence(self, fence: dict[str, Any]) -> dict[str, Any]: ...

    def read_fence(
        self, *, package_id: str, endpoint_role: str, repository_id: str
    ) -> dict[str, Any] | None: ...

    def observe(self, request: dict[str, Any]) -> Mapping[str, Any]: ...

    def validate_branch_closure(self, request: dict[str, Any]) -> Mapping[str, Any]: ...


class AdoptionRecoveryError(RuntimeError):
    pass


class AdoptionRecoveryCrash(AdoptionRecoveryError):
    """Deterministic response-loss injection for recovery tests."""


def _safe_id(kind: str, value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise AdoptionRecoveryError(f"unsafe {kind}: {value!r}")
    return value


def _time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise AdoptionRecoveryError(f"invalid recovery time: {value!r}") from exc
    if result.tzinfo is None:
        raise AdoptionRecoveryError("recovery time must have an offset")
    return result.astimezone(timezone.utc)


def _signature_subject(record: Mapping[str, Any]) -> str:
    subject = deepcopy(dict(record))
    subject.pop("recordDigest", None)
    subject.pop("signatureSubjectDigest", None)
    subject.pop("signatures", None)
    return semantic_digest(subject)


def _verification_request_digest(
    record: Mapping[str, Any],
    purpose: str,
    *,
    allowed_fingerprints: tuple[str, ...],
    threshold: int,
    required_roles: tuple[str, ...],
) -> str:
    signatures = list(record["signatures"])
    return semantic_digest(
        {
            "schema": "external-cryptographic-verification-request/v1",
            "purpose": purpose,
            "subjectDigest": record["signatureSubjectDigest"],
            "signatures": signatures,
            "allowedFingerprints": list(allowed_fingerprints),
            "threshold": threshold,
            "requiredRoles": list(required_roles),
        }
    )


def _derived_id(prefix: str, *parts: str) -> str:
    suffix = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{suffix}"


class AdoptionPublicationRecoveryStore:
    """Package-global authority-loss recovery state machine.

    This store closes coordination invariants only. Git publication, adoption FV,
    registry transition, and repository-handoff closure remain explicit callers of
    the selected branch and are represented here by ``branchClosureDigest``.
    """

    def __init__(
        self,
        authority_root: str | Path,
        *,
        root_policy: RecoveryRootPolicy,
        cryptographic_verifier: RecoveryCryptographicVerifier,
        controller: RecoveryController,
    ) -> None:
        supplied = Path(authority_root).expanduser()
        if not supplied.is_absolute() or supplied.is_symlink():
            raise AdoptionRecoveryError("recovery authority root must be absolute and non-symlinked")
        if str(supplied.resolve(strict=False)) != str(supplied):
            raise AdoptionRecoveryError("recovery authority root must be normalized")
        supplied.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(supplied, 0o700)
        metadata = os.stat(supplied)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise AdoptionRecoveryError("recovery authority root is not owner-controlled mode 0700")
        if not isinstance(root_policy, RecoveryRootPolicy):
            raise AdoptionRecoveryError("an independently pinned recovery root policy is mandatory")
        if not _DIGEST.fullmatch(root_policy.root_digest) or root_policy.root_epoch < 1:
            raise AdoptionRecoveryError("recovery root policy identity is invalid")
        if not root_policy.verifier_authority_ref.startswith("https://"):
            raise AdoptionRecoveryError("recovery verifier authority must be independently pinned HTTPS")
        if not root_policy.controller_authority_ref.startswith("https://"):
            raise AdoptionRecoveryError("recovery controller authority must be independently pinned HTTPS")
        if not callable(cryptographic_verifier):
            raise AdoptionRecoveryError("an independently pinned cryptographic verifier is mandatory")
        if controller is None or not isinstance(getattr(controller, "authority_ref", None), str):
            raise AdoptionRecoveryError("an independently pinned recovery controller is mandatory")
        if controller.authority_ref != root_policy.controller_authority_ref:
            raise AdoptionRecoveryError("recovery controller does not match the pinned authority")
        if any(
            not callable(getattr(controller, name, None))
            for name in ("apply_fence", "read_fence", "observe", "validate_branch_closure")
        ):
            raise AdoptionRecoveryError("recovery controller interface is incomplete")
        if set(root_policy.role_signers) != set(_RECOVERY_ROLES):
            raise AdoptionRecoveryError("recovery root policy role set is not exact")
        normalized_roles: dict[str, tuple[tuple[str, str], ...]] = {}
        all_identities: list[str] = []
        all_fingerprints: list[str] = []
        for role in _RECOVERY_ROLES:
            entries = tuple(root_policy.role_signers[role])
            if entries != tuple(sorted(entries)) or not entries:
                raise AdoptionRecoveryError(
                    f"trusted recovery role {role} must be sorted and nonempty"
                )
            for identity, fingerprint in entries:
                _safe_id("trusted signer identity", identity)
                if not _DIGEST.fullmatch(fingerprint):
                    raise AdoptionRecoveryError("trusted recovery signer fingerprint is invalid")
                all_identities.append(identity)
                all_fingerprints.append(fingerprint)
            normalized_roles[role] = entries
        for role in ("new_repository_owner", "old_repository_owner", "security_recovery_owner"):
            if len(normalized_roles[role]) != 1:
                raise AdoptionRecoveryError(
                    f"trusted recovery role {role} requires exactly one signer"
                )
        if (
            root_policy.root_recovery_threshold < 1
            or root_policy.root_recovery_threshold > len(normalized_roles["root_recovery"])
        ):
            raise AdoptionRecoveryError("pinned root recovery threshold is invalid")
        if len(set(all_identities)) != len(all_identities) or len(set(all_fingerprints)) != len(
            all_fingerprints
        ):
            raise AdoptionRecoveryError(
                "trusted recovery roles require globally distinct identities and keys"
            )
        self.root = supplied
        self.root_policy = root_policy
        self.trusted_role_signers = normalized_roles
        self.cryptographic_verifier = cryptographic_verifier
        self.controller = controller
        self.registry = BootstrapSchemaRegistry()
        for name in ("locks", "packages"):
            directory = self.root / name
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)

    @staticmethod
    def _crash(crash_after: str | None, phase: str) -> None:
        if crash_after == phase:
            raise AdoptionRecoveryCrash(f"injected response loss after {phase}")

    def _validate(self, value: dict[str, Any]) -> None:
        try:
            self.registry.validate(value)
        except BootstrapSchemaError as exc:
            raise AdoptionRecoveryError(str(exc)) from exc

    def _read(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_size > 4 * 1024 * 1024
        ):
            raise AdoptionRecoveryError(f"recovery record is not a bounded owner-only file: {path}")
        value = load_canonical_json(path.read_bytes())
        self._validate(value)
        return value

    def _write_immutable(self, path: Path, value: dict[str, Any]) -> dict[str, Any]:
        self._validate(value)
        encoded = canonical_bytes(value)
        existing = self._read(path)
        if existing is not None:
            if canonical_bytes(existing) != encoded:
                raise AdoptionRecoveryError(f"immutable recovery record drift: {path}")
            return existing
        atomic_write(path, encoded, mode=0o600, create_only=True)
        readback = self._read(path)
        if readback is None or canonical_bytes(readback) != encoded:
            raise AdoptionRecoveryError(f"recovery record readback failed: {path}")
        return readback

    def _write_current(self, path: Path, value: dict[str, Any]) -> dict[str, Any]:
        self._validate(value)
        atomic_write(path, canonical_bytes(value), mode=0o600)
        readback = self._read(path)
        if readback is None or readback["recordDigest"] != value["recordDigest"]:
            raise AdoptionRecoveryError(f"recovery current-head readback failed: {path}")
        return readback

    @contextlib.contextmanager
    def _package_lock(self, package_id: str) -> Iterator[None]:
        path = self.root / "locks" / f"{_safe_id('package id', package_id)}.lock"
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

    def _package(self, package_id: str) -> Path:
        return self.root / "packages" / _safe_id("package id", package_id)

    @staticmethod
    def _signer_tuples(record: Mapping[str, Any]) -> list[tuple[str, str, str]]:
        return sorted(
            (item["role"], item["identity"], item["keyFingerprint"])
            for item in record["signatures"]
        )

    @staticmethod
    def _verified_tuples(verification: Mapping[str, Any]) -> list[tuple[str, str, str]]:
        return sorted(
            (item["role"], item["identity"], item["keyFingerprint"])
            for item in verification["verifiedSigners"]
        )

    def _verify_external(
        self,
        *,
        record: dict[str, Any],
        verification: dict[str, Any] | None,
        purpose: str,
        not_before: str,
        not_after: str,
    ) -> dict[str, Any]:
        self._validate(record)
        if record["signatureSubjectDigest"] != _signature_subject(record):
            raise AdoptionRecoveryError("recovery signed subject digest mismatch")
        required_roles = tuple(_RECOVERY_ROLES)
        allowed_fingerprints = tuple(
            sorted(
                fingerprint
                for entries in self.trusted_role_signers.values()
                for _, fingerprint in entries
            )
        )
        threshold = 3 + self.root_policy.root_recovery_threshold
        trusted_tuples = {
            (role, identity, fingerprint)
            for role, entries in self.trusted_role_signers.items()
            for identity, fingerprint in entries
        }
        signer_tuples = self._signer_tuples(record)
        if len(signer_tuples) != len(set(signer_tuples)) or not set(signer_tuples).issubset(
            trusted_tuples
        ):
            raise AdoptionRecoveryError("recovery signature set is outside the pinned root policy")
        request = RecoveryVerificationRequest(
            purpose=purpose,
            subject_digest=record["signatureSubjectDigest"],
            signatures=tuple(record["signatures"]),
            allowed_fingerprints=allowed_fingerprints,
            threshold=threshold,
            required_roles=required_roles,
        )
        trusted_verification = self.cryptographic_verifier(request)
        if not isinstance(trusted_verification, dict):
            raise AdoptionRecoveryError("pinned cryptographic verifier returned no receipt")
        self._validate(trusted_verification)
        if verification is not None:
            self._validate(verification)
            if canonical_bytes(verification) != canonical_bytes(trusted_verification):
                raise AdoptionRecoveryError("caller verification differs from the pinned verifier receipt")
        verification = trusted_verification
        verified_at = _time(verification["verifiedAt"])
        lower = _time(not_before)
        upper = _time(not_after)
        if lower > upper or verified_at < lower or verified_at > upper:
            raise AdoptionRecoveryError("recovery verification time is outside its bound subject window")
        for item in record["signatures"]:
            signed_at = _time(item["signedAt"])
            if signed_at < lower or signed_at > verified_at:
                raise AdoptionRecoveryError("recovery signature time is outside its bound subject window")
        if (
            verification["purpose"] != purpose
            or verification["subjectDigest"] != record["signatureSubjectDigest"]
            or verification["requestDigest"]
            != _verification_request_digest(
                record,
                purpose,
                allowed_fingerprints=allowed_fingerprints,
                threshold=threshold,
                required_roles=required_roles,
            )
            or self._verified_tuples(verification) != self._signer_tuples(record)
            or verification["verifierAuthorityRef"]
            != self.root_policy.verifier_authority_ref
        ):
            raise AdoptionRecoveryError("recovery external verification does not bind every signature")
        return verification

    def _verify_authorization_roles(
        self,
        authorization: dict[str, Any],
        verification: dict[str, Any],
        *,
        effective_at: str,
    ) -> dict[str, Any]:
        purpose = "bootstrap_claim_adoption_publication_recovery_authorization"
        if (
            authorization["rootDigest"] != self.root_policy.root_digest
            or authorization["rootEpoch"] != self.root_policy.root_epoch
            or authorization["rootRecoveryThreshold"]
            != self.root_policy.root_recovery_threshold
        ):
            raise AdoptionRecoveryError("recovery authorization does not match the pinned root policy")
        verification = self._verify_external(
            record=authorization,
            verification=verification,
            purpose=purpose,
            not_before=authorization["authorizedAt"],
            not_after=effective_at,
        )
        signatures = authorization["signatures"]
        signer_order = [
            (item["role"], item["identity"], item["keyFingerprint"])
            for item in signatures
        ]
        if signer_order != sorted(signer_order):
            raise AdoptionRecoveryError("recovery authorization signatures must be sorted")
        fingerprints = [item["keyFingerprint"] for item in signatures]
        if len(set(fingerprints)) != len(fingerprints):
            raise AdoptionRecoveryError("recovery authorization roles require separate keys")
        roles = {role: [] for role in _RECOVERY_ROLES}
        for item in signatures:
            roles[item["role"]].append(item["identity"])
        if set(authorization["requiredRoles"]) != set(_RECOVERY_ROLES):
            raise AdoptionRecoveryError("recovery authorization required-role set is not exact")
        if roles["old_repository_owner"] != [authorization["oldRepositoryOwnerId"]]:
            raise AdoptionRecoveryError("old-repository owner authorization mismatch")
        if roles["new_repository_owner"] != [authorization["newRepositoryOwnerId"]]:
            raise AdoptionRecoveryError("new-repository owner authorization mismatch")
        if roles["security_recovery_owner"] != [authorization["securityRecoveryOwnerId"]]:
            raise AdoptionRecoveryError("security/recovery owner authorization mismatch")
        root_identities = roles["root_recovery"]
        if (
            root_identities != authorization["rootRecoverySignerIdentities"]
            or root_identities != sorted(set(root_identities))
            or len(root_identities) < authorization["rootRecoveryThreshold"]
        ):
            raise AdoptionRecoveryError("root recovery threshold was not met")
        trusted_ids = {
            role: [identity for identity, _ in self.trusted_role_signers[role]]
            for role in _RECOVERY_ROLES
        }
        if (
            trusted_ids["old_repository_owner"] != [authorization["oldRepositoryOwnerId"]]
            or trusted_ids["new_repository_owner"] != [authorization["newRepositoryOwnerId"]]
            or trusted_ids["security_recovery_owner"]
            != [authorization["securityRecoveryOwnerId"]]
            or not set(root_identities).issubset(trusted_ids["root_recovery"])
        ):
            raise AdoptionRecoveryError("recovery authorization identities differ from pinned policy")
        all_role_identities = [
            authorization["oldRepositoryOwnerId"],
            authorization["newRepositoryOwnerId"],
            authorization["securityRecoveryOwnerId"],
            *root_identities,
        ]
        if len(set(all_role_identities)) != len(all_role_identities) or authorization[
            "executorId"
        ] in set(all_role_identities):
            raise AdoptionRecoveryError("all recovery roles and executor must be identity-distinct")
        return verification

    def _persist_authorization(
        self,
        *,
        authorization: dict[str, Any],
        verification: dict[str, Any],
        effective_at: str,
    ) -> None:
        package = self._package(authorization["packageId"])
        authorization_path = package / "authorization.json"
        verification_path = package / "authorization-verification.json"
        existing_authorization = self._read(authorization_path)
        existing_verification = self._read(verification_path)
        if existing_authorization is not None and existing_authorization["recordDigest"] != authorization["recordDigest"]:
            raise AdoptionRecoveryError("another recovery authorization already owns this package")
        if existing_verification is not None and existing_verification["recordDigest"] != verification["recordDigest"]:
            raise AdoptionRecoveryError("recovery authorization verification drift")
        if existing_authorization is None or existing_verification is None:
            accepted = _time(effective_at)
            authorized = _time(authorization["authorizedAt"])
            expires = _time(authorization["expiresAt"])
            verified = _time(verification["verifiedAt"])
            if authorized >= expires or accepted < authorized or accepted >= expires or verified < authorized or verified > accepted:
                raise AdoptionRecoveryError("recovery authorization is outside its acceptance window")
        self._write_immutable(authorization_path, authorization)
        self._write_immutable(verification_path, verification)

    def _deny_paths(self, package_id: str) -> tuple[Path, Path]:
        root = self._package(package_id) / "authority-deny"
        return root / "generations", root / "current.json"

    def _initial_deny(
        self,
        authorization: dict[str, Any],
        verification: dict[str, Any],
        effective_at: str,
    ) -> dict[str, Any]:
        generations, current_path = self._deny_paths(authorization["packageId"])
        initial_path = generations / "00000000000000000000.json"
        initial = self._read(initial_path)
        if initial is None:
            current = self._read(current_path)
            if current is not None:
                raise AdoptionRecoveryError("package-global recovery authority deny has no genesis")
            initial = with_self_digest(
                {
                    "schema": "bootstrap-claim-adoption-recovery-authority-deny/v1",
                    "denyId": _derived_id("recovery-deny", authorization["packageId"]),
                    "packageId": authorization["packageId"],
                    "packageDigest": authorization["packageDigest"],
                    "prepareResultDigest": authorization["prepareResultDigest"],
                    "operationId": authorization["operationId"],
                    "authorizationDigest": authorization["recordDigest"],
                    "authorizationVerificationDigest": verification["recordDigest"],
                    "idempotencyKey": authorization["idempotencyKey"],
                    "rootDigest": authorization["rootDigest"],
                    "rootEpoch": authorization["rootEpoch"],
                    "oldAuthorityEpoch": authorization["oldAuthorityEpoch"],
                    "newAuthorityEpoch": authorization["newAuthorityEpoch"],
                    "generation": 0,
                    "state": "recovery_deny",
                    "previousDenyDigest": None,
                    "selectionHeadDigest": None,
                    "branchClosureDigest": None,
                    "updatedAt": effective_at,
                }
            )
            self._write_immutable(initial_path, initial)
            self._write_current(current_path, initial)
        expected = {
            "packageDigest": authorization["packageDigest"],
            "prepareResultDigest": authorization["prepareResultDigest"],
            "operationId": authorization["operationId"],
            "authorizationDigest": authorization["recordDigest"],
            "authorizationVerificationDigest": verification["recordDigest"],
            "idempotencyKey": authorization["idempotencyKey"],
            "rootDigest": authorization["rootDigest"],
            "rootEpoch": authorization["rootEpoch"],
            "oldAuthorityEpoch": authorization["oldAuthorityEpoch"],
            "newAuthorityEpoch": authorization["newAuthorityEpoch"],
        }
        if any(initial[field] != value for field, value in expected.items()):
            raise AdoptionRecoveryError("package-global recovery authority deny binding drift")
        current = self._read(current_path)
        if current is None:
            current = self._write_current(current_path, initial)
        if current["operationId"] != authorization["operationId"]:
            raise AdoptionRecoveryError("another recovery operation owns the package-global deny")
        if current["generation"] == 0 and current["recordDigest"] != initial["recordDigest"]:
            raise AdoptionRecoveryError("package-global recovery deny same-generation conflict")
        return initial

    def _release_deny(
        self,
        *,
        authorization: dict[str, Any],
        initial: dict[str, Any],
        outcome: str,
        selection_head: dict[str, Any],
        branch_closure_digest: str,
        effective_at: str,
    ) -> dict[str, Any]:
        generations, current_path = self._deny_paths(authorization["packageId"])
        current = self._read(current_path)
        target = f"released_after_{outcome}"
        if current is None:
            raise AdoptionRecoveryError("package-global recovery deny disappeared")
        if current["state"] != "recovery_deny":
            if (
                current["state"] == target
                and current["previousDenyDigest"] == initial["recordDigest"]
                and current["selectionHeadDigest"] == selection_head["recordDigest"]
                and current["branchClosureDigest"] == branch_closure_digest
            ):
                return current
            raise AdoptionRecoveryError("package-global recovery deny has conflicting terminal state")
        release = with_self_digest(
            {
                **{key: value for key, value in initial.items() if key != "recordDigest"},
                "generation": 1,
                "state": target,
                "previousDenyDigest": initial["recordDigest"],
                "selectionHeadDigest": selection_head["recordDigest"],
                "branchClosureDigest": branch_closure_digest,
                "updatedAt": effective_at,
            }
        )
        self._write_immutable(generations / "00000000000000000001.json", release)
        return self._write_current(current_path, release)

    def _endpoint_paths(self, package_id: str, role: str) -> tuple[Path, Path]:
        root = self._package(package_id) / "endpoint-fences" / role
        return root / "generations", root / "current.json"

    def _append_fence(self, fence: dict[str, Any]) -> dict[str, Any]:
        generations, current_path = self._endpoint_paths(fence["packageId"], fence["endpointRole"])
        path = generations / f"{fence['generation']:020d}.json"
        self._validate_fence_semantics(fence)
        current = self._read(current_path)
        if current is not None:
            if current["generation"] > fence["generation"]:
                raise AdoptionRecoveryError("endpoint fence generation rollback")
            if (
                current["generation"] == fence["generation"]
                and current["recordDigest"] != fence["recordDigest"]
            ):
                raise AdoptionRecoveryError("endpoint fence same-generation conflict")
        applied = self.controller.apply_fence(deepcopy(fence))
        if not isinstance(applied, dict) or canonical_bytes(applied) != canonical_bytes(fence):
            raise AdoptionRecoveryError("recovery controller did not byte-confirm the endpoint fence")
        readback = self.controller.read_fence(
            package_id=fence["packageId"],
            endpoint_role=fence["endpointRole"],
            repository_id=fence["repositoryId"],
        )
        if not isinstance(readback, dict) or canonical_bytes(readback) != canonical_bytes(fence):
            raise AdoptionRecoveryError("recovery controller endpoint fence readback mismatch")
        stored = self._write_immutable(path, fence)
        if current is None or current["generation"] < stored["generation"]:
            self._write_current(current_path, stored)
        elif current["generation"] == stored["generation"]:
            if current["recordDigest"] != stored["recordDigest"]:
                raise AdoptionRecoveryError("endpoint fence same-generation conflict")
        elif current["recordDigest"] != stored["recordDigest"]:
            raise AdoptionRecoveryError("endpoint fence generation rollback")
        return stored

    def _validate_fence_semantics(self, fence: dict[str, Any]) -> None:
        self._validate(fence)
        state = fence["state"]
        if _time(fence["readbackAt"]) < _time(fence["installedAt"]):
            raise AdoptionRecoveryError("endpoint fence readback predates installation")
        expected_scope = (
            "all_non_recovery_writes"
            if state in {"transition_fenced", "recovery_deny"}
            else "permanent_noncanonical"
            if state == "permanent_noncanonical"
            else "released"
        )
        if fence["denyWriteScope"] != expected_scope:
            raise AdoptionRecoveryError("endpoint fence state/write-scope mismatch")
        if state == "recovery_deny":
            if (
                fence["operationId"] is None
                or fence["authorizationDigest"] is None
                or fence["recoveryExceptionOperationId"] != fence["operationId"]
                or fence["branchClosureDigest"] is not None
            ):
                raise AdoptionRecoveryError("recovery-deny fence fields are inconsistent")
        elif state in {"released_after_success", "released_after_abort"}:
            if (
                fence["recoveryExceptionOperationId"] is not None
                or fence["branchClosureDigest"] is None
                or fence["authorizationDigest"] is None
            ):
                raise AdoptionRecoveryError("released endpoint fence fields are inconsistent")
        elif state == "permanent_noncanonical":
            if fence["recoveryExceptionOperationId"] is not None:
                raise AdoptionRecoveryError("permanent old fence cannot retain a recovery exception")

    def _derived_fence(
        self,
        *,
        authorization: dict[str, Any],
        current: dict[str, Any],
        state: str,
        branch_closure_digest: str | None,
        effective_at: str,
    ) -> dict[str, Any]:
        scope = (
            "permanent_noncanonical"
            if state == "permanent_noncanonical"
            else "released"
            if state.startswith("released_after_")
            else "all_non_recovery_writes"
        )
        return with_self_digest(
            {
                "schema": "bootstrap-claim-adoption-repository-fence/v1",
                "fenceId": _derived_id(
                    "recovery-fence", authorization["operationId"], current["endpointRole"], state
                ),
                "packageId": authorization["packageId"],
                "operationId": authorization["operationId"],
                "authorizationDigest": authorization["recordDigest"],
                "endpointRole": current["endpointRole"],
                "repositoryId": current["repositoryId"],
                "generation": current["generation"] + 1,
                "state": state,
                "previousFenceDigest": current["recordDigest"],
                "previousState": current["state"],
                "authorityEpoch": current["authorityEpoch"],
                "credentialEpoch": current["credentialEpoch"],
                "denyWriteScope": scope,
                "recoveryExceptionOperationId": (
                    authorization["operationId"] if state == "recovery_deny" else None
                ),
                "transitionSubjectDigest": current["transitionSubjectDigest"],
                "branchClosureDigest": branch_closure_digest,
                "installedAt": effective_at,
                "readbackAt": effective_at,
            }
        )

    def _old_recovery_fence(
        self,
        *,
        authorization: dict[str, Any],
        old_fence_prestate: dict[str, Any],
        effective_at: str,
    ) -> dict[str, Any]:
        self._validate(old_fence_prestate)
        self._validate_fence_semantics(old_fence_prestate)
        if (
            old_fence_prestate["schema"] != "bootstrap-claim-adoption-repository-fence/v1"
            or old_fence_prestate["recordDigest"] != authorization["oldFencePrestateDigest"]
            or old_fence_prestate["packageId"] != authorization["packageId"]
            or old_fence_prestate["endpointRole"] != "old_repository"
            or old_fence_prestate["repositoryId"] != authorization["oldRepositoryId"]
            or old_fence_prestate["state"] != authorization["expectedOldFenceState"]
            or old_fence_prestate["authorityEpoch"] != authorization["oldAuthorityEpoch"]
            or old_fence_prestate["credentialEpoch"] != authorization["oldCredentialEpoch"]
        ):
            raise AdoptionRecoveryError("old endpoint fence prestate substitution")
        generations, current_path = self._endpoint_paths(authorization["packageId"], "old_repository")
        current = self._read(current_path)
        controller_prestate = self.controller.read_fence(
            package_id=authorization["packageId"],
            endpoint_role="old_repository",
            repository_id=authorization["oldRepositoryId"],
        )
        expected_controller = current if current is not None else old_fence_prestate
        if not isinstance(controller_prestate, dict) or canonical_bytes(
            controller_prestate
        ) != canonical_bytes(expected_controller):
            recovery_path = generations / f"{old_fence_prestate['generation'] + 1:020d}.json"
            crash_recovery = self._read(recovery_path)
            if crash_recovery is None or canonical_bytes(controller_prestate) != canonical_bytes(
                crash_recovery
            ):
                raise AdoptionRecoveryError("old endpoint controller prestate readback mismatch")
        if current is not None and current["recordDigest"] != old_fence_prestate["recordDigest"]:
            if not (
                current["operationId"] == authorization["operationId"]
                and current["authorizationDigest"] == authorization["recordDigest"]
                and current["state"] in {"recovery_deny", "permanent_noncanonical", "released_after_abort"}
            ):
                raise AdoptionRecoveryError("old endpoint fence is owned by another transition")
        self._write_immutable(
            generations / f"{old_fence_prestate['generation']:020d}.json", old_fence_prestate
        )
        if current is None or current["generation"] < old_fence_prestate["generation"]:
            self._write_current(current_path, old_fence_prestate)
        elif current["generation"] == old_fence_prestate["generation"] and current["recordDigest"] != old_fence_prestate["recordDigest"]:
            raise AdoptionRecoveryError("old endpoint fence is owned by another transition")
        if old_fence_prestate["state"] == "permanent_noncanonical":
            return old_fence_prestate
        recovery_path = generations / f"{old_fence_prestate['generation'] + 1:020d}.json"
        existing_recovery = self._read(recovery_path)
        if existing_recovery is not None:
            if (
                existing_recovery["state"] != "recovery_deny"
                or existing_recovery["previousFenceDigest"] != old_fence_prestate["recordDigest"]
                or existing_recovery["operationId"] != authorization["operationId"]
                or existing_recovery["authorizationDigest"] != authorization["recordDigest"]
            ):
                raise AdoptionRecoveryError("old recovery-deny fence generation drift")
            current = self._read(current_path)
            if (
                current is not None
                and current["generation"] > existing_recovery["generation"]
                and current["previousFenceDigest"] == existing_recovery["recordDigest"]
                and current["state"] in {"permanent_noncanonical", "released_after_abort"}
            ):
                return existing_recovery
            return self._append_fence(existing_recovery)
        recovery = self._derived_fence(
            authorization=authorization,
            current=old_fence_prestate,
            state="recovery_deny",
            branch_closure_digest=None,
            effective_at=effective_at,
        )
        return self._append_fence(recovery)

    def _new_recovery_fence(
        self,
        *,
        authorization: dict[str, Any],
        transition_subject_digest: str,
        effective_at: str,
    ) -> dict[str, Any]:
        if not _DIGEST.fullmatch(transition_subject_digest):
            raise AdoptionRecoveryError("new endpoint transition subject digest is invalid")
        generations, current_path = self._endpoint_paths(authorization["packageId"], "new_repository")
        genesis_path = generations / "00000000000000000000.json"
        genesis = self._read(genesis_path)
        if genesis is not None:
            if (
                genesis["operationId"] == authorization["operationId"]
                and genesis["authorizationDigest"] == authorization["recordDigest"]
                and genesis["state"] == "recovery_deny"
                and genesis["repositoryId"] == authorization["newRepositoryId"]
            ):
                current = self._read(current_path)
                if (
                    current is not None
                    and current["generation"] > genesis["generation"]
                    and current["previousFenceDigest"] == genesis["recordDigest"]
                    and current["state"] in {"released_after_success", "released_after_abort"}
                ):
                    return genesis
                return self._append_fence(genesis)
            raise AdoptionRecoveryError("new endpoint recovery-deny genesis drift")
        current = self._read(current_path)
        if current is not None:
            raise AdoptionRecoveryError("new endpoint fence prestate was not absent")
        controller_current = self.controller.read_fence(
            package_id=authorization["packageId"],
            endpoint_role="new_repository",
            repository_id=authorization["newRepositoryId"],
        )
        if controller_current is not None:
            raise AdoptionRecoveryError("new endpoint controller prestate was not absent")
        recovery = with_self_digest(
            {
                "schema": "bootstrap-claim-adoption-repository-fence/v1",
                "fenceId": _derived_id("recovery-fence", authorization["operationId"], "new_repository"),
                "packageId": authorization["packageId"],
                "operationId": authorization["operationId"],
                "authorizationDigest": authorization["recordDigest"],
                "endpointRole": "new_repository",
                "repositoryId": authorization["newRepositoryId"],
                "generation": 0,
                "state": "recovery_deny",
                "previousFenceDigest": None,
                "previousState": None,
                "authorityEpoch": authorization["newAuthorityEpoch"],
                "credentialEpoch": authorization["newCredentialEpoch"],
                "denyWriteScope": "all_non_recovery_writes",
                "recoveryExceptionOperationId": authorization["operationId"],
                "transitionSubjectDigest": transition_subject_digest,
                "branchClosureDigest": None,
                "installedAt": effective_at,
                "readbackAt": effective_at,
            }
        )
        return self._append_fence(recovery)

    def _operation_root(self, authorization: dict[str, Any]) -> Path:
        return self._package(authorization["packageId"]) / "operations" / _safe_id(
            "operation id", authorization["operationId"]
        )

    def _head(
        self,
        *,
        authorization: dict[str, Any],
        authority_deny_digest: str,
        sequence: int,
        state: str,
        previous: dict[str, Any] | None,
        old_fence_digest: str | None,
        new_fence_digest: str | None,
        observation_digest: str | None,
        selected_outcome: str | None,
        branch_closure_digest: str | None,
        branch_closure_validation_digest: str | None,
        effective_at: str,
    ) -> dict[str, Any]:
        operation_root = self._operation_root(authorization)
        head_path = operation_root / "heads" / f"{sequence:020d}.json"
        existing = self._read(head_path)
        expected = {
            "operationId": authorization["operationId"],
            "packageId": authorization["packageId"],
            "packageDigest": authorization["packageDigest"],
            "authorizationDigest": authorization["recordDigest"],
            "authorityDenyDigest": authority_deny_digest,
            "sequence": sequence,
            "state": state,
            "previousHeadDigest": None if previous is None else previous["recordDigest"],
            "oldFenceDigest": old_fence_digest,
            "newFenceDigest": new_fence_digest,
            "observationDigest": observation_digest,
            "selectedOutcome": selected_outcome,
            "branchClosureDigest": branch_closure_digest,
            "branchClosureValidationDigest": branch_closure_validation_digest,
        }
        if existing is not None:
            if any(existing[field] != value for field, value in expected.items()):
                raise AdoptionRecoveryError("append-only recovery operation head fork")
            current = self._read(operation_root / "current.json")
            if current is None or current["sequence"] < sequence:
                self._write_current(operation_root / "current.json", existing)
            elif current["sequence"] == sequence and current["recordDigest"] != existing["recordDigest"]:
                raise AdoptionRecoveryError("recovery operation current-head fork")
            return existing
        current = self._read(operation_root / "current.json")
        if previous is None:
            if current is not None:
                raise AdoptionRecoveryError("recovery operation genesis is not unique")
        elif current is None or current["recordDigest"] != previous["recordDigest"]:
            raise AdoptionRecoveryError("recovery operation head CAS failed")
        head = with_self_digest(
            {
                "schema": "bootstrap-claim-adoption-publication-recovery-operation-head/v1",
                **expected,
                "recordedAt": effective_at,
            }
        )
        self._write_immutable(head_path, head)
        return self._write_current(operation_root / "current.json", head)

    def _observation(
        self,
        *,
        authorization: dict[str, Any],
        old_fence: dict[str, Any],
        new_fence: dict[str, Any],
        observations: Mapping[str, Any],
        effective_at: str,
    ) -> dict[str, Any]:
        if set(observations) != {"oldReadable", "newReadable", "oldMain", "newMain"}:
            raise AdoptionRecoveryError("recovery observation field set is not exact")
        observation_request = {
            "schema": "bootstrap-adoption-recovery-observation-request/v1",
            "controllerAuthorityRef": self.controller.authority_ref,
            "operationId": authorization["operationId"],
            "packageId": authorization["packageId"],
            "observationProfileDigest": authorization["observationProfileDigest"],
            "oldFenceDigest": old_fence["recordDigest"],
            "newFenceDigest": new_fence["recordDigest"],
            "expectedOldMain": authorization["expectedOldMain"],
            "candidateCommit": authorization["candidateCommit"],
        }
        request_digest = semantic_digest(observation_request)
        controlled = self.controller.observe(deepcopy(observation_request))
        if not isinstance(controlled, Mapping) or set(controlled) != {
            "controllerAuthorityRef",
            "observationRequestDigest",
            "observationReceiptDigest",
            "oldReadable",
            "newReadable",
            "oldMain",
            "newMain",
        }:
            raise AdoptionRecoveryError("recovery controller observation response is malformed")
        if (
            controlled["controllerAuthorityRef"] != self.controller.authority_ref
            or controlled["observationRequestDigest"] != request_digest
            or not isinstance(controlled["observationReceiptDigest"], str)
            or not _DIGEST.fullmatch(controlled["observationReceiptDigest"])
        ):
            raise AdoptionRecoveryError("recovery controller observation response is unbound")
        controlled_observations = {
            field: controlled[field]
            for field in ("oldReadable", "newReadable", "oldMain", "newMain")
        }
        if canonical_bytes(controlled_observations) != canonical_bytes(dict(observations)):
            raise AdoptionRecoveryError("caller observations differ from controller readback")
        path = self._operation_root(authorization) / "observation.json"
        existing = self._read(path)
        expected = {
            "operationId": authorization["operationId"],
            "packageId": authorization["packageId"],
            "observationProfileDigest": authorization["observationProfileDigest"],
            "oldFenceDigest": old_fence["recordDigest"],
            "newFenceDigest": new_fence["recordDigest"],
            "oldFenceState": old_fence["state"],
            "newFenceState": new_fence["state"],
            "oldReadable": observations["oldReadable"],
            "newReadable": observations["newReadable"],
            "oldMain": observations["oldMain"],
            "newMain": observations["newMain"],
            "controllerAuthorityRef": self.controller.authority_ref,
            "observationRequestDigest": request_digest,
            "observationReceiptDigest": controlled["observationReceiptDigest"],
        }
        if existing is not None:
            if any(existing[field] != value for field, value in expected.items()):
                raise AdoptionRecoveryError("committed recovery observation drift")
            return existing
        value = with_self_digest(
            {
                "schema": "bootstrap-claim-adoption-publication-recovery-observation/v1",
                **expected,
                "observedAt": effective_at,
            }
        )
        return self._write_immutable(path, value)

    @staticmethod
    def _select(authorization: dict[str, Any], observation: dict[str, Any]) -> str:
        if not observation["oldReadable"] or not observation["newReadable"]:
            return "ambiguous"
        old_expected = observation["oldMain"] == authorization["expectedOldMain"]
        if (
            old_expected
            and observation["newMain"] is None
            and observation["oldFenceState"] == "recovery_deny"
        ):
            return "abort"
        if (
            old_expected
            and observation["newMain"] == authorization["candidateCommit"]
            and observation["oldFenceState"] in {"recovery_deny", "permanent_noncanonical"}
        ):
            return "success"
        return "ambiguous"

    def _close_endpoint_fences(
        self,
        *,
        authorization: dict[str, Any],
        outcome: str,
        old_fence: dict[str, Any],
        new_fence: dict[str, Any],
        branch_closure_digest: str,
        effective_at: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        old_target = "released_after_abort" if outcome == "abort" else "permanent_noncanonical"
        new_target = "released_after_abort" if outcome == "abort" else "released_after_success"
        if old_fence["state"] == old_target:
            old_terminal = old_fence
        elif old_fence["state"] == "recovery_deny":
            old_terminal = self._append_fence(
                self._derived_fence(
                    authorization=authorization,
                    current=old_fence,
                    state=old_target,
                    branch_closure_digest=branch_closure_digest,
                    effective_at=effective_at,
                )
            )
        elif outcome == "success" and old_fence["state"] == "permanent_noncanonical":
            old_terminal = old_fence
        else:
            raise AdoptionRecoveryError("old endpoint fence cannot close the selected branch")
        if new_fence["state"] == new_target:
            new_terminal = new_fence
        elif new_fence["state"] == "recovery_deny":
            new_terminal = self._append_fence(
                self._derived_fence(
                    authorization=authorization,
                    current=new_fence,
                    state=new_target,
                    branch_closure_digest=branch_closure_digest,
                    effective_at=effective_at,
                )
            )
        else:
            raise AdoptionRecoveryError("new endpoint fence cannot close the selected branch")
        return old_terminal, new_terminal

    def _validate_branch_closure(
        self,
        *,
        authorization: dict[str, Any],
        outcome: str,
        observation: dict[str, Any],
        selected_head: dict[str, Any],
        old_fence: dict[str, Any],
        new_fence: dict[str, Any],
        branch_closure_digest: str,
    ) -> str:
        request = {
            "schema": "bootstrap-adoption-recovery-branch-validation-request/v1",
            "controllerAuthorityRef": self.controller.authority_ref,
            "operationId": authorization["operationId"],
            "packageId": authorization["packageId"],
            "packageDigest": authorization["packageDigest"],
            "outcome": outcome,
            "branchClosureDigest": branch_closure_digest,
            "observationDigest": observation["recordDigest"],
            "selectedHeadDigest": selected_head["recordDigest"],
            "oldFenceDigest": old_fence["recordDigest"],
            "newFenceDigest": new_fence["recordDigest"],
        }
        request_digest = semantic_digest(request)
        result = self.controller.validate_branch_closure(deepcopy(request))
        if not isinstance(result, Mapping) or set(result) != {
            "controllerAuthorityRef",
            "validationRequestDigest",
            "validationReceiptDigest",
            "outcome",
            "branchClosureDigest",
            "valid",
        }:
            raise AdoptionRecoveryError("recovery branch validation response is malformed")
        if (
            result["controllerAuthorityRef"] != self.controller.authority_ref
            or result["validationRequestDigest"] != request_digest
            or result["outcome"] != outcome
            or result["branchClosureDigest"] != branch_closure_digest
            or result["valid"] is not True
            or not isinstance(result["validationReceiptDigest"], str)
            or not _DIGEST.fullmatch(result["validationReceiptDigest"])
        ):
            raise AdoptionRecoveryError("recovery branch closure was not independently validated")
        return result["validationReceiptDigest"]

    def _head_lineage(self, authorization: dict[str, Any], terminal_sequence: int) -> list[str]:
        result: list[str] = []
        previous = None
        for sequence in range(terminal_sequence + 1):
            head = self._read(
                self._operation_root(authorization) / "heads" / f"{sequence:020d}.json"
            )
            if head is None or head["previousHeadDigest"] != previous:
                raise AdoptionRecoveryError("recovery operation head lineage is incomplete")
            result.append(head["recordDigest"])
            previous = head["recordDigest"]
        return result

    def _verify_terminal_receipt(
        self,
        *,
        authorization: dict[str, Any],
        authorization_verification: dict[str, Any],
        receipt: dict[str, Any],
        verification: dict[str, Any] | None,
        effective_at: str,
    ) -> dict[str, Any]:
        verification = self._verify_external(
            record=receipt,
            verification=verification,
            purpose="bootstrap_claim_adoption_publication_recovery_receipt",
            not_before=receipt["completedAt"],
            not_after=effective_at,
        )
        if self._verified_tuples(verification) != self._verified_tuples(authorization_verification):
            raise AdoptionRecoveryError("recovery receipt signer set differs from its authorization")
        expected = {
            "operationId": authorization["operationId"],
            "rootDigest": authorization["rootDigest"],
            "packageId": authorization["packageId"],
            "packageDigest": authorization["packageDigest"],
            "authorizationDigest": authorization["recordDigest"],
            "authorizationVerificationDigest": authorization_verification["recordDigest"],
        }
        if any(receipt[field] != value for field, value in expected.items()):
            raise AdoptionRecoveryError("terminal recovery receipt binding drift")
        return verification

    def _find_digest(self, root: Path, record_digest: str) -> dict[str, Any]:
        matches: list[dict[str, Any]] = []
        for path in root.rglob("*.json"):
            value = self._read(path)
            if value is not None and value["recordDigest"] == record_digest:
                matches.append(value)
        if len(matches) != 1:
            raise AdoptionRecoveryError("terminal recovery closure digest is absent or ambiguous")
        return matches[0]

    def _validate_terminal_closure(
        self,
        *,
        authorization: dict[str, Any],
        receipt: dict[str, Any],
    ) -> None:
        outcome = receipt["outcome"]
        terminal_sequence = 3 if outcome == "ambiguous" else 4
        lineage = self._head_lineage(authorization, terminal_sequence)
        if receipt["operationHeadDigests"] != lineage:
            raise AdoptionRecoveryError("terminal recovery receipt head lineage drift")
        operation_root = self._operation_root(authorization)
        current_head = self._read(operation_root / "current.json")
        if current_head is None or current_head["recordDigest"] != lineage[-1]:
            raise AdoptionRecoveryError("terminal recovery operation current head drift")
        observation = self._read(operation_root / "observation.json")
        if observation is None:
            raise AdoptionRecoveryError("terminal recovery observation is absent")
        selected = self._read(operation_root / "heads" / "00000000000000000003.json")
        if (
            selected is None
            or selected["selectedOutcome"] != outcome
            or selected["observationDigest"] != observation["recordDigest"]
        ):
            raise AdoptionRecoveryError("terminal recovery selection closure drift")
        endpoint_root = self._package(authorization["packageId"]) / "endpoint-fences"
        selected_old = self._find_digest(endpoint_root / "old_repository" / "generations", selected["oldFenceDigest"])
        selected_new = self._find_digest(endpoint_root / "new_repository" / "generations", selected["newFenceDigest"])
        self._observation(
            authorization=authorization,
            old_fence=selected_old,
            new_fence=selected_new,
            observations={
                field: observation[field]
                for field in ("oldReadable", "newReadable", "oldMain", "newMain")
            },
            effective_at=observation["observedAt"],
        )
        deny_current = self._read(self._deny_paths(authorization["packageId"])[1])
        old_current = self._read(self._endpoint_paths(authorization["packageId"], "old_repository")[1])
        new_current = self._read(self._endpoint_paths(authorization["packageId"], "new_repository")[1])
        if deny_current is None or old_current is None or new_current is None:
            raise AdoptionRecoveryError("terminal recovery current closure is incomplete")
        for fence in (old_current, new_current):
            controller_fence = self.controller.read_fence(
                package_id=fence["packageId"],
                endpoint_role=fence["endpointRole"],
                repository_id=fence["repositoryId"],
            )
            if not isinstance(controller_fence, dict) or canonical_bytes(
                controller_fence
            ) != canonical_bytes(fence):
                raise AdoptionRecoveryError("terminal endpoint controller readback drift")
        if outcome == "ambiguous":
            expected = {
                "retainedOldFenceDigest": old_current["recordDigest"],
                "retainedNewFenceDigest": new_current["recordDigest"],
                "retainedAuthorityDenyDigest": deny_current["recordDigest"],
                "ambiguousHeadDigest": current_head["recordDigest"],
                "completedAt": current_head["recordedAt"],
            }
            if deny_current["state"] != "recovery_deny":
                raise AdoptionRecoveryError("ambiguous recovery released its authority deny")
        else:
            validation_digest = self._validate_branch_closure(
                authorization=authorization,
                outcome=outcome,
                observation=observation,
                selected_head=selected,
                old_fence=selected_old,
                new_fence=selected_new,
                branch_closure_digest=receipt["branchClosureDigest"],
            )
            expected = {
                "branchClosureValidationDigest": validation_digest,
                "newFenceReleaseDigest": new_current["recordDigest"],
                "authorityDenyReleaseDigest": deny_current["recordDigest"],
                "recoveryClosedHeadDigest": current_head["recordDigest"],
                "completedAt": current_head["recordedAt"],
            }
            if outcome == "abort":
                expected["oldFenceReleaseDigest"] = old_current["recordDigest"]
                terminal_states = ("released_after_abort", "released_after_abort", "released_after_abort")
            else:
                expected["oldPermanentFenceDigest"] = old_current["recordDigest"]
                terminal_states = ("released_after_success", "permanent_noncanonical", "released_after_success")
            if (deny_current["state"], old_current["state"], new_current["state"]) != terminal_states:
                raise AdoptionRecoveryError("terminal recovery state tuple is inconsistent")
            if current_head["branchClosureValidationDigest"] != validation_digest:
                raise AdoptionRecoveryError("terminal branch validation/head binding drift")
        if any(receipt[field] != value for field, value in expected.items()):
            raise AdoptionRecoveryError("terminal recovery receipt closure drift")

    def _terminal_receipt(
        self,
        *,
        authorization: dict[str, Any],
        authorization_verification: dict[str, Any],
        subject: dict[str, Any],
        issuer: RecoveryReceiptIssuer,
        crash_after: str | None,
        effective_at: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        operation_root = self._operation_root(authorization)
        final_path = operation_root / "recovery-receipt.json"
        final_verification_path = operation_root / "recovery-receipt-verification.json"
        final = self._read(final_path)
        final_verification = self._read(final_verification_path)
        if final is not None:
            final_verification = self._verify_terminal_receipt(
                authorization=authorization,
                authorization_verification=authorization_verification,
                receipt=final,
                verification=final_verification,
                effective_at=effective_at,
            )
            self._write_immutable(final_verification_path, final_verification)
            self._validate_terminal_closure(authorization=authorization, receipt=final)
            return final, final_verification

        candidate_path = operation_root / "recovery-receipt-candidate.json"
        candidate_verification_path = operation_root / "recovery-receipt-verification-candidate.json"
        candidate = self._read(candidate_path)
        candidate_verification = self._read(candidate_verification_path)
        if candidate is None:
            if candidate_verification is not None:
                raise AdoptionRecoveryError("recovery receipt verification exists without its candidate")
            candidate, candidate_verification = issuer(
                "bootstrap_claim_adoption_publication_recovery_receipt", subject
            )
            candidate_verification = self._verify_terminal_receipt(
                authorization=authorization,
                authorization_verification=authorization_verification,
                receipt=candidate,
                verification=candidate_verification,
                effective_at=effective_at,
            )
            for field, value in subject.items():
                if candidate[field] != value:
                    raise AdoptionRecoveryError("recovery receipt issuer changed its subject")
            self._write_immutable(candidate_path, candidate)
            self._write_immutable(candidate_verification_path, candidate_verification)
        else:
            candidate_verification = self._verify_terminal_receipt(
                authorization=authorization,
                authorization_verification=authorization_verification,
                receipt=candidate,
                verification=candidate_verification,
                effective_at=effective_at,
            )
            for field, value in subject.items():
                if candidate[field] != value:
                    raise AdoptionRecoveryError("stored recovery receipt candidate subject drift")
            self._write_immutable(candidate_verification_path, candidate_verification)
        self._crash(crash_after, "receipt_candidate_written")
        self._write_immutable(final_path, candidate)
        self._write_immutable(final_verification_path, candidate_verification)
        self._crash(crash_after, "receipt_written")
        self._validate_terminal_closure(authorization=authorization, receipt=candidate)
        return candidate, candidate_verification

    def recover(
        self,
        *,
        authorization: dict[str, Any],
        authorization_verification: dict[str, Any],
        old_fence_prestate: dict[str, Any],
        new_transition_subject_digest: str,
        observations: Mapping[str, Any],
        branch_closure_digest: str | None,
        issuer: RecoveryReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run or resume one exact package-global authority-loss recovery."""

        authorization_verification = self._verify_authorization_roles(
            authorization,
            authorization_verification,
            effective_at=effective_at,
        )
        if (
            new_transition_subject_digest != authorization["transitionSubjectDigest"]
            or old_fence_prestate.get("transitionSubjectDigest") != authorization["transitionSubjectDigest"]
        ):
            raise AdoptionRecoveryError("recovery transition subject substitution")
        package_id = authorization["packageId"]
        with self._package_lock(package_id):
            operation_root = self._operation_root(authorization)
            terminal = self._read(operation_root / "recovery-receipt.json")
            terminal_verification = self._read(
                operation_root / "recovery-receipt-verification.json"
            )
            if terminal is not None and terminal_verification is not None:
                observation = self._read(operation_root / "observation.json")
                if observation is None or any(
                    observation[field] != observations[field]
                    for field in ("oldReadable", "newReadable", "oldMain", "newMain")
                ):
                    raise AdoptionRecoveryError("terminal recovery retry observation drift")
                if terminal["outcome"] == "ambiguous":
                    if branch_closure_digest is not None:
                        raise AdoptionRecoveryError("ambiguous recovery forbids a branch closure")
                elif terminal["branchClosureDigest"] != branch_closure_digest:
                    raise AdoptionRecoveryError("terminal recovery retry branch closure drift")
                terminal_verification = self._verify_terminal_receipt(
                    authorization=authorization,
                    authorization_verification=authorization_verification,
                    receipt=terminal,
                    verification=terminal_verification,
                    effective_at=effective_at,
                )
                self._validate_terminal_closure(
                    authorization=authorization,
                    receipt=terminal,
                )
                return terminal, terminal_verification

            self._persist_authorization(
                authorization=authorization,
                verification=authorization_verification,
                effective_at=effective_at,
            )
            deny = self._initial_deny(authorization, authorization_verification, effective_at)
            self._crash(crash_after, "authority_deny_committed")
            prepared = self._head(
                authorization=authorization,
                authority_deny_digest=deny["recordDigest"],
                sequence=0,
                state="recovery_prepared",
                previous=None,
                old_fence_digest=None,
                new_fence_digest=None,
                observation_digest=None,
                selected_outcome=None,
                branch_closure_digest=None,
                branch_closure_validation_digest=None,
                effective_at=effective_at,
            )
            self._crash(crash_after, "recovery_prepared")

            old_fence = self._old_recovery_fence(
                authorization=authorization,
                old_fence_prestate=old_fence_prestate,
                effective_at=effective_at,
            )
            self._crash(crash_after, "old_fence_committed")
            new_fence = self._new_recovery_fence(
                authorization=authorization,
                transition_subject_digest=new_transition_subject_digest,
                effective_at=effective_at,
            )
            fenced = self._head(
                authorization=authorization,
                authority_deny_digest=deny["recordDigest"],
                sequence=1,
                state="dual_fences_committed",
                previous=prepared,
                old_fence_digest=old_fence["recordDigest"],
                new_fence_digest=new_fence["recordDigest"],
                observation_digest=None,
                selected_outcome=None,
                branch_closure_digest=None,
                branch_closure_validation_digest=None,
                effective_at=effective_at,
            )
            self._crash(crash_after, "dual_fences_committed")

            observation = self._observation(
                authorization=authorization,
                old_fence=old_fence,
                new_fence=new_fence,
                observations=observations,
                effective_at=effective_at,
            )
            observed = self._head(
                authorization=authorization,
                authority_deny_digest=deny["recordDigest"],
                sequence=2,
                state="observations_committed",
                previous=fenced,
                old_fence_digest=old_fence["recordDigest"],
                new_fence_digest=new_fence["recordDigest"],
                observation_digest=observation["recordDigest"],
                selected_outcome=None,
                branch_closure_digest=None,
                branch_closure_validation_digest=None,
                effective_at=effective_at,
            )
            self._crash(crash_after, "observations_committed")

            outcome = self._select(authorization, observation)
            selected = self._head(
                authorization=authorization,
                authority_deny_digest=deny["recordDigest"],
                sequence=3,
                state=f"{outcome}_blocked" if outcome == "ambiguous" else f"{outcome}_selected",
                previous=observed,
                old_fence_digest=old_fence["recordDigest"],
                new_fence_digest=new_fence["recordDigest"],
                observation_digest=observation["recordDigest"],
                selected_outcome=outcome,
                branch_closure_digest=None,
                branch_closure_validation_digest=None,
                effective_at=effective_at,
            )
            self._crash(crash_after, "branch_selected")

            common = {
                "schema": "bootstrap-claim-adoption-publication-recovery-receipt/v1",
                "receiptId": _derived_id("recovery-receipt", authorization["operationId"]),
                "operationId": authorization["operationId"],
                "rootDigest": authorization["rootDigest"],
                "packageId": package_id,
                "packageDigest": authorization["packageDigest"],
                "authorizationDigest": authorization["recordDigest"],
                "authorizationVerificationDigest": authorization_verification["recordDigest"],
                "outcome": outcome,
            }
            if outcome == "ambiguous":
                if branch_closure_digest is not None:
                    raise AdoptionRecoveryError("ambiguous recovery forbids a branch closure")
                subject = {
                    **common,
                    "operationHeadDigests": self._head_lineage(authorization, 3),
                    "retainedOldFenceDigest": old_fence["recordDigest"],
                    "retainedNewFenceDigest": new_fence["recordDigest"],
                    "retainedAuthorityDenyDigest": deny["recordDigest"],
                    "ambiguousHeadDigest": selected["recordDigest"],
                    "completedAt": selected["recordedAt"],
                }
                return self._terminal_receipt(
                    authorization=authorization,
                    authorization_verification=authorization_verification,
                    subject=subject,
                    issuer=issuer,
                    crash_after=crash_after,
                    effective_at=effective_at,
                )

            if not isinstance(branch_closure_digest, str) or not _DIGEST.fullmatch(
                branch_closure_digest
            ):
                raise AdoptionRecoveryError("selected recovery branch requires an exact closure digest")
            branch_closure_validation_digest = self._validate_branch_closure(
                authorization=authorization,
                outcome=outcome,
                observation=observation,
                selected_head=selected,
                old_fence=old_fence,
                new_fence=new_fence,
                branch_closure_digest=branch_closure_digest,
            )
            old_terminal, new_terminal = self._close_endpoint_fences(
                authorization=authorization,
                outcome=outcome,
                old_fence=old_fence,
                new_fence=new_fence,
                branch_closure_digest=branch_closure_digest,
                effective_at=effective_at,
            )
            self._crash(crash_after, "endpoint_fences_closed")
            deny_release = self._release_deny(
                authorization=authorization,
                initial=deny,
                outcome=outcome,
                selection_head=selected,
                branch_closure_digest=branch_closure_digest,
                effective_at=effective_at,
            )
            self._crash(crash_after, "authority_deny_released")
            closed = self._head(
                authorization=authorization,
                authority_deny_digest=deny_release["recordDigest"],
                sequence=4,
                state="recovery_closed",
                previous=selected,
                old_fence_digest=old_terminal["recordDigest"],
                new_fence_digest=new_terminal["recordDigest"],
                observation_digest=observation["recordDigest"],
                selected_outcome=outcome,
                branch_closure_digest=branch_closure_digest,
                branch_closure_validation_digest=branch_closure_validation_digest,
                effective_at=effective_at,
            )
            self._crash(crash_after, "recovery_closed")
            subject = {
                **common,
                "operationHeadDigests": self._head_lineage(authorization, 4),
                "branchClosureDigest": branch_closure_digest,
                "branchClosureValidationDigest": branch_closure_validation_digest,
                **(
                    {
                        "oldFenceReleaseDigest": old_terminal["recordDigest"],
                        "newFenceReleaseDigest": new_terminal["recordDigest"],
                    }
                    if outcome == "abort"
                    else {
                        "oldPermanentFenceDigest": old_terminal["recordDigest"],
                        "newFenceReleaseDigest": new_terminal["recordDigest"],
                    }
                ),
                "authorityDenyReleaseDigest": deny_release["recordDigest"],
                "recoveryClosedHeadDigest": closed["recordDigest"],
                "completedAt": closed["recordedAt"],
            }
            return self._terminal_receipt(
                authorization=authorization,
                authorization_verification=authorization_verification,
                subject=subject,
                issuer=issuer,
                crash_after=crash_after,
                effective_at=effective_at,
            )
