from __future__ import annotations

import base64
import contextlib
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Iterable, Mapping

from dasops.protected.canonical import (
    canonical_bytes,
    load_canonical_json,
    semantic_digest,
    with_self_digest,
)
from dasops.protected.state_store import StateStoreError, atomic_write

from .schema_registry import BootstrapSchemaError, BootstrapSchemaRegistry


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
TERMINAL_STATES = frozenset(
    {"cancelled_pre_cas", "adopted", "compensated", "abandoned", "emergency_recovered"}
)


class RootRotationError(RuntimeError):
    pass


class RootRotationCrash(RootRotationError):
    """Deterministic failure injection used to prove response-loss recovery."""


@dataclass(frozen=True)
class RotationApprovalRequest:
    operation_id: str
    acceptance_kind: str
    rotation_subject_digest: str
    threshold: int
    allowed_fingerprints: tuple[str, ...]
    signatures: tuple[dict[str, Any], ...]
    verified_at: str


@dataclass(frozen=True)
class RootAuthenticationRequest:
    root: dict[str, Any]
    purpose: str
    verified_at: str


@dataclass(frozen=True)
class AdoptionClosureAuthenticationRequest:
    activation_state: dict[str, Any]
    current_head: dict[str, Any]
    verified_at: str


@dataclass(frozen=True)
class RootRotationResult:
    transition: dict[str, Any]
    current_head: dict[str, Any]
    operation_result: dict[str, Any]
    authorizations: tuple[dict[str, Any], ...]


ApprovalVerifier = Callable[[RotationApprovalRequest], dict[str, Any]]
RootAuthenticator = Callable[[RootAuthenticationRequest], dict[str, Any]]
AdoptionClosureAuthenticator = Callable[[AdoptionClosureAuthenticationRequest], dict[str, Any]]
FrontierReader = Callable[[], dict[str, Any]]
NonceFactory = Callable[[], bytes]
PopVerifier = Callable[[dict[str, Any], bytes], dict[str, Any]]


def _safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise RootRotationError(f"unsafe {label}: {value!r}")
    return value


def _time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise RootRotationError(f"invalid {label}") from exc
    if parsed.tzinfo is None:
        raise RootRotationError(f"{label} must contain an offset")
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _signature_subject(record: dict[str, Any]) -> str:
    subject = dict(record)
    subject.pop("recordDigest", None)
    subject.pop("signatureSubjectDigest", None)
    subject.pop("signatures", None)
    return semantic_digest(subject)


def _sorted_unique(values: Iterable[str], label: str) -> tuple[str, ...]:
    result = tuple(values)
    if result != tuple(sorted(result)) or len(result) != len(set(result)):
        raise RootRotationError(f"{label} must be sorted and unique")
    return result


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _strict_nonce(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != 43 or "=" in value:
        raise RootRotationError("successor activation nonce is not canonical unpadded base64url")
    try:
        result = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except Exception as exc:
        raise RootRotationError("successor activation nonce is invalid") from exc
    if len(result) != 32 or base64.urlsafe_b64encode(result).decode("ascii").rstrip("=") != value:
        raise RootRotationError("successor activation nonce is not canonical")
    return result


def successor_v3_activation_slot_digest(state: Mapping[str, Any]) -> str:
    return semantic_digest(
        {
            "schema": "bootstrap-successor-v3-activation-slot-subject/v1",
            "registryId": state["registryId"],
            "adoptionReceiptDigest": state["adoptionReceiptDigest"],
            "taskLockV3Digest": state["taskLockV3Digest"],
            "activationGeneration": state["activationGeneration"],
            "operation": "adoption_activation",
        }
    )


def successor_v3_activation_subject_digest(state: Mapping[str, Any]) -> str:
    return semantic_digest(
        {
            "schema": "bootstrap-successor-v3-activation-subject/v1",
            "activationSlotDigest": state["activationSlotDigest"],
            "registryId": state["registryId"],
            "rootEpoch": state["rootEpoch"],
            "rootDigest": state["rootDigest"],
            "rotationHeadDigest": state["rotationHeadDigest"],
            "adoptionReceiptDigest": state["adoptionReceiptDigest"],
            "successorProfileDigest": state["successorProfileDigest"],
            "successorRegistryDigest": state["successorRegistryDigest"],
            "taskLockV3Digest": state["taskLockV3Digest"],
            "tokenHash": state["tokenHash"],
            "activationGeneration": state["activationGeneration"],
            "operation": "adoption_activation",
        }
    )


def successor_v3_activation_response(token: bytes, challenge: dict[str, Any]) -> bytes:
    """Derive a PoP response without serializing or returning the raw token."""

    if not isinstance(token, bytes) or len(token) != 32:
        raise RootRotationError("successor activation token must be exactly 32 bytes")
    _strict_nonce(challenge["nonceBase64"])
    if not isinstance(challenge.get("recordDigest"), str) or not DIGEST.fullmatch(challenge["recordDigest"]):
        raise RootRotationError("successor activation challenge digest is invalid")
    subject = b"bootstrap-successor-v3-activation/v2\0" + canonical_bytes(
        {"challengeDigest": challenge["recordDigest"]}
    )
    return hmac.new(token, subject, hashlib.sha256).digest()


class RootEpochRotationStore:
    """Owner-controlled normal root rotation and successor-v3 activation core.

    All durable records are strict canonical JSON. Rotation records, approvals,
    heads, challenges, receipts and state generations are content addressed or
    create-only. Only small current-pointer files are replaceable, under one
    owner-only flock and exact predecessor comparison.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        registry_id: str,
        approval_verifier: ApprovalVerifier,
        root_authenticator: RootAuthenticator,
        adoption_closure_authenticator: AdoptionClosureAuthenticator,
        frontier_reader: FrontierReader,
        anchor_owner_fingerprints: Iterable[str],
        anchor_owner_threshold: int = 1,
        nonce_factory: NonceFactory | None = None,
        pop_verifier: PopVerifier | None = None,
        schemas: BootstrapSchemaRegistry | None = None,
    ) -> None:
        supplied = Path(root).expanduser()
        if not supplied.is_absolute() or supplied.is_symlink():
            raise RootRotationError("rotation store must be a non-symlink absolute path")
        if (
            not callable(approval_verifier)
            or not callable(root_authenticator)
            or not callable(adoption_closure_authenticator)
            or not callable(frontier_reader)
        ):
            raise RootRotationError(
                "external approval/root/adoption authenticators and authoritative frontier reader are mandatory"
            )
        owners = _sorted_unique(anchor_owner_fingerprints, "anchor-owner fingerprints")
        if not owners or any(not DIGEST.fullmatch(value) for value in owners):
            raise RootRotationError("anchor-owner fingerprint set is invalid")
        if anchor_owner_threshold < 1 or anchor_owner_threshold > len(owners):
            raise RootRotationError("anchor-owner threshold is invalid")
        if nonce_factory is not None and not callable(nonce_factory):
            raise RootRotationError("nonce factory is not callable")
        if pop_verifier is not None and not callable(pop_verifier):
            raise RootRotationError("PoP verifier is not callable")
        self.root = supplied.resolve()
        self.registry_id = _safe_id(registry_id, "registry id")
        self.approval_verifier = approval_verifier
        self.root_authenticator = root_authenticator
        self.adoption_closure_authenticator = adoption_closure_authenticator
        self.frontier_reader = frontier_reader
        self.anchor_owner_fingerprints = owners
        self.anchor_owner_threshold = anchor_owner_threshold
        self.nonce_factory = nonce_factory or (lambda: os.urandom(32))
        self.pop_verifier = pop_verifier
        self.schemas = schemas or BootstrapSchemaRegistry()
        self._initialize()

    def _initialize(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = os.stat(self.root)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise RootRotationError("rotation store is not an owner-controlled directory")
        os.chmod(self.root, 0o700)
        for name in ("activations", "authorizations", "challenges", "heads", "locks", "objects", "operations", "receipts", "states"):
            path = self.root / name
            path.mkdir(mode=0o700, exist_ok=True)
            if path.is_symlink() or os.stat(path).st_uid != os.getuid():
                raise RootRotationError(f"rotation store directory is not owner controlled: {name}")
            os.chmod(path, 0o700)
        subjects = self.root / "activations" / "subjects"
        subjects.mkdir(mode=0o700, exist_ok=True)
        os.chmod(subjects, 0o700)
        _fsync_directory(self.root)

    @contextlib.contextmanager
    def _lock(self):
        path = self.root / "locks" / "root-rotation.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _validate(self, record: dict[str, Any], expected_schema: str | None = None) -> None:
        try:
            self.schemas.validate(record, schema_id=expected_schema)
        except BootstrapSchemaError as exc:
            raise RootRotationError(str(exc)) from exc

    def _read(self, path: Path, expected_schema: str | None = None) -> dict[str, Any] | None:
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(os.stat(path).st_mode) != 0o600:
            raise RootRotationError(f"unsafe rotation record: {path.name}")
        try:
            record = load_canonical_json(path.read_bytes())
        except Exception as exc:
            raise RootRotationError(f"rotation record is not strict canonical JSON: {path.name}") from exc
        self._validate(record, expected_schema)
        return record

    def _write_create_only(self, path: Path, record: dict[str, Any]) -> dict[str, Any]:
        self._validate(record)
        encoded = canonical_bytes(record)
        existing = self._read(path)
        if existing is not None:
            if canonical_bytes(existing) != encoded:
                raise RootRotationError(f"immutable rotation record drift: {path.name}")
            return existing
        try:
            atomic_write(path, encoded, create_only=True)
        except StateStoreError as exc:
            existing = self._read(path)
            if existing is None or canonical_bytes(existing) != encoded:
                raise RootRotationError(f"immutable rotation record collision: {path.name}") from exc
        readback = self._read(path)
        if readback is None or canonical_bytes(readback) != encoded:
            raise RootRotationError(f"immutable rotation record readback failed: {path.name}")
        return readback

    def _object_path(self, record: dict[str, Any]) -> Path:
        schema_name = record["schema"].replace("/", "-")
        return self.root / "objects" / schema_name / f"{record['recordDigest'][7:]}.json"

    def _put_object(self, record: dict[str, Any]) -> dict[str, Any]:
        return self._write_create_only(self._object_path(record), record)

    def _current_path(self) -> Path:
        return self.root / "heads" / "current.json"

    def current_head(self) -> dict[str, Any]:
        record = self._read(self._current_path(), "bootstrap-root-registry-current-head/v1")
        if record is None:
            raise RootRotationError("root/registry current head is not initialized")
        immutable = self._read(self._object_path(record), "bootstrap-root-registry-current-head/v1")
        if immutable is None or immutable["recordDigest"] != record["recordDigest"]:
            raise RootRotationError("current head has no byte-equal immutable object")
        return record

    def initialize_current(
        self,
        *,
        root: dict[str, Any],
        activated_at: str,
        registry_sequence: int = 0,
    ) -> dict[str, Any]:
        """Install the genesis current pointer; it never replaces an existing head."""

        _safe_id(root.get("rootId"), "root id")
        self._validate_root(root)
        if not isinstance(registry_sequence, int) or isinstance(registry_sequence, bool) or registry_sequence < 0:
            raise RootRotationError("initial registry sequence is invalid")
        when = _time(activated_at, "genesis activation time")
        self._valid_at(root, when)
        root_authentication = self._authenticate_root(
            root,
            purpose="genesis_root",
            effective_at=when,
        )
        head = with_self_digest(
            {
                "schema": "bootstrap-root-registry-current-head/v1",
                "headId": f"root-head-{root['epoch']:020d}",
                "registryId": self.registry_id,
                "rootId": root["rootId"],
                "rootEpoch": root["epoch"],
                "rootDigest": root["recordDigest"],
                "rootVerificationReceiptDigest": root_authentication[
                    "verificationReceiptDigest"
                ],
                "registryProfileDigest": root["registryProfileDigest"],
                "registrySequence": registry_sequence,
                "previousHeadDigest": None,
                "transitionDigest": None,
                "activatedAt": _timestamp(when),
            }
        )
        with self._lock():
            if self._current_path().exists():
                existing = self.current_head()
                if existing != head:
                    raise RootRotationError("root/registry current head is already initialized differently")
                return existing
            self._put_object(root)
            self._put_object(head)
            try:
                atomic_write(self._current_path(), canonical_bytes(head), create_only=True)
            except StateStoreError as exc:
                raise RootRotationError("genesis current-head creation raced") from exc
            return self.current_head()

    def _validate_root(self, root: dict[str, Any]) -> None:
        self._validate(root, "bootstrap-root/v1")
        if root["signatureSubjectDigest"] != _signature_subject(root):
            raise RootRotationError("root signature-subject digest mismatch")
        keys = root["keys"]
        key_ids = [item["keyId"] for item in keys]
        fingerprints = [item["fingerprint"] for item in keys]
        if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)) or len(fingerprints) != len(set(fingerprints)):
            raise RootRotationError("root keys must be sorted with unique IDs and fingerprints")
        for item in keys:
            _sorted_unique(item["roles"], f"roles for root key {item['keyId']}")
        signers = [item for item in keys if "root_signer" in item["roles"]]
        recovery_keys = [item for item in keys if "recovery" in item["roles"]]
        if root["ordinaryThreshold"] > len(signers):
            raise RootRotationError("root ordinary threshold exceeds its signer set")
        if root["recoveryThreshold"] > len(recovery_keys):
            raise RootRotationError("root recovery threshold exceeds its recovery-key set")
        if _time(root["validFrom"], "root validFrom") >= _time(root["validUntil"], "root validUntil"):
            raise RootRotationError("root validity window is inverted")

    def _valid_at(self, root: dict[str, Any], when: datetime) -> None:
        if not (_time(root["validFrom"], "root validFrom") <= when < _time(root["validUntil"], "root validUntil")):
            raise RootRotationError("root is outside its validity window")

    def _authenticate_root(
        self,
        root: dict[str, Any],
        *,
        purpose: str,
        effective_at: datetime,
    ) -> dict[str, Any]:
        response = self.root_authenticator(
            RootAuthenticationRequest(
                root=deepcopy(root),
                purpose=purpose,
                verified_at=_timestamp(effective_at),
            )
        )
        if not isinstance(response, dict) or set(response) != {
            "anchorDigest",
            "revocationStatus",
            "rootDigest",
            "verificationReceiptDigest",
            "verifierAuthorityRef",
            "verifiedAt",
        }:
            raise RootRotationError("external root authentication response is malformed")
        if (
            response["rootDigest"] != root["recordDigest"]
            or response["revocationStatus"] != "good"
            or not isinstance(response["anchorDigest"], str)
            or not DIGEST.fullmatch(response["anchorDigest"])
            or not isinstance(response["verificationReceiptDigest"], str)
            or not DIGEST.fullmatch(response["verificationReceiptDigest"])
            or not isinstance(response["verifierAuthorityRef"], str)
            or not response["verifierAuthorityRef"].startswith("https://")
            or _time(response["verifiedAt"], "root authentication time") != effective_at
        ):
            raise RootRotationError("external root authentication did not prove anchor/signature/revocation closure")
        return response

    def _authenticate_adoption_closure(
        self,
        state: dict[str, Any],
        current: dict[str, Any],
    ) -> dict[str, Any]:
        response = self.adoption_closure_authenticator(
            AdoptionClosureAuthenticationRequest(
                activation_state=deepcopy(state),
                current_head=deepcopy(current),
                verified_at=state["adoptionClosureVerifiedAt"],
            )
        )
        closure_fields = {
            "activationGeneration",
            "adoptionReceiptDigest",
            "rotationHeadDigest",
            "successorProfileDigest",
            "successorRegistryDigest",
            "taskLockV3Digest",
            "tokenHash",
        }
        required = closure_fields | {
            "verificationReceiptDigest",
            "verifierAuthorityRef",
            "verifiedAt",
        }
        if not isinstance(response, dict) or set(response) != required:
            raise RootRotationError("external adoption-closure authentication response is malformed")
        if any(response[field] != state[field] for field in closure_fields):
            raise RootRotationError("external adoption-closure authentication subject mismatch")
        if (
            response["verificationReceiptDigest"] != state["adoptionClosureVerificationReceiptDigest"]
            or response["verifierAuthorityRef"] != state["adoptionClosureVerifierAuthorityRef"]
            or response["verifiedAt"] != state["adoptionClosureVerifiedAt"]
            or not response["verifierAuthorityRef"].startswith("https://")
            or _time(response["verifiedAt"], "adoption closure verification time")
            > _time(state["updatedAt"], "activation state update time")
        ):
            raise RootRotationError("external adoption-closure authentication receipt mismatch")
        return response

    def _assert_no_pending_activations(self) -> None:
        indexed_ids: set[str] = set()
        for index_path in sorted((self.root / "activations" / "subjects").glob("*.json")):
            index = self._read(
                index_path, "bootstrap-successor-v3-activation-subject-index/v1"
            )
            if index is None:
                continue
            indexed_ids.add(index["activationId"])
            state = self._read(
                self._activation_state_path(index["activationId"]),
                "bootstrap-successor-v3-activation-state/v1",
            )
            if state is None:
                raise RootRotationError(
                    f"root rotation is fenced by in-flight successor activation {index['activationId']}"
                )
            if (
                state["activationSlotDigest"] != index["activationSlotDigest"]
                or state["activationSubjectDigest"] != index["activationSubjectDigest"]
            ):
                raise RootRotationError("activation subject index/state binding drift")
        for path in sorted((self.root / "activations").glob("*/current.json")):
            state = self._read(path, "bootstrap-successor-v3-activation-state/v1")
            if state is None:
                continue
            if state["activationId"] not in indexed_ids:
                raise RootRotationError("successor activation has no global subject reservation")
            if state["successorState"] != "active" or state["activationReceiptDigest"] is None:
                raise RootRotationError(
                    f"root rotation is fenced by pending successor activation {state['activationId']}"
                )

    def _validate_frontier(
        self,
        frontier: dict[str, Any],
        *,
        current: dict[str, Any],
        old_root: dict[str, Any],
        effective_at: datetime,
    ) -> None:
        self._validate(frontier, "bootstrap-root-rotation-frontier/v1")
        if (
            frontier["registryId"] != self.registry_id
            or frontier["rootDigest"] != old_root["recordDigest"]
            or frontier["rootEpoch"] != old_root["epoch"]
            or frontier["currentHeadDigest"] != current["recordDigest"]
            or frontier["registrySequence"] != current["registrySequence"]
        ):
            raise RootRotationError("terminal frontier is not bound to the current old epoch/head")
        attempts = frontier["attempts"]
        ids = [item["attemptId"] for item in attempts]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise RootRotationError("terminal frontier attempts must be sorted and unique")
        if any(item["state"] not in TERMINAL_STATES for item in attempts):
            raise RootRotationError("normal rotation cannot strand a live attempt")
        if any(item["tokenState"] != "disposed" or item["writerState"] != "fenced" for item in attempts):
            raise RootRotationError("normal rotation requires every token disposed and writer fenced")
        if _time(frontier["capturedAt"], "frontier capture time") > effective_at:
            raise RootRotationError("terminal frontier is from the future")

    def _authoritative_frontier(
        self,
        expected: dict[str, Any],
        *,
        current: dict[str, Any],
        old_root: dict[str, Any],
        effective_at: datetime,
    ) -> None:
        observed = self.frontier_reader()
        if not isinstance(observed, dict):
            raise RootRotationError("authoritative frontier reader returned no record")
        self._validate_frontier(observed, current=current, old_root=old_root, effective_at=effective_at)
        if observed["recordDigest"] != expected["recordDigest"] or canonical_bytes(observed) != canonical_bytes(expected):
            raise RootRotationError("authoritative terminal frontier changed")

    def _verify_authorization(
        self,
        *,
        operation_id: str,
        acceptance_kind: str,
        rotation_subject_digest: str,
        threshold: int,
        allowed_fingerprints: tuple[str, ...],
        signatures: list[dict[str, Any]],
        effective_at: str,
    ) -> dict[str, Any]:
        expected_role = "anchor_owner" if acceptance_kind == "anchor_owner" else "root_signer"
        if threshold < 1 or threshold > len(allowed_fingerprints):
            raise RootRotationError(f"{acceptance_kind} threshold is invalid")
        signature_order = [
            (item.get("role"), item.get("identity"), item.get("keyFingerprint"))
            for item in signatures
            if isinstance(item, dict)
        ]
        if len(signature_order) != len(signatures) or signature_order != sorted(signature_order):
            raise RootRotationError(f"{acceptance_kind} signatures must be canonically sorted")
        if len(set(signature_order)) != len(signature_order):
            raise RootRotationError(f"{acceptance_kind} signatures must be unique")
        identities: list[str] = []
        fingerprints: list[str] = []
        for item in signatures:
            if set(item) != {"keyFingerprint", "identity", "role", "algorithm", "signatureBase64", "signedAt"}:
                raise RootRotationError(f"{acceptance_kind} signature shape is not strict")
            if item["role"] != expected_role or item["algorithm"] != "ed25519":
                raise RootRotationError(f"{acceptance_kind} signature role or algorithm is invalid")
            if item["keyFingerprint"] not in allowed_fingerprints:
                raise RootRotationError(f"{acceptance_kind} signature uses an unauthorized fingerprint")
            _safe_id(item["identity"], "signer identity")
            _time(item["signedAt"], "signature time")
            identities.append(item["identity"])
            fingerprints.append(item["keyFingerprint"])
        if len(set(identities)) != len(identities) or len(set(fingerprints)) < threshold:
            raise RootRotationError(f"{acceptance_kind} signer threshold or identity separation failed")
        request = RotationApprovalRequest(
            operation_id=operation_id,
            acceptance_kind=acceptance_kind,
            rotation_subject_digest=rotation_subject_digest,
            threshold=threshold,
            allowed_fingerprints=allowed_fingerprints,
            signatures=tuple(signatures),
            verified_at=effective_at,
        )
        response = self.approval_verifier(request)
        if not isinstance(response, dict) or set(response) != {
            "verifierAuthorityRef",
            "verifierReceiptDigest",
            "verifiedSigners",
        }:
            raise RootRotationError("external approval verifier response is malformed")
        if not isinstance(response["verifierAuthorityRef"], str) or not response["verifierAuthorityRef"].startswith("https://"):
            raise RootRotationError("external approval verifier authority is absent or local-only")
        if not isinstance(response["verifierReceiptDigest"], str) or not DIGEST.fullmatch(response["verifierReceiptDigest"]):
            raise RootRotationError("external approval verifier receipt digest is invalid")
        verified = response["verifiedSigners"]
        if not isinstance(verified, list):
            raise RootRotationError("external approval verifier signer set is absent")
        expected_signers = {
            (item["role"], item["identity"], item["keyFingerprint"])
            for item in signatures
        }
        observed_signers: set[tuple[str, str, str]] = set()
        for item in verified:
            if not isinstance(item, dict) or set(item) != {"keyFingerprint", "identity", "role"}:
                raise RootRotationError("external verified signer is malformed")
            triple = (item["role"], item["identity"], item["keyFingerprint"])
            if triple not in expected_signers or triple in observed_signers:
                raise RootRotationError("external verified signer is unbound or duplicated")
            observed_signers.add(triple)
        if observed_signers != expected_signers or len({item[2] for item in observed_signers}) < threshold:
            raise RootRotationError("external approval verification is not set-equal or below threshold")
        normalized = [
            {"role": role, "identity": identity, "keyFingerprint": fingerprint}
            for role, identity, fingerprint in sorted(observed_signers)
        ]
        authorization = with_self_digest(
            {
                "schema": "bootstrap-root-rotation-authorization/v1",
                "operationId": operation_id,
                "acceptanceKind": acceptance_kind,
                "rotationSubjectDigest": rotation_subject_digest,
                "threshold": threshold,
                "allowedFingerprints": list(allowed_fingerprints),
                "signatures": signatures,
                "verifiedSigners": normalized,
                "verifierAuthorityRef": response["verifierAuthorityRef"],
                "verifierReceiptDigest": response["verifierReceiptDigest"],
                "verifiedAt": effective_at,
            }
        )
        self._validate(authorization)
        return authorization

    def _authorization(
        self,
        *,
        operation_id: str,
        acceptance_kind: str,
        rotation_subject_digest: str,
        threshold: int,
        allowed_fingerprints: tuple[str, ...],
        signatures: list[dict[str, Any]],
        effective_at: str,
    ) -> dict[str, Any]:
        path = self.root / "authorizations" / operation_id / f"{acceptance_kind}.json"
        existing = self._read(path, "bootstrap-root-rotation-authorization/v1")
        if existing is not None:
            if (
                existing["rotationSubjectDigest"] != rotation_subject_digest
                or existing["threshold"] != threshold
                or existing["allowedFingerprints"] != list(allowed_fingerprints)
                or existing["signatures"] != signatures
                or existing["verifiedAt"] != effective_at
            ):
                raise RootRotationError(f"stored {acceptance_kind} authorization drift")
            return existing
        authorization = self._verify_authorization(
            operation_id=operation_id,
            acceptance_kind=acceptance_kind,
            rotation_subject_digest=rotation_subject_digest,
            threshold=threshold,
            allowed_fingerprints=allowed_fingerprints,
            signatures=signatures,
            effective_at=effective_at,
        )
        return self._write_create_only(path, authorization)

    @staticmethod
    def _crash(crash_after: str | None, phase: str) -> None:
        if crash_after == phase:
            raise RootRotationCrash(f"injected root-rotation crash after {phase}")

    def _result_bundle(self, result: dict[str, Any]) -> RootRotationResult:
        transition = self._read(
            self.root / "objects" / "bootstrap-registry-epoch-transition-v1" / f"{result['transitionDigest'][7:]}.json",
            "bootstrap-registry-epoch-transition/v1",
        )
        head = self._read(
            self.root / "objects" / "bootstrap-root-registry-current-head-v1" / f"{result['currentHeadDigest'][7:]}.json",
            "bootstrap-root-registry-current-head/v1",
        )
        if transition is None or head is None:
            raise RootRotationError("rotation result references missing immutable objects")
        authorizations: list[dict[str, Any]] = []
        for kind, field in (
            ("old_threshold", "oldThresholdAuthorizationDigest"),
            ("new_threshold", "newThresholdAuthorizationDigest"),
            ("anchor_owner", "anchorOwnerAuthorizationDigest"),
        ):
            authorization = self._read(
                self.root / "authorizations" / result["operationId"] / f"{kind}.json",
                "bootstrap-root-rotation-authorization/v1",
            )
            if authorization is None or authorization["recordDigest"] != result[field]:
                raise RootRotationError("rotation result authorization closure is incomplete")
            authorizations.append(authorization)
        return RootRotationResult(transition, head, result, tuple(authorizations))

    def rotate_normal(
        self,
        *,
        operation_id: str,
        idempotency_key: str,
        expected_current_head_digest: str,
        old_root: dict[str, Any],
        new_root: dict[str, Any],
        terminal_frontier: dict[str, Any],
        old_threshold_signatures: list[dict[str, Any]],
        new_threshold_signatures: list[dict[str, Any]],
        anchor_owner_signatures: list[dict[str, Any]],
        effective_at: str,
        crash_after: str | None = None,
    ) -> RootRotationResult:
        operation_id = _safe_id(operation_id, "operation id")
        idempotency_key = _safe_id(idempotency_key, "idempotency key")
        if not DIGEST.fullmatch(expected_current_head_digest):
            raise RootRotationError("expected current-head digest is invalid")
        self._validate_root(old_root)
        self._validate_root(new_root)
        self._validate(terminal_frontier, "bootstrap-root-rotation-frontier/v1")
        when = _time(effective_at, "rotation effective time")
        effective_at = _timestamp(when)
        self._valid_at(old_root, when)
        self._valid_at(new_root, when)
        old_root_authentication = self._authenticate_root(
            old_root,
            purpose="normal_rotation_old_root",
            effective_at=when,
        )
        new_root_authentication = self._authenticate_root(
            new_root,
            purpose="normal_rotation_new_root",
            effective_at=when,
        )
        if (
            new_root["rootId"] != old_root["rootId"]
            or new_root["anchorId"] != old_root["anchorId"]
            or new_root["epoch"] != old_root["epoch"] + 1
            or new_root["previousRootDigest"] != old_root["recordDigest"]
        ):
            raise RootRotationError("new root does not form the next normal epoch")
        old_fingerprints = tuple(sorted(item["fingerprint"] for item in old_root["keys"] if "root_signer" in item["roles"]))
        new_fingerprints = tuple(sorted(item["fingerprint"] for item in new_root["keys"] if "root_signer" in item["roles"]))
        rotation_subject = {
            "schema": "bootstrap-root-registry-rotation-subject/v1",
            "operationId": operation_id,
            "registryId": self.registry_id,
            "rootId": old_root["rootId"],
            "oldRootEpoch": old_root["epoch"],
            "oldRootDigest": old_root["recordDigest"],
            "oldRootVerificationReceiptDigest": old_root_authentication[
                "verificationReceiptDigest"
            ],
            "oldRegistryProfileDigest": old_root["registryProfileDigest"],
            "oldHeadDigest": expected_current_head_digest,
            "newRootEpoch": new_root["epoch"],
            "newRootDigest": new_root["recordDigest"],
            "newRootVerificationReceiptDigest": new_root_authentication[
                "verificationReceiptDigest"
            ],
            "newRegistryProfileDigest": new_root["registryProfileDigest"],
            "registrySequence": terminal_frontier["registrySequence"] + 1,
            "terminalFrontierDigest": terminal_frontier["recordDigest"],
            "activationMode": "normal_rotation",
            "transitionedAt": effective_at,
        }
        rotation_subject_digest = semantic_digest(rotation_subject)
        request_digest = semantic_digest(
            {
                "schema": "bootstrap-root-rotation-request-identity/v1",
                "idempotencyKey": idempotency_key,
                "rotationSubjectDigest": rotation_subject_digest,
                "oldThresholdSignaturesDigest": semantic_digest({"signatures": old_threshold_signatures}),
                "newThresholdSignaturesDigest": semantic_digest({"signatures": new_threshold_signatures}),
                "anchorOwnerSignaturesDigest": semantic_digest({"signatures": anchor_owner_signatures}),
            }
        )
        result_path = self.root / "operations" / f"{operation_id}.json"
        with self._lock():
            existing_result = self._read(result_path, "bootstrap-root-rotation-operation-result/v1")
            if existing_result is not None:
                if existing_result["requestDigest"] != request_digest:
                    raise RootRotationError("rotation operation id was replayed with different bytes")
                return self._result_bundle(existing_result)
            self._assert_no_pending_activations()
            current = self.current_head()
            if current["transitionDigest"] is not None:
                prior = self._read(
                    self.root / "objects" / "bootstrap-registry-epoch-transition-v1" / f"{current['transitionDigest'][7:]}.json",
                    "bootstrap-registry-epoch-transition/v1",
                )
                if prior is not None and prior["operationId"] == operation_id:
                    if prior["requestDigest"] != request_digest:
                        raise RootRotationError("published rotation operation drift")
                    recovered = with_self_digest(
                        {
                            "schema": "bootstrap-root-rotation-operation-result/v1",
                            "operationId": operation_id,
                            "requestDigest": request_digest,
                            "transitionDigest": prior["recordDigest"],
                            "currentHeadDigest": current["recordDigest"],
                            "oldThresholdAuthorizationDigest": prior["oldThresholdAuthorizationDigest"],
                            "newThresholdAuthorizationDigest": prior["newThresholdAuthorizationDigest"],
                            "anchorOwnerAuthorizationDigest": prior["anchorOwnerAuthorizationDigest"],
                            "outcome": "rotated",
                            "completedAt": effective_at,
                        }
                    )
                    result = self._write_create_only(result_path, recovered)
                    return self._result_bundle(result)
            if (
                current["recordDigest"] != expected_current_head_digest
                or current["rootDigest"] != old_root["recordDigest"]
                or current["rootEpoch"] != old_root["epoch"]
                or current["rootId"] != old_root["rootId"]
                or current["registryProfileDigest"] != old_root["registryProfileDigest"]
            ):
                raise RootRotationError("normal rotation expected old current root/head is stale")
            self._validate_frontier(terminal_frontier, current=current, old_root=old_root, effective_at=when)
            self._authoritative_frontier(terminal_frontier, current=current, old_root=old_root, effective_at=when)
            self._put_object(old_root)
            self._put_object(new_root)
            old_auth = self._authorization(
                operation_id=operation_id,
                acceptance_kind="old_threshold",
                rotation_subject_digest=rotation_subject_digest,
                threshold=old_root["ordinaryThreshold"],
                allowed_fingerprints=old_fingerprints,
                signatures=old_threshold_signatures,
                effective_at=effective_at,
            )
            self._crash(crash_after, "old_authorization")
            new_auth = self._authorization(
                operation_id=operation_id,
                acceptance_kind="new_threshold",
                rotation_subject_digest=rotation_subject_digest,
                threshold=new_root["ordinaryThreshold"],
                allowed_fingerprints=new_fingerprints,
                signatures=new_threshold_signatures,
                effective_at=effective_at,
            )
            self._crash(crash_after, "new_authorization")
            owner_auth = self._authorization(
                operation_id=operation_id,
                acceptance_kind="anchor_owner",
                rotation_subject_digest=rotation_subject_digest,
                threshold=self.anchor_owner_threshold,
                allowed_fingerprints=self.anchor_owner_fingerprints,
                signatures=anchor_owner_signatures,
                effective_at=effective_at,
            )
            self._crash(crash_after, "anchor_authorization")
            transition = with_self_digest(
                {
                    "schema": "bootstrap-registry-epoch-transition/v1",
                    "transitionId": f"registry-epoch-{new_root['epoch']:020d}",
                    "operationId": operation_id,
                    "requestDigest": request_digest,
                    "registryId": self.registry_id,
                    "rootId": old_root["rootId"],
                    "oldRootEpoch": old_root["epoch"],
                    "oldRootDigest": old_root["recordDigest"],
                    "oldRootVerificationReceiptDigest": old_root_authentication[
                        "verificationReceiptDigest"
                    ],
                    "oldRegistryProfileDigest": old_root["registryProfileDigest"],
                    "oldHeadDigest": current["recordDigest"],
                    "newRootEpoch": new_root["epoch"],
                    "newRootDigest": new_root["recordDigest"],
                    "newRootVerificationReceiptDigest": new_root_authentication[
                        "verificationReceiptDigest"
                    ],
                    "newRegistryProfileDigest": new_root["registryProfileDigest"],
                    "registrySequence": terminal_frontier["registrySequence"] + 1,
                    "terminalFrontierDigest": terminal_frontier["recordDigest"],
                    "rotationSubjectDigest": rotation_subject_digest,
                    "oldThresholdAuthorizationDigest": old_auth["recordDigest"],
                    "newThresholdAuthorizationDigest": new_auth["recordDigest"],
                    "anchorOwnerAuthorizationDigest": owner_auth["recordDigest"],
                    "activationMode": "normal_rotation",
                    "transitionedAt": effective_at,
                }
            )
            transition = self._put_object(transition)
            self._crash(crash_after, "transition")
            head = with_self_digest(
                {
                    "schema": "bootstrap-root-registry-current-head/v1",
                    "headId": f"root-head-{new_root['epoch']:020d}",
                    "registryId": self.registry_id,
                    "rootId": new_root["rootId"],
                    "rootEpoch": new_root["epoch"],
                    "rootDigest": new_root["recordDigest"],
                    "rootVerificationReceiptDigest": new_root_authentication[
                        "verificationReceiptDigest"
                    ],
                    "registryProfileDigest": new_root["registryProfileDigest"],
                    "registrySequence": transition["registrySequence"],
                    "previousHeadDigest": current["recordDigest"],
                    "transitionDigest": transition["recordDigest"],
                    "activatedAt": effective_at,
                }
            )
            head = self._put_object(head)
            self._crash(crash_after, "head")
            # Recheck both mutable authorities immediately before the sole pointer CAS.
            if self.current_head()["recordDigest"] != current["recordDigest"]:
                raise RootRotationError("current root/head changed before rotation CAS")
            self._assert_no_pending_activations()
            self._authoritative_frontier(terminal_frontier, current=current, old_root=old_root, effective_at=when)
            atomic_write(self._current_path(), canonical_bytes(head))
            if self.current_head()["recordDigest"] != head["recordDigest"]:
                raise RootRotationError("rotated current-head readback failed")
            self._crash(crash_after, "current")
            result = with_self_digest(
                {
                    "schema": "bootstrap-root-rotation-operation-result/v1",
                    "operationId": operation_id,
                    "requestDigest": request_digest,
                    "transitionDigest": transition["recordDigest"],
                    "currentHeadDigest": head["recordDigest"],
                    "oldThresholdAuthorizationDigest": old_auth["recordDigest"],
                    "newThresholdAuthorizationDigest": new_auth["recordDigest"],
                    "anchorOwnerAuthorizationDigest": owner_auth["recordDigest"],
                    "outcome": "rotated",
                    "completedAt": effective_at,
                }
            )
            result = self._write_create_only(result_path, result)
            self._crash(crash_after, "result")
            return self._result_bundle(result)

    def _activation_state_path(self, activation_id: str) -> Path:
        return self.root / "activations" / _safe_id(activation_id, "activation id") / "current.json"

    def _activation_state(self, activation_id: str) -> dict[str, Any]:
        state = self._read(self._activation_state_path(activation_id), "bootstrap-successor-v3-activation-state/v1")
        if state is None:
            raise RootRotationError("successor activation state is absent")
        immutable = self._read(self._object_path(state), "bootstrap-successor-v3-activation-state/v1")
        if immutable is None or immutable["recordDigest"] != state["recordDigest"]:
            raise RootRotationError("successor activation state lacks an immutable generation")
        return state

    def install_pending_activation(
        self,
        state: dict[str, Any],
        *,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        self._validate(state, "bootstrap-successor-v3-activation-state/v1")
        if state["registryId"] != self.registry_id or state["adoptionState"] != "adopted":
            raise RootRotationError("successor activation is not bound to an adopted registry subject")
        if state["successorState"] != "successor_inactive" or state["activationReceiptDigest"] is not None:
            raise RootRotationError("installed successor activation must be inactive and unreceipted")
        if (
            state["activationSlotDigest"] != successor_v3_activation_slot_digest(state)
            or state["activationSubjectDigest"] != successor_v3_activation_subject_digest(state)
        ):
            raise RootRotationError("successor activation slot/subject digest mismatch")
        with self._lock():
            current = self.current_head()
            if (
                state["rootEpoch"] != current["rootEpoch"]
                or state["rootDigest"] != current["rootDigest"]
                or state["rotationHeadDigest"] != current["recordDigest"]
                or current["transitionDigest"] is None
            ):
                raise RootRotationError("successor activation does not bind the current post-rotation head")
            self._authenticate_adoption_closure(state, current)
            path = self._activation_state_path(state["activationId"])
            subject_index = with_self_digest(
                {
                    "schema": "bootstrap-successor-v3-activation-subject-index/v1",
                    "activationSlotDigest": state["activationSlotDigest"],
                    "activationSubjectDigest": state["activationSubjectDigest"],
                    "activationId": state["activationId"],
                    "activationStateDigest": state["recordDigest"],
                    "reservedAt": state["updatedAt"],
                }
            )
            subject_path = (
                self.root
                / "activations"
                / "subjects"
                / f"{state['activationSlotDigest'][7:]}.json"
            )
            self._write_create_only(subject_path, subject_index)
            self._crash(crash_after, "activation_subject_reserved")
            existing = self._read(path, "bootstrap-successor-v3-activation-state/v1")
            if existing is not None:
                if existing != state:
                    raise RootRotationError("successor activation state is already installed differently")
                return existing
            self._put_object(state)
            self._crash(crash_after, "activation_state_object")
            try:
                atomic_write(path, canonical_bytes(state), create_only=True)
            except StateStoreError as exc:
                raise RootRotationError("successor activation state creation raced") from exc
            self._crash(crash_after, "activation_state_current")
            return self._activation_state(state["activationId"])

    def issue_activation_challenge(
        self,
        *,
        activation_id: str,
        challenge_id: str,
        idempotency_key: str,
        issued_at: str,
        lifetime_seconds: int = 300,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        activation_id = _safe_id(activation_id, "activation id")
        challenge_id = _safe_id(challenge_id, "challenge id")
        idempotency_key = _safe_id(idempotency_key, "idempotency key")
        if lifetime_seconds < 30 or lifetime_seconds > 600:
            raise RootRotationError("activation challenge lifetime must be 30 to 600 seconds")
        issued = _time(issued_at, "activation challenge issue time")
        issued_at = _timestamp(issued)
        path = self.root / "challenges" / f"{challenge_id}.json"
        with self._lock():
            state = self._activation_state(activation_id)
            existing = self._read(path, "bootstrap-successor-v3-activation-challenge/v1")
            selected_path = self.root / "activations" / activation_id / "challenge.json"
            selected = self._read(selected_path, "bootstrap-successor-v3-activation-challenge/v1")
            if existing is not None:
                if (
                    existing["activationId"] != activation_id
                    or existing["idempotencyKey"] != idempotency_key
                    or existing["issuedAt"] != issued_at
                    or _time(existing["expiresAt"], "challenge expiry") != issued + timedelta(seconds=lifetime_seconds)
                ):
                    raise RootRotationError("activation challenge id was replayed with different bytes")
                if selected is None:
                    self._write_create_only(selected_path, existing)
                elif selected["recordDigest"] != existing["recordDigest"]:
                    raise RootRotationError("activation challenge selection drift")
                self._crash(crash_after, "challenge_selected")
                return existing
            if selected is not None:
                raise RootRotationError("successor activation already has a different selected challenge")
            if state["successorState"] != "successor_inactive" or state["activationReceiptDigest"] is not None:
                raise RootRotationError("successor profile is not pending activation")
            current = self.current_head()
            if state["rotationHeadDigest"] != current["recordDigest"] or state["rootDigest"] != current["rootDigest"]:
                raise RootRotationError("successor activation root/head is stale")
            nonce = self.nonce_factory()
            if not isinstance(nonce, bytes) or len(nonce) != 32:
                raise RootRotationError("activation nonce source must return exactly 32 bytes")
            nonce_base64 = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
            challenge = with_self_digest(
                {
                    "schema": "bootstrap-successor-v3-activation-challenge/v1",
                    "challengeId": challenge_id,
                    "idempotencyKey": idempotency_key,
                    "activationStateDigest": state["recordDigest"],
                    "activationSlotDigest": state["activationSlotDigest"],
                    "activationSubjectDigest": state["activationSubjectDigest"],
                    "activationId": activation_id,
                    "rootEpoch": state["rootEpoch"],
                    "rootDigest": state["rootDigest"],
                    "rotationHeadDigest": state["rotationHeadDigest"],
                    "adoptionReceiptDigest": state["adoptionReceiptDigest"],
                    "adoptionClosureVerificationReceiptDigest": state[
                        "adoptionClosureVerificationReceiptDigest"
                    ],
                    "successorProfileDigest": state["successorProfileDigest"],
                    "successorRegistryDigest": state["successorRegistryDigest"],
                    "taskLockV3Digest": state["taskLockV3Digest"],
                    "tokenHash": state["tokenHash"],
                    "activationGeneration": state["activationGeneration"],
                    "operation": "adoption_activation",
                    "nonceBase64": nonce_base64,
                    "issuedAt": issued_at,
                    "expiresAt": _timestamp(issued + timedelta(seconds=lifetime_seconds)),
                }
            )
            self._put_object(challenge)
            challenge = self._write_create_only(path, challenge)
            self._crash(crash_after, "challenge_record")
            self._write_create_only(selected_path, challenge)
            self._crash(crash_after, "challenge_selected")
            return challenge

    def _activate_state(self, state: dict[str, Any], receipt: dict[str, Any], activated_at: str) -> dict[str, Any]:
        if state["successorState"] == "active":
            if state["activationReceiptDigest"] != receipt["recordDigest"]:
                raise RootRotationError("active successor state receipt drift")
            return state
        subject = dict(state)
        subject.pop("recordDigest")
        subject.update(
            {
                "successorState": "active",
                "activationReceiptDigest": receipt["recordDigest"],
                "updatedAt": activated_at,
            }
        )
        active = with_self_digest(subject)
        self._put_object(active)
        atomic_write(self._activation_state_path(state["activationId"]), canonical_bytes(active))
        return self._activation_state(state["activationId"])

    def _require_challenge_current(self, challenge: dict[str, Any]) -> dict[str, Any]:
        current = self.current_head()
        if (
            challenge["rotationHeadDigest"] != current["recordDigest"]
            or challenge["rootDigest"] != current["rootDigest"]
            or challenge["rootEpoch"] != current["rootEpoch"]
        ):
            raise RootRotationError("successor activation current root/head changed")
        return current

    def complete_activation(
        self,
        *,
        activation_id: str,
        challenge_id: str,
        response: bytes,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        activation_id = _safe_id(activation_id, "activation id")
        challenge_id = _safe_id(challenge_id, "challenge id")
        if not isinstance(response, bytes) or len(response) != 32:
            raise RootRotationError("activation response must be exactly 32 bytes")
        when = _time(effective_at, "activation effective time")
        effective_at = _timestamp(when)
        response_digest = semantic_digest({"responseSha256": hashlib.sha256(response).hexdigest()})
        receipt_path = self.root / "receipts" / f"{challenge_id}.json"
        with self._lock():
            challenge = self._read(
                self.root / "challenges" / f"{challenge_id}.json",
                "bootstrap-successor-v3-activation-challenge/v1",
            )
            if challenge is None or challenge["activationId"] != activation_id:
                raise RootRotationError("activation challenge is absent or belongs to another subject")
            selected = self._read(
                self.root / "activations" / activation_id / "challenge.json",
                "bootstrap-successor-v3-activation-challenge/v1",
            )
            if selected is None or selected["recordDigest"] != challenge["recordDigest"]:
                raise RootRotationError("activation challenge is not the selected durable challenge")
            state = self._activation_state(activation_id)
            existing = self._read(receipt_path, "bootstrap-successor-v3-activation-receipt/v1")
            if existing is not None:
                if existing["responseDigest"] != response_digest or existing["challengeDigest"] != challenge["recordDigest"]:
                    raise RootRotationError("completed activation was replayed with a different response")
                self._require_challenge_current(challenge)
                active = self._activate_state(state, existing, existing["activatedAt"])
                return existing, active
            if state["successorState"] != "successor_inactive" or state["recordDigest"] != challenge["activationStateDigest"]:
                raise RootRotationError("successor activation state/challenge closure mismatch")
            self._require_challenge_current(challenge)
            if (
                challenge["activationSlotDigest"] != state["activationSlotDigest"]
                or challenge["activationSubjectDigest"] != state["activationSubjectDigest"]
                or challenge["adoptionClosureVerificationReceiptDigest"]
                != state["adoptionClosureVerificationReceiptDigest"]
            ):
                raise RootRotationError("successor activation challenge subject closure mismatch")
            if when < _time(challenge["issuedAt"], "challenge issue time") or when >= _time(challenge["expiresAt"], "challenge expiry"):
                raise RootRotationError("successor activation challenge is not currently valid")
            if self.pop_verifier is None:
                raise RootRotationError("independent successor PoP verifier is not installed")
            verification = self.pop_verifier(challenge, response)
            if not isinstance(verification, dict) or set(verification) != {
                "matched",
                "tokenHash",
                "verificationReceiptDigest",
            }:
                raise RootRotationError("successor PoP verifier response is malformed")
            if (
                verification["matched"] is not True
                or verification["tokenHash"] != challenge["tokenHash"]
                or not isinstance(verification["verificationReceiptDigest"], str)
                or not DIGEST.fullmatch(verification["verificationReceiptDigest"])
            ):
                raise RootRotationError("successor activation proof of possession failed")
            receipt = with_self_digest(
                {
                    "schema": "bootstrap-successor-v3-activation-receipt/v1",
                    "receiptId": f"successor-v3-{challenge_id}",
                    "activationId": activation_id,
                    "challengeDigest": challenge["recordDigest"],
                    "activationStateDigest": state["recordDigest"],
                    "activationSlotDigest": challenge["activationSlotDigest"],
                    "activationSubjectDigest": challenge["activationSubjectDigest"],
                    "rootEpoch": challenge["rootEpoch"],
                    "rootDigest": challenge["rootDigest"],
                    "rotationHeadDigest": challenge["rotationHeadDigest"],
                    "adoptionReceiptDigest": challenge["adoptionReceiptDigest"],
                    "adoptionClosureVerificationReceiptDigest": challenge[
                        "adoptionClosureVerificationReceiptDigest"
                    ],
                    "successorProfileDigest": challenge["successorProfileDigest"],
                    "successorRegistryDigest": challenge["successorRegistryDigest"],
                    "taskLockV3Digest": challenge["taskLockV3Digest"],
                    "tokenHash": challenge["tokenHash"],
                    "activationGeneration": challenge["activationGeneration"],
                    "responseDigest": response_digest,
                    "brokerVerificationReceiptDigest": verification["verificationReceiptDigest"],
                    "outcome": "active",
                    "activatedAt": effective_at,
                }
            )
            self._put_object(receipt)
            receipt = self._write_create_only(receipt_path, receipt)
            self._crash(crash_after, "activation_receipt")
            active = self._activate_state(state, receipt, effective_at)
            self._crash(crash_after, "activation_state")
            return receipt, active
