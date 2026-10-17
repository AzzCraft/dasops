from __future__ import annotations

import contextlib
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Iterator, Protocol

from dasops.protected.canonical import (
    canonical_bytes,
    load_canonical_json,
    semantic_digest,
    with_self_digest,
)
from dasops.protected.encoding import strict_urlsafe_b64decode
from dasops.protected.state_store import atomic_write

from .authority import VerifiedOperation
from .registry import BootstrapAttemptRegistry, BootstrapRegistryError


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class LegacyClaimError(RuntimeError):
    pass


class LegacyClaimCrash(LegacyClaimError):
    """Deterministic crash injection for response-loss tests."""


class LegacyPrepareAdapter(Protocol):
    def prepare(self, request: dict[str, Any], *, recovery: bool) -> dict[str, Any]: ...


class CanonicalClaimPublisher(Protocol):
    def head(self) -> str: ...

    def cas(self, *, old_commit: str, new_commit: str) -> None: ...


SignedReceiptIssuer = Callable[[str, dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]]


def _safe_id(kind: str, value: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise LegacyClaimError(f"unsafe {kind}: {value!r}")
    return value


def _derived_id(operation_id: str, suffix: str) -> str:
    digest = hashlib.sha256(f"{operation_id}\0{suffix}".encode()).hexdigest()[:12]
    return f"{operation_id[:80]}-{suffix[:24]}-{digest}"


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise LegacyClaimError(f"invalid RFC3339 time: {value!r}") from exc
    if parsed.tzinfo is None:
        raise LegacyClaimError("legacy-claim time must include an offset")
    return parsed.astimezone(timezone.utc)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _signature_subject(record: dict[str, Any]) -> str:
    subject = deepcopy(record)
    subject.pop("recordDigest", None)
    subject.pop("signatureSubjectDigest", None)
    subject.pop("signatures", None)
    return semantic_digest(subject)


def handoff_response(token: bytes, challenge: dict[str, Any]) -> bytes:
    try:
        nonce = strict_urlsafe_b64decode(challenge["nonceBase64"], expected_size=32)
    except Exception as exc:
        raise LegacyClaimError("handoff challenge nonce is invalid") from exc
    subject = b"bootstrap-handoff-pop/v1\0" + nonce + canonical_bytes(
        {
            "attemptId": challenge["attemptId"],
            "challengeId": challenge["challengeId"],
            "destinationLockPath": challenge["destinationLockPath"],
            "tokenHash": challenge["tokenHash"],
            "worker": challenge["worker"],
        }
    )
    return hmac.new(token, subject, hashlib.sha256).digest()


class LegacyClaimCoordinator:
    """Root-verified bootstrap claim preparation/publication/handoff coordinator."""

    def __init__(self, registry: BootstrapAttemptRegistry) -> None:
        self.registry = registry
        self.root = registry.root / "legacy-claim"
        self.root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        if self.root.is_symlink() or os.stat(self.root).st_uid != os.getuid():
            raise LegacyClaimError("legacy-claim authority store is not owner controlled")
        for name in ("locks", "operations", "receipts"):
            directory = self.root / name
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        _fsync_directory(self.root)

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        path = self.root / "locks" / "coordinator.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _operation_dir(self, operation_id: str) -> Path:
        return self.root / "operations" / _safe_id("operation id", operation_id)

    def _receipt_path(self, operation_id: str, kind: str) -> Path:
        return self.root / "receipts" / _safe_id("operation id", operation_id) / f"{_safe_id('receipt kind', kind)}.json"

    def _write_record(self, path: Path, record: dict[str, Any]) -> None:
        self.registry._validate(record)
        encoded = canonical_bytes(record)
        if path.exists():
            if path.is_symlink() or path.read_bytes() != encoded:
                raise LegacyClaimError(f"immutable legacy-claim record drift: {path.name}")
            return
        atomic_write(path, encoded, mode=0o600, create_only=True)

    def _read_record(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        if path.is_symlink() or stat.S_IMODE(os.stat(path).st_mode) != 0o600:
            raise LegacyClaimError(f"legacy-claim record is not a mode-0600 regular file: {path}")
        value = load_canonical_json(path.read_bytes())
        self.registry._validate(value)
        return value

    def _append_wal(self, operation_id: str, phase: str, record: dict[str, Any]) -> None:
        self._write_record(self._operation_dir(operation_id) / f"{_safe_id('WAL phase', phase)}.json", record)

    @staticmethod
    def _crash(crash_after: str | None, phase: str) -> None:
        if crash_after == phase:
            raise LegacyClaimCrash(f"injected crash after {phase}")

    def _verify_operation(
        self,
        operation: VerifiedOperation,
        *,
        expected_operation: str,
        records: list[dict[str, Any]],
        change_id: str,
        task_id: str,
        effective_at: str,
        not_before: tuple[str, ...],
    ) -> str:
        try:
            manifest = self.registry._validate_operation(
                operation,
                expected_operation=expected_operation,
                records=records,
                change_id=change_id,
                task_id=task_id,
            )
            self.registry._validate_operation_time(
                operation,
                effective_at=effective_at,
                not_before=not_before,
            )
        except BootstrapRegistryError as exc:
            raise LegacyClaimError(str(exc)) from exc
        return manifest

    def _verify_signed_record(
        self,
        *,
        record: dict[str, Any],
        verification: dict[str, Any],
        purpose: str,
        operation: VerifiedOperation,
    ) -> None:
        self.registry._validate(record)
        self.registry._validate(verification)
        if record["signatureSubjectDigest"] != _signature_subject(record):
            raise LegacyClaimError("signed receipt subject digest mismatch")
        if verification["purpose"] != purpose or verification["subjectDigest"] != record["signatureSubjectDigest"]:
            raise LegacyClaimError("external receipt verification subject/purpose mismatch")
        root = operation.tool_release.authority.root
        required = sorted(root["toolPolicy"]["requiredOperationRoles"])
        if verification["requiredRoles"] != required or verification["threshold"] < len(required):
            raise LegacyClaimError("external receipt verification omitted required roles")
        root_keys = {item["fingerprint"]: item for item in root["keys"]}
        supplied = {
            (item["role"], item["identity"], item["keyFingerprint"])
            for item in record["signatures"]
        }
        identities: set[str] = set()
        fingerprints: set[str] = set()
        observed_roles: set[str] = set()
        for signer in verification["verifiedSigners"]:
            fingerprint = signer["keyFingerprint"]
            identity = signer["identity"]
            role = signer["role"]
            if (role, identity, fingerprint) not in supplied:
                raise LegacyClaimError("verified receipt signer is absent from receipt signatures")
            if fingerprint not in root_keys or role not in root_keys[fingerprint]["roles"]:
                raise LegacyClaimError("verified receipt signer role/key is not root-authorized")
            if identity in identities:
                raise LegacyClaimError("one identity cannot fill multiple receipt roles")
            identities.add(identity)
            fingerprints.add(fingerprint)
            observed_roles.add(role)
        if len(fingerprints) < verification["threshold"] or not set(required).issubset(observed_roles):
            raise LegacyClaimError("verified receipt roles are incomplete")
        if record.get("rootDigest") != root["recordDigest"]:
            raise LegacyClaimError("signed receipt root mismatch")

    def _issue(
        self,
        *,
        issuer: SignedReceiptIssuer,
        purpose: str,
        subject: dict[str, Any],
        operation: VerifiedOperation,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        receipt, verification = issuer(purpose, deepcopy(subject))
        if not isinstance(receipt, dict) or not isinstance(verification, dict):
            raise LegacyClaimError("receipt issuer returned no structured receipt/verification")
        self._verify_signed_record(
            record=receipt,
            verification=verification,
            purpose=purpose,
            operation=operation,
        )
        return receipt, verification

    def _worker_lock_path(self, value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise LegacyClaimError("legacy worker-lock path must be absolute")
        parent = path.parent.resolve()
        resolved = parent / path.name
        try:
            resolved.relative_to(self.registry.root)
        except ValueError:
            pass
        else:
            raise LegacyClaimError("raw legacy token cannot enter the authority store")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or os.stat(parent).st_uid != os.getuid():
            raise LegacyClaimError("legacy worker-lock parent is not owner controlled")
        os.chmod(parent, stat.S_IMODE(os.stat(parent).st_mode) & ~0o077)
        return resolved

    def _read_worker_lock(self, path: Path) -> tuple[bytes, bytes, str]:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid():
            raise LegacyClaimError("legacy worker lock is not an owner-controlled mode-0600 regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            data = os.read(descriptor, 65537)
        finally:
            os.close(descriptor)
        if len(data) > 65536:
            raise LegacyClaimError("legacy worker lock exceeds 65536 bytes")
        value = load_canonical_json(data)
        if not isinstance(value, dict) or not isinstance(value.get("tokenBase64"), str):
            raise LegacyClaimError("legacy worker lock does not contain its sole private token field")
        try:
            token = strict_urlsafe_b64decode(value["tokenBase64"], expected_size=32)
        except Exception as exc:
            raise LegacyClaimError("legacy worker lock token encoding is invalid") from exc
        token_hash = "sha256:" + hashlib.sha256(token).hexdigest()
        if value.get("tokenHash") != token_hash:
            raise LegacyClaimError("legacy worker lock token/hash mismatch")
        return data, token, token_hash

    def _candidate_wal(
        self,
        *,
        request: dict[str, Any],
        operation: VerifiedOperation,
        phase: str,
        effective_at: str,
        candidate_commit: str | None = None,
        result_digest: str | None = None,
    ) -> dict[str, Any]:
        return with_self_digest(
            {
                "schema": "bootstrap-candidate-preparation-wal/v1",
                "operationId": request["operationId"],
                "requestDigest": request["recordDigest"],
                "phase": phase,
                "attemptId": request["attemptId"],
                "registeredHeadDigest": request["headDigest"],
                "baseCommit": request["baseCommit"],
                "candidateCommit": candidate_commit,
                "temporaryPathManifestDigest": request["temporaryPathManifestDigest"],
                "toolReleaseDigest": operation.tool_release.release["recordDigest"],
                "legacyTokenProfileDigest": request["legacyTokenProfileDigest"],
                "worker": request["worker"],
                "idempotencyKeyDigest": request["idempotencyKeyDigest"],
                "resultDigest": result_digest,
                "recordedAt": effective_at,
            }
        )

    def prepare_candidate(
        self,
        *,
        request: dict[str, Any],
        operation: VerifiedOperation,
        adapter: LegacyPrepareAdapter,
        effective_at: str,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        self.registry._validate(request)
        operation_id = _safe_id("operation id", request["operationId"])
        current = self.registry.current()
        if current is None:
            raise LegacyClaimError("bootstrap attempt is absent")
        entry = self.registry.object(current["entryDigest"])
        manifest = self._verify_operation(
            operation,
            expected_operation="prepare_candidate",
            records=[request],
            change_id=entry["changeId"],
            task_id=entry["taskId"],
            effective_at=effective_at,
            not_before=(request["requestedAt"],),
        )
        root = operation.tool_release.authority.root
        completed_result = self._read_record(self._receipt_path(operation_id, "candidate-preparation-result"))
        if completed_result is not None and (self._operation_dir(operation_id) / "registry_transition_completed.json").exists():
            if (
                completed_result["attemptId"] != request["attemptId"]
                or completed_result["registeredHeadDigest"] != request["headDigest"]
                or completed_result["requestDigest"] != manifest
            ):
                raise LegacyClaimError("completed candidate-preparation result does not bind the retry")
            return completed_result
        for field, expected in (
            ("rootDigest", root["recordDigest"]),
            ("headDigest", current["headDigest"]),
            ("attemptId", current["attemptId"]),
            ("changeId", entry["changeId"]),
            ("taskId", entry["taskId"]),
            ("worker", entry["worker"]),
            ("baseCommit", entry["baseCommit"]),
            ("legacyTokenProfileDigest", root["legacyTokenProfileDigest"]),
        ):
            if request[field] != expected:
                raise LegacyClaimError(f"candidate-preparation {field} mismatch")
        worker_lock = self._worker_lock_path(request["workerLockPath"])

        with self._lock():
            request_path = self._operation_dir(operation_id) / "request.json"
            self._write_record(request_path, request)
            self._append_wal(
                operation_id,
                "candidate_preparation_pending",
                self._candidate_wal(
                    request=request,
                    operation=operation,
                    phase="candidate_preparation_pending",
                    effective_at=effective_at,
                ),
            )
            self._crash(crash_after, "candidate_preparation_pending")

            result_path = self._receipt_path(operation_id, "candidate-preparation-result")
            result = self._read_record(result_path)
            if result is None:
                recovery = worker_lock.exists() or worker_lock.is_symlink()
                prior_token_hash: str | None = None
                if recovery:
                    _prior_bytes, _prior_token, prior_token_hash = self._read_worker_lock(worker_lock)
                self._append_wal(
                    operation_id,
                    "legacy_invocation_started",
                    self._candidate_wal(
                        request=request,
                        operation=operation,
                        phase="legacy_invocation_started",
                        effective_at=effective_at,
                    ),
                )
                self._crash(crash_after, "legacy_invocation_started")
                metadata = adapter.prepare(deepcopy(request), recovery=recovery)
                if not isinstance(metadata, dict):
                    raise LegacyClaimError("legacy preparation adapter returned no structured metadata")
                forbidden = [key for key in metadata if any(word in key.lower() for word in ("token", "secret", "credential"))]
                if forbidden:
                    raise LegacyClaimError(f"legacy adapter leaked secret-like fields: {sorted(forbidden)}")
                lock_bytes, _token, token_hash = self._read_worker_lock(worker_lock)
                if prior_token_hash is not None and token_hash != prior_token_hash:
                    raise LegacyClaimError("legacy recovery regenerated the existing token")
                required = {
                    "candidateCommit", "candidateTree", "activeLockSubjectDigest", "archiveDigest",
                    "candidateInventoryDigest", "bridgeReceiptDigest",
                }
                if set(metadata) != required:
                    raise LegacyClaimError("legacy preparation metadata field set is not exact")
                result = with_self_digest(
                    {
                        "schema": "bootstrap-candidate-preparation-result/v1",
                        "operationId": operation_id,
                        "outcome": "prepared",
                        "requestDigest": manifest,
                        "attemptId": request["attemptId"],
                        "registeredHeadDigest": request["headDigest"],
                        "baseCommit": request["baseCommit"],
                        "candidateCommit": metadata["candidateCommit"],
                        "candidateTree": metadata["candidateTree"],
                        "tokenHash": token_hash,
                        "activeLockSubjectDigest": metadata["activeLockSubjectDigest"],
                        "workerLockPath": str(worker_lock),
                        "workerLockSha256": hashlib.sha256(lock_bytes).hexdigest(),
                        "archiveDigest": metadata["archiveDigest"],
                        "candidateInventoryDigest": metadata["candidateInventoryDigest"],
                        "bridgeReceiptDigest": metadata["bridgeReceiptDigest"],
                        "completedAt": effective_at,
                    }
                )
                self._write_record(result_path, result)
            self._append_wal(
                operation_id,
                "legacy_invocation_completed",
                self._candidate_wal(
                    request=request,
                    operation=operation,
                    phase="legacy_invocation_completed",
                    effective_at=effective_at,
                    candidate_commit=result["candidateCommit"],
                    result_digest=result["recordDigest"],
                ),
            )
            self._crash(crash_after, "legacy_invocation_completed")
            transition = self.registry._transition_attempt(
                operation_id=_derived_id(operation_id, "registry-prepared"),
                operation="prepare_candidate",
                expected_head_digest=request["headDigest"],
                expected_state="registered",
                target_state="candidate_prepared",
                target_token_state="generated",
                evidence_digest=result["recordDigest"],
                input_records=[request, result],
                effective_at=effective_at,
            )
            self._write_record(self._operation_dir(operation_id) / "registry-transition.json", transition)
            self._append_wal(
                operation_id,
                "registry_transition_completed",
                self._candidate_wal(
                    request=request,
                    operation=operation,
                    phase="registry_transition_completed",
                    effective_at=effective_at,
                    candidate_commit=result["candidateCommit"],
                    result_digest=result["recordDigest"],
                ),
            )
            self._crash(crash_after, "registry_transition_completed")
            return result

    def _publication_wal(
        self,
        *,
        request: dict[str, Any],
        phase: str,
        registry_head_digest: str,
        effective_at: str,
        receipt_digest: str | None = None,
    ) -> dict[str, Any]:
        return with_self_digest(
            {
                "schema": "bootstrap-claim-publication-wal/v1",
                "operationId": request["operationId"],
                "requestDigest": request["recordDigest"],
                "phase": phase,
                "attemptId": request["attemptId"],
                "baseCommit": request["baseCommit"],
                "candidateCommit": request["candidateCommit"],
                "registryHeadDigest": registry_head_digest,
                "publicationReceiptDigest": receipt_digest,
                "recordedAt": effective_at,
            }
        )

    def publish_claim(
        self,
        *,
        request: dict[str, Any],
        candidate_result: dict[str, Any],
        candidate_receipt: dict[str, Any],
        candidate_receipt_verification: dict[str, Any],
        operation: VerifiedOperation,
        publisher: CanonicalClaimPublisher,
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for record in (request, candidate_result, candidate_receipt, candidate_receipt_verification):
            self.registry._validate(record)
        operation_id = _safe_id("operation id", request["operationId"])
        records = [request, candidate_result, candidate_receipt, candidate_receipt_verification]
        self._verify_operation(
            operation,
            expected_operation="publish_claim",
            records=records,
            change_id=operation.descriptor["changeId"],
            task_id=operation.descriptor["taskId"],
            effective_at=effective_at,
            not_before=(request["requestedAt"], candidate_receipt["validFrom"]),
        )
        self._verify_signed_record(
            record=candidate_receipt,
            verification=candidate_receipt_verification,
            purpose="bootstrap_claim_candidate_receipt",
            operation=operation,
        )
        if _utc(effective_at) >= _utc(candidate_receipt["validUntil"]):
            raise LegacyClaimError("claim candidate receipt expired before publication")
        relations = {
            "attemptId": candidate_result["attemptId"],
            "candidateResultDigest": candidate_result["recordDigest"],
            "candidateReceiptDigest": candidate_receipt["recordDigest"],
            "candidateReceiptVerificationDigest": candidate_receipt_verification["recordDigest"],
            "baseCommit": candidate_result["baseCommit"],
            "candidateCommit": candidate_result["candidateCommit"],
            "tokenHash": candidate_result["tokenHash"],
        }
        for field, expected in relations.items():
            if request[field] != expected:
                raise LegacyClaimError(f"claim-publication {field} mismatch")
        if (
            candidate_receipt["candidateResultDigest"] != candidate_result["recordDigest"]
            or candidate_receipt["tokenHash"] != candidate_result["tokenHash"]
            or candidate_receipt["activeLockSubjectDigest"] != candidate_result["activeLockSubjectDigest"]
            or candidate_receipt["rootDigest"] != operation.tool_release.authority.root["recordDigest"]
        ):
            raise LegacyClaimError("claim candidate receipt/result/worker binding mismatch")

        with self._lock():
            final_receipt_path = self._receipt_path(operation_id, "publication-receipt")
            final_verification_path = self._receipt_path(operation_id, "publication-verification")
            final_receipt = self._read_record(final_receipt_path)
            final_verification = self._read_record(final_verification_path)
            if (
                final_receipt is not None
                and final_verification is not None
                and (self._operation_dir(operation_id) / "slot_closed.json").exists()
            ):
                return final_receipt, final_verification
            active = self.registry.current()
            if active is None or active["attemptId"] != request["attemptId"]:
                raise LegacyClaimError("claim-publication active attempt mismatch")
            active_entry = self.registry.object(active["entryDigest"])
            if (
                active_entry["worker"] != candidate_receipt["intendedWorker"]
                or active_entry["changeId"] != operation.descriptor["changeId"]
                or active_entry["taskId"] != operation.descriptor["taskId"]
            ):
                raise LegacyClaimError("claim-publication task/worker binding mismatch")
            self._write_record(self._operation_dir(operation_id) / "request.json", request)
            self._append_wal(
                operation_id,
                "publication_intent",
                self._publication_wal(
                    request=request,
                    phase="publication_intent",
                    registry_head_digest=request["candidatePreparedHeadDigest"],
                    effective_at=effective_at,
                ),
            )
            self._crash(crash_after, "publication_intent")
            pending = self.registry._transition_attempt(
                operation_id=_derived_id(operation_id, "registry-pending"),
                operation="publish_claim_pending",
                expected_head_digest=request["candidatePreparedHeadDigest"],
                expected_state="candidate_prepared",
                target_state="claim_publication_pending",
                target_token_state="generated",
                evidence_digest=request["recordDigest"],
                input_records=records,
                effective_at=effective_at,
            )
            self._append_wal(
                operation_id,
                "pending_checkpoint",
                self._publication_wal(
                    request=request,
                    phase="pending_checkpoint",
                    registry_head_digest=pending["headDigest"],
                    effective_at=effective_at,
                ),
            )
            self._crash(crash_after, "pending_checkpoint")

            candidate_path = self._operation_dir(operation_id) / "publication-receipt-candidate.json"
            candidate_verification_path = self._operation_dir(operation_id) / "publication-verification-candidate.json"
            publication_receipt = self._read_record(candidate_path)
            publication_verification = self._read_record(candidate_verification_path)
            if publication_receipt is None or publication_verification is None:
                subject = {
                    "schema": "bootstrap-publication-receipt/v1",
                    "receiptId": f"publication-{operation_id}",
                    "operationId": operation_id,
                    "rootDigest": operation.tool_release.authority.root["recordDigest"],
                    "attemptId": request["attemptId"],
                    "baseCommit": request["baseCommit"],
                    "candidateCommit": request["candidateCommit"],
                    "canonicalReadback": request["candidateCommit"],
                    "outcome": "published",
                    "publisherAuthorityRef": operation.descriptor_verification["verifierAuthorityRef"],
                    "publishedAt": effective_at,
                }
                publication_receipt, publication_verification = self._issue(
                    issuer=issuer,
                    purpose="bootstrap_publication_receipt",
                    subject=subject,
                    operation=operation,
                )
                self._write_record(candidate_path, publication_receipt)
                self._write_record(candidate_verification_path, publication_verification)
            self._append_wal(
                operation_id,
                "cas_started",
                self._publication_wal(
                    request=request,
                    phase="cas_started",
                    registry_head_digest=pending["headDigest"],
                    effective_at=effective_at,
                    receipt_digest=publication_receipt["recordDigest"],
                ),
            )
            self._crash(crash_after, "cas_started")
            head = publisher.head()
            if head == request["baseCommit"]:
                publisher.cas(old_commit=request["baseCommit"], new_commit=request["candidateCommit"])
            elif head != request["candidateCommit"]:
                raise LegacyClaimError("claim publication CAS is ambiguous or canonical head drifted")
            if publisher.head() != request["candidateCommit"]:
                raise LegacyClaimError("claim publication readback failed")
            self._append_wal(
                operation_id,
                "cas_applied",
                self._publication_wal(
                    request=request,
                    phase="cas_applied",
                    registry_head_digest=pending["headDigest"],
                    effective_at=effective_at,
                    receipt_digest=publication_receipt["recordDigest"],
                ),
            )
            self._crash(crash_after, "cas_applied")
            self._write_record(final_receipt_path, publication_receipt)
            self._write_record(final_verification_path, publication_verification)
            self._append_wal(
                operation_id,
                "receipt_written",
                self._publication_wal(
                    request=request,
                    phase="receipt_written",
                    registry_head_digest=pending["headDigest"],
                    effective_at=effective_at,
                    receipt_digest=publication_receipt["recordDigest"],
                ),
            )
            self._crash(crash_after, "receipt_written")
            claimed = self.registry._transition_attempt(
                operation_id=_derived_id(operation_id, "registry-claimed"),
                operation="publish_claim",
                expected_head_digest=pending["headDigest"],
                expected_state="claim_publication_pending",
                target_state="claimed",
                target_token_state="generated",
                evidence_digest=publication_receipt["recordDigest"],
                input_records=[request, publication_receipt, publication_verification],
                effective_at=effective_at,
            )
            self._append_wal(
                operation_id,
                "claimed_checkpoint",
                self._publication_wal(
                    request=request,
                    phase="claimed_checkpoint",
                    registry_head_digest=claimed["headDigest"],
                    effective_at=effective_at,
                    receipt_digest=publication_receipt["recordDigest"],
                ),
            )
            self._crash(crash_after, "claimed_checkpoint")
            self.registry._close_normal_receipt_slot(
                operation_id=_derived_id(operation_id, "publication-slot"),
                attempt_id=request["attemptId"],
                head_digest=claimed["headDigest"],
                receipt=publication_receipt,
                effective_at=effective_at,
            )
            self._append_wal(
                operation_id,
                "slot_closed",
                self._publication_wal(
                    request=request,
                    phase="slot_closed",
                    registry_head_digest=claimed["headDigest"],
                    effective_at=effective_at,
                    receipt_digest=publication_receipt["recordDigest"],
                ),
            )
            self._crash(crash_after, "slot_closed")
            return publication_receipt, publication_verification

    def handoff_claim(
        self,
        *,
        request: dict[str, Any],
        candidate_result: dict[str, Any],
        publication_receipt: dict[str, Any],
        publication_verification: dict[str, Any],
        challenge: dict[str, Any],
        response: bytes,
        operation: VerifiedOperation,
        publisher: CanonicalClaimPublisher,
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        records = [request, candidate_result, publication_receipt, publication_verification, challenge]
        for record in records:
            self.registry._validate(record)
        self._verify_operation(
            operation,
            expected_operation="handoff_claim",
            records=records,
            change_id=operation.descriptor["changeId"],
            task_id=operation.descriptor["taskId"],
            effective_at=effective_at,
            not_before=(request["requestedAt"], challenge["issuedAt"]),
        )
        self._verify_signed_record(
            record=publication_receipt,
            verification=publication_verification,
            purpose="bootstrap_publication_receipt",
            operation=operation,
        )
        response_digest = semantic_digest({"responseSha256": hashlib.sha256(response).hexdigest()})
        relations = {
            "attemptId": candidate_result["attemptId"],
            "publicationReceiptDigest": publication_receipt["recordDigest"],
            "challengeDigest": challenge["recordDigest"],
            "responseDigest": response_digest,
            "tokenHash": candidate_result["tokenHash"],
            "worker": challenge["worker"],
            "destinationLockPath": challenge["destinationLockPath"],
            "expectedCandidateCommit": candidate_result["candidateCommit"],
        }
        for field, expected in relations.items():
            if request[field] != expected:
                raise LegacyClaimError(f"handoff {field} mismatch")
        if challenge["attemptId"] != candidate_result["attemptId"] or challenge["tokenHash"] != candidate_result["tokenHash"]:
            raise LegacyClaimError("handoff registry/challenge state mismatch")
        if _utc(effective_at) >= _utc(challenge["expiresAt"]):
            raise LegacyClaimError("handoff challenge expired")
        source = self._worker_lock_path(candidate_result["workerLockPath"])
        destination = self._worker_lock_path(request["destinationLockPath"])
        if source == destination:
            raise LegacyClaimError("handoff source and destination must differ")
        operation_id = _safe_id("operation id", request["operationId"])

        completed_receipt = self._read_record(self._receipt_path(operation_id, "handoff-receipt"))
        completed_verification = self._read_record(self._receipt_path(operation_id, "handoff-verification"))
        if completed_receipt is not None and completed_verification is not None:
            if completed_receipt["outcome"] == "acknowledged" and source.exists():
                source.unlink()
                _fsync_directory(source.parent)
            return completed_receipt, completed_verification
        current = self.registry.current()
        if current is None or current["state"] != "claimed" or current["attemptId"] != request["attemptId"] or current["headDigest"] != request["claimedHeadDigest"]:
            raise LegacyClaimError("handoff requires the exact claimed registry head")
        entry = self.registry.object(current["entryDigest"])
        if entry["worker"] != request["worker"]:
            raise LegacyClaimError("handoff worker does not match the claimed attempt")

        with self._lock():
            receipt_path = self._receipt_path(operation_id, "handoff-receipt")
            verification_path = self._receipt_path(operation_id, "handoff-verification")
            receipt = self._read_record(receipt_path)
            verification = self._read_record(verification_path)
            if receipt is not None and verification is not None:
                if receipt["outcome"] == "acknowledged" and source.exists():
                    source.unlink()
                    _fsync_directory(source.parent)
                return receipt, verification
            lock_bytes, token, token_hash = self._read_worker_lock(source)
            expected_response = handoff_response(token, challenge)
            pop_verified = token_hash == request["tokenHash"] and hmac.compare_digest(response, expected_response)
            ancestry_verified = publisher.head() == request["expectedCandidateCommit"]
            acknowledged = pop_verified and ancestry_verified
            if acknowledged:
                if destination.exists():
                    before = os.lstat(destination)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or stat.S_IMODE(before.st_mode) != 0o600
                        or before.st_uid != os.getuid()
                        or destination.read_bytes() != lock_bytes
                    ):
                        raise LegacyClaimError("handoff destination already contains different bytes")
                else:
                    atomic_write(destination, lock_bytes, mode=0o600, create_only=True)
                if destination.read_bytes() != lock_bytes:
                    raise LegacyClaimError("handoff destination readback failed")
                self._crash(crash_after, "destination_copied")
            subject = {
                "schema": "bootstrap-claim-lock-handoff-receipt/v1",
                "receiptId": f"handoff-{operation_id}",
                "operationId": operation_id,
                "rootDigest": operation.tool_release.authority.root["recordDigest"],
                "attemptId": request["attemptId"],
                "publicationReceiptDigest": publication_receipt["recordDigest"],
                "outcome": "acknowledged" if acknowledged else "failed",
                "worker": request["worker"],
                "destinationLockPath": str(destination) if acknowledged else None,
                "destinationLockSha256": hashlib.sha256(lock_bytes).hexdigest() if acknowledged else None,
                "ancestryVerified": True if acknowledged else None,
                "workerAcknowledged": True if acknowledged else None,
                "popVerified": True if acknowledged else None,
                "challengeDigest": challenge["recordDigest"],
                "responseDigest": response_digest,
                "sourceDisposition": "transferred" if acknowledged else "retained",
                "failureReason": None if acknowledged else ("proof_of_possession_failed" if not pop_verified else "candidate_ancestry_failed"),
                "workAuthority": "legacy_bootstrap_only" if acknowledged else "none",
                "completedAt": effective_at,
            }
            receipt, verification = self._issue(
                issuer=issuer,
                purpose="bootstrap_handoff_receipt",
                subject=subject,
                operation=operation,
            )
            self._validate_handoff_receipt(receipt)
            self._write_record(receipt_path, receipt)
            self._write_record(verification_path, verification)
            self.registry._write_object(receipt)
            self.registry._write_object(verification)
            self._crash(crash_after, "handoff_receipt_written")
            if acknowledged:
                source.unlink()
                _fsync_directory(source.parent)
            return receipt, verification

    @staticmethod
    def _validate_handoff_receipt(receipt: dict[str, Any]) -> None:
        success_fields = (
            receipt["destinationLockPath"], receipt["destinationLockSha256"], receipt["ancestryVerified"],
            receipt["workerAcknowledged"], receipt["popVerified"],
        )
        if receipt["outcome"] == "acknowledged":
            if any(value in (None, False) for value in success_fields) or receipt["failureReason"] is not None or receipt["sourceDisposition"] != "transferred" or receipt["workAuthority"] != "legacy_bootstrap_only":
                raise LegacyClaimError("acknowledged handoff receipt has incomplete success closure")
        elif any(value is not None for value in success_fields) or receipt["failureReason"] is None or receipt["sourceDisposition"] != "retained" or receipt["workAuthority"] != "none":
            raise LegacyClaimError("failed handoff receipt contains success authority")

    def _early_wal(
        self,
        *,
        authorization: dict[str, Any],
        phase: str,
        registry_head_digest: str,
        effective_at: str,
        result_digest: str | None = None,
    ) -> dict[str, Any]:
        return with_self_digest(
            {
                "schema": "bootstrap-claim-early-closure-wal/v1",
                "operationId": authorization["operationId"],
                "operation": authorization["operation"],
                "requestDigest": authorization["recordDigest"],
                "phase": phase,
                "attemptId": authorization["attemptId"],
                "baseCommit": authorization["baseCommit"],
                "candidateCommit": authorization["candidateCommit"],
                "registryHeadDigest": registry_head_digest,
                "resultDigest": result_digest,
                "recordedAt": effective_at,
            }
        )

    def close_early_claim(
        self,
        *,
        authorization: dict[str, Any],
        candidate_result: dict[str, Any],
        publication_receipt: dict[str, Any],
        publication_verification: dict[str, Any],
        handoff_receipt: dict[str, Any],
        handoff_verification: dict[str, Any],
        operation: VerifiedOperation,
        publisher: CanonicalClaimPublisher,
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        records = [
            authorization, candidate_result, publication_receipt, publication_verification,
            handoff_receipt, handoff_verification,
        ]
        for record in records:
            self.registry._validate(record)
        operation_name = authorization["operation"]
        current = self.registry.current()
        if current is None:
            raise LegacyClaimError("claimed registry head is absent")
        entry = self.registry.object(current["entryDigest"])
        self._verify_operation(
            operation,
            expected_operation=operation_name,
            records=records,
            change_id=entry["changeId"],
            task_id=entry["taskId"],
            effective_at=effective_at,
            not_before=(authorization["authorizedAt"],),
        )
        self._verify_signed_record(record=publication_receipt, verification=publication_verification, purpose="bootstrap_publication_receipt", operation=operation)
        self._verify_signed_record(record=handoff_receipt, verification=handoff_verification, purpose="bootstrap_handoff_receipt", operation=operation)
        expected_handoff = "failed" if operation_name == "compensate_claim" else "acknowledged"
        expected_outcome = "compensated" if operation_name == "compensate_claim" else "abandoned"
        if handoff_receipt["outcome"] != expected_handoff:
            raise LegacyClaimError(f"{operation_name} requires a {expected_handoff} handoff receipt")
        operation_id = _safe_id("operation id", authorization["operationId"])
        completed_result = self._read_record(self._receipt_path(operation_id, "early-closure-result"))
        completed_verification = self._read_record(self._receipt_path(operation_id, "early-closure-verification"))
        if (
            completed_result is not None
            and completed_verification is not None
            and (self._operation_dir(operation_id) / "slot_closed.json").exists()
        ):
            return completed_result, completed_verification
        candidate_path = self._operation_dir(operation_id) / "early-result-candidate.json"
        candidate_verification_path = self._operation_dir(operation_id) / "early-verification-candidate.json"
        pending_result = self._read_record(candidate_path)
        relations = {
            "attemptId": candidate_result["attemptId"],
            "baseCommit": candidate_result["baseCommit"],
            "candidateCommit": candidate_result["candidateCommit"],
            "publicationReceiptDigest": publication_receipt["recordDigest"],
            "handoffReceiptDigest": handoff_receipt["recordDigest"],
        }
        for field, expected in relations.items():
            if authorization[field] != expected:
                raise LegacyClaimError(f"early-closure {field} mismatch")
        if current["state"] == "claimed":
            if current["headDigest"] != authorization["claimedHeadDigest"]:
                raise LegacyClaimError("early-closure claimed head is stale")
        elif current["state"] == expected_outcome:
            if (
                pending_result is None
                or entry["priorHeadDigest"] != authorization["claimedHeadDigest"]
                or entry["transitionEvidenceDigest"] != pending_result["recordDigest"]
            ):
                raise LegacyClaimError("terminal early-closure retry lacks its exact prior transition")
        else:
            raise LegacyClaimError("early closure requires the claimed or exact terminal registry state")
        with self._lock():
            receipt_path = self._receipt_path(operation_id, "early-closure-result")
            verification_path = self._receipt_path(operation_id, "early-closure-verification")
            result = self._read_record(receipt_path)
            verification = self._read_record(verification_path)
            if result is not None and verification is not None and (self._operation_dir(operation_id) / "slot_closed.json").exists():
                return result, verification
            self._append_wal(
                operation_id,
                "closure_intent",
                self._early_wal(
                    authorization=authorization,
                    phase="closure_intent",
                    registry_head_digest=authorization["claimedHeadDigest"],
                    effective_at=effective_at,
                ),
            )
            self._crash(crash_after, "closure_intent")
            result = self._read_record(candidate_path)
            verification = self._read_record(candidate_verification_path)
            if result is None or verification is None:
                subject = {
                    "schema": "bootstrap-claim-early-closure-result/v1",
                    "receiptId": f"early-{operation_id}",
                    "operationId": operation_id,
                    "rootDigest": operation.tool_release.authority.root["recordDigest"],
                    "attemptId": authorization["attemptId"],
                    "outcome": expected_outcome,
                    "baseCommit": authorization["baseCommit"],
                    "candidateCommit": authorization["candidateCommit"],
                    "canonicalReadback": authorization["baseCommit"],
                    "publicationReceiptDigest": authorization["publicationReceiptDigest"],
                    "handoffReceiptDigest": authorization["handoffReceiptDigest"],
                    "tokenDisposition": "destroyed",
                    "workDisposition": "complete",
                    "completedAt": effective_at,
                }
                result, verification = self._issue(
                    issuer=issuer,
                    purpose="bootstrap_early_closure_receipt",
                    subject=subject,
                    operation=operation,
                )
                self._write_record(candidate_path, result)
                self._write_record(candidate_verification_path, verification)
            self._append_wal(
                operation_id,
                "cas_started",
                self._early_wal(
                    authorization=authorization,
                    phase="cas_started",
                    registry_head_digest=authorization["claimedHeadDigest"],
                    effective_at=effective_at,
                    result_digest=result["recordDigest"],
                ),
            )
            self._crash(crash_after, "cas_started")
            head = publisher.head()
            if head == authorization["candidateCommit"]:
                publisher.cas(old_commit=authorization["candidateCommit"], new_commit=authorization["baseCommit"])
            elif head != authorization["baseCommit"]:
                raise LegacyClaimError("early-closure reversion CAS is ambiguous or canonical head drifted")
            if publisher.head() != authorization["baseCommit"]:
                raise LegacyClaimError("early-closure canonical readback failed")
            self._append_wal(
                operation_id,
                "cas_reverted",
                self._early_wal(
                    authorization=authorization,
                    phase="cas_reverted",
                    registry_head_digest=authorization["claimedHeadDigest"],
                    effective_at=effective_at,
                    result_digest=result["recordDigest"],
                ),
            )
            self._crash(crash_after, "cas_reverted")
            token_path = (
                self._worker_lock_path(candidate_result["workerLockPath"])
                if handoff_receipt["outcome"] == "failed"
                else self._worker_lock_path(handoff_receipt["destinationLockPath"])
            )
            token_disposed_wal = self._operation_dir(operation_id) / "token_disposed.json"
            if not token_path.exists() and not token_disposed_wal.exists():
                raise LegacyClaimError("early-closure token lock vanished before disposition was recorded")
            if token_path.exists():
                before = os.lstat(token_path)
                if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
                    raise LegacyClaimError("early-closure token lock is not safely disposable")
                token_path.unlink()
                _fsync_directory(token_path.parent)
            self._append_wal(
                operation_id,
                "token_disposed",
                self._early_wal(
                    authorization=authorization,
                    phase="token_disposed",
                    registry_head_digest=authorization["claimedHeadDigest"],
                    effective_at=effective_at,
                    result_digest=result["recordDigest"],
                ),
            )
            self._crash(crash_after, "token_disposed")
            transition = self.registry._transition_attempt(
                operation_id=_derived_id(operation_id, "registry-terminal"),
                operation=operation_name,
                expected_head_digest=authorization["claimedHeadDigest"],
                expected_state="claimed",
                target_state=expected_outcome,
                target_token_state="disposed",
                evidence_digest=result["recordDigest"],
                input_records=[authorization, result, verification],
                effective_at=effective_at,
            )
            self._append_wal(
                operation_id,
                "registry_terminal",
                self._early_wal(
                    authorization=authorization,
                    phase="registry_terminal",
                    registry_head_digest=transition["headDigest"],
                    effective_at=effective_at,
                    result_digest=result["recordDigest"],
                ),
            )
            self._crash(crash_after, "registry_terminal")
            self._write_record(receipt_path, result)
            self._write_record(verification_path, verification)
            self.registry._close_normal_receipt_slot(
                operation_id=_derived_id(operation_id, "early-slot"),
                attempt_id=authorization["attemptId"],
                head_digest=transition["headDigest"],
                receipt=result,
                effective_at=effective_at,
            )
            self._append_wal(
                operation_id,
                "slot_closed",
                self._early_wal(
                    authorization=authorization,
                    phase="slot_closed",
                    registry_head_digest=transition["headDigest"],
                    effective_at=effective_at,
                    result_digest=result["recordDigest"],
                ),
            )
            self._crash(crash_after, "slot_closed")
            return result, verification
