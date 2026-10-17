from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Iterator

from dasops.protected.canonical import (
    canonical_bytes,
    load_canonical_json,
    semantic_digest,
    verify_self_digest,
    with_self_digest,
)
from dasops.protected.state_store import atomic_write

from .authority import VerifiedOperation
from .schema_registry import BootstrapSchemaError, BootstrapSchemaRegistry


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TERMINAL_STATES = frozenset(
    {"cancelled_pre_cas", "adopted", "compensated", "abandoned", "emergency_recovered"}
)
CANCELLABLE_STATES = frozenset({"registered", "candidate_prepared", "claim_publication_pending"})
REQUIRED_WAIVER_ROLES = ["independent_verifier", "orchestrator", "repository_owner"]


class BootstrapRegistryError(RuntimeError):
    pass


class BootstrapRegistryCrash(BootstrapRegistryError):
    """Deterministic failure injection used to prove retry recovery."""


def input_manifest_digest(operation: str, records: Iterable[dict[str, Any]]) -> str:
    return semantic_digest(
        {
            "schema": "bootstrap-operation-input-manifest/v1",
            "operation": operation,
            "recordDigests": [record["recordDigest"] for record in records],
        }
    )


def output_profile_digest(operation: str) -> str:
    outputs = {
        "register_attempt": [
            "bootstrap-attempt-operation-wal/v1",
            "bootstrap-attempt-registry-entry/v1",
            "bootstrap-registry-head/v1",
            "bootstrap-receipt-slot/v1",
            "bootstrap-head-slot-commit/v1",
            "bootstrap-current-head/v1",
            "bootstrap-registry-operation-result/v1",
        ],
        "cancel_attempt": [
            "bootstrap-attempt-operation-wal/v1",
            "bootstrap-attempt-registry-entry/v1",
            "bootstrap-registry-head/v1",
            "bootstrap-receipt-slot/v1",
            "bootstrap-head-slot-commit/v1",
            "bootstrap-current-head/v1",
            "bootstrap-registry-operation-result/v1",
        ],
        "recover_receipt": [
            "bootstrap-attempt-operation-wal/v1",
            "bootstrap-receipt-slot/v1",
            "bootstrap-receipt-recovery-result/v1",
        ],
        "prepare_candidate": [
            "bootstrap-candidate-preparation-wal/v1",
            "bootstrap-candidate-preparation-result/v1",
            "bootstrap-attempt-transition-result/v1",
        ],
        "publish_claim": [
            "bootstrap-claim-publication-wal/v1",
            "bootstrap-publication-receipt/v1",
            "external-role-verification/v1",
            "bootstrap-attempt-transition-result/v1",
            "bootstrap-receipt-closure-result/v1",
        ],
        "handoff_claim": [
            "bootstrap-claim-lock-handoff-receipt/v1",
            "external-role-verification/v1",
        ],
        "compensate_claim": [
            "bootstrap-claim-early-closure-wal/v1",
            "bootstrap-claim-early-closure-result/v1",
            "external-role-verification/v1",
            "bootstrap-attempt-transition-result/v1",
            "bootstrap-receipt-closure-result/v1",
        ],
        "abandon_claim": [
            "bootstrap-claim-early-closure-wal/v1",
            "bootstrap-claim-early-closure-result/v1",
            "external-role-verification/v1",
            "bootstrap-attempt-transition-result/v1",
            "bootstrap-receipt-closure-result/v1",
        ],
        "adopt_prepare": [
            "bootstrap-adoption-private-state/v1",
            "bootstrap-adoption-prepare-wal/v1",
            "bootstrap-adoption-package/v2",
            "bootstrap-adoption-lifecycle-state/v1",
            "bootstrap-adoption-approval-subject/v2",
            "bootstrap-adoption-prepare-result/v2",
        ],
        "adopt_publish": [
            "foundation-verification-store-manifest/v1",
            "foundation-verification-descriptor-head/v1",
            "bootstrap-repository-handoff-transaction/v1",
            "foundation-program-selector-head/v1",
            "verification-profile-transition-head/v1",
            "bootstrap-adoption-lifecycle-state/v1",
            "bootstrap-adoption-publish-wal/v1",
            "bootstrap-adoption-publish-result/v1",
            "external-role-verification/v1",
            "bootstrap-attempt-transition-result/v1",
            "bootstrap-receipt-closure-result/v1",
            "bootstrap-adoption-activation-challenge/v1",
            "bootstrap-adoption-activation-receipt/v1",
        ],
        "adopt_cancel": [
            "foundation-verification-store-manifest/v1",
            "foundation-verification-descriptor-head/v1",
            "bootstrap-adoption-lifecycle-state/v1",
            "bootstrap-adoption-disposition-tombstone/v1",
            "bootstrap-adoption-fence-release-receipt/v1",
            "bootstrap-adoption-cancel-result/v2",
            "external-role-verification/v1",
        ],
        "recover_publication": [
            "foundation-verification-store-manifest/v1",
            "foundation-verification-descriptor-head/v1",
            "bootstrap-adoption-lifecycle-state/v1",
            "bootstrap-adoption-publish-wal/v1",
            "bootstrap-adoption-publish-result/v1",
            "external-role-verification/v1",
            "bootstrap-attempt-transition-result/v1",
            "bootstrap-receipt-closure-result/v1",
        ],
    }
    if operation not in outputs:
        raise BootstrapRegistryError(f"unsupported bootstrap registry operation: {operation}")
    return semantic_digest(
        {
            "schema": "bootstrap-operation-output-profile/v1",
            "operation": operation,
            "recordSchemas": outputs[operation],
        }
    )


def authority_profile_digest(root: dict[str, Any]) -> str:
    return semantic_digest(
        {
            "schema": "bootstrap-registry-authority-profile/v1",
            "registryProfileDigest": root["registryProfileDigest"],
            "storeProfileDigest": root["storeProfileDigest"],
            "checkpointProfileDigest": root["checkpointProfileDigest"],
            "legacyTokenProfileDigest": root["legacyTokenProfileDigest"],
        }
    )


def _safe_id(kind: str, value: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise BootstrapRegistryError(f"unsafe {kind}: {value!r}")
    return value


def _utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise BootstrapRegistryError(f"invalid RFC3339 time: {value!r}") from exc
    if result.tzinfo is None:
        raise BootstrapRegistryError("bootstrap registry time must include an offset")
    return result.astimezone(timezone.utc)


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise BootstrapRegistryError(f"{label} must be unique")


def _sequence(value: int) -> str:
    if value < 0 or value > 99_999_999_999_999_999_999:
        raise BootstrapRegistryError("registry sequence is outside the 20-digit range")
    return f"{value:020d}"


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class BootstrapAttemptRegistry:
    """Owner-controlled append-only bootstrap registry with CAS pointers.

    Registry objects are immutable and content addressed. Only `current.json` and
    each head's receipt-slot pointer are mutable; both are updated under an
    owner-only flock after an exact expected-digest comparison.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        registry_id: str,
        schemas: BootstrapSchemaRegistry | None = None,
    ) -> None:
        supplied = Path(root).expanduser()
        if not supplied.is_absolute():
            raise BootstrapRegistryError("bootstrap authority store must be an absolute path")
        if supplied.exists() and supplied.is_symlink():
            raise BootstrapRegistryError("bootstrap authority store cannot be a symlink")
        self.root = supplied.resolve()
        self.registry_id = _safe_id("registry id", registry_id)
        self.schemas = schemas or BootstrapSchemaRegistry()
        self._initialize()

    def _initialize(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or os.stat(self.root).st_uid != os.getuid():
            raise BootstrapRegistryError("bootstrap authority store is not owner controlled")
        os.chmod(self.root, 0o700)
        for name in ("locks", "objects", "operations", "pointers", "results", "slots"):
            path = self.root / name
            path.mkdir(mode=0o700, exist_ok=True)
            if path.is_symlink() or os.stat(path).st_uid != os.getuid():
                raise BootstrapRegistryError(f"bootstrap store directory is not owner controlled: {name}")
            os.chmod(path, 0o700)
        _fsync_directory(self.root)

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        path = self.root / "locks" / "registry.lock"
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _validate(self, record: dict[str, Any]) -> None:
        try:
            self.schemas.validate(record)
        except BootstrapSchemaError as exc:
            raise BootstrapRegistryError(str(exc)) from exc

    def _object_path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise BootstrapRegistryError("invalid object digest")
        return self.root / "objects" / digest.removeprefix("sha256:")[:2] / f"{digest.removeprefix('sha256:')}.json"

    def _write_object(self, record: dict[str, Any]) -> Path:
        self._validate(record)
        path = self._object_path(record["recordDigest"])
        encoded = canonical_bytes(record)
        if path.exists():
            if path.is_symlink() or path.read_bytes() != encoded:
                raise BootstrapRegistryError(f"immutable object drift: {record['recordDigest']}")
            return path
        atomic_write(path, encoded, mode=0o600, create_only=True)
        return path

    def object(self, digest: str) -> dict[str, Any]:
        path = self._object_path(digest)
        if not path.is_file() or path.is_symlink() or stat.S_IMODE(os.stat(path).st_mode) != 0o600:
            raise BootstrapRegistryError(f"bootstrap object is absent or not mode 0600: {digest}")
        value = load_canonical_json(path.read_bytes())
        self._validate(value)
        if value["recordDigest"] != digest:
            raise BootstrapRegistryError("content-addressed object path/digest mismatch")
        return value

    @property
    def _current_path(self) -> Path:
        return self.root / "pointers" / "current.json"

    def current(self) -> dict[str, Any] | None:
        if not self._current_path.exists():
            return None
        if self._current_path.is_symlink() or stat.S_IMODE(os.stat(self._current_path).st_mode) != 0o600:
            raise BootstrapRegistryError("current registry pointer is not a mode-0600 regular file")
        value = load_canonical_json(self._current_path.read_bytes())
        self._validate(value)
        if value["schema"] != "bootstrap-current-head/v1" or value["registryId"] != self.registry_id:
            raise BootstrapRegistryError("current pointer registry identity mismatch")
        self._validate_current_closure(value)
        return value

    def _slot_pointer_path(self, head_digest: str) -> Path:
        safe = head_digest.removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", safe):
            raise BootstrapRegistryError("invalid receipt-slot head digest")
        return self.root / "slots" / safe / "current.json"

    def receipt_slot(self, head_digest: str) -> dict[str, Any]:
        path = self._slot_pointer_path(head_digest)
        if not path.is_file() or path.is_symlink() or stat.S_IMODE(os.stat(path).st_mode) != 0o600:
            raise BootstrapRegistryError("receipt-slot pointer is absent or not mode 0600")
        slot = load_canonical_json(path.read_bytes())
        self._validate(slot)
        if slot["schema"] != "bootstrap-receipt-slot/v1" or slot["headDigest"] != head_digest:
            raise BootstrapRegistryError("receipt-slot pointer subject mismatch")
        self._validate_slot(slot)
        return slot

    def _validate_current_closure(self, current: dict[str, Any]) -> None:
        head = self.object(current["headDigest"])
        entry = self.object(current["entryDigest"])
        commit = self.object(current["headSlotCommitDigest"])
        slot = self.receipt_slot(current["headDigest"])
        base_slot = self.object(current["slotDigest"])
        if (
            head["registryId"] != self.registry_id
            or entry["registryId"] != self.registry_id
            or head["entryDigest"] != entry["recordDigest"]
            or head["sequence"] != current["sequence"]
            or entry["sequence"] != current["sequence"]
            or head["state"] != current["state"]
            or entry["state"] != current["state"]
            or head["attemptId"] != current["attemptId"]
            or entry["attemptId"] != current["attemptId"]
            or head["priorHeadDigest"] != entry["priorHeadDigest"]
            or commit["headDigest"] != head["recordDigest"]
            or commit["headSequence"] != head["sequence"]
            or commit["slotDigest"] != current["slotDigest"]
            or base_slot["recordDigest"] != current["slotDigest"]
            or base_slot["headDigest"] != head["recordDigest"]
            or base_slot["attemptId"] != head["attemptId"]
            or base_slot["generation"] != 0
            or base_slot["status"] != "open"
            or (slot["generation"] == 1 and slot["previousSlotDigest"] != base_slot["recordDigest"])
            or (slot["generation"] == 0 and slot["recordDigest"] != base_slot["recordDigest"])
        ):
            raise BootstrapRegistryError("current head/entry/slot checkpoint closure is inconsistent")
        if head["terminalHeadDigests"] != current["terminalHeadDigests"]:
            raise BootstrapRegistryError("current terminal history mismatch")
        self._validate_head_chain(head)

    def _validate_head_chain(self, head: dict[str, Any]) -> None:
        seen: set[str] = set()
        cursor = head
        while True:
            digest = cursor["recordDigest"]
            if digest in seen:
                raise BootstrapRegistryError("registry head chain contains a cycle")
            seen.add(digest)
            entry = self.object(cursor["entryDigest"])
            if (
                cursor["registryId"] != self.registry_id
                or entry["registryId"] != self.registry_id
                or cursor["sequence"] != entry["sequence"]
                or cursor["attemptId"] != entry["attemptId"]
                or cursor["state"] != entry["state"]
                or cursor["priorHeadDigest"] != entry["priorHeadDigest"]
                or cursor["terminalHeadDigests"] != entry["terminalHeadDigests"]
            ):
                raise BootstrapRegistryError("registry head/entry chain is inconsistent")
            prior_digest = cursor["priorHeadDigest"]
            sequence = int(cursor["sequence"])
            if prior_digest is None:
                if sequence != 1 or entry["priorEntryDigest"] is not None:
                    raise BootstrapRegistryError("registry genesis sequence/ancestry is invalid")
                if entry["terminalHeadDigests"]:
                    raise BootstrapRegistryError("registry genesis cannot import terminal history")
                return
            prior = self.object(prior_digest)
            if prior["schema"] != "bootstrap-registry-head/v1":
                raise BootstrapRegistryError("registry prior-head object has the wrong schema")
            if int(prior["sequence"]) + 1 != sequence or entry["priorEntryDigest"] != prior["entryDigest"]:
                raise BootstrapRegistryError("registry sequence rollback, gap or fork detected")
            if entry["transition"] == "register_attempt":
                expected_history = [*prior["terminalHeadDigests"], prior["recordDigest"]]
                if prior["state"] not in TERMINAL_STATES or entry["terminalHeadDigests"] != expected_history:
                    raise BootstrapRegistryError("new registration did not import one terminal predecessor")
            elif entry["attemptId"] != prior["attemptId"] or entry["terminalHeadDigests"] != prior["terminalHeadDigests"]:
                raise BootstrapRegistryError("attempt transition changed identity or terminal history")
            cursor = prior

    def _validate_slot(self, slot: dict[str, Any]) -> None:
        if slot["status"] == "open":
            if any(
                value is not None
                for value in (slot["closureVariant"], slot["receiptDigest"], slot["previousSlotDigest"], slot["closedAt"])
            ) or slot["generation"] != 0:
                raise BootstrapRegistryError("open receipt slot has closure fields")
        elif (
            slot["generation"] != 1
            or slot["closureVariant"] is None
            or slot["receiptDigest"] is None
            or slot["previousSlotDigest"] is None
            or slot["closedAt"] is None
        ):
            raise BootstrapRegistryError("closed receipt slot lacks one complete closure")

    def _operation_dir(self, operation_id: str) -> Path:
        return self.root / "operations" / _safe_id("operation id", operation_id)

    def _bundle_path(self, operation_id: str) -> Path:
        return self._operation_dir(operation_id) / "bundle.json"

    def _result_path(self, operation_id: str) -> Path:
        return self.root / "results" / f"{_safe_id('operation id', operation_id)}.json"

    def _load_bundle(self, operation_id: str) -> dict[str, Any] | None:
        path = self._bundle_path(operation_id)
        if not path.exists():
            return None
        value = load_canonical_json(path.read_bytes())
        try:
            verify_self_digest(value)
        except Exception as exc:
            raise BootstrapRegistryError("bootstrap transaction bundle digest mismatch") from exc
        return value

    def operation_prestate_current(
        self,
        operation_id: str,
        *,
        expected_operation: str,
    ) -> tuple[bool, dict[str, Any] | None]:
        """Return an existing transaction's immutable prestate current object.

        The boolean distinguishes no transaction from an initial transaction whose
        valid prestate has no head. Callers use this for retry-safe exact-prestate
        checks and still rely on the operation coordinator to reject input drift.
        """

        bundle = self._load_bundle(_safe_id("operation id", operation_id))
        if bundle is None:
            return False, None
        if bundle["operation"] != expected_operation:
            raise BootstrapRegistryError("operation id is bound to another operation")
        pointer_digest = bundle["expectedPointerDigest"]
        if pointer_digest is None:
            return True, None
        pointer = self.object(pointer_digest)
        if pointer["schema"] != "bootstrap-current-head/v1":
            raise BootstrapRegistryError("operation prestate is not a registry current-head object")
        return True, pointer

    def operation_prestate_head(
        self,
        operation_id: str,
        *,
        expected_operation: str,
    ) -> tuple[bool, str | None]:
        exists, pointer = self.operation_prestate_current(
            operation_id,
            expected_operation=expected_operation,
        )
        return exists, (None if pointer is None else pointer["headDigest"])

    def _write_bundle(self, bundle: dict[str, Any]) -> None:
        path = self._bundle_path(bundle["operationId"])
        encoded = canonical_bytes(bundle)
        if path.exists():
            if path.read_bytes() != encoded:
                raise BootstrapRegistryError("operation id was already used for different immutable bytes")
            return
        atomic_write(path, encoded, mode=0o600, create_only=True)

    def _write_wal(
        self,
        bundle: dict[str, Any],
        phase: str,
        *,
        result_digest: str | None = None,
    ) -> None:
        value = with_self_digest(
            {
                "schema": "bootstrap-attempt-operation-wal/v1",
                "operationId": bundle["operationId"],
                "operation": bundle["operation"],
                "requestDigest": bundle["requestDigest"],
                "phase": phase,
                "expectedPointerDigest": bundle["expectedPointerDigest"],
                "candidatePointerDigest": bundle["candidatePointerDigest"],
                "resultDigest": result_digest,
                "recordedAt": bundle["effectiveAt"],
            }
        )
        self._validate(value)
        path = self._operation_dir(bundle["operationId"]) / f"{phase}.json"
        encoded = canonical_bytes(value)
        if path.exists():
            if path.read_bytes() != encoded:
                raise BootstrapRegistryError(f"WAL phase drift: {phase}")
            return
        atomic_write(path, encoded, mode=0o600, create_only=True)

    def _existing_exact_result(self, bundle: dict[str, Any]) -> dict[str, Any] | None:
        path = self._result_path(bundle["operationId"])
        if not path.exists():
            return None
        encoded = canonical_bytes(bundle["result"])
        if path.is_symlink() or path.read_bytes() != encoded:
            raise BootstrapRegistryError("operation result drift")
        self._write_wal(bundle, "completed", result_digest=bundle["result"]["recordDigest"])
        return bundle["result"]

    @staticmethod
    def _maybe_crash(crash_after: str | None, phase: str) -> None:
        if crash_after == phase:
            raise BootstrapRegistryCrash(f"injected crash after {phase}")

    def _validate_operation(
        self,
        operation: VerifiedOperation,
        *,
        expected_operation: str,
        records: list[dict[str, Any]],
        change_id: str,
        task_id: str,
    ) -> str:
        if not isinstance(operation, VerifiedOperation):
            raise BootstrapRegistryError("an externally verified operation descriptor is mandatory")
        descriptor = operation.descriptor
        verification = operation.descriptor_verification
        self._validate(descriptor)
        self._validate(verification)
        if descriptor["operation"] != expected_operation:
            raise BootstrapRegistryError("verified descriptor operation mismatch")
        if descriptor["changeId"] != change_id or descriptor["taskId"] != task_id:
            raise BootstrapRegistryError("verified descriptor task subject mismatch")
        if descriptor["rootDigest"] != operation.tool_release.authority.root["recordDigest"]:
            raise BootstrapRegistryError("verified descriptor/root mismatch")
        if verification["subjectDigest"] != descriptor["signatureSubjectDigest"]:
            raise BootstrapRegistryError("external verification does not bind the descriptor")
        manifest = input_manifest_digest(expected_operation, records)
        if descriptor["inputManifestDigest"] != manifest:
            raise BootstrapRegistryError("operation descriptor input manifest mismatch")
        if descriptor["outputManifestDigest"] != output_profile_digest(expected_operation):
            raise BootstrapRegistryError("operation descriptor output profile mismatch")
        return manifest

    def _validate_window(self, issued_at: str, expires_at: str, effective_at: str) -> None:
        issued = _utc(issued_at)
        expires = _utc(expires_at)
        effective = _utc(effective_at)
        if issued >= expires or effective < issued or effective >= expires:
            raise BootstrapRegistryError("bootstrap record is outside its validity window")

    def _validate_operation_time(
        self,
        operation: VerifiedOperation,
        *,
        effective_at: str,
        not_before: Iterable[str],
    ) -> None:
        effective = _utc(effective_at)
        descriptor = operation.descriptor
        if effective < _utc(descriptor["validFrom"]) or effective >= _utc(descriptor["validUntil"]):
            raise BootstrapRegistryError("operation execution is outside the descriptor validity window")
        if any(effective < _utc(value) for value in not_before):
            raise BootstrapRegistryError("operation execution predates its authorization inputs")

    def _checkpoint_records(
        self,
        *,
        prior: dict[str, Any] | None,
        entry_subject: dict[str, Any],
        effective_at: str,
    ) -> dict[str, dict[str, Any]]:
        entry = with_self_digest(entry_subject)
        head = with_self_digest(
            {
                "schema": "bootstrap-registry-head/v1",
                "registryId": self.registry_id,
                "sequence": entry["sequence"],
                "priorHeadDigest": prior["headDigest"] if prior is not None else None,
                "entryDigest": entry["recordDigest"],
                "attemptId": entry["attemptId"],
                "state": entry["state"],
                "terminalHeadDigests": entry["terminalHeadDigests"],
                "createdAt": effective_at,
            }
        )
        slot = with_self_digest(
            {
                "schema": "bootstrap-receipt-slot/v1",
                "slotId": f"slot-{head['recordDigest'].removeprefix('sha256:')[:32]}",
                "headDigest": head["recordDigest"],
                "attemptId": entry["attemptId"],
                "slotSequence": _sequence(0),
                "generation": 0,
                "status": "open",
                "closureVariant": None,
                "receiptDigest": None,
                "previousSlotDigest": None,
                "openedAt": effective_at,
                "closedAt": None,
            }
        )
        commit = with_self_digest(
            {
                "schema": "bootstrap-head-slot-commit/v1",
                "headDigest": head["recordDigest"],
                "headSequence": head["sequence"],
                "slotDigest": slot["recordDigest"],
                "slotGeneration": 0,
                "committedAt": effective_at,
            }
        )
        current = with_self_digest(
            {
                "schema": "bootstrap-current-head/v1",
                "registryId": self.registry_id,
                "sequence": head["sequence"],
                "headDigest": head["recordDigest"],
                "entryDigest": entry["recordDigest"],
                "attemptId": head["attemptId"],
                "state": head["state"],
                "slotDigest": slot["recordDigest"],
                "headSlotCommitDigest": commit["recordDigest"],
                "terminalHeadDigests": head["terminalHeadDigests"],
                "updatedAt": effective_at,
            }
        )
        records = {"entry": entry, "head": head, "slot": slot, "commit": commit, "current": current}
        for record in records.values():
            self._validate(record)
        return records

    def _checkpoint_result(
        self,
        *,
        operation_id: str,
        operation: str,
        outcome: str,
        request_digest: str,
        records: dict[str, dict[str, Any]],
        effective_at: str,
    ) -> dict[str, Any]:
        result = with_self_digest(
            {
                "schema": "bootstrap-registry-operation-result/v1",
                "operationId": operation_id,
                "operation": operation,
                "outcome": outcome,
                "requestDigest": request_digest,
                "entryDigest": records["entry"]["recordDigest"],
                "headDigest": records["head"]["recordDigest"],
                "slotDigest": records["slot"]["recordDigest"],
                "headSlotCommitDigest": records["commit"]["recordDigest"],
                "currentDigest": records["current"]["recordDigest"],
                "completedAt": effective_at,
            }
        )
        self._validate(result)
        return result

    def _recover_checkpoint_bundle(
        self,
        bundle: dict[str, Any],
        *,
        crash_after: str | None,
    ) -> dict[str, Any]:
        records = bundle["records"]
        result = bundle["result"]
        existing_result = self._existing_exact_result(bundle)
        if existing_result is not None:
            return existing_result
        self._write_wal(bundle, "prepared")
        self._maybe_crash(crash_after, "prepared")
        for record in (*bundle["inputRecords"], records["entry"], records["head"], records["slot"], records["commit"], records["current"], result):
            self._write_object(record)
        self._write_wal(bundle, "objects_written")
        self._maybe_crash(crash_after, "objects_written")

        slot_path = self._slot_pointer_path(records["head"]["recordDigest"])
        slot_bytes = canonical_bytes(records["slot"])
        if slot_path.exists():
            if slot_path.read_bytes() != slot_bytes:
                raise BootstrapRegistryError("new head receipt slot was already initialized differently")
        else:
            atomic_write(slot_path, slot_bytes, mode=0o600, create_only=True)

        current = self.current()
        expected = bundle["expectedPointerDigest"]
        candidate = records["current"]
        if current is not None and current["recordDigest"] == candidate["recordDigest"]:
            pass
        elif (current["recordDigest"] if current is not None else None) != expected:
            raise BootstrapRegistryError("registry current-head CAS failed")
        else:
            atomic_write(self._current_path, canonical_bytes(candidate), mode=0o600)
        readback = self.current()
        if readback is None or readback["recordDigest"] != candidate["recordDigest"]:
            raise BootstrapRegistryError("registry current-head readback failed")
        self._write_wal(bundle, "pointer_published")
        self._maybe_crash(crash_after, "pointer_published")

        result_path = self._result_path(bundle["operationId"])
        result_bytes = canonical_bytes(result)
        if result_path.exists():
            if result_path.read_bytes() != result_bytes:
                raise BootstrapRegistryError("operation result drift")
        else:
            atomic_write(result_path, result_bytes, mode=0o600, create_only=True)
        self._write_wal(bundle, "completed", result_digest=result["recordDigest"])
        self._maybe_crash(crash_after, "completed")
        return result

    def register_attempt(
        self,
        *,
        intent: dict[str, Any],
        waiver: dict[str, Any],
        operation: VerifiedOperation,
        effective_at: str,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        self._validate(intent)
        self._validate(waiver)
        operation_id = _safe_id("operation id", intent["operationId"])
        request_digest = self._validate_operation(
            operation,
            expected_operation="register_attempt",
            records=[intent, waiver],
            change_id=intent["changeId"],
            task_id=intent["taskId"],
        )
        root_digest = operation.tool_release.authority.root["recordDigest"]
        if waiver["operationId"] != operation_id or waiver["attemptIntentDigest"] != intent["recordDigest"]:
            raise BootstrapRegistryError("attempt waiver does not bind the intent/operation")
        if intent["rootDigest"] != root_digest or waiver["rootDigest"] != root_digest:
            raise BootstrapRegistryError("attempt registration root mismatch")
        if waiver["registrationKind"] != intent["registrationKind"]:
            raise BootstrapRegistryError("attempt waiver registration kind mismatch")
        if waiver["authorityProfileDigest"] != authority_profile_digest(operation.tool_release.authority.root):
            raise BootstrapRegistryError("attempt waiver authority profile mismatch")
        if waiver["requiredRoles"] != REQUIRED_WAIVER_ROLES:
            raise BootstrapRegistryError("attempt waiver requires the exact three distinct roles")
        _unique(intent["priorTerminalHeadDigests"], "prior terminal history")
        self._validate_window(intent["issuedAt"], intent["expiresAt"], effective_at)
        self._validate_window(waiver["issuedAt"], waiver["expiresAt"], effective_at)
        self._validate_operation_time(
            operation,
            effective_at=effective_at,
            not_before=(intent["issuedAt"], waiver["issuedAt"]),
        )

        with self._lock():
            existing_bundle = self._load_bundle(operation_id)
            if existing_bundle is not None:
                if existing_bundle["operation"] != "register_attempt" or existing_bundle["requestDigest"] != request_digest:
                    raise BootstrapRegistryError("operation-id replay has different registration inputs")
                return self._recover_checkpoint_bundle(existing_bundle, crash_after=crash_after)

            prior = self.current()
            if prior is not None and prior["state"] not in TERMINAL_STATES:
                raise BootstrapRegistryError("another bootstrap attempt is still live")
            terminal_history = [] if prior is None else [*prior["terminalHeadDigests"], prior["headDigest"]]
            if intent["priorTerminalHeadDigests"] != terminal_history:
                raise BootstrapRegistryError("registration does not import the complete prior terminal history")
            next_sequence = _sequence(1 if prior is None else int(prior["sequence"]) + 1)
            entry_subject = {
                "schema": "bootstrap-attempt-registry-entry/v1",
                "registryId": self.registry_id,
                "sequence": next_sequence,
                "attemptId": intent["attemptId"],
                "rootDigest": root_digest,
                "priorHeadDigest": prior["headDigest"] if prior is not None else None,
                "priorEntryDigest": prior["entryDigest"] if prior is not None else None,
                "state": "registered",
                "transition": "register_attempt",
                "changeId": intent["changeId"],
                "taskId": intent["taskId"],
                "worker": intent["worker"],
                "baseCommit": intent["baseCommit"],
                "registrationKind": intent["registrationKind"],
                "intentDigest": intent["recordDigest"],
                "waiverDigest": waiver["recordDigest"],
                "tokenState": "not_generated",
                "terminalHeadDigests": terminal_history,
                "transitionEvidenceDigest": operation.descriptor["recordDigest"],
                "effectiveAt": effective_at,
            }
            records = self._checkpoint_records(prior=prior, entry_subject=entry_subject, effective_at=effective_at)
            result = self._checkpoint_result(
                operation_id=operation_id,
                operation="register_attempt",
                outcome="registered",
                request_digest=request_digest,
                records=records,
                effective_at=effective_at,
            )
            bundle = with_self_digest(
                {
                    "schema": "bootstrap-internal-transaction-bundle/v1",
                    "operationId": operation_id,
                    "operation": "register_attempt",
                    "requestDigest": request_digest,
                    "expectedPointerDigest": prior["recordDigest"] if prior is not None else None,
                    "candidatePointerDigest": records["current"]["recordDigest"],
                    "effectiveAt": effective_at,
                    "inputRecords": [intent, waiver],
                    "records": records,
                    "result": result,
                }
            )
            self._write_bundle(bundle)
            return self._recover_checkpoint_bundle(bundle, crash_after=crash_after)

    def cancel_attempt(
        self,
        *,
        authorization: dict[str, Any],
        operation: VerifiedOperation,
        effective_at: str,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        self._validate(authorization)
        operation_id = _safe_id("operation id", authorization["operationId"])
        current = self.current()
        if current is None:
            raise BootstrapRegistryError("no bootstrap attempt exists")
        entry = self.object(current["entryDigest"])
        request_digest = self._validate_operation(
            operation,
            expected_operation="cancel_attempt",
            records=[authorization],
            change_id=entry["changeId"],
            task_id=entry["taskId"],
        )
        root_digest = operation.tool_release.authority.root["recordDigest"]
        if authorization["rootDigest"] != root_digest or entry["rootDigest"] != root_digest:
            raise BootstrapRegistryError("cancellation root mismatch")
        self._validate_operation_time(
            operation,
            effective_at=effective_at,
            not_before=(authorization["authorizedAt"],),
        )

        with self._lock():
            existing_bundle = self._load_bundle(operation_id)
            if existing_bundle is not None:
                if existing_bundle["operation"] != "cancel_attempt" or existing_bundle["requestDigest"] != request_digest:
                    raise BootstrapRegistryError("operation-id replay has different cancellation inputs")
                return self._recover_checkpoint_bundle(existing_bundle, crash_after=crash_after)
            current = self.current()
            if current is None or current["headDigest"] != authorization["headDigest"]:
                raise BootstrapRegistryError("cancellation head is stale")
            entry = self.object(current["entryDigest"])
            if current["attemptId"] != authorization["attemptId"] or current["state"] != authorization["expectedState"]:
                raise BootstrapRegistryError("cancellation attempt/state mismatch")
            if current["state"] not in CANCELLABLE_STATES:
                raise BootstrapRegistryError("bootstrap attempt state is not cancellable")
            expected_token = "not_generated" if entry["tokenState"] == "not_generated" else "destroyed"
            if authorization["tokenDisposition"] != expected_token:
                raise BootstrapRegistryError("cancellation token disposition is incomplete")
            expected_wal = "disposed" if current["state"] == "claim_publication_pending" else "absent"
            if authorization["publicationWalDisposition"] != expected_wal:
                raise BootstrapRegistryError("cancellation publication-WAL disposition is incomplete")
            next_sequence = _sequence(int(current["sequence"]) + 1)
            entry_subject = {
                key: entry[key]
                for key in (
                    "schema", "registryId", "attemptId", "rootDigest", "changeId", "taskId", "worker",
                    "baseCommit", "registrationKind", "intentDigest", "waiverDigest", "terminalHeadDigests",
                )
            }
            entry_subject.update(
                {
                    "sequence": next_sequence,
                    "priorHeadDigest": current["headDigest"],
                    "priorEntryDigest": current["entryDigest"],
                    "state": "cancelled_pre_cas",
                    "transition": "cancel_attempt",
                    "tokenState": "not_generated" if expected_token == "not_generated" else "disposed",
                    "transitionEvidenceDigest": authorization["recordDigest"],
                    "effectiveAt": effective_at,
                }
            )
            records = self._checkpoint_records(prior=current, entry_subject=entry_subject, effective_at=effective_at)
            result = self._checkpoint_result(
                operation_id=operation_id,
                operation="cancel_attempt",
                outcome="cancelled_pre_cas",
                request_digest=request_digest,
                records=records,
                effective_at=effective_at,
            )
            bundle = with_self_digest(
                {
                    "schema": "bootstrap-internal-transaction-bundle/v1",
                    "operationId": operation_id,
                    "operation": "cancel_attempt",
                    "requestDigest": request_digest,
                    "expectedPointerDigest": current["recordDigest"],
                    "candidatePointerDigest": records["current"]["recordDigest"],
                    "effectiveAt": effective_at,
                    "inputRecords": [authorization],
                    "records": records,
                    "result": result,
                }
            )
            self._write_bundle(bundle)
            return self._recover_checkpoint_bundle(bundle, crash_after=crash_after)

    def recover_receipt(
        self,
        *,
        authorization: dict[str, Any],
        search: dict[str, Any],
        operation: VerifiedOperation,
        effective_at: str,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        self._validate(authorization)
        self._validate(search)
        operation_id = _safe_id("operation id", authorization["operationId"])
        current = self.current()
        if current is None:
            raise BootstrapRegistryError("no bootstrap attempt exists")
        entry = self.object(current["entryDigest"])
        request_digest = self._validate_operation(
            operation,
            expected_operation="recover_receipt",
            records=[authorization, search],
            change_id=entry["changeId"],
            task_id=entry["taskId"],
        )
        root_digest = operation.tool_release.authority.root["recordDigest"]
        if authorization["rootDigest"] != root_digest or entry["rootDigest"] != root_digest:
            raise BootstrapRegistryError("receipt-recovery root mismatch")
        if search["recoveryId"] != authorization["recoveryId"]:
            raise BootstrapRegistryError("receipt-recovery search/authorization mismatch")
        self._validate_operation_time(
            operation,
            effective_at=effective_at,
            not_before=(authorization["authorizedAt"], search["completedAt"]),
        )
        reason = authorization["reason"]
        compromise_at = authorization["compromiseEffectiveAt"]
        if (reason == "old_receipt_authority_compromised") != (compromise_at is not None):
            raise BootstrapRegistryError("receipt-recovery compromise bound is missing or inapplicable")
        classification = search["classification"]
        if classification == "accepted_original":
            if search["acceptedCandidateCount"] != 1 or search["acceptedReceiptDigest"] is None or search["recoveredReceiptDigest"] is not None:
                raise BootstrapRegistryError("accepted-original recovery is not unique and exact")
            if reason == "old_receipt_authority_compromised":
                signing_time = search["acceptedTrustedSigningTime"]
                if signing_time is None or _utc(signing_time) >= _utc(compromise_at):
                    raise BootstrapRegistryError("accepted original is not proven before compromise")
        elif classification == "zero_accepted":
            if search["acceptedCandidateCount"] != 0 or search["acceptedReceiptDigest"] is not None or search["recoveredReceiptDigest"] is None:
                raise BootstrapRegistryError("zero-accepted recovery cardinality is invalid")
        elif (
            search["acceptedReceiptDigest"] is not None
            or search["recoveredReceiptDigest"] is not None
            or search["acceptedTrustedSigningTime"] is not None
        ):
            raise BootstrapRegistryError("ambiguous recovery cannot select any receipt")
        if classification == "zero_accepted" and search["acceptedTrustedSigningTime"] is not None:
            raise BootstrapRegistryError("zero-accepted recovery cannot bind an accepted signing time")

        with self._lock():
            existing_bundle = self._load_bundle(operation_id)
            if existing_bundle is not None:
                if existing_bundle["operation"] != "recover_receipt" or existing_bundle["requestDigest"] != request_digest:
                    raise BootstrapRegistryError("operation-id replay has different recovery inputs")
                return self._recover_receipt_bundle(existing_bundle, crash_after=crash_after)
            current = self.current()
            if current is None or current["headDigest"] != authorization["headDigest"] or current["attemptId"] != authorization["attemptId"]:
                raise BootstrapRegistryError("receipt-recovery head/attempt is stale")
            prior_slot = self.receipt_slot(current["headDigest"])
            if prior_slot["status"] != "open" or prior_slot["generation"] != 0:
                raise BootstrapRegistryError("receipt slot is already terminal")
            closed_slot: dict[str, Any] | None = None
            receipt_digest: str | None = None
            outcome = "ambiguous_blocked"
            if classification == "accepted_original":
                outcome = "promoted_original"
                receipt_digest = search["acceptedReceiptDigest"]
            elif classification == "zero_accepted":
                outcome = "recovered_alternate"
                receipt_digest = search["recoveredReceiptDigest"]
            if receipt_digest is not None:
                closed_slot = with_self_digest(
                    {
                        "schema": "bootstrap-receipt-slot/v1",
                        "slotId": prior_slot["slotId"],
                        "headDigest": prior_slot["headDigest"],
                        "attemptId": prior_slot["attemptId"],
                        "slotSequence": prior_slot["slotSequence"],
                        "generation": 1,
                        "status": "closed",
                        "closureVariant": outcome,
                        "receiptDigest": receipt_digest,
                        "previousSlotDigest": prior_slot["recordDigest"],
                        "openedAt": prior_slot["openedAt"],
                        "closedAt": effective_at,
                    }
                )
                self._validate(closed_slot)
                self._validate_slot(closed_slot)
            result = with_self_digest(
                {
                    "schema": "bootstrap-receipt-recovery-result/v1",
                    "operationId": operation_id,
                    "outcome": outcome,
                    "requestDigest": request_digest,
                    "authorizationDigest": authorization["recordDigest"],
                    "searchDigest": search["recordDigest"],
                    "currentHeadDigest": current["headDigest"],
                    "priorSlotDigest": prior_slot["recordDigest"],
                    "slotDigest": closed_slot["recordDigest"] if closed_slot is not None else None,
                    "receiptDigest": receipt_digest,
                    "completedAt": effective_at,
                }
            )
            self._validate(result)
            bundle = with_self_digest(
                {
                    "schema": "bootstrap-internal-transaction-bundle/v1",
                    "operationId": operation_id,
                    "operation": "recover_receipt",
                    "requestDigest": request_digest,
                    "expectedPointerDigest": prior_slot["recordDigest"],
                    "candidatePointerDigest": closed_slot["recordDigest"] if closed_slot is not None else None,
                    "effectiveAt": effective_at,
                    "inputRecords": [authorization, search],
                    "currentHeadDigest": current["headDigest"],
                    "slot": closed_slot,
                    "result": result,
                }
            )
            self._write_bundle(bundle)
            return self._recover_receipt_bundle(bundle, crash_after=crash_after)

    def _recover_receipt_bundle(
        self,
        bundle: dict[str, Any],
        *,
        crash_after: str | None,
    ) -> dict[str, Any]:
        result = bundle["result"]
        existing_result = self._existing_exact_result(bundle)
        if existing_result is not None:
            return existing_result
        self._write_wal(bundle, "prepared")
        self._maybe_crash(crash_after, "prepared")
        for record in bundle["inputRecords"]:
            self._write_object(record)
        if bundle["slot"] is not None:
            self._write_object(bundle["slot"])
        self._write_object(result)
        self._write_wal(bundle, "objects_written")
        self._maybe_crash(crash_after, "objects_written")

        current = self.current()
        if current is None or current["headDigest"] != bundle["currentHeadDigest"]:
            raise BootstrapRegistryError("registry head changed during receipt recovery")
        prior_slot = self.receipt_slot(bundle["currentHeadDigest"])
        candidate = bundle["slot"]
        if candidate is not None:
            if prior_slot["recordDigest"] == candidate["recordDigest"]:
                pass
            elif prior_slot["recordDigest"] != bundle["expectedPointerDigest"]:
                raise BootstrapRegistryError("receipt-slot generation CAS failed")
            else:
                atomic_write(
                    self._slot_pointer_path(bundle["currentHeadDigest"]),
                    canonical_bytes(candidate),
                    mode=0o600,
                )
            readback = self.receipt_slot(bundle["currentHeadDigest"])
            if readback["recordDigest"] != candidate["recordDigest"]:
                raise BootstrapRegistryError("receipt-slot readback failed")
        self._write_wal(bundle, "pointer_published")
        self._maybe_crash(crash_after, "pointer_published")

        result_path = self._result_path(bundle["operationId"])
        result_bytes = canonical_bytes(result)
        if result_path.exists():
            if result_path.read_bytes() != result_bytes:
                raise BootstrapRegistryError("receipt-recovery result drift")
        else:
            atomic_write(result_path, result_bytes, mode=0o600, create_only=True)
        self._write_wal(bundle, "completed", result_digest=result["recordDigest"])
        self._maybe_crash(crash_after, "completed")
        return result

    def _transition_attempt(
        self,
        *,
        operation_id: str,
        operation: str,
        expected_head_digest: str,
        expected_state: str,
        target_state: str,
        target_token_state: str,
        evidence_digest: str,
        input_records: list[dict[str, Any]],
        effective_at: str,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        """Internal exact-state transition used by root-verified coordinators.

        Callers must first verify their operation descriptor and exact input
        manifest. This method intentionally remains private: it supplies durable
        registry mechanics, not an authority surface.
        """
        transitions = {
            ("registered", "prepare_candidate"): ("candidate_prepared", "generated"),
            ("candidate_prepared", "publish_claim_pending"): ("claim_publication_pending", "generated"),
            ("claim_publication_pending", "publish_claim"): ("claimed", "generated"),
            ("claimed", "compensate_claim"): ("compensated", "disposed"),
            ("claimed", "abandon_claim"): ("abandoned", "disposed"),
            ("claimed", "adopt_claim"): ("adopted", "generated"),
            ("claim_publication_pending", "emergency_recover"): ("emergency_recovered", "disposed"),
            ("claimed", "emergency_recover"): ("emergency_recovered", "disposed"),
        }
        expected_target = transitions.get((expected_state, operation))
        if expected_target != (target_state, target_token_state):
            raise BootstrapRegistryError("attempt transition is outside the closed state graph")
        operation_id = _safe_id("operation id", operation_id)
        for record in input_records:
            self._validate(record)
        request_digest = semantic_digest(
            {
                "schema": "bootstrap-attempt-transition-input/v1",
                "operation": operation,
                "recordDigests": [record["recordDigest"] for record in input_records],
            }
        )
        with self._lock():
            existing_bundle = self._load_bundle(operation_id)
            if existing_bundle is not None:
                if existing_bundle["operation"] != operation or existing_bundle["requestDigest"] != request_digest:
                    raise BootstrapRegistryError("operation-id replay has different transition inputs")
                return self._recover_checkpoint_bundle(existing_bundle, crash_after=crash_after)
            current = self.current()
            if current is None or current["headDigest"] != expected_head_digest or current["state"] != expected_state:
                raise BootstrapRegistryError("attempt transition head/state CAS precondition failed")
            entry = self.object(current["entryDigest"])
            if operation == "prepare_candidate" and entry["registrationKind"] != "normal_original":
                raise BootstrapRegistryError("recovery-assisted registration cannot prepare a candidate")
            next_sequence = _sequence(int(current["sequence"]) + 1)
            entry_subject = {
                key: entry[key]
                for key in (
                    "schema", "registryId", "attemptId", "rootDigest", "changeId", "taskId", "worker",
                    "baseCommit", "registrationKind", "intentDigest", "waiverDigest", "terminalHeadDigests",
                )
            }
            entry_subject.update(
                {
                    "sequence": next_sequence,
                    "priorHeadDigest": current["headDigest"],
                    "priorEntryDigest": current["entryDigest"],
                    "state": target_state,
                    "transition": operation,
                    "tokenState": target_token_state,
                    "transitionEvidenceDigest": evidence_digest,
                    "effectiveAt": effective_at,
                }
            )
            records = self._checkpoint_records(prior=current, entry_subject=entry_subject, effective_at=effective_at)
            result = with_self_digest(
                {
                    "schema": "bootstrap-attempt-transition-result/v1",
                    "operationId": operation_id,
                    "operation": operation,
                    "requestDigest": request_digest,
                    "attemptId": current["attemptId"],
                    "priorHeadDigest": current["headDigest"],
                    "entryDigest": records["entry"]["recordDigest"],
                    "headDigest": records["head"]["recordDigest"],
                    "slotDigest": records["slot"]["recordDigest"],
                    "headSlotCommitDigest": records["commit"]["recordDigest"],
                    "currentDigest": records["current"]["recordDigest"],
                    "state": target_state,
                    "completedAt": effective_at,
                }
            )
            self._validate(result)
            bundle = with_self_digest(
                {
                    "schema": "bootstrap-internal-transaction-bundle/v1",
                    "operationId": operation_id,
                    "operation": operation,
                    "requestDigest": request_digest,
                    "expectedPointerDigest": current["recordDigest"],
                    "candidatePointerDigest": records["current"]["recordDigest"],
                    "effectiveAt": effective_at,
                    "inputRecords": input_records,
                    "records": records,
                    "result": result,
                }
            )
            self._write_bundle(bundle)
            return self._recover_checkpoint_bundle(bundle, crash_after=crash_after)

    def _close_normal_receipt_slot(
        self,
        *,
        operation_id: str,
        attempt_id: str,
        head_digest: str,
        receipt: dict[str, Any],
        effective_at: str,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        """Internal normal-original slot closure for a verified publisher."""
        self._validate(receipt)
        operation_id = _safe_id("operation id", operation_id)
        request_digest = semantic_digest(
            {
                "schema": "bootstrap-normal-receipt-closure-input/v1",
                "attemptId": attempt_id,
                "headDigest": head_digest,
                "receiptDigest": receipt["recordDigest"],
            }
        )
        with self._lock():
            existing_bundle = self._load_bundle(operation_id)
            if existing_bundle is not None:
                if existing_bundle["operation"] != "close_receipt" or existing_bundle["requestDigest"] != request_digest:
                    raise BootstrapRegistryError("operation-id replay has different receipt closure inputs")
                return self._recover_receipt_bundle(existing_bundle, crash_after=crash_after)
            current = self.current()
            if current is None or current["headDigest"] != head_digest or current["attemptId"] != attempt_id:
                raise BootstrapRegistryError("normal receipt closure head/attempt is stale")
            prior_slot = self.receipt_slot(head_digest)
            if prior_slot["status"] != "open" or prior_slot["generation"] != 0:
                raise BootstrapRegistryError("normal receipt slot is already terminal")
            slot = with_self_digest(
                {
                    "schema": "bootstrap-receipt-slot/v1",
                    "slotId": prior_slot["slotId"],
                    "headDigest": head_digest,
                    "attemptId": attempt_id,
                    "slotSequence": prior_slot["slotSequence"],
                    "generation": 1,
                    "status": "closed",
                    "closureVariant": "normal_original",
                    "receiptDigest": receipt["recordDigest"],
                    "previousSlotDigest": prior_slot["recordDigest"],
                    "openedAt": prior_slot["openedAt"],
                    "closedAt": effective_at,
                }
            )
            self._validate(slot)
            self._validate_slot(slot)
            result = with_self_digest(
                {
                    "schema": "bootstrap-receipt-closure-result/v1",
                    "operationId": operation_id,
                    "attemptId": attempt_id,
                    "headDigest": head_digest,
                    "priorSlotDigest": prior_slot["recordDigest"],
                    "slotDigest": slot["recordDigest"],
                    "closureVariant": "normal_original",
                    "receiptDigest": receipt["recordDigest"],
                    "completedAt": effective_at,
                }
            )
            self._validate(result)
            bundle = with_self_digest(
                {
                    "schema": "bootstrap-internal-transaction-bundle/v1",
                    "operationId": operation_id,
                    "operation": "close_receipt",
                    "requestDigest": request_digest,
                    "expectedPointerDigest": prior_slot["recordDigest"],
                    "candidatePointerDigest": slot["recordDigest"],
                    "effectiveAt": effective_at,
                    "inputRecords": [receipt],
                    "currentHeadDigest": head_digest,
                    "slot": slot,
                    "result": result,
                }
            )
            self._write_bundle(bundle)
            return self._recover_receipt_bundle(bundle, crash_after=crash_after)
