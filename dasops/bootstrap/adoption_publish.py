from __future__ import annotations

import base64
from contextlib import ExitStack
from copy import deepcopy
from datetime import timedelta
import hashlib
import hmac
from pathlib import Path
from typing import Any, ContextManager, Protocol

from dasops.protected.canonical import canonical_bytes, semantic_digest, with_self_digest
from dasops.protected.encoding import strict_urlsafe_b64decode
from dasops.protected.state_store import atomic_write

from .adoption_prepare import AdoptionPrepareCoordinator, _fsync_directory
from .authority import VerifiedOperation
from .foundation_verification import AdoptionFoundationVerificationStore, FoundationVerificationError
from .legacy_claim import LegacyClaimCoordinator, LegacyClaimError, SignedReceiptIssuer, _utc
from .registry import BootstrapAttemptRegistry, BootstrapRegistryError
from .repository_handoff import RepositoryHandoffCrash, RepositoryHandoffError, RepositoryHandoffStore


class AdoptionPublishError(RuntimeError):
    pass


class AdoptionPublishCrash(AdoptionPublishError):
    pass


class AdoptionRepositoryController(Protocol):
    def lock(self) -> ContextManager[None]: ...

    def snapshot(self) -> dict[str, Any]: ...

    def drain(self) -> None: ...

    def prefence(self) -> None: ...

    def stage(self, ref: str, commit: str) -> None: ...

    def candidate_identity(self, commit: str) -> dict[str, str]: ...

    def create_main_from_absent(self, commit: str) -> None: ...

    def remove_staging(self, namespace: str) -> None: ...

    def permanent_fence(self) -> None: ...

    def restore_access(self) -> None: ...


def adoption_activation_response(token: bytes, challenge: dict[str, Any]) -> bytes:
    try:
        nonce = strict_urlsafe_b64decode(challenge["nonceBase64"], expected_size=32)
    except Exception as exc:
        raise AdoptionPublishError("adoption activation nonce is invalid") from exc
    subject = b"bootstrap-adoption-activation/v1\0" + nonce + canonical_bytes(
        {
            "adoptionTokenHash": challenge["adoptionTokenHash"],
            "challengeId": challenge["challengeId"],
            "newMain": challenge["newMain"],
            "packageDigest": challenge["packageDigest"],
            "packageId": challenge["packageId"],
        }
    )
    return hmac.new(token, subject, hashlib.sha256).digest()


class AdoptionPublishCoordinator:
    """One-way old-to-new canonical adoption with crash recovery."""

    def __init__(
        self,
        registry: BootstrapAttemptRegistry,
        *,
        foundation_store: AdoptionFoundationVerificationStore | None = None,
        foundation_authorized_head: dict[str, Any] | None = None,
        repository_handoff_store: RepositoryHandoffStore | None = None,
    ) -> None:
        self.registry = registry
        self.prepare_store = AdoptionPrepareCoordinator(registry)
        self.root = self.prepare_store.root
        self.foundation_store = foundation_store
        self.foundation_authorized_head = foundation_authorized_head
        self.repository_handoff_store = repository_handoff_store

    def _foundation_authorized(self, package: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.foundation_store is None or self.foundation_authorized_head is None:
            raise AdoptionPublishError("adoption Foundation Verification authority is absent")
        try:
            chain = self.foundation_store.validate_chain()
            head = self.foundation_authorized_head
            if (
                head not in chain
                or head["milestone"] != "FV-M2"
                or head["state"] != "adoption_authorized"
                or head["packageDigest"] != package["recordDigest"]
                or head["candidateCommit"] != package["candidateCommit"]
            ):
                raise FoundationVerificationError("FV-M2 head is not in the current verified chain")
            manifest = self.foundation_store.manifest(head)
            if manifest is None:
                raise FoundationVerificationError("FV-M2 manifest is absent")
            return head, manifest
        except FoundationVerificationError as exc:
            raise AdoptionPublishError(str(exc)) from exc

    def _foundation_published(self, package: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.foundation_store is None:
            raise AdoptionPublishError("adoption Foundation Verification authority is absent")
        try:
            head = self.foundation_store.require(
                milestone="FV-M3", state="adoption_published", package=package
            )
            manifest = self.foundation_store.manifest(head)
            if manifest is None:
                raise FoundationVerificationError("FV-M3 manifest is absent")
            return head, manifest
        except FoundationVerificationError as exc:
            raise AdoptionPublishError(str(exc)) from exc

    def _repository_genesis(self, package: dict[str, Any]) -> dict[str, dict[str, Any]]:
        if self.repository_handoff_store is None:
            raise AdoptionPublishError("repository handoff authority is absent")
        try:
            return self.repository_handoff_store.genesis(package=package)
        except RepositoryHandoffError as exc:
            raise AdoptionPublishError(str(exc)) from exc

    def _repository_handoff_published(
        self,
        package: dict[str, Any],
        publish_result: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        if self.repository_handoff_store is None:
            raise AdoptionPublishError("repository handoff authority is absent")
        try:
            return self.repository_handoff_store.require(
                package=package,
                publish_result=publish_result,
            )
        except RepositoryHandoffError as exc:
            raise AdoptionPublishError(str(exc)) from exc

    @property
    def _state_path(self) -> Path:
        return self.root / "packages" / "state.json"

    def lifecycle(self) -> dict[str, Any]:
        state = self.prepare_store._read_record(self._state_path)
        if state is None or state["schema"] != "bootstrap-adoption-lifecycle-state/v1":
            raise AdoptionPublishError("adoption lifecycle state is absent")
        return state

    def _write_state(self, value: dict[str, Any], *, expected_digest: str | None) -> dict[str, Any]:
        self.registry._validate(value)
        existing = self.prepare_store._read_record(self._state_path)
        if existing is None:
            if expected_digest is not None:
                raise AdoptionPublishError("adoption lifecycle CAS expected an existing state")
        elif existing["recordDigest"] == value["recordDigest"]:
            return value
        elif existing["recordDigest"] != expected_digest:
            raise AdoptionPublishError("adoption lifecycle CAS failed")
        atomic_write(self._state_path, canonical_bytes(value), mode=0o600)
        return value

    @staticmethod
    def _advance(state: dict[str, Any], effective_at: str, **changes: Any) -> dict[str, Any]:
        subject = deepcopy(state)
        subject.pop("recordDigest")
        subject.update(changes)
        subject["generation"] = state["generation"] + 1
        subject["updatedAt"] = effective_at
        return with_self_digest(subject)

    @staticmethod
    def _crash(crash_after: str | None, phase: str) -> None:
        if crash_after == phase:
            raise AdoptionPublishCrash(f"injected crash after {phase}")

    def _operation_dir(self, operation_id: str) -> Path:
        return self.root / "operations" / operation_id

    def _write_record(self, path: Path, value: dict[str, Any]) -> None:
        self.prepare_store._write_record(path, value)

    def _read_record(self, path: Path) -> dict[str, Any] | None:
        return self.prepare_store._read_record(path)

    def _task_subject(self, package: dict[str, Any]) -> tuple[str, str]:
        current = self.registry.current()
        if current is None or current["attemptId"] != package["attemptId"]:
            raise AdoptionPublishError("adoption package does not bind the current attempt")
        entry = self.registry.object(current["entryDigest"])
        if entry["rootDigest"] != package["rootDigest"]:
            raise AdoptionPublishError("adoption package root does not bind the current attempt")
        return entry["changeId"], entry["taskId"]

    def _append_publish_wal(
        self,
        *,
        request: dict[str, Any],
        phase: str,
        lifecycle: dict[str, Any],
        effective_at: str,
        result_digest: str | None = None,
    ) -> None:
        path = self._operation_dir(request["operationId"]) / f"{phase}.json"
        existing = self._read_record(path)
        if existing is not None:
            if existing["requestDigest"] != request["recordDigest"] or existing["phase"] != phase:
                raise AdoptionPublishError("adoption publication WAL replay drift")
            return
        wal = with_self_digest(
            {
                "schema": "bootstrap-adoption-publish-wal/v1",
                "operationId": request["operationId"],
                "packageId": request["packageId"],
                "requestDigest": request["recordDigest"],
                "phase": phase,
                "oldMain": request["oldMain"],
                "candidateCommit": request["candidateCommit"],
                "lifecycleDigest": lifecycle["recordDigest"],
                "resultDigest": result_digest,
                "recordedAt": effective_at,
            }
        )
        self._write_record(path, wal)

    def _verify_signed(
        self,
        record: dict[str, Any],
        verification: dict[str, Any],
        purpose: str,
        operation: VerifiedOperation,
    ) -> None:
        try:
            LegacyClaimCoordinator._verify_signed_record(
                self,
                record=record,
                verification=verification,
                purpose=purpose,
                operation=operation,
            )
        except LegacyClaimError as exc:
            raise AdoptionPublishError(str(exc)) from exc

    def _verify_publish_inputs(
        self,
        *,
        request: dict[str, Any],
        package: dict[str, Any],
        prepare_result: dict[str, Any],
        approval_subject: dict[str, Any],
        approval: dict[str, Any],
        approval_verification: dict[str, Any],
        operation: VerifiedOperation,
        effective_at: str,
        expected_operation: str = "adopt_publish",
        extra_records: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        records = [request, package, prepare_result, approval_subject, approval, approval_verification]
        if extra_records:
            records = [*records, *extra_records]
        for record in records:
            self.registry._validate(record)
        change_id, task_id = self._task_subject(package)
        try:
            self.registry._validate_operation(
                operation,
                expected_operation=expected_operation,
                records=records,
                change_id=change_id,
                task_id=task_id,
            )
            self.registry._validate_operation_time(
                operation,
                effective_at=effective_at,
                not_before=(request["requestedAt"], approval["issuedAt"]),
            )
        except BootstrapRegistryError as exc:
            raise AdoptionPublishError(str(exc)) from exc
        self._verify_signed(approval, approval_verification, "bootstrap_adoption_approval", operation)
        if _utc(approval["issuedAt"]) <= _utc(package["preparedAt"]):
            raise AdoptionPublishError("adoption approval was not issued after package preparation")
        if _utc(effective_at) >= _utc(approval["expiresAt"]):
            raise AdoptionPublishError("adoption approval expired")
        relations = {
            "packageId": package["packageId"],
            "packageDigest": package["recordDigest"],
            "prepareResultDigest": prepare_result["recordDigest"],
            "approvalSubjectDigest": approval_subject["recordDigest"],
            "approvalDigest": approval["recordDigest"],
            "approvalVerificationDigest": approval_verification["recordDigest"],
            "privateStateDigest": prepare_result["privateStateDigest"],
            "oldMain": package["oldMain"],
            "candidateCommit": package["candidateCommit"],
        }
        for field, expected in relations.items():
            if request[field] != expected:
                raise AdoptionPublishError(f"adoption publish {field} mismatch")
        if (
            prepare_result["packageDigest"] != package["recordDigest"]
            or prepare_result["approvalSubjectDigest"] != approval_subject["recordDigest"]
            or approval_subject["packageDigest"] != package["recordDigest"]
            or approval["packageDigest"] != package["recordDigest"]
            or approval["approvalSubjectDigest"] != approval_subject["recordDigest"]
            or approval["rootDigest"] != package["rootDigest"]
            or package["candidateParent"] != package["oldMain"]
            or package["candidateCommit"] == package["oldMain"]
            or approval_subject["rootDigest"] != package["rootDigest"]
            or approval_subject["attemptId"] != package["attemptId"]
            or approval_subject["oldRepositoryPath"] != package["oldRepositoryPath"]
            or approval_subject["newRepositoryPath"] != package["newRepositoryPath"]
            or approval_subject["workerRepositoryPath"] != package["workerRepositoryPath"]
            or approval_subject["oldMain"] != package["oldMain"]
            or approval_subject["candidateCommit"] != package["candidateCommit"]
            or approval_subject["candidateTree"] != package["candidateTree"]
            or approval_subject["candidateParent"] != package["candidateParent"]
            or approval_subject["claimAdoptionRequestDigest"] != package["claimAdoptionRequestDigest"]
            or approval_subject["foundationPayloadManifestDigest"] != package["foundationPayloadManifestDigest"]
            or approval_subject["preparedPackageManifestDigest"] != package["preparedPackageManifestDigest"]
            or approval_subject["legacyTokenHash"] != package["legacyTokenHash"]
            or approval_subject["adoptionTokenHash"] != package["adoptionTokenHash"]
            or approval_subject["keyEnvelopeDigest"] != package["keyEnvelopeDigest"]
            or approval_subject["generation"] != package["generation"]
            or prepare_result["claimAdoptionRequestDigest"] != package["claimAdoptionRequestDigest"]
            or prepare_result["foundationPayloadManifestDigest"] != package["foundationPayloadManifestDigest"]
            or prepare_result["preparedPackageManifestDigest"] != package["preparedPackageManifestDigest"]
        ):
            raise AdoptionPublishError("adoption package/subject/approval closure mismatch")
        return records

    @staticmethod
    def _snapshot(controller: AdoptionRepositoryController) -> dict[str, Any]:
        return AdoptionPrepareCoordinator._snapshot(controller)

    def publish(
        self,
        *,
        request: dict[str, Any],
        package: dict[str, Any],
        prepare_result: dict[str, Any],
        approval_subject: dict[str, Any],
        approval: dict[str, Any],
        approval_verification: dict[str, Any],
        operation: VerifiedOperation,
        old_repository: AdoptionRepositoryController,
        new_repository: AdoptionRepositoryController,
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
        _authorization_effective_at: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fv_authorized_head, fv_authorized_manifest = self._foundation_authorized(package)
        repository_genesis = self._repository_genesis(package)
        records = self._verify_publish_inputs(
            request=request,
            package=package,
            prepare_result=prepare_result,
            approval_subject=approval_subject,
            approval=approval,
            approval_verification=approval_verification,
            operation=operation,
            effective_at=_authorization_effective_at or effective_at,
            extra_records=[
                fv_authorized_head,
                fv_authorized_manifest,
                repository_genesis["selectorHead"],
                repository_genesis["selectorVerification"],
                repository_genesis["profileHead"],
                repository_genesis["profileVerification"],
            ],
        )
        result_path = self.root / "results" / f"{request['operationId']}-publish.json"
        verification_path = self.root / "results" / f"{request['operationId']}-publish-verification.json"
        completed = self._read_record(result_path)
        completed_verification = self._read_record(verification_path)
        state = self.lifecycle()
        if completed is not None and completed_verification is not None and state["status"] in {"published_pending_activation", "consumed"}:
            try:
                self.foundation_store.require(
                    milestone="FV-M3", state="adoption_published", package=package
                )
            except FoundationVerificationError as exc:
                raise AdoptionPublishError(str(exc)) from exc
            self._repository_handoff_published(package, completed)
            return completed, completed_verification
        if state["packageDigest"] != package["recordDigest"] or state["status"] not in {"awaiting_approval", "publishing", "published_pending_activation"}:
            raise AdoptionPublishError("adoption package lifecycle is not publishable")
        if state["status"] == "awaiting_approval" and _utc(effective_at) >= _utc(package["expiresAt"]):
            raise AdoptionPublishError("adoption package expired before publication")

        with self.prepare_store._lock(), ExitStack() as stack:
            stack.enter_context(old_repository.lock())
            stack.enter_context(new_repository.lock())
            self._foundation_authorized(package)
            state = self.lifecycle()
            if state["status"] == "awaiting_approval":
                publishing = self._advance(
                    state,
                    effective_at,
                    status="publishing",
                    publishRequestDigest=request["recordDigest"],
                )
                state = self._write_state(publishing, expected_digest=state["recordDigest"])
            elif state["publishRequestDigest"] != request["recordDigest"]:
                raise AdoptionPublishError("adoption publishing state belongs to another request")
            self._append_publish_wal(request=request, phase="publish_intent", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "publish_intent")

            old = self._snapshot(old_repository)
            new = self._snapshot(new_repository)
            if old["path"] != package["oldRepositoryPath"] or new["path"] != package["newRepositoryPath"]:
                raise AdoptionPublishError("adoption repository substitution")
            if old["objectFormat"] != package["objectFormat"] or new["objectFormat"] != package["objectFormat"]:
                raise AdoptionPublishError("adoption object-format drift")
            if old["main"] != package["oldMain"]:
                raise AdoptionPublishError("old canonical main changed after preparation")
            if new["main"] not in {None, package["candidateCommit"]}:
                raise AdoptionPublishError("new canonical main is ambiguous")
            allowed_refs = {"refs/heads/main"}
            if any(ref not in allowed_refs and not ref.startswith(package["allowedStagingNamespace"]) for ref in new["refs"]):
                raise AdoptionPublishError("new repository contains an unexpected ref")

            if not old["drained"]:
                old_repository.drain()
            old = self._snapshot(old_repository)
            if old["main"] != package["oldMain"] or not old["drained"]:
                raise AdoptionPublishError("old repository drain readback failed")
            state = self._write_state(self._advance(state, effective_at, oldDrained=True), expected_digest=state["recordDigest"])
            self._append_publish_wal(request=request, phase="old_drained", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "old_drained")

            old = self._snapshot(old_repository)
            if not old["fenced"]:
                old_repository.prefence()
            old = self._snapshot(old_repository)
            if (
                old["main"] != package["oldMain"]
                or not old["drained"]
                or not old["fenced"]
                or old["fenceMode"] not in {"prefenced", "permanent"}
            ):
                raise AdoptionPublishError("old repository pre-fence readback failed")
            state = self._write_state(self._advance(state, effective_at, oldFenced=True), expected_digest=state["recordDigest"])
            self._append_publish_wal(request=request, phase="old_prefenced", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "old_prefenced")

            staging_ref = f"{package['allowedStagingNamespace']}candidate"
            new = self._snapshot(new_repository)
            if new["main"] is None and staging_ref not in new["refs"]:
                new_repository.stage(staging_ref, package["candidateCommit"])
            new = self._snapshot(new_repository)
            if new["main"] is None and staging_ref not in new["refs"]:
                raise AdoptionPublishError("new repository staging readback failed")
            candidate_identity = new_repository.candidate_identity(package["candidateCommit"])
            if candidate_identity != {
                "commit": package["candidateCommit"],
                "tree": package["candidateTree"],
                "parent": package["candidateParent"],
            }:
                raise AdoptionPublishError("staged foundation candidate identity/ancestry readback failed")
            state = self._write_state(self._advance(state, effective_at, stagingRef=staging_ref), expected_digest=state["recordDigest"])
            self._append_publish_wal(request=request, phase="new_staged", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "new_staged")

            new = self._snapshot(new_repository)
            if new["main"] is None:
                new_repository.create_main_from_absent(package["candidateCommit"])
            elif new["main"] != package["candidateCommit"]:
                raise AdoptionPublishError("new-main zero-OID CAS cannot be reconciled")
            new = self._snapshot(new_repository)
            if new["main"] != package["candidateCommit"] or "refs/heads/main" not in new["refs"]:
                raise AdoptionPublishError("new-main zero-OID CAS readback failed")
            state = self._write_state(self._advance(state, effective_at, newMain=package["candidateCommit"]), expected_digest=state["recordDigest"])
            self._append_publish_wal(request=request, phase="new_main_created", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "new_main_created")

            new_repository.remove_staging(package["allowedStagingNamespace"])
            new = self._snapshot(new_repository)
            if new["main"] != package["candidateCommit"] or any(
                ref.startswith(package["allowedStagingNamespace"]) for ref in new["refs"]
            ):
                raise AdoptionPublishError("new repository staging removal readback failed")
            state = self._write_state(self._advance(state, effective_at, stagingRef=None), expected_digest=state["recordDigest"])
            self._append_publish_wal(request=request, phase="staging_removed", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "staging_removed")

            old_repository.permanent_fence()
            old = self._snapshot(old_repository)
            if (
                old["main"] != package["oldMain"]
                or not old["drained"]
                or not old["fenced"]
                or old["fenceMode"] != "permanent"
            ):
                raise AdoptionPublishError("old permanent-fence readback failed")
            state = self._write_state(self._advance(state, effective_at, oldFenced=True), expected_digest=state["recordDigest"])
            self._append_publish_wal(request=request, phase="old_permanent_fenced", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "old_permanent_fenced")

            registry_transition = self.registry._transition_attempt(
                operation_id=f"{request['operationId'][:80]}-registry-adopted",
                operation="adopt_claim",
                expected_head_digest=package["claimedHeadDigest"],
                expected_state="claimed",
                target_state="adopted",
                target_token_state="generated",
                evidence_digest=request["recordDigest"],
                input_records=records,
                effective_at=effective_at,
            )
            self._append_publish_wal(request=request, phase="registry_adopted", lifecycle=state, effective_at=effective_at)
            self._crash(crash_after, "registry_adopted")

            candidate_result_path = self._operation_dir(request["operationId"]) / "publish-result-candidate.json"
            candidate_verification_path = self._operation_dir(request["operationId"]) / "publish-verification-candidate.json"
            result = self._read_record(candidate_result_path)
            verification = self._read_record(candidate_verification_path)
            if result is None or verification is None:
                subject = {
                    "schema": "bootstrap-adoption-publish-result/v1",
                    "receiptId": f"adoption-publish-{request['operationId']}",
                    "operationId": request["operationId"],
                    "rootDigest": package["rootDigest"],
                    "packageId": package["packageId"],
                    "packageDigest": package["recordDigest"],
                    "outcome": "published_pending_activation",
                    "oldMain": package["oldMain"],
                    "newMain": package["candidateCommit"],
                    "oldPermanentFence": True,
                    "stagingRemoved": True,
                    "registryHeadDigest": registry_transition["headDigest"],
                    "completedAt": effective_at,
                }
                result, verification = issuer("bootstrap_adoption_publish_result", subject)
                self._verify_signed(result, verification, "bootstrap_adoption_publish_result", operation)
                self._write_record(candidate_result_path, result)
                self._write_record(candidate_verification_path, verification)
            try:
                fv_descriptor = self.foundation_store.object(fv_authorized_head["descriptorDigest"])
                fv_published_head, fv_published_manifest = self.foundation_store.publish(
                    descriptor=fv_descriptor,
                    package=package,
                    publish_result=result,
                    publish_verification=verification,
                    registry_result=registry_transition,
                    effective_at=effective_at,
                )
            except FoundationVerificationError as exc:
                raise AdoptionPublishError(str(exc)) from exc
            self._crash(crash_after, "fv_m3_published")
            try:
                self.repository_handoff_store.publish(
                    package=package,
                    publish_result=result,
                    registry_result=registry_transition,
                    fv_head=fv_published_head,
                    fv_manifest=fv_published_manifest,
                    issuer=issuer,
                    effective_at=effective_at,
                    crash_after=crash_after,
                )
            except RepositoryHandoffCrash as exc:
                raise AdoptionPublishCrash(str(exc)) from exc
            except RepositoryHandoffError as exc:
                raise AdoptionPublishError(str(exc)) from exc
            self._write_record(result_path, result)
            self._write_record(verification_path, verification)
            self.registry._close_normal_receipt_slot(
                operation_id=f"{request['operationId'][:80]}-adopted-slot",
                attempt_id=package["attemptId"],
                head_digest=registry_transition["headDigest"],
                receipt=result,
                effective_at=effective_at,
            )
            self._append_publish_wal(request=request, phase="result_written", lifecycle=state, effective_at=effective_at, result_digest=result["recordDigest"])
            self._crash(crash_after, "result_written")
            final = self._advance(
                state,
                effective_at,
                status="published_pending_activation",
                publishResultDigest=result["recordDigest"],
                newMain=package["candidateCommit"],
                oldDrained=True,
                oldFenced=True,
                stagingRef=None,
            )
            state = self._write_state(final, expected_digest=state["recordDigest"])
            self._append_publish_wal(request=request, phase="published_pending_activation", lifecycle=state, effective_at=effective_at, result_digest=result["recordDigest"])
            self._crash(crash_after, "published_pending_activation")
            return result, verification

    def recover_publication(
        self,
        *,
        recovery_request: dict[str, Any],
        request: dict[str, Any],
        package: dict[str, Any],
        prepare_result: dict[str, Any],
        approval_subject: dict[str, Any],
        approval: dict[str, Any],
        approval_verification: dict[str, Any],
        recovery_operation: VerifiedOperation,
        publish_operation: VerifiedOperation,
        old_repository: AdoptionRepositoryController,
        new_repository: AdoptionRepositoryController,
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Reconcile one exact, already-started publication without guessing.

        The recovery descriptor binds the current observation and classification.
        The original publish descriptor remains mandatory and binds the mutation
        bytes. A proved pre-CAS abort is routed to the separately authorized
        cancellation transaction rather than being inferred here.
        """
        fv_authorized_head, fv_authorized_manifest = self._foundation_authorized(package)
        repository_genesis = self._repository_genesis(package)
        recovery_records = [
            recovery_request,
            request,
            package,
            prepare_result,
            approval_subject,
            approval,
            approval_verification,
            fv_authorized_head,
            fv_authorized_manifest,
            repository_genesis["selectorHead"],
            repository_genesis["selectorVerification"],
            repository_genesis["profileHead"],
            repository_genesis["profileVerification"],
        ]
        for record in recovery_records:
            self.registry._validate(record)
        change_id, task_id = self._task_subject(package)
        try:
            self.registry._validate_operation(
                recovery_operation,
                expected_operation="recover_publication",
                records=recovery_records,
                change_id=change_id,
                task_id=task_id,
            )
            self.registry._validate_operation_time(
                recovery_operation,
                effective_at=effective_at,
                not_before=(recovery_request["requestedAt"],),
            )
            self.registry._validate_operation(
                publish_operation,
                expected_operation="adopt_publish",
                records=[
                    request,
                    package,
                    prepare_result,
                    approval_subject,
                    approval,
                    approval_verification,
                    fv_authorized_head,
                    fv_authorized_manifest,
                    repository_genesis["selectorHead"],
                    repository_genesis["selectorVerification"],
                    repository_genesis["profileHead"],
                    repository_genesis["profileVerification"],
                ],
                change_id=change_id,
                task_id=task_id,
            )
        except BootstrapRegistryError as exc:
            raise AdoptionPublishError(str(exc)) from exc
        if (
            recovery_request["packageId"] != package["packageId"]
            or recovery_request["packageDigest"] != package["recordDigest"]
            or recovery_request["publishRequestDigest"] != request["recordDigest"]
        ):
            raise AdoptionPublishError("adoption recovery package/request mismatch")

        state = self.lifecycle()
        old = self._snapshot(old_repository)
        new = self._snapshot(new_repository)
        observed = {
            "oldMainObserved": old["main"],
            "newMainObserved": new["main"],
            "oldFenceObserved": old["fenced"],
        }
        if any(recovery_request[field] != value for field, value in observed.items()):
            raise AdoptionPublishError("adoption recovery observation drift")
        classification = recovery_request["classification"]
        if classification == "ambiguous_blocked":
            raise AdoptionPublishError("adoption publication remains fenced: authority-loss ambiguity")
        if classification == "proved_pre_cas_abort":
            if old["main"] != package["oldMain"] or new["main"] is not None:
                raise AdoptionPublishError("adoption recovery abort classification is not proved pre-CAS")
            raise AdoptionPublishError("proved pre-CAS abort requires the signed adopt-cancel transaction")
        if classification != "resume_publish" or state["status"] != "publishing":
            raise AdoptionPublishError("adoption recovery is not an exact in-progress publication")
        if old["main"] != package["oldMain"] or new["main"] not in {None, package["candidateCommit"]}:
            raise AdoptionPublishError("adoption recovery cannot reconcile dual-canonical or unknown main state")

        return self.publish(
            request=request,
            package=package,
            prepare_result=prepare_result,
            approval_subject=approval_subject,
            approval=approval,
            approval_verification=approval_verification,
            operation=publish_operation,
            old_repository=old_repository,
            new_repository=new_repository,
            issuer=issuer,
            effective_at=effective_at,
            crash_after=crash_after,
            _authorization_effective_at=request["requestedAt"],
        )

    def cancel(
        self,
        *,
        authorization: dict[str, Any],
        authorization_verification: dict[str, Any],
        prepare_request: dict[str, Any],
        package: dict[str, Any],
        prepare_result: dict[str, Any],
        operation: VerifiedOperation,
        old_repository: AdoptionRepositoryController,
        new_repository: AdoptionRepositoryController,
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fv_authorized_head, fv_authorized_manifest = self._foundation_authorized(package)
        repository_genesis = self._repository_genesis(package)
        records = [
            authorization,
            authorization_verification,
            prepare_request,
            package,
            prepare_result,
            fv_authorized_head,
            fv_authorized_manifest,
            repository_genesis["selectorHead"],
            repository_genesis["selectorVerification"],
            repository_genesis["profileHead"],
            repository_genesis["profileVerification"],
        ]
        for record in records:
            self.registry._validate(record)
        change_id, task_id = self._task_subject(package)
        try:
            self.registry._validate_operation(
                operation,
                expected_operation="adopt_cancel",
                records=records,
                change_id=change_id,
                task_id=task_id,
            )
            self.registry._validate_operation_time(
                operation,
                effective_at=effective_at,
                not_before=(authorization["authorizedAt"],),
            )
        except BootstrapRegistryError as exc:
            raise AdoptionPublishError(str(exc)) from exc
        self._verify_signed(authorization, authorization_verification, "bootstrap_adoption_cancel_authorization", operation)
        if (
            authorization["packageId"] != package["packageId"]
            or authorization["packageDigest"] != package["recordDigest"]
            or prepare_request["packageId"] != package["packageId"]
            or prepare_result["packageDigest"] != package["recordDigest"]
        ):
            raise AdoptionPublishError("adoption cancellation package closure mismatch")
        result_path = self.root / "results" / f"{authorization['operationId']}-cancel.json"
        verification_path = self.root / "results" / f"{authorization['operationId']}-cancel-verification.json"
        tombstone_path = self.root / "results" / f"{authorization['operationId']}-disposition-tombstone.json"
        tombstone_verification_path = (
            self.root / "results" / f"{authorization['operationId']}-disposition-tombstone-verification.json"
        )
        fence_release_path = self.root / "results" / f"{authorization['operationId']}-fence-release.json"
        fence_release_verification_path = (
            self.root / "results" / f"{authorization['operationId']}-fence-release-verification.json"
        )
        with self.prepare_store._lock(), ExitStack() as stack:
            stack.enter_context(old_repository.lock())
            stack.enter_context(new_repository.lock())
            state = self.lifecycle()
            existing = self._read_record(result_path)
            existing_verification = self._read_record(verification_path)
            if existing is not None and existing_verification is not None and state["status"] == "cancelled":
                tombstone = self._read_record(tombstone_path)
                tombstone_verification = self._read_record(tombstone_verification_path)
                fence_release = self._read_record(fence_release_path)
                fence_release_verification = self._read_record(fence_release_verification_path)
                if None in (
                    tombstone,
                    tombstone_verification,
                    fence_release,
                    fence_release_verification,
                ):
                    raise AdoptionPublishError("adoption cancellation terminal closure is incomplete")
                self._verify_signed(
                    tombstone,
                    tombstone_verification,
                    "bootstrap_adoption_disposition_tombstone",
                    operation,
                )
                self._verify_signed(
                    fence_release,
                    fence_release_verification,
                    "bootstrap_adoption_fence_release_receipt",
                    operation,
                )
                self._verify_signed(existing, existing_verification, "bootstrap_adoption_cancel_result", operation)
                try:
                    abort_head = self.foundation_store.require(
                        milestone="FV-MA", state="aborted_pre_cas", package=package
                    )
                except FoundationVerificationError as exc:
                    raise AdoptionPublishError(str(exc)) from exc
                if (
                    existing["fvAbortHeadDigest"] != abort_head["recordDigest"]
                    or existing["dispositionTombstoneDigest"] != tombstone["recordDigest"]
                    or existing["fenceReleaseReceiptDigest"] != fence_release["recordDigest"]
                ):
                    raise AdoptionPublishError("adoption cancellation terminal closure drift")
                return existing, existing_verification
            if state["status"] == "cancelled":
                raise AdoptionPublishError("adoption cancellation terminal closure is incomplete")
            if (
                state["packageDigest"] != package["recordDigest"]
                or (state["status"] != authorization["expectedStatus"] and existing is None)
                or state["status"] not in {authorization["expectedStatus"], "cancelled"}
            ):
                raise AdoptionPublishError("adoption cancellation package/state mismatch")
            old = self._snapshot(old_repository)
            new = self._snapshot(new_repository)
            if old["main"] != package["oldMain"] or new["main"] is not None:
                raise AdoptionPublishError("adoption cancellation cannot roll back an applied or ambiguous new-main CAS")
            if not authorization["oldMainUnchanged"] or not authorization["newMainAbsent"]:
                raise AdoptionPublishError("adoption cancellation lacks the proved pre-CAS state")
            new_repository.remove_staging(package["allowedStagingNamespace"])
            old = self._snapshot(old_repository)
            new = self._snapshot(new_repository)
            if (
                old["main"] != package["oldMain"]
                or new["main"] is not None
                or any(ref.startswith(package["allowedStagingNamespace"]) for ref in new["refs"])
            ):
                raise AdoptionPublishError("adoption cancellation pre-disposition readback failed")
            try:
                fv_descriptor = self.foundation_store.object(fv_authorized_head["descriptorDigest"])
                fv_abort_head, fv_abort_manifest = self.foundation_store.abort(
                    descriptor=fv_descriptor,
                    package=package,
                    abort_subject=authorization,
                    effective_at=effective_at,
                )
            except FoundationVerificationError as exc:
                raise AdoptionPublishError(str(exc)) from exc
            self._crash(crash_after, "fv_ma_aborted")
            private_path = self.prepare_store._private_path(prepare_request["privateStatePath"])
            if private_path.exists():
                private = self.prepare_store._read_private(private_path)
                if private["recordDigest"] != prepare_result["privateStateDigest"]:
                    raise AdoptionPublishError("adoption private state drift before cancellation")
                private_path.unlink()
                _fsync_directory(private_path.parent)
            tombstone = self._read_record(tombstone_path)
            tombstone_verification = self._read_record(tombstone_verification_path)
            if tombstone is None or tombstone_verification is None:
                tombstone_subject = {
                    "schema": "bootstrap-adoption-disposition-tombstone/v1",
                    "tombstoneId": f"disposition-{authorization['operationId']}",
                    "operationId": authorization["operationId"],
                    "rootDigest": package["rootDigest"],
                    "packageId": package["packageId"],
                    "packageDigest": package["recordDigest"],
                    "authorizationDigest": authorization["recordDigest"],
                    "fvAbortHeadDigest": fv_abort_head["recordDigest"],
                    "fvAbortManifestDigest": fv_abort_manifest["recordDigest"],
                    "privateStateDigest": prepare_result["privateStateDigest"],
                    "privateStateDisposition": "destroyed",
                    "keyEnvelopeDigest": package["keyEnvelopeDigest"],
                    "keyEnvelopeDisposition": "digest_retained_no_secret",
                    "secureEraseClaimed": False,
                    "disposedAt": effective_at,
                }
                tombstone, tombstone_verification = issuer(
                    "bootstrap_adoption_disposition_tombstone", tombstone_subject
                )
                self._verify_signed(
                    tombstone,
                    tombstone_verification,
                    "bootstrap_adoption_disposition_tombstone",
                    operation,
                )
                self._write_record(tombstone_path, tombstone)
                self._write_record(tombstone_verification_path, tombstone_verification)
            elif (
                tombstone["authorizationDigest"] != authorization["recordDigest"]
                or tombstone["fvAbortHeadDigest"] != fv_abort_head["recordDigest"]
                or tombstone["privateStateDigest"] != prepare_result["privateStateDigest"]
            ):
                raise AdoptionPublishError("adoption cancellation disposition tombstone drift")
            else:
                self._verify_signed(
                    tombstone,
                    tombstone_verification,
                    "bootstrap_adoption_disposition_tombstone",
                    operation,
                )
            self._crash(crash_after, "cancel_disposed")
            old_repository.restore_access()
            old = self._snapshot(old_repository)
            new = self._snapshot(new_repository)
            if (
                old["main"] != package["oldMain"]
                or old["drained"]
                or old["fenced"]
                or old["fenceMode"] != "open"
                or new["main"] is not None
                or any(ref.startswith(package["allowedStagingNamespace"]) for ref in new["refs"])
            ):
                raise AdoptionPublishError("adoption cancellation fence-release readback failed")
            fence_release = self._read_record(fence_release_path)
            fence_release_verification = self._read_record(fence_release_verification_path)
            if fence_release is None or fence_release_verification is None:
                fence_release_subject = {
                    "schema": "bootstrap-adoption-fence-release-receipt/v1",
                    "receiptId": f"fence-release-{authorization['operationId']}",
                    "operationId": authorization["operationId"],
                    "rootDigest": package["rootDigest"],
                    "packageId": package["packageId"],
                    "packageDigest": package["recordDigest"],
                    "fvAbortHeadDigest": fv_abort_head["recordDigest"],
                    "dispositionTombstoneDigest": tombstone["recordDigest"],
                    "oldMain": package["oldMain"],
                    "oldAccessRestored": True,
                    "newMainAbsent": True,
                    "stagingRemoved": True,
                    "completedAt": effective_at,
                }
                fence_release, fence_release_verification = issuer(
                    "bootstrap_adoption_fence_release_receipt", fence_release_subject
                )
                self._verify_signed(
                    fence_release,
                    fence_release_verification,
                    "bootstrap_adoption_fence_release_receipt",
                    operation,
                )
                self._write_record(fence_release_path, fence_release)
                self._write_record(fence_release_verification_path, fence_release_verification)
            elif (
                fence_release["fvAbortHeadDigest"] != fv_abort_head["recordDigest"]
                or fence_release["dispositionTombstoneDigest"] != tombstone["recordDigest"]
                or fence_release["oldMain"] != package["oldMain"]
            ):
                raise AdoptionPublishError("adoption cancellation fence-release receipt drift")
            else:
                self._verify_signed(
                    fence_release,
                    fence_release_verification,
                    "bootstrap_adoption_fence_release_receipt",
                    operation,
                )
            self._crash(crash_after, "cancel_fence_released")
            if existing is None or existing_verification is None:
                subject = {
                    "schema": "bootstrap-adoption-cancel-result/v2",
                    "receiptId": f"adoption-cancel-{authorization['operationId']}",
                    "operationId": authorization["operationId"],
                    "rootDigest": package["rootDigest"],
                    "packageId": package["packageId"],
                    "packageDigest": package["recordDigest"],
                    "outcome": "cancelled",
                    "fvAbortHeadDigest": fv_abort_head["recordDigest"],
                    "fvAbortManifestDigest": fv_abort_manifest["recordDigest"],
                    "dispositionTombstoneDigest": tombstone["recordDigest"],
                    "dispositionVerificationDigest": tombstone_verification["recordDigest"],
                    "fenceReleaseReceiptDigest": fence_release["recordDigest"],
                    "fenceReleaseVerificationDigest": fence_release_verification["recordDigest"],
                    "oldAccessRestored": True,
                    "newMainAbsent": True,
                    "stagingRemoved": True,
                    "privateStateDisposition": "destroyed",
                    "completedAt": effective_at,
                }
                result, verification = issuer("bootstrap_adoption_cancel_result", subject)
                self._verify_signed(result, verification, "bootstrap_adoption_cancel_result", operation)
                self._write_record(result_path, result)
                self._write_record(verification_path, verification)
            else:
                result, verification = existing, existing_verification
                self._verify_signed(result, verification, "bootstrap_adoption_cancel_result", operation)
                if (
                    result["fvAbortHeadDigest"] != fv_abort_head["recordDigest"]
                    or result["dispositionTombstoneDigest"] != tombstone["recordDigest"]
                    or result["fenceReleaseReceiptDigest"] != fence_release["recordDigest"]
                ):
                    raise AdoptionPublishError("adoption cancellation result closure drift")
            self._crash(crash_after, "cancel_result_written")
            cancelled = self._advance(
                state,
                effective_at,
                status="cancelled",
                oldDrained=False,
                oldFenced=False,
                newMain=None,
                stagingRef=None,
                cancelResultDigest=result["recordDigest"],
            )
            self._write_state(cancelled, expected_digest=state["recordDigest"])
            self._crash(crash_after, "cancelled")
            return result, verification

    def issue_activation_challenge(
        self,
        *,
        package: dict[str, Any],
        publish_result: dict[str, Any],
        challenge_id: str,
        nonce: bytes,
        issued_at: str,
        lifetime_seconds: int = 300,
    ) -> dict[str, Any]:
        if len(nonce) != 32 or lifetime_seconds < 30 or lifetime_seconds > 600:
            raise AdoptionPublishError("adoption activation challenge parameters are invalid")
        self.registry._validate(package)
        self.registry._validate(publish_result)
        self._foundation_published(package)
        self._repository_handoff_published(package, publish_result)
        state = self.lifecycle()
        if (
            state["status"] != "published_pending_activation"
            or state["packageDigest"] != package["recordDigest"]
            or state["publishResultDigest"] != publish_result["recordDigest"]
            or publish_result["packageDigest"] != package["recordDigest"]
            or publish_result["newMain"] != package["candidateCommit"]
            or _utc(issued_at) < _utc(publish_result["completedAt"])
        ):
            raise AdoptionPublishError("adoption package is not pending activation")
        expires = (_utc(issued_at) + timedelta(seconds=lifetime_seconds)).isoformat().replace("+00:00", "Z")
        challenge = with_self_digest(
            {
                "schema": "bootstrap-adoption-activation-challenge/v1",
                "challengeId": challenge_id,
                "packageId": package["packageId"],
                "packageDigest": package["recordDigest"],
                "adoptionTokenHash": package["adoptionTokenHash"],
                "newMain": publish_result["newMain"],
                "nonceBase64": base64.urlsafe_b64encode(nonce).decode().rstrip("="),
                "issuedAt": issued_at,
                "expiresAt": expires,
            }
        )
        path = self.root / "packages" / f"challenge-{challenge_id}.json"
        self._write_record(path, challenge)
        return challenge

    def activate(
        self,
        *,
        package: dict[str, Any],
        prepare_request: dict[str, Any],
        prepare_result: dict[str, Any],
        publish_result: dict[str, Any],
        challenge: dict[str, Any],
        response: bytes,
        operation: VerifiedOperation,
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fv_published_head, fv_published_manifest = self._foundation_published(package)
        repository_handoff = self._repository_handoff_published(package, publish_result)
        for record in (
            package,
            prepare_request,
            prepare_result,
            publish_result,
            challenge,
            fv_published_head,
            fv_published_manifest,
            repository_handoff["transaction"],
            repository_handoff["selectorHead"],
            repository_handoff["selectorVerification"],
            repository_handoff["profileHead"],
            repository_handoff["profileVerification"],
        ):
            self.registry._validate(record)
        change_id, task_id = self._task_subject(package)
        try:
            self.registry._validate_operation(
                operation,
                expected_operation="adopt_publish",
                records=[
                    package,
                    prepare_request,
                    prepare_result,
                    publish_result,
                    challenge,
                    fv_published_head,
                    fv_published_manifest,
                    repository_handoff["transaction"],
                    repository_handoff["selectorHead"],
                    repository_handoff["selectorVerification"],
                    repository_handoff["profileHead"],
                    repository_handoff["profileVerification"],
                ],
                change_id=change_id,
                task_id=task_id,
            )
            self.registry._validate_operation_time(
                operation,
                effective_at=effective_at,
                not_before=(challenge["issuedAt"],),
            )
        except BootstrapRegistryError as exc:
            raise AdoptionPublishError(str(exc)) from exc
        receipt_path = self.root / "results" / f"{package['packageId']}-activation.json"
        verification_path = self.root / "results" / f"{package['packageId']}-activation-verification.json"
        state = self.lifecycle()
        existing = self._read_record(receipt_path)
        existing_verification = self._read_record(verification_path)
        if existing is not None and existing_verification is not None and state["status"] == "consumed":
            return existing, existing_verification
        if state["status"] != "published_pending_activation" or _utc(effective_at) >= _utc(challenge["expiresAt"]):
            raise AdoptionPublishError("adoption activation state or challenge expiry is invalid")
        if (
            state["packageDigest"] != package["recordDigest"]
            or state["publishResultDigest"] != publish_result["recordDigest"]
            or prepare_result["packageDigest"] != package["recordDigest"]
            or challenge["packageDigest"] != package["recordDigest"]
            or challenge["packageId"] != package["packageId"]
            or challenge["adoptionTokenHash"] != package["adoptionTokenHash"]
            or challenge["newMain"] != publish_result["newMain"]
            or publish_result["packageDigest"] != package["recordDigest"]
        ):
            raise AdoptionPublishError("adoption activation closure mismatch")
        private_path = self.prepare_store._private_path(prepare_request["privateStatePath"])
        if existing is not None and existing_verification is not None:
            receipt, verification = existing, existing_verification
            self._verify_signed(receipt, verification, "bootstrap_adoption_activation_receipt", operation)
            if (
                receipt["packageDigest"] != package["recordDigest"]
                or receipt["publishResultDigest"] != publish_result["recordDigest"]
                or receipt["challengeDigest"] != challenge["recordDigest"]
                or receipt["adoptionTokenHash"] != package["adoptionTokenHash"]
                or receipt["newMain"] != publish_result["newMain"]
            ):
                raise AdoptionPublishError("stored adoption activation receipt drift")
        else:
            private = self.prepare_store._read_private(private_path)
            if private["recordDigest"] != prepare_result["privateStateDigest"] or private["tokenHash"] != package["adoptionTokenHash"]:
                raise AdoptionPublishError("adoption private state does not bind the package")
            token = strict_urlsafe_b64decode(private["tokenBase64"], expected_size=32)
            expected = adoption_activation_response(token, challenge)
            if not hmac.compare_digest(response, expected):
                raise AdoptionPublishError("adoption activation proof of possession failed")
            response_digest = semantic_digest({"responseSha256": hashlib.sha256(response).hexdigest()})
            subject = {
                "schema": "bootstrap-adoption-activation-receipt/v1",
                "receiptId": f"adoption-activation-{package['packageId']}",
                "rootDigest": package["rootDigest"],
                "packageId": package["packageId"],
                "packageDigest": package["recordDigest"],
                "publishResultDigest": publish_result["recordDigest"],
                "challengeDigest": challenge["recordDigest"],
                "responseDigest": response_digest,
                "adoptionTokenHash": package["adoptionTokenHash"],
                "newMain": publish_result["newMain"],
                "outcome": "consumed",
                "privateStateDisposition": "destroyed",
                "activatedAt": effective_at,
            }
            receipt, verification = issuer("bootstrap_adoption_activation_receipt", subject)
            self._verify_signed(receipt, verification, "bootstrap_adoption_activation_receipt", operation)
            self._write_record(receipt_path, receipt)
            self._write_record(verification_path, verification)
        self._crash(crash_after, "activation_result_written")
        if private_path.exists():
            private = self.prepare_store._read_private(private_path)
            if private["recordDigest"] != prepare_result["privateStateDigest"]:
                raise AdoptionPublishError("adoption private state drift before disposition")
            private_path.unlink()
            _fsync_directory(private_path.parent)
        self._crash(crash_after, "activation_private_disposed")
        consumed = self._advance(
            state,
            effective_at,
            status="consumed",
            activationReceiptDigest=receipt["recordDigest"],
        )
        self._write_state(consumed, expected_digest=state["recordDigest"])
        self._crash(crash_after, "consumed")
        return receipt, verification
