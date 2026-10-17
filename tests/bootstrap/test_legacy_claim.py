from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from dasops.bootstrap.legacy_claim import (
    LegacyClaimCoordinator,
    LegacyClaimCrash,
    LegacyClaimError,
    handoff_response,
)
from dasops.bootstrap.registry import BootstrapAttemptRegistry
from dasops.protected.canonical import canonical_bytes, semantic_digest, with_self_digest
from dasops.protected.state_store import atomic_write

from .test_authority import digest, signature, signed, verified_chain
from .test_registry import EFFECTIVE, register, verified_operation


class FakeAdapter:
    def __init__(
        self,
        worker_lock: Path,
        *,
        candidate_commit: str = "b" * 40,
        candidate_tree: str = "c" * 40,
    ) -> None:
        self.worker_lock = worker_lock
        self.calls = 0
        self.recovery_calls = 0
        self.token = b"L" * 32
        self.candidate_commit = candidate_commit
        self.candidate_tree = candidate_tree

    def prepare(self, request, *, recovery: bool):
        self.calls += 1
        self.recovery_calls += int(recovery)
        token_hash = "sha256:" + hashlib.sha256(self.token).hexdigest()
        lock = {
            "schema": "legacy-worker-lock/v1",
            "attemptId": request["attemptId"],
            "worker": request["worker"],
            "tokenBase64": base64.urlsafe_b64encode(self.token).decode().rstrip("="),
            "tokenHash": token_hash,
            "status": "candidate_prepared",
        }
        encoded = canonical_bytes(lock)
        if self.worker_lock.exists():
            assert recovery and self.worker_lock.read_bytes() == encoded
        else:
            atomic_write(self.worker_lock, encoded, mode=0o600, create_only=True)
        return {
            "candidateCommit": self.candidate_commit,
            "candidateTree": self.candidate_tree,
            "activeLockSubjectDigest": semantic_digest({"attemptId": request["attemptId"], "worker": request["worker"]}),
            "archiveDigest": digest("d"),
            "candidateInventoryDigest": digest("e"),
            "bridgeReceiptDigest": digest("f"),
        }


class FakePublisher:
    def __init__(self, head: str) -> None:
        self.value = head
        self.cas_count = 0

    def head(self) -> str:
        return self.value

    def cas(self, *, old_commit: str, new_commit: str) -> None:
        if self.value != old_commit:
            raise RuntimeError("fake CAS mismatch")
        self.value = new_commit
        self.cas_count += 1


class FakeIssuer:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, purpose: str, subject: dict):
        self.calls.append(purpose)
        signatures = [
            signature(digest("7"), "independent-reviewer", "independent_verifier"),
            signature(digest("9"), "orchestrator", "orchestrator"),
            signature(digest("5"), "repository-owner", "repository_owner"),
        ]
        receipt = signed(subject, signatures)
        verification = with_self_digest(
            {
                "schema": "external-role-verification/v1",
                "purpose": purpose,
                "subjectDigest": receipt["signatureSubjectDigest"],
                "requiredRoles": ["independent_verifier", "orchestrator", "repository_owner"],
                "threshold": 3,
                "verifiedSigners": [
                    {"role": item["role"], "identity": item["identity"], "keyFingerprint": item["keyFingerprint"]}
                    for item in signatures
                ],
                "verifierAuthorityRef": "https://authority.example/bootstrap-receipts/epoch-1",
                "verifierReceiptDigest": digest("a"),
                "verifiedAt": EFFECTIVE,
            }
        )
        return receipt, verification


def candidate_receipt(tool, result, issuer: FakeIssuer):
    subject = {
        "schema": "bootstrap-claim-candidate-receipt/v1",
        "receiptId": "candidate-receipt-001",
        "rootDigest": tool.authority.root["recordDigest"],
        "attemptId": result["attemptId"],
        "candidateResultDigest": result["recordDigest"],
        "tokenHash": result["tokenHash"],
        "activeLockSubjectDigest": result["activeLockSubjectDigest"],
        "intendedWorker": "worker-root",
        "validFrom": "2026-07-16T11:50:00Z",
        "validUntil": "2026-07-16T12:10:00Z",
    }
    return issuer("bootstrap_claim_candidate_receipt", subject)


def setup_registered(
    tmp_path: Path,
    chain,
    *,
    candidate_commit: str = "b" * 40,
    candidate_tree: str = "c" * 40,
    base_commit: str = "a" * 40,
):
    registry = BootstrapAttemptRegistry(tmp_path / "authority", registry_id="example-bootstrap-registry")
    register(registry, chain, base_commit=base_commit)
    coordinator = LegacyClaimCoordinator(registry)
    worker_lock = tmp_path / "private-worker" / "legacy.lock"
    adapter = FakeAdapter(
        worker_lock,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
    )
    return registry, coordinator, worker_lock, adapter


def prepare_request(tool, registry, worker_lock: Path, operation_id="prepare-001"):
    current = registry.current()
    entry = registry.object(current["entryDigest"])
    return with_self_digest(
        {
            "schema": "bootstrap-candidate-preparation-request/v1",
            "operationId": operation_id,
            "attemptId": current["attemptId"],
            "headDigest": current["headDigest"],
            "rootDigest": tool.authority.root["recordDigest"],
            "changeId": entry["changeId"],
            "taskId": entry["taskId"],
            "worker": entry["worker"],
            "baseCommit": entry["baseCommit"],
            "workerLockPath": str(worker_lock),
            "temporaryPathManifestDigest": digest("1"),
            "idempotencyKeyDigest": digest("2"),
            "legacyTokenProfileDigest": tool.authority.root["legacyTokenProfileDigest"],
            "requestedAt": EFFECTIVE,
        }
    )


def prepare(
    tmp_path: Path,
    chain,
    *,
    crash_after=None,
    candidate_commit: str = "b" * 40,
    candidate_tree: str = "c" * 40,
    base_commit: str = "a" * 40,
):
    registry, coordinator, worker_lock, adapter = setup_registered(
        tmp_path,
        chain,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        base_commit=base_commit,
    )
    verifier, _authority, tool, descriptor = chain
    request = prepare_request(tool, registry, worker_lock)
    operation = verified_operation(verifier, tool, descriptor, "prepare_candidate", [request])
    result = coordinator.prepare_candidate(
        request=request,
        operation=operation,
        adapter=adapter,
        effective_at=EFFECTIVE,
        crash_after=crash_after,
    )
    return registry, coordinator, worker_lock, adapter, result, request, operation


def publish_request(registry, result, candidate, candidate_verification, operation_id="publish-001"):
    current = registry.current()
    return with_self_digest(
        {
            "schema": "bootstrap-claim-publication-request/v1",
            "operationId": operation_id,
            "attemptId": result["attemptId"],
            "candidatePreparedHeadDigest": current["headDigest"],
            "candidateResultDigest": result["recordDigest"],
            "candidateReceiptDigest": candidate["recordDigest"],
            "candidateReceiptVerificationDigest": candidate_verification["recordDigest"],
            "baseCommit": result["baseCommit"],
            "candidateCommit": result["candidateCommit"],
            "tokenHash": result["tokenHash"],
            "requestedAt": EFFECTIVE,
        }
    )


def publish(
    tmp_path: Path,
    chain,
    *,
    crash_after=None,
    candidate_commit: str = "b" * 40,
    candidate_tree: str = "c" * 40,
    base_commit: str = "a" * 40,
    claim_publisher=None,
):
    registry, coordinator, worker_lock, adapter, result, _prepare_request, _prepare_operation = prepare(
        tmp_path,
        chain,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        base_commit=base_commit,
    )
    verifier, _authority, tool, descriptor = chain
    issuer = FakeIssuer()
    candidate, candidate_verification = candidate_receipt(tool, result, issuer)
    request = publish_request(registry, result, candidate, candidate_verification)
    operation = verified_operation(
        verifier,
        tool,
        descriptor,
        "publish_claim",
        [request, result, candidate, candidate_verification],
    )
    publisher = claim_publisher or FakePublisher(result["baseCommit"])
    receipt, verification = coordinator.publish_claim(
        request=request,
        candidate_result=result,
        candidate_receipt=candidate,
        candidate_receipt_verification=candidate_verification,
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
        crash_after=crash_after,
    )
    return (
        registry, coordinator, worker_lock, adapter, result, publisher, issuer,
        receipt, verification, request, operation,
    )


def handoff_inputs(registry, result, publication_receipt, worker_lock: Path, response: bytes | None = None):
    destination = worker_lock.parent / "active.lock"
    challenge = with_self_digest(
        {
            "schema": "bootstrap-handoff-challenge/v1",
            "challengeId": "handoff-challenge-001",
            "attemptId": result["attemptId"],
            "tokenHash": result["tokenHash"],
            "worker": "worker-root",
            "destinationLockPath": str(destination),
            "nonceBase64": base64.urlsafe_b64encode(b"N" * 32).decode().rstrip("="),
            "issuedAt": "2026-07-16T11:59:00Z",
            "expiresAt": "2026-07-16T12:05:00Z",
        }
    )
    token = base64.urlsafe_b64decode(json.loads(worker_lock.read_text())["tokenBase64"] + "==")
    actual_response = handoff_response(token, challenge) if response is None else response
    current = registry.current()
    request = with_self_digest(
        {
            "schema": "bootstrap-claim-lock-handoff-request/v1",
            "operationId": "handoff-001",
            "attemptId": result["attemptId"],
            "claimedHeadDigest": current["headDigest"],
            "publicationReceiptDigest": publication_receipt["recordDigest"],
            "challengeDigest": challenge["recordDigest"],
            "responseDigest": semantic_digest({"responseSha256": hashlib.sha256(actual_response).hexdigest()}),
            "tokenHash": result["tokenHash"],
            "worker": "worker-root",
            "destinationLockPath": str(destination),
            "expectedCandidateCommit": result["candidateCommit"],
            "requestedAt": EFFECTIVE,
        }
    )
    return request, challenge, actual_response, destination


def test_wal_precedes_adapter_and_candidate_preparation_is_idempotent(tmp_path: Path) -> None:
    chain = verified_chain()
    registry, coordinator, worker_lock, adapter, result, request, operation = prepare(tmp_path, chain)
    assert result["outcome"] == "prepared"
    assert registry.current()["state"] == "candidate_prepared"
    assert worker_lock.exists() and (worker_lock.stat().st_mode & 0o777) == 0o600
    assert (coordinator.root / "operations" / "prepare-001" / "candidate_preparation_pending.json").is_file()
    assert coordinator.prepare_candidate(request=request, operation=operation, adapter=adapter, effective_at=EFFECTIVE) == result
    assert adapter.calls == 1
    shared = b"".join(path.read_bytes() for path in coordinator.root.rglob("*.json"))
    assert base64.urlsafe_b64encode(adapter.token).rstrip(b"=") not in shared


@pytest.mark.parametrize(
    "phase",
    ["candidate_preparation_pending", "legacy_invocation_started", "legacy_invocation_completed", "registry_transition_completed"],
)
def test_candidate_preparation_recovers_each_phase(tmp_path: Path, phase: str) -> None:
    chain = verified_chain()
    registry, coordinator, worker_lock, adapter = setup_registered(tmp_path, chain)
    verifier, _authority, tool, descriptor = chain
    request = prepare_request(tool, registry, worker_lock)
    operation = verified_operation(verifier, tool, descriptor, "prepare_candidate", [request])
    with pytest.raises(LegacyClaimCrash, match=phase):
        coordinator.prepare_candidate(
            request=request,
            operation=operation,
            adapter=adapter,
            effective_at=EFFECTIVE,
            crash_after=phase,
        )
    result = coordinator.prepare_candidate(request=request, operation=operation, adapter=adapter, effective_at=EFFECTIVE)
    assert result["outcome"] == "prepared"
    assert adapter.calls == 1


def test_publication_exact_cas_receipt_and_claimed_slot(tmp_path: Path) -> None:
    chain = verified_chain()
    values = publish(tmp_path, chain)
    registry, coordinator, _worker_lock, _adapter, result, publisher, issuer, receipt, verification, request, operation = values
    assert publisher.head() == result["candidateCommit"] and publisher.cas_count == 1
    assert registry.current()["state"] == "claimed"
    assert registry.receipt_slot(registry.current()["headDigest"])["closureVariant"] == "normal_original"
    retry = coordinator.publish_claim(
        request=request,
        candidate_result=result,
        candidate_receipt=registry.object(request["candidateReceiptDigest"]),
        candidate_receipt_verification=registry.object(request["candidateReceiptVerificationDigest"]),
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    assert retry == (receipt, verification) and publisher.cas_count == 1


@pytest.mark.parametrize(
    "phase",
    [
        "publication_intent", "pending_checkpoint", "cas_started", "cas_applied",
        "receipt_written", "claimed_checkpoint", "slot_closed",
    ],
)
def test_publication_recovers_every_response_loss_boundary_without_republishing(tmp_path: Path, phase: str) -> None:
    chain = verified_chain()
    registry, coordinator, _worker_lock, _adapter, result, _request0, _operation0 = prepare(tmp_path, chain)
    verifier, _authority, tool, descriptor = chain
    issuer = FakeIssuer()
    candidate, candidate_verification = candidate_receipt(tool, result, issuer)
    request = publish_request(registry, result, candidate, candidate_verification)
    operation = verified_operation(verifier, tool, descriptor, "publish_claim", [request, result, candidate, candidate_verification])
    publisher = FakePublisher(result["baseCommit"])
    with pytest.raises(LegacyClaimCrash, match=phase):
        coordinator.publish_claim(
            request=request,
            candidate_result=result,
            candidate_receipt=candidate,
            candidate_receipt_verification=candidate_verification,
            operation=operation,
            publisher=publisher,
            issuer=issuer,
            effective_at=EFFECTIVE,
            crash_after=phase,
        )
    coordinator.publish_claim(
        request=request,
        candidate_result=result,
        candidate_receipt=candidate,
        candidate_receipt_verification=candidate_verification,
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    assert publisher.cas_count == 1 and registry.current()["state"] == "claimed"


def test_acknowledged_handoff_requires_pop_and_moves_only_private_lock(tmp_path: Path) -> None:
    chain = verified_chain()
    values = publish(tmp_path, chain)
    registry, coordinator, worker_lock, _adapter, result, publisher, issuer, publication, pub_verification, _request, _op = values
    verifier, _authority, tool, descriptor = chain
    request, challenge, response, destination = handoff_inputs(registry, result, publication, worker_lock)
    operation = verified_operation(
        verifier, tool, descriptor, "handoff_claim",
        [request, result, publication, pub_verification, challenge],
    )
    receipt, verification = coordinator.handoff_claim(
        request=request,
        candidate_result=result,
        publication_receipt=publication,
        publication_verification=pub_verification,
        challenge=challenge,
        response=response,
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    assert receipt["outcome"] == "acknowledged" and receipt["workAuthority"] == "legacy_bootstrap_only"
    assert destination.exists() and not worker_lock.exists()
    assert coordinator.handoff_claim(
        request=request,
        candidate_result=result,
        publication_receipt=publication,
        publication_verification=pub_verification,
        challenge=challenge,
        response=response,
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    ) == (receipt, verification)


@pytest.mark.parametrize("phase", ["destination_copied", "handoff_receipt_written"])
def test_handoff_recovers_copy_and_receipt_response_boundaries(tmp_path: Path, phase: str) -> None:
    chain = verified_chain()
    values = publish(tmp_path, chain)
    registry, coordinator, worker_lock, _adapter, result, publisher, issuer, publication, pub_verification, _request, _op = values
    verifier, _authority, tool, descriptor = chain
    request, challenge, response, destination = handoff_inputs(registry, result, publication, worker_lock)
    operation = verified_operation(
        verifier, tool, descriptor, "handoff_claim",
        [request, result, publication, pub_verification, challenge],
    )
    with pytest.raises(LegacyClaimCrash, match=phase):
        coordinator.handoff_claim(
            request=request,
            candidate_result=result,
            publication_receipt=publication,
            publication_verification=pub_verification,
            challenge=challenge,
            response=response,
            operation=operation,
            publisher=publisher,
            issuer=issuer,
            effective_at=EFFECTIVE,
            crash_after=phase,
        )
    receipt, _verification = coordinator.handoff_claim(
        request=request,
        candidate_result=result,
        publication_receipt=publication,
        publication_verification=pub_verification,
        challenge=challenge,
        response=response,
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    assert receipt["outcome"] == "acknowledged"
    assert destination.exists() and not worker_lock.exists()


@pytest.mark.parametrize("closure", ["compensate_claim", "abandon_claim"])
def test_failed_handoff_compensates_and_acknowledged_handoff_abandons(tmp_path: Path, closure: str) -> None:
    chain = verified_chain()
    values = publish(tmp_path, chain)
    registry, coordinator, worker_lock, _adapter, result, publisher, issuer, publication, pub_verification, _request, _op = values
    verifier, _authority, tool, descriptor = chain
    requested_response = b"X" * 32 if closure == "compensate_claim" else None
    request, challenge, response, destination = handoff_inputs(registry, result, publication, worker_lock, requested_response)
    handoff_operation = verified_operation(
        verifier, tool, descriptor, "handoff_claim",
        [request, result, publication, pub_verification, challenge],
    )
    handoff, handoff_verification = coordinator.handoff_claim(
        request=request,
        candidate_result=result,
        publication_receipt=publication,
        publication_verification=pub_verification,
        challenge=challenge,
        response=response,
        operation=handoff_operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    expected_handoff = "failed" if closure == "compensate_claim" else "acknowledged"
    assert handoff["outcome"] == expected_handoff
    current = registry.current()
    authorization = with_self_digest(
        {
            "schema": "bootstrap-claim-early-closure-authorization/v1",
            "operationId": "early-001",
            "operation": closure,
            "attemptId": result["attemptId"],
            "claimedHeadDigest": current["headDigest"],
            "baseCommit": result["baseCommit"],
            "candidateCommit": result["candidateCommit"],
            "publicationReceiptDigest": publication["recordDigest"],
            "handoffReceiptDigest": handoff["recordDigest"],
            "priorFenceCommitted": True,
            "workDisposition": "complete",
            "tokenDisposition": "destroyed",
            "taskOnlyReversion": True,
            "authorizedAt": EFFECTIVE,
        }
    )
    records = [authorization, result, publication, pub_verification, handoff, handoff_verification]
    operation = verified_operation(verifier, tool, descriptor, closure, records)
    receipt, _verification = coordinator.close_early_claim(
        authorization=authorization,
        candidate_result=result,
        publication_receipt=publication,
        publication_verification=pub_verification,
        handoff_receipt=handoff,
        handoff_verification=handoff_verification,
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    expected_state = "compensated" if closure == "compensate_claim" else "abandoned"
    assert receipt["outcome"] == expected_state
    assert publisher.head() == result["baseCommit"]
    assert registry.current()["state"] == expected_state
    assert not worker_lock.exists() and not destination.exists()


@pytest.mark.parametrize(
    "phase",
    ["closure_intent", "cas_started", "cas_reverted", "token_disposed", "registry_terminal", "slot_closed"],
)
def test_compensation_recovers_every_response_loss_boundary(tmp_path: Path, phase: str) -> None:
    chain = verified_chain()
    values = publish(tmp_path, chain)
    registry, coordinator, worker_lock, _adapter, result, publisher, issuer, publication, pub_verification, _request, _op = values
    verifier, _authority, tool, descriptor = chain
    request, challenge, response, destination = handoff_inputs(registry, result, publication, worker_lock, b"X" * 32)
    handoff_operation = verified_operation(
        verifier, tool, descriptor, "handoff_claim",
        [request, result, publication, pub_verification, challenge],
    )
    handoff, handoff_verification = coordinator.handoff_claim(
        request=request,
        candidate_result=result,
        publication_receipt=publication,
        publication_verification=pub_verification,
        challenge=challenge,
        response=response,
        operation=handoff_operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    current = registry.current()
    authorization = with_self_digest(
        {
            "schema": "bootstrap-claim-early-closure-authorization/v1",
            "operationId": "early-crash",
            "operation": "compensate_claim",
            "attemptId": result["attemptId"],
            "claimedHeadDigest": current["headDigest"],
            "baseCommit": result["baseCommit"],
            "candidateCommit": result["candidateCommit"],
            "publicationReceiptDigest": publication["recordDigest"],
            "handoffReceiptDigest": handoff["recordDigest"],
            "priorFenceCommitted": True,
            "workDisposition": "complete",
            "tokenDisposition": "destroyed",
            "taskOnlyReversion": True,
            "authorizedAt": EFFECTIVE,
        }
    )
    records = [authorization, result, publication, pub_verification, handoff, handoff_verification]
    operation = verified_operation(verifier, tool, descriptor, "compensate_claim", records)
    with pytest.raises(LegacyClaimCrash, match=phase):
        coordinator.close_early_claim(
            authorization=authorization,
            candidate_result=result,
            publication_receipt=publication,
            publication_verification=pub_verification,
            handoff_receipt=handoff,
            handoff_verification=handoff_verification,
            operation=operation,
            publisher=publisher,
            issuer=issuer,
            effective_at=EFFECTIVE,
            crash_after=phase,
        )
    receipt, _verification = coordinator.close_early_claim(
        authorization=authorization,
        candidate_result=result,
        publication_receipt=publication,
        publication_verification=pub_verification,
        handoff_receipt=handoff,
        handoff_verification=handoff_verification,
        operation=operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    assert receipt["outcome"] == "compensated"
    assert registry.current()["state"] == "compensated"
    assert publisher.cas_count == 2
    assert not worker_lock.exists() and not destination.exists()


def test_manifest_drift_local_verification_and_adapter_secret_fields_fail_closed(tmp_path: Path) -> None:
    chain = verified_chain()
    registry, coordinator, worker_lock, adapter = setup_registered(tmp_path, chain)
    verifier, _authority, tool, descriptor = chain
    request = prepare_request(tool, registry, worker_lock)
    operation = verified_operation(verifier, tool, descriptor, "prepare_candidate", [request])
    forged = deepcopy(operation.descriptor)
    forged["outputManifestDigest"] = digest("0")
    from dasops.bootstrap.authority import VerifiedOperation

    with pytest.raises(LegacyClaimError, match="self-digest"):
        coordinator.prepare_candidate(
            request=request,
            operation=VerifiedOperation(operation.tool_release, forged, operation.descriptor_verification),
            adapter=adapter,
            effective_at=EFFECTIVE,
        )

    class LeakyAdapter(FakeAdapter):
        def prepare(self, request, *, recovery):
            result = super().prepare(request, recovery=recovery)
            result["rawToken"] = "forbidden"
            return result

    leaky = LeakyAdapter(worker_lock)
    with pytest.raises(LegacyClaimError, match="secret-like"):
        coordinator.prepare_candidate(request=request, operation=operation, adapter=leaky, effective_at=EFFECTIVE)
