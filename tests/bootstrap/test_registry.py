from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from dasops.bootstrap.registry import (
    authority_profile_digest,
    BootstrapAttemptRegistry,
    BootstrapRegistryCrash,
    BootstrapRegistryError,
    input_manifest_digest,
    output_profile_digest,
)
from dasops.protected.canonical import semantic_digest, with_self_digest

from .test_authority import NOW, digest, signed, verified_chain


EFFECTIVE = "2026-07-16T12:00:00Z"


def attempt_records(
    tool,
    operation_id: str = "register-001",
    attempt_id: str = "attempt-001",
    prior=None,
    base_commit: str = "a" * 40,
):
    prior = [] if prior is None else prior
    intent = with_self_digest(
        {
            "schema": "bootstrap-attempt-intent/v1",
            "intentId": f"intent-{attempt_id}",
            "operationId": operation_id,
            "attemptId": attempt_id,
            "rootDigest": tool.authority.root["recordDigest"],
            "changeId": "example-recovery-program",
            "taskId": "TASK-026",
            "worker": "worker-root",
            "baseCommit": base_commit,
            "registrationKind": "normal_original",
            "tokenState": "not_generated",
            "priorTerminalHeadDigests": prior,
            "issuedAt": "2026-07-16T11:45:00Z",
            "expiresAt": "2026-07-16T12:15:00Z",
        }
    )
    waiver = with_self_digest(
        {
            "schema": "bootstrap-attempt-waiver/v1",
            "waiverId": f"waiver-{attempt_id}",
            "operationId": operation_id,
            "attemptIntentDigest": intent["recordDigest"],
            "rootDigest": tool.authority.root["recordDigest"],
            "registrationKind": intent["registrationKind"],
            "authorityProfileDigest": authority_profile_digest(tool.authority.root),
            "requiredRoles": ["independent_verifier", "orchestrator", "repository_owner"],
            "issuedAt": "2026-07-16T11:45:00Z",
            "expiresAt": "2026-07-16T12:15:00Z",
        }
    )
    return intent, waiver


def verified_operation(verifier, tool, descriptor_template, operation: str, records):
    subject = {
        key: deepcopy(value)
        for key, value in descriptor_template.items()
        if key not in {"recordDigest", "signatureSubjectDigest", "signatures"}
    }
    subject.update(
        {
            "descriptorId": f"descriptor-{records[0]['recordDigest'][-12:]}",
            "operation": operation,
            "inputManifestDigest": input_manifest_digest(operation, records),
            "outputManifestDigest": output_profile_digest(operation),
        }
    )
    descriptor = signed(subject, descriptor_template["signatures"])
    return verifier.verify_operation_descriptor(
        tool_release=tool,
        descriptor=descriptor,
        expected_operation=operation,
        change_id="example-recovery-program",
        task_id="TASK-026",
        now=NOW,
    )


@pytest.fixture
def chain():
    return verified_chain()


@pytest.fixture
def store(tmp_path: Path):
    return BootstrapAttemptRegistry(tmp_path / "authority", registry_id="example-bootstrap-registry")


def register(
    store,
    chain,
    *,
    operation_id="register-001",
    attempt_id="attempt-001",
    prior=None,
    crash_after=None,
    base_commit="a" * 40,
):
    verifier, _authority, tool, descriptor = chain
    intent, waiver = attempt_records(
        tool,
        operation_id,
        attempt_id,
        prior,
        base_commit=base_commit,
    )
    operation = verified_operation(verifier, tool, descriptor, "register_attempt", [intent, waiver])
    result = store.register_attempt(
        intent=intent,
        waiver=waiver,
        operation=operation,
        effective_at=EFFECTIVE,
        crash_after=crash_after,
    )
    return result, intent, waiver, operation


def cancel_authorization(tool, current, *, operation_id="cancel-001", state=None, candidate_at_main=False):
    return with_self_digest(
        {
            "schema": "bootstrap-attempt-cancel-authorization/v1",
            "operationId": operation_id,
            "attemptId": current["attemptId"],
            "headDigest": current["headDigest"],
            "expectedState": state or current["state"],
            "candidateAtMain": candidate_at_main,
            "tokenDisposition": "not_generated",
            "publicationWalDisposition": "absent",
            "residualsDisposition": "complete",
            "rootDigest": tool.authority.root["recordDigest"],
            "authorizedAt": EFFECTIVE,
        }
    )


def recovery_records(tool, current, *, operation_id, classification, reason="unavailable"):
    recovery_id = f"recovery-{operation_id}"
    authorization = with_self_digest(
        {
            "schema": "bootstrap-receipt-recovery-authorization/v1",
            "operationId": operation_id,
            "recoveryId": recovery_id,
            "attemptId": current["attemptId"],
            "headDigest": current["headDigest"],
            "rootDigest": tool.authority.root["recordDigest"],
            "reason": reason,
            "compromiseEffectiveAt": "2026-07-16T11:59:00Z" if reason == "old_receipt_authority_compromised" else None,
            "proofDigest": digest("1"),
            "authorizedAt": EFFECTIVE,
        }
    )
    accepted_count = 1 if classification == "accepted_original" else (0 if classification == "zero_accepted" else 2)
    search = with_self_digest(
        {
            "schema": "bootstrap-receipt-recovery-search/v1",
            "recoveryId": recovery_id,
            "fencesCommitted": True,
            "cutoffsComplete": True,
            "candidateInventoryComplete": True,
            "quarantineComplete": True,
            "cutoffsDigest": digest("2"),
            "candidateInventoryDigest": digest("3"),
            "quarantineManifestDigest": digest("4"),
            "classification": classification,
            "acceptedCandidateCount": accepted_count,
            "acceptedReceiptDigest": digest("5") if classification == "accepted_original" else None,
            "recoveredReceiptDigest": digest("6") if classification == "zero_accepted" else None,
            "acceptedTrustedSigningTime": "2026-07-16T11:58:00Z" if classification == "accepted_original" and reason == "old_receipt_authority_compromised" else None,
            "completedAt": EFFECTIVE,
        }
    )
    return authorization, search


def test_registration_checkpoint_closure_modes_and_idempotent_readback(store, chain) -> None:
    result, intent, waiver, operation = register(store, chain)
    assert result["outcome"] == "registered"
    current = store.current()
    assert current is not None
    assert current["sequence"] == "00000000000000000001"
    assert current["state"] == "registered"
    slot = store.receipt_slot(current["headDigest"])
    assert (slot["generation"], slot["status"], slot["closureVariant"]) == (0, "open", None)
    assert store.object(current["entryDigest"])["intentDigest"] == intent["recordDigest"]
    assert store.object(current["entryDigest"])["waiverDigest"] == waiver["recordDigest"]
    retry = store.register_attempt(intent=intent, waiver=waiver, operation=operation, effective_at="2026-07-16T12:01:00Z")
    assert retry == result
    assert store.current() == current
    assert stat_mode(store.root) == 0o700
    assert all(stat_mode(path) == 0o600 for path in store.root.rglob("*.json"))
    serialized = b"".join(path.read_bytes() for path in store.root.rglob("*.json"))
    assert b"plaintext-legacy-token" not in serialized


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


@pytest.mark.parametrize("phase", ["prepared", "objects_written", "pointer_published", "completed"])
def test_registration_recovers_every_lost_response_boundary(tmp_path: Path, chain, phase: str) -> None:
    store = BootstrapAttemptRegistry(tmp_path / phase, registry_id="example-bootstrap-registry")
    with pytest.raises(BootstrapRegistryCrash, match=phase):
        register(store, chain, crash_after=phase)
    result, _intent, _waiver, _operation = register(store, chain)
    assert result["outcome"] == "registered"
    assert store.current()["recordDigest"] == result["currentDigest"]
    for expected in ("prepared", "objects_written", "pointer_published", "completed"):
        assert (store.root / "operations" / "register-001" / f"{expected}.json").is_file()


def test_live_attempt_and_competing_checkpoint_cas_fail_closed(tmp_path: Path, chain) -> None:
    store = BootstrapAttemptRegistry(tmp_path / "authority", registry_id="example-bootstrap-registry")
    result, _intent, _waiver, _operation = register(store, chain)
    with pytest.raises(BootstrapRegistryError, match="still live"):
        register(store, chain, operation_id="register-002", attempt_id="attempt-002")

    raced = BootstrapAttemptRegistry(tmp_path / "race", registry_id="example-bootstrap-registry")
    with pytest.raises(BootstrapRegistryCrash, match="objects_written"):
        register(raced, chain, operation_id="register-a", attempt_id="attempt-a", crash_after="objects_written")
    register(raced, chain, operation_id="register-b", attempt_id="attempt-b")
    with pytest.raises(BootstrapRegistryError, match="CAS failed"):
        register(raced, chain, operation_id="register-a", attempt_id="attempt-a")
    assert result["recordDigest"].startswith("sha256:")


def test_pre_cas_cancellation_is_terminal_idempotent_and_imported(store, chain) -> None:
    register(store, chain)
    verifier, _authority, tool, descriptor = chain
    current = store.current()
    authorization = cancel_authorization(tool, current)
    operation = verified_operation(verifier, tool, descriptor, "cancel_attempt", [authorization])
    result = store.cancel_attempt(authorization=authorization, operation=operation, effective_at=EFFECTIVE)
    terminal = store.current()
    assert result["outcome"] == "cancelled_pre_cas"
    assert terminal["state"] == "cancelled_pre_cas"
    assert store.cancel_attempt(authorization=authorization, operation=operation, effective_at="2026-07-16T12:02:00Z") == result

    second, _intent, _waiver, _operation = register(
        store,
        chain,
        operation_id="register-002",
        attempt_id="attempt-002",
        prior=[terminal["headDigest"]],
    )
    assert second["outcome"] == "registered"
    assert store.current()["sequence"] == "00000000000000000003"
    assert store.current()["terminalHeadDigests"] == [terminal["headDigest"]]
    assert store.cancel_attempt(authorization=authorization, operation=operation, effective_at=EFFECTIVE) == result


@pytest.mark.parametrize("phase", ["prepared", "objects_written", "pointer_published", "completed"])
def test_cancellation_recovers_every_lost_response_boundary(tmp_path: Path, chain, phase: str) -> None:
    store = BootstrapAttemptRegistry(tmp_path / phase, registry_id="example-bootstrap-registry")
    register(store, chain)
    verifier, _authority, tool, descriptor = chain
    authorization = cancel_authorization(tool, store.current())
    operation = verified_operation(verifier, tool, descriptor, "cancel_attempt", [authorization])
    with pytest.raises(BootstrapRegistryCrash, match=phase):
        store.cancel_attempt(
            authorization=authorization,
            operation=operation,
            effective_at=EFFECTIVE,
            crash_after=phase,
        )
    result = store.cancel_attempt(authorization=authorization, operation=operation, effective_at=EFFECTIVE)
    assert result["outcome"] == "cancelled_pre_cas"
    assert store.current()["state"] == "cancelled_pre_cas"


def test_cancellation_rejects_candidate_at_main_stale_state_and_bad_disposition(store, chain) -> None:
    register(store, chain)
    verifier, _authority, tool, descriptor = chain
    current = store.current()

    invalid = cancel_authorization(tool, current, candidate_at_main=True)
    operation = verified_operation(verifier, tool, descriptor, "cancel_attempt", [invalid])
    with pytest.raises(BootstrapRegistryError, match="False was expected"):
        store.cancel_attempt(authorization=invalid, operation=operation, effective_at=EFFECTIVE)

    stale = cancel_authorization(tool, current, state="candidate_prepared", operation_id="cancel-stale")
    operation = verified_operation(verifier, tool, descriptor, "cancel_attempt", [stale])
    with pytest.raises(BootstrapRegistryError, match="state mismatch"):
        store.cancel_attempt(authorization=stale, operation=operation, effective_at=EFFECTIVE)

    wrong = deepcopy(cancel_authorization(tool, current, operation_id="cancel-wrong"))
    wrong.pop("recordDigest")
    wrong["publicationWalDisposition"] = "disposed"
    wrong = with_self_digest(wrong)
    operation = verified_operation(verifier, tool, descriptor, "cancel_attempt", [wrong])
    with pytest.raises(BootstrapRegistryError, match="WAL disposition"):
        store.cancel_attempt(authorization=wrong, operation=operation, effective_at=EFFECTIVE)


@pytest.mark.parametrize(
    ("classification", "outcome", "variant"),
    [
        ("accepted_original", "promoted_original", "promoted_original"),
        ("zero_accepted", "recovered_alternate", "recovered_alternate"),
        ("ambiguous_blocked", "ambiguous_blocked", None),
    ],
)
def test_receipt_recovery_has_three_exact_classifications(tmp_path: Path, chain, classification, outcome, variant) -> None:
    store = BootstrapAttemptRegistry(tmp_path / classification, registry_id="example-bootstrap-registry")
    register(store, chain)
    verifier, _authority, tool, descriptor = chain
    current_before = store.current()
    authorization, search = recovery_records(
        tool,
        current_before,
        operation_id=f"recover-{classification}",
        classification=classification,
    )
    operation = verified_operation(verifier, tool, descriptor, "recover_receipt", [authorization, search])
    result = store.recover_receipt(
        authorization=authorization,
        search=search,
        operation=operation,
        effective_at=EFFECTIVE,
    )
    assert result["outcome"] == outcome
    assert store.current() == current_before
    slot = store.receipt_slot(current_before["headDigest"])
    if variant is None:
        assert (slot["status"], slot["generation"]) == ("open", 0)
        assert result["slotDigest"] is None
    else:
        assert (slot["status"], slot["generation"], slot["closureVariant"]) == ("closed", 1, variant)
        assert result["slotDigest"] == slot["recordDigest"]


def test_receipt_recovery_requires_pre_compromise_time_and_exact_cardinality(store, chain) -> None:
    register(store, chain)
    verifier, _authority, tool, descriptor = chain
    current = store.current()
    authorization, search = recovery_records(
        tool,
        current,
        operation_id="recover-compromised",
        classification="accepted_original",
        reason="old_receipt_authority_compromised",
    )
    drifted = deepcopy(search)
    drifted.pop("recordDigest")
    drifted["acceptedTrustedSigningTime"] = authorization["compromiseEffectiveAt"]
    drifted = with_self_digest(drifted)
    operation = verified_operation(verifier, tool, descriptor, "recover_receipt", [authorization, drifted])
    with pytest.raises(BootstrapRegistryError, match="before compromise"):
        store.recover_receipt(
            authorization=authorization,
            search=drifted,
            operation=operation,
            effective_at=EFFECTIVE,
        )

    bad_count = deepcopy(search)
    bad_count.pop("recordDigest")
    bad_count["acceptedCandidateCount"] = 2
    bad_count = with_self_digest(bad_count)
    operation = verified_operation(verifier, tool, descriptor, "recover_receipt", [authorization, bad_count])
    with pytest.raises(BootstrapRegistryError, match="unique"):
        store.recover_receipt(
            authorization=authorization,
            search=bad_count,
            operation=operation,
            effective_at=EFFECTIVE,
        )


@pytest.mark.parametrize("phase", ["prepared", "objects_written", "pointer_published", "completed"])
def test_receipt_recovery_recovers_every_lost_response_boundary(tmp_path: Path, chain, phase: str) -> None:
    store = BootstrapAttemptRegistry(tmp_path / phase, registry_id="example-bootstrap-registry")
    register(store, chain)
    verifier, _authority, tool, descriptor = chain
    current = store.current()
    authorization, search = recovery_records(
        tool,
        current,
        operation_id="recover-crash",
        classification="zero_accepted",
    )
    operation = verified_operation(verifier, tool, descriptor, "recover_receipt", [authorization, search])
    with pytest.raises(BootstrapRegistryCrash, match=phase):
        store.recover_receipt(
            authorization=authorization,
            search=search,
            operation=operation,
            effective_at=EFFECTIVE,
            crash_after=phase,
        )
    result = store.recover_receipt(
        authorization=authorization,
        search=search,
        operation=operation,
        effective_at=EFFECTIVE,
    )
    assert result["outcome"] == "recovered_alternate"
    assert store.receipt_slot(current["headDigest"])["status"] == "closed"


def test_unknown_fields_manifest_drift_and_operation_id_replay_fail_closed(store, chain) -> None:
    verifier, _authority, tool, descriptor = chain
    intent, waiver = attempt_records(tool)
    unknown = deepcopy(intent)
    unknown.pop("recordDigest")
    unknown["rawToken"] = "plaintext-legacy-token"
    unknown = with_self_digest(unknown)
    operation = verified_operation(verifier, tool, descriptor, "register_attempt", [unknown, waiver])
    with pytest.raises(BootstrapRegistryError, match="Additional properties"):
        store.register_attempt(intent=unknown, waiver=waiver, operation=operation, effective_at=EFFECTIVE)

    operation = verified_operation(verifier, tool, descriptor, "register_attempt", [intent, waiver])
    drifted = deepcopy(operation.descriptor)
    drifted["inputManifestDigest"] = semantic_digest({"wrong": True})
    from dasops.bootstrap.authority import VerifiedOperation

    forged = VerifiedOperation(operation.tool_release, drifted, operation.descriptor_verification)
    with pytest.raises(BootstrapRegistryError, match="self-digest"):
        store.register_attempt(intent=intent, waiver=waiver, operation=forged, effective_at=EFFECTIVE)

    register(store, chain)
    other_intent, other_waiver = attempt_records(tool, operation_id="register-001", attempt_id="attempt-other")
    other_operation = verified_operation(verifier, tool, descriptor, "register_attempt", [other_intent, other_waiver])
    with pytest.raises(BootstrapRegistryError, match="different registration inputs"):
        store.register_attempt(
            intent=other_intent,
            waiver=other_waiver,
            operation=other_operation,
            effective_at=EFFECTIVE,
        )
