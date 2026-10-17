from __future__ import annotations

from pathlib import Path

import pytest

from dasops.bootstrap.foundation_verification import (
    AdoptionFoundationVerificationStore,
    FoundationVerificationCrash,
    FoundationVerificationError,
)
from dasops.protected.canonical import with_self_digest

from .test_adoption_publish import REQUESTED, publish_setup, run_publish
from .test_authority import digest
from .test_legacy_claim import FakeIssuer


VERIFIED = "2026-07-16T12:01:30Z"
AUTHORIZED = "2026-07-16T12:01:45Z"
PUBLISHED = "2026-07-16T12:02:00Z"


def verification_result(values, descriptor, m0_head, m0_manifest, *, outcome="accepted"):
    return FakeIssuer()(
        "bootstrap_candidate_verification_result",
        {
            "schema": "bootstrap-candidate-verification-result/v1",
            "resultId": f"verification-{values['package']['packageId']}-{outcome}",
            "descriptorDigest": descriptor["recordDigest"],
            "preparedHeadDigest": m0_head["recordDigest"],
            "m0ManifestDigest": m0_manifest["recordDigest"],
            "packageDigest": values["package"]["recordDigest"],
            "candidateCommit": values["package"]["candidateCommit"],
            "candidateTree": values["package"]["candidateTree"],
            "candidateParent": values["package"]["candidateParent"],
            "outcome": outcome,
            "findingsDigest": digest("0" if outcome == "accepted" else "f"),
            "completedAt": VERIFIED,
        },
    )


def prepared_store(tmp_path: Path):
    values = publish_setup(tmp_path)
    store = AdoptionFoundationVerificationStore(
        (tmp_path / "foundation-verification").resolve(),
        slot_id="example-adoption-001",
    )
    descriptor, m0_head, m0_manifest = store.prepare(
        package=values["package"],
        approval_subject=values["approval_subject"],
        prepare_result=values["prepare_result"],
        effective_at=REQUESTED,
    )
    return values, store, descriptor, m0_head, m0_manifest


def authorized_store(tmp_path: Path):
    values, store, descriptor, m0_head, m0_manifest = prepared_store(tmp_path)
    result, result_verification = verification_result(values, descriptor, m0_head, m0_manifest)
    m1_head, _m1_manifest = store.verify(
        descriptor=descriptor,
        package=values["package"],
        verification_result=result,
        result_verification=result_verification,
        effective_at=VERIFIED,
    )
    assert store.verify(
        descriptor=descriptor,
        package=values["package"],
        verification_result=result,
        result_verification=result_verification,
        effective_at=VERIFIED,
    )[0] == m1_head
    m2_head, _m2_manifest = store.authorize(
        descriptor=descriptor,
        package=values["package"],
        approval=values["approval"],
        approval_verification=values["approval_verification"],
        publish_request=values["request"],
        effective_at=AUTHORIZED,
    )
    assert store.authorize(
        descriptor=descriptor,
        package=values["package"],
        approval=values["approval"],
        approval_verification=values["approval_verification"],
        publish_request=values["request"],
        effective_at=AUTHORIZED,
    )[0] == m2_head
    return values, store, descriptor, m0_head, m1_head, m2_head


def registry_result(values, publish_result):
    return with_self_digest(
        {
            "schema": "bootstrap-attempt-transition-result/v1",
            "operationId": f"{values['request']['operationId']}-registry-adopted",
            "operation": "adopt_claim",
            "requestDigest": values["request"]["recordDigest"],
            "attemptId": values["package"]["attemptId"],
            "priorHeadDigest": values["package"]["claimedHeadDigest"],
            "entryDigest": digest("1"),
            "headDigest": publish_result["registryHeadDigest"],
            "slotDigest": digest("2"),
            "headSlotCommitDigest": digest("3"),
            "currentDigest": digest("4"),
            "state": "adopted",
            "completedAt": PUBLISHED,
        }
    )


def test_adoption_fv_m0_m1_m2_m3_ma_state_machine(tmp_path: Path) -> None:
    values, store, descriptor, m0_head, m1_head, m2_head = authorized_store(tmp_path / "published")
    assert [(head["milestone"], head["state"]) for head in (m0_head, m1_head, m2_head)] == [
        ("FV-M0", "prepared"),
        ("FV-M1", "verified"),
        ("FV-M2", "adoption_authorized"),
    ]
    publish_result, publish_verification = run_publish(values)
    m3_head, m3_manifest = store.publish(
        descriptor=descriptor,
        package=values["package"],
        publish_result=publish_result,
        publish_verification=publish_verification,
        registry_result=registry_result(values, publish_result),
        effective_at=PUBLISHED,
    )
    assert (m3_head["milestone"], m3_head["state"], m3_head["sequence"]) == (
        "FV-M3", "adoption_published", 3,
    )
    assert m3_manifest["previousManifestDigest"] is not None
    assert store.require(
        milestone="FV-M3", state="adoption_published", package=values["package"]
    ) == m3_head
    assert [head["milestone"] for head in store.validate_chain()] == ["FV-M0", "FV-M1", "FV-M2", "FV-M3"]
    assert store.publish(
        descriptor=descriptor,
        package=values["package"],
        publish_result=publish_result,
        publish_verification=publish_verification,
        registry_result=registry_result(values, publish_result),
        effective_at=PUBLISHED,
    )[0] == m3_head

    aborted_values, aborted_store, aborted_descriptor, _m0, _m1, _m2 = authorized_store(
        tmp_path / "aborted"
    )
    abort_subject, _verification = FakeIssuer()(
        "bootstrap_adoption_cancel_authorization",
        {
            "schema": "bootstrap-adoption-cancel-authorization/v1",
            "authorizationId": "authorization-fv-abort",
            "operationId": "fv-abort-001",
            "rootDigest": aborted_values["package"]["rootDigest"],
            "packageId": aborted_values["package"]["packageId"],
            "packageDigest": aborted_values["package"]["recordDigest"],
            "expectedStatus": "awaiting_approval",
            "reason": "owner_cancel",
            "oldMainUnchanged": True,
            "newMainAbsent": True,
            "stagingDisposition": "complete",
            "privateStateDisposition": "destroyed",
            "authorizedAt": PUBLISHED,
        },
    )
    ma_head, _ma_manifest = aborted_store.abort(
        descriptor=aborted_descriptor,
        package=aborted_values["package"],
        abort_subject=abort_subject,
        effective_at=PUBLISHED,
    )
    assert (ma_head["milestone"], ma_head["state"], ma_head["sequence"]) == (
        "FV-MA", "aborted_pre_cas", 3,
    )
    assert aborted_store.abort(
        descriptor=aborted_descriptor,
        package=aborted_values["package"],
        abort_subject=abort_subject,
        effective_at=PUBLISHED,
    )[0] == ma_head
    with pytest.raises(FoundationVerificationError, match="adoption-authorized head"):
        aborted_store.publish(
            descriptor=aborted_descriptor,
            package=aborted_values["package"],
            publish_result=publish_result,
            publish_verification=publish_verification,
            registry_result=registry_result(values, publish_result),
            effective_at=PUBLISHED,
        )


@pytest.mark.parametrize("phase", ["objects_written", "manifest_written", "head_written", "current_committed"])
def test_fv_m0_recovers_every_persistence_boundary(tmp_path: Path, phase: str) -> None:
    values = publish_setup(tmp_path)
    store = AdoptionFoundationVerificationStore(
        (tmp_path / "foundation-verification").resolve(), slot_id="example-crash-001"
    )
    with pytest.raises(FoundationVerificationCrash, match=phase):
        store.prepare(
            package=values["package"],
            approval_subject=values["approval_subject"],
            prepare_result=values["prepare_result"],
            effective_at=REQUESTED,
            crash_after=phase,
        )
    descriptor, head, manifest = store.prepare(
        package=values["package"],
        approval_subject=values["approval_subject"],
        prepare_result=values["prepare_result"],
        effective_at=REQUESTED,
    )
    assert head["milestone"] == "FV-M0"
    assert manifest["descriptorDigest"] == descriptor["recordDigest"]


def test_rejected_verification_does_not_create_fv_m1_or_ma(tmp_path: Path) -> None:
    values, store, descriptor, m0_head, m0_manifest = prepared_store(tmp_path)
    result, result_verification = verification_result(
        values, descriptor, m0_head, m0_manifest, outcome="rejected"
    )
    assert store.verify(
        descriptor=descriptor,
        package=values["package"],
        verification_result=result,
        result_verification=result_verification,
        effective_at=VERIFIED,
    ) is None
    assert store.current() == m0_head
    assert list((store.root / "rejected").glob("*.json"))
    with pytest.raises(FoundationVerificationError, match="verified head"):
        store.authorize(
            descriptor=descriptor,
            package=values["package"],
            approval=values["approval"],
            approval_verification=values["approval_verification"],
            publish_request=values["request"],
            effective_at=AUTHORIZED,
        )


def test_fv_chain_rejects_missing_content_addressed_object(tmp_path: Path) -> None:
    values, store, _descriptor, m0_head, _m0_manifest = prepared_store(tmp_path)
    manifest = store.manifest(m0_head)
    assert manifest is not None
    (store.root / "objects" / f"{manifest['entries'][0]['digest'][7:]}.json").unlink()
    with pytest.raises(FoundationVerificationError, match="object closure"):
        store.require(milestone="FV-M0", state="prepared", package=values["package"])
