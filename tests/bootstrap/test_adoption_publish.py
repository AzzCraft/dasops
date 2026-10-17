from __future__ import annotations

import contextlib
from copy import deepcopy
from pathlib import Path

import pytest

from dasops.bootstrap.adoption_publish import (
    AdoptionPublishCoordinator,
    AdoptionPublishCrash,
    AdoptionPublishError,
    adoption_activation_response,
)
from dasops.bootstrap.foundation_verification import AdoptionFoundationVerificationStore
from dasops.bootstrap.repository_handoff import RepositoryHandoffError, RepositoryHandoffStore
from dasops.protected.canonical import with_self_digest

from .test_adoption_prepare import FakeRepository, run_prepare, setup_adoption
from .test_authority import digest
from .test_legacy_claim import FakeIssuer
from .test_registry import verified_operation


PREPARED = "2026-07-16T12:00:00Z"
APPROVED = "2026-07-16T12:01:00Z"
REQUESTED = "2026-07-16T12:02:00Z"
RECOVERY_REQUESTED = "2026-07-16T12:11:00Z"
RECOVERED = "2026-07-16T12:12:00Z"


class ControlledRepository(FakeRepository):
    def __init__(self, source: FakeRepository):
        value = source.value
        super().__init__(
            Path(value["path"]),
            main=value["main"],
            refs=value["refs"],
            object_format=value["objectFormat"],
            drained=value["drained"],
            fenced=value["fenced"],
            fence_mode=value["fenceMode"],
        )
        self.cas_count = 0
        self.lock_depth = 0
        self.staged_commit = None
        self.candidate = None

    @contextlib.contextmanager
    def lock(self):
        self.lock_depth += 1
        try:
            yield
        finally:
            self.lock_depth -= 1

    def _locked(self):
        if self.lock_depth != 1:
            raise RuntimeError("repository mutation was not singly locked")

    def drain(self):
        self._locked()
        self.value["drained"] = True

    def prefence(self):
        self._locked()
        self.value["fenced"] = True
        self.value["fenceMode"] = "prefenced"

    def stage(self, ref, commit):
        self._locked()
        if self.value["main"] is not None or commit is None:
            raise RuntimeError("invalid staging precondition")
        self.staged_commit = commit
        self.value["refs"] = sorted(set([*self.value["refs"], ref]))

    def candidate_identity(self, commit):
        self._locked()
        if self.candidate is None:
            raise RuntimeError("candidate object is absent")
        return deepcopy(self.candidate)

    def create_main_from_absent(self, commit):
        self._locked()
        if self.value["main"] is not None:
            raise RuntimeError("zero-OID CAS failed")
        self.value["main"] = commit
        self.value["refs"] = sorted(set([*self.value["refs"], "refs/heads/main"]))
        self.cas_count += 1

    def remove_staging(self, namespace):
        self._locked()
        self.value["refs"] = [ref for ref in self.value["refs"] if not ref.startswith(namespace)]

    def permanent_fence(self):
        self._locked()
        self.value["drained"] = True
        self.value["fenced"] = True
        self.value["fenceMode"] = "permanent"

    def restore_access(self):
        self._locked()
        self.value["drained"] = False
        self.value["fenced"] = False
        self.value["fenceMode"] = "open"


def publish_setup(tmp_path: Path, *, adoption_values=None, use_fake_controllers=True):
    values = list(setup_adoption(tmp_path) if adoption_values is None else adoption_values)
    if use_fake_controllers:
        values[9] = ControlledRepository(values[9])
        values[10] = ControlledRepository(values[10])
    package, approval_subject, prepare_result = run_prepare(tuple(values), effective_at=PREPARED)
    if use_fake_controllers:
        values[10].candidate = {
            "commit": package["candidateCommit"],
            "tree": package["candidateTree"],
            "parent": package["candidateParent"],
        }
    chain, registry = values[0], values[1]
    approval, approval_verification = FakeIssuer()(
        "bootstrap_adoption_approval",
        {
            "schema": "bootstrap-adoption-approval/v1",
            "approvalId": "adoption-approval-001",
            "rootDigest": package["rootDigest"],
            "packageDigest": package["recordDigest"],
            "approvalSubjectDigest": approval_subject["recordDigest"],
            "action": "publish",
            "issuedAt": APPROVED,
            "expiresAt": "2026-07-16T12:10:00Z",
        },
    )
    request = with_self_digest(
        {
            "schema": "bootstrap-adoption-publish-request/v1",
            "operationId": "adopt-publish-001",
            "packageId": package["packageId"],
            "packageDigest": package["recordDigest"],
            "prepareResultDigest": prepare_result["recordDigest"],
            "approvalSubjectDigest": approval_subject["recordDigest"],
            "approvalDigest": approval["recordDigest"],
            "approvalVerificationDigest": approval_verification["recordDigest"],
            "privateStateDigest": prepare_result["privateStateDigest"],
            "oldMain": package["oldMain"],
            "candidateCommit": package["candidateCommit"],
            "requestedAt": REQUESTED,
        }
    )
    foundation_store = AdoptionFoundationVerificationStore(
        (tmp_path / "integrated-foundation-verification").resolve(),
        slot_id="example-integrated-adoption",
    )
    foundation_descriptor, m0_head, m0_manifest = foundation_store.prepare(
        package=package,
        approval_subject=approval_subject,
        prepare_result=prepare_result,
        effective_at=APPROVED,
    )
    verification_result, result_verification = FakeIssuer()(
        "bootstrap_candidate_verification_result",
        {
            "schema": "bootstrap-candidate-verification-result/v1",
            "resultId": "integrated-adoption-verification",
            "descriptorDigest": foundation_descriptor["recordDigest"],
            "preparedHeadDigest": m0_head["recordDigest"],
            "m0ManifestDigest": m0_manifest["recordDigest"],
            "packageDigest": package["recordDigest"],
            "candidateCommit": package["candidateCommit"],
            "candidateTree": package["candidateTree"],
            "candidateParent": package["candidateParent"],
            "outcome": "accepted",
            "findingsDigest": digest("0"),
            "completedAt": APPROVED,
        },
    )
    foundation_store.verify(
        descriptor=foundation_descriptor,
        package=package,
        verification_result=verification_result,
        result_verification=result_verification,
        effective_at=APPROVED,
    )
    foundation_authorized_head, foundation_authorized_manifest = foundation_store.authorize(
        descriptor=foundation_descriptor,
        package=package,
        approval=approval,
        approval_verification=approval_verification,
        publish_request=request,
        effective_at=APPROVED,
    )
    repository_handoff_store = RepositoryHandoffStore(
        (tmp_path / "integrated-repository-handoff").resolve(),
        foundation_program_id="example-recovery-program",
        profile_digest=digest("6"),
    )
    repository_genesis = repository_handoff_store.initialize(
        package=package,
        issuer=FakeIssuer(),
        effective_at=APPROVED,
    )
    verifier, _authority, tool, descriptor = chain
    records = [
        request,
        package,
        prepare_result,
        approval_subject,
        approval,
        approval_verification,
        foundation_authorized_head,
        foundation_authorized_manifest,
        repository_genesis["selectorHead"],
        repository_genesis["selectorVerification"],
        repository_genesis["profileHead"],
        repository_genesis["profileVerification"],
    ]
    operation = verified_operation(verifier, tool, descriptor, "adopt_publish", records)
    coordinator = AdoptionPublishCoordinator(
        registry,
        foundation_store=foundation_store,
        foundation_authorized_head=foundation_authorized_head,
        repository_handoff_store=repository_handoff_store,
    )
    return {
        "chain": chain,
        "registry": registry,
        "coordinator": coordinator,
        "prepare_request": values[8],
        "old": values[9],
        "new": values[10],
        "secret": values[11],
        "package": package,
        "approval_subject": approval_subject,
        "prepare_result": prepare_result,
        "approval": approval,
        "approval_verification": approval_verification,
        "request": request,
        "operation": operation,
        "issuer": FakeIssuer(),
        "foundation_store": foundation_store,
        "foundation_descriptor": foundation_descriptor,
        "foundation_verification_result": verification_result,
        "foundation_result_verification": result_verification,
        "foundation_authorized_head": foundation_authorized_head,
        "foundation_authorized_manifest": foundation_authorized_manifest,
        "repository_handoff_store": repository_handoff_store,
        "repository_genesis": repository_genesis,
    }


def run_publish(values, *, effective_at=REQUESTED, crash_after=None):
    return values["coordinator"].publish(
        request=values["request"],
        package=values["package"],
        prepare_result=values["prepare_result"],
        approval_subject=values["approval_subject"],
        approval=values["approval"],
        approval_verification=values["approval_verification"],
        operation=values["operation"],
        old_repository=values["old"],
        new_repository=values["new"],
        issuer=values["issuer"],
        effective_at=effective_at,
        crash_after=crash_after,
    )


def cancellation_inputs(values, *, expected_status="awaiting_approval", operation_id="adopt-cancel-001", reason="owner_cancel"):
    authorization, verification = FakeIssuer()(
        "bootstrap_adoption_cancel_authorization",
        {
            "schema": "bootstrap-adoption-cancel-authorization/v1",
            "authorizationId": f"authorization-{operation_id}",
            "operationId": operation_id,
            "rootDigest": values["package"]["rootDigest"],
            "packageId": values["package"]["packageId"],
            "packageDigest": values["package"]["recordDigest"],
            "expectedStatus": expected_status,
            "reason": reason,
            "oldMainUnchanged": True,
            "newMainAbsent": True,
            "stagingDisposition": "complete",
            "privateStateDisposition": "destroyed",
            "authorizedAt": REQUESTED,
        },
    )
    verifier, _authority, tool, descriptor = values["chain"]
    records = [
        authorization,
        verification,
        values["prepare_request"],
        values["package"],
        values["prepare_result"],
        values["foundation_authorized_head"],
        values["foundation_authorized_manifest"],
        values["repository_genesis"]["selectorHead"],
        values["repository_genesis"]["selectorVerification"],
        values["repository_genesis"]["profileHead"],
        values["repository_genesis"]["profileVerification"],
    ]
    operation = verified_operation(verifier, tool, descriptor, "adopt_cancel", records)
    return authorization, verification, operation


def run_cancel(values, inputs, *, crash_after=None):
    authorization, verification, operation = inputs
    return values["coordinator"].cancel(
        authorization=authorization,
        authorization_verification=verification,
        prepare_request=values["prepare_request"],
        package=values["package"],
        prepare_result=values["prepare_result"],
        operation=operation,
        old_repository=values["old"],
        new_repository=values["new"],
        issuer=values["issuer"],
        effective_at=REQUESTED,
        crash_after=crash_after,
    )


def recovery_inputs(values, classification):
    old = values["old"].snapshot()
    new = values["new"].snapshot()
    recovery_request = with_self_digest(
        {
            "schema": "bootstrap-adoption-recovery-request/v1",
            "operationId": f"recover-{classification}",
            "packageId": values["package"]["packageId"],
            "packageDigest": values["package"]["recordDigest"],
            "publishRequestDigest": values["request"]["recordDigest"],
            "classification": classification,
            "oldMainObserved": old["main"],
            "newMainObserved": new["main"],
            "oldFenceObserved": old["fenced"],
            "requestedAt": RECOVERY_REQUESTED,
        }
    )
    records = [
        recovery_request,
        values["request"],
        values["package"],
        values["prepare_result"],
        values["approval_subject"],
        values["approval"],
        values["approval_verification"],
        values["foundation_authorized_head"],
        values["foundation_authorized_manifest"],
        values["repository_genesis"]["selectorHead"],
        values["repository_genesis"]["selectorVerification"],
        values["repository_genesis"]["profileHead"],
        values["repository_genesis"]["profileVerification"],
    ]
    verifier, _authority, tool, descriptor = values["chain"]
    operation = verified_operation(verifier, tool, descriptor, "recover_publication", records)
    return recovery_request, operation


def activation_inputs(values):
    result, _verification = run_publish(values)
    challenge = values["coordinator"].issue_activation_challenge(
        package=values["package"],
        publish_result=result,
        challenge_id="activation-001",
        nonce=b"N" * 32,
        issued_at="2026-07-16T12:03:00Z",
    )
    response = adoption_activation_response(values["secret"].token, challenge)
    verifier, _authority, tool, descriptor = values["chain"]
    fv_published_head = values["foundation_store"].current()
    fv_published_manifest = values["foundation_store"].manifest(fv_published_head)
    repository_handoff = values["repository_handoff_store"].require(
        package=values["package"], publish_result=result
    )
    records = [
        values["package"],
        values["prepare_request"],
        values["prepare_result"],
        result,
        challenge,
        fv_published_head,
        fv_published_manifest,
        repository_handoff["transaction"],
        repository_handoff["selectorHead"],
        repository_handoff["selectorVerification"],
        repository_handoff["profileHead"],
        repository_handoff["profileVerification"],
    ]
    operation = verified_operation(verifier, tool, descriptor, "adopt_publish", records)
    return result, challenge, response, operation


def run_activate(values, inputs, *, crash_after=None):
    result, challenge, response, operation = inputs
    return values["coordinator"].activate(
        package=values["package"],
        prepare_request=values["prepare_request"],
        prepare_result=values["prepare_result"],
        publish_result=result,
        challenge=challenge,
        response=response,
        operation=operation,
        issuer=values["issuer"],
        effective_at="2026-07-16T12:04:00Z",
        crash_after=crash_after,
    )


def test_publish_and_activation_complete_one_way_transition(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    result, challenge, response, operation = activation_inputs(values)
    verification = values["coordinator"]._read_record(
        values["coordinator"].root / "results" / f"{values['request']['operationId']}-publish-verification.json"
    )
    assert result["outcome"] == "published_pending_activation"
    assert verification["purpose"] == "bootstrap_adoption_publish_result"
    assert values["new"].value["main"] == values["package"]["candidateCommit"]
    assert values["new"].cas_count == 1
    assert values["old"].value["drained"] and values["old"].value["fenced"]
    assert values["registry"].current()["state"] == "adopted"
    assert values["registry"].receipt_slot(values["registry"].current()["headDigest"])["status"] == "closed"
    assert values["coordinator"].lifecycle()["status"] == "published_pending_activation"
    foundation_head = values["foundation_store"].current()
    assert foundation_head["milestone"] == "FV-M3"
    assert foundation_head["state"] == "adoption_published"
    assert foundation_head["packageDigest"] == values["package"]["recordDigest"]
    handoff = values["repository_handoff_store"].require(package=values["package"], publish_result=result)
    assert handoff["selectorHead"]["repositoryBindingId"] == handoff["profileHead"]["repositoryBindingId"]
    assert handoff["selectorHead"]["repositoryBindingKind"] == "adoption_handoff"
    assert handoff["profileHead"]["headKind"] == "repository_handoff"
    assert Path(values["prepare_request"]["privateStatePath"]).exists()

    receipt, receipt_verification = run_activate(values, (result, challenge, response, operation))
    assert receipt["outcome"] == "consumed"
    assert receipt_verification["purpose"] == "bootstrap_adoption_activation_receipt"
    assert values["coordinator"].lifecycle()["status"] == "consumed"
    assert not Path(values["prepare_request"]["privateStatePath"]).exists()


def test_adoption_candidate_parent_and_new_main_are_exact(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    package = values["package"]
    assert package["candidateParent"] == package["oldMain"]
    assert package["candidateCommit"] != package["oldMain"]
    assert values["request"]["candidateCommit"] == package["candidateCommit"]
    result, _verification = run_publish(values)
    assert result["oldMain"] == package["oldMain"]
    assert result["newMain"] == package["candidateCommit"]
    assert values["old"].value["main"] == package["oldMain"]
    assert values["new"].value["main"] == package["candidateCommit"]
    assert values["new"].staged_commit == package["candidateCommit"]
    assert values["new"].cas_count == 1


def test_publish_requires_bound_fv_m2_authority(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    values["coordinator"] = AdoptionPublishCoordinator(values["registry"])
    with pytest.raises(AdoptionPublishError, match="Foundation Verification authority is absent"):
        run_publish(values)


def test_activation_requires_intact_fv_m3_closure(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    result, _verification = run_publish(values)
    head = values["foundation_store"].current()
    manifest_path = values["foundation_store"].root / "manifests" / f"{head['manifestDigest'][7:]}.json"
    manifest_path.unlink()
    with pytest.raises(AdoptionPublishError, match="manifest closure"):
        values["coordinator"].issue_activation_challenge(
            package=values["package"],
            publish_result=result,
            challenge_id="activation-missing-fv-m3",
            nonce=b"M" * 32,
            issued_at="2026-07-16T12:03:00Z",
        )


@pytest.mark.parametrize("defect", ["profile_current", "profile_verification"])
def test_activation_requires_complete_repository_handoff_pair(tmp_path: Path, defect: str) -> None:
    values = publish_setup(tmp_path)
    result, _verification = run_publish(values)
    handoff = values["repository_handoff_store"].require(
        package=values["package"], publish_result=result
    )
    if defect == "profile_current":
        values["repository_handoff_store"]._profile_current_path.unlink()
    else:
        (
            values["repository_handoff_store"].root
            / "profile"
            / "verifications"
            / f"{handoff['profileHead']['recordDigest'][7:]}.json"
        ).unlink()
    with pytest.raises(AdoptionPublishError, match="current pair is absent|verification closure"):
        values["coordinator"].issue_activation_challenge(
            package=values["package"],
            publish_result=result,
            challenge_id=f"activation-handoff-{defect}",
            nonce=b"H" * 32,
            issued_at="2026-07-16T12:03:00Z",
        )


def test_repository_handoff_is_one_way_after_publication(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    run_publish(values)
    with pytest.raises(RepositoryHandoffError, match="genesis pair"):
        values["repository_handoff_store"].initialize(
            package=values["package"],
            issuer=values["issuer"],
            effective_at="2026-07-16T12:05:00Z",
        )


@pytest.mark.parametrize("field", ["commit", "tree", "parent"])
def test_publish_rejects_staged_candidate_identity_or_ancestry_drift(tmp_path: Path, field: str) -> None:
    values = publish_setup(tmp_path)
    values["new"].candidate[field] = "9" * 40
    with pytest.raises(AdoptionPublishError, match="candidate identity/ancestry"):
        run_publish(values)


@pytest.mark.parametrize("phase", ["activation_result_written", "activation_private_disposed", "consumed"])
def test_activation_recovers_every_response_loss_boundary(tmp_path: Path, phase: str) -> None:
    values = publish_setup(tmp_path)
    inputs = activation_inputs(values)
    with pytest.raises(AdoptionPublishCrash, match=phase):
        run_activate(values, inputs, crash_after=phase)
    receipt, verification = run_activate(values, inputs)
    assert receipt["outcome"] == "consumed"
    assert verification["purpose"] == "bootstrap_adoption_activation_receipt"
    assert values["coordinator"].lifecycle()["status"] == "consumed"
    assert not Path(values["prepare_request"]["privateStatePath"]).exists()


@pytest.mark.parametrize(
    "phase",
    [
        "publish_intent", "old_drained", "old_prefenced", "new_staged", "new_main_created",
        "staging_removed", "old_permanent_fenced", "registry_adopted", "result_written",
        "fv_m3_published", "repository_selector_handoff_committed",
        "repository_profile_handoff_committed", "published_pending_activation",
    ],
)
def test_publish_recovers_every_response_loss_boundary(tmp_path: Path, phase: str) -> None:
    values = publish_setup(tmp_path)
    with pytest.raises(AdoptionPublishCrash, match=phase):
        run_publish(values, crash_after=phase)
    result, _verification = run_publish(values)
    assert result["outcome"] == "published_pending_activation"
    assert values["new"].cas_count == 1
    assert values["registry"].current()["state"] == "adopted"
    assert values["coordinator"].lifecycle()["status"] == "published_pending_activation"
    assert values["foundation_store"].current()["milestone"] == "FV-M3"
    handoff = values["repository_handoff_store"].require(package=values["package"], publish_result=result)
    assert handoff["selectorHead"]["repositoryBindingId"] == handoff["profileHead"]["repositoryBindingId"]


@pytest.mark.parametrize(
    "phase",
    ["fv_ma_aborted", "cancel_disposed", "cancel_fence_released", "cancel_result_written", "cancelled"],
)
def test_cancel_recovers_every_response_loss_boundary(tmp_path: Path, phase: str) -> None:
    values = publish_setup(tmp_path)
    inputs = cancellation_inputs(values)
    with pytest.raises(AdoptionPublishCrash, match=phase):
        run_cancel(values, inputs, crash_after=phase)
    result, verification = run_cancel(values, inputs)
    assert result["outcome"] == "cancelled"
    assert result["schema"] == "bootstrap-adoption-cancel-result/v2"
    assert verification["purpose"] == "bootstrap_adoption_cancel_result"
    assert values["coordinator"].lifecycle()["status"] == "cancelled"
    foundation_head = values["foundation_store"].current()
    assert foundation_head["milestone"] == "FV-MA"
    assert foundation_head["state"] == "aborted_pre_cas"
    tombstone = values["coordinator"]._read_record(
        values["coordinator"].root / "results" / "adopt-cancel-001-disposition-tombstone.json"
    )
    fence_release = values["coordinator"]._read_record(
        values["coordinator"].root / "results" / "adopt-cancel-001-fence-release.json"
    )
    assert result["fvAbortHeadDigest"] == foundation_head["recordDigest"]
    assert result["dispositionTombstoneDigest"] == tombstone["recordDigest"]
    assert result["fenceReleaseReceiptDigest"] == fence_release["recordDigest"]
    assert tombstone["secureEraseClaimed"] is False
    assert not Path(values["prepare_request"]["privateStatePath"]).exists()


def test_cancel_disposes_secret_before_releasing_old_fence(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    values["old"].value.update({"drained": True, "fenced": True, "fenceMode": "prefenced"})
    inputs = cancellation_inputs(values)
    with pytest.raises(AdoptionPublishCrash, match="cancel_disposed"):
        run_cancel(values, inputs, crash_after="cancel_disposed")
    assert values["old"].value["fenceMode"] == "prefenced"
    assert values["foundation_store"].current()["milestone"] == "FV-MA"
    assert not Path(values["prepare_request"]["privateStatePath"]).exists()
    assert (
        values["coordinator"].root / "results" / "adopt-cancel-001-disposition-tombstone.json"
    ).exists()
    assert not (
        values["coordinator"].root / "results" / "adopt-cancel-001-fence-release.json"
    ).exists()
    run_cancel(values, inputs)
    assert values["old"].value["fenceMode"] == "open"


def test_cancel_retry_rejects_missing_terminal_closure_member(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    inputs = cancellation_inputs(values)
    run_cancel(values, inputs)
    (
        values["coordinator"].root / "results" / "adopt-cancel-001-disposition-tombstone.json"
    ).unlink()
    with pytest.raises(AdoptionPublishError, match="terminal closure is incomplete"):
        run_cancel(values, inputs)


def test_recovery_resumes_exact_partial_cas_after_original_approval_expiry(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    with pytest.raises(AdoptionPublishCrash, match="new_main_created"):
        run_publish(values, crash_after="new_main_created")
    recovery_request, recovery_operation = recovery_inputs(values, "resume_publish")
    result, _verification = values["coordinator"].recover_publication(
        recovery_request=recovery_request,
        request=values["request"],
        package=values["package"],
        prepare_result=values["prepare_result"],
        approval_subject=values["approval_subject"],
        approval=values["approval"],
        approval_verification=values["approval_verification"],
        recovery_operation=recovery_operation,
        publish_operation=values["operation"],
        old_repository=values["old"],
        new_repository=values["new"],
        issuer=values["issuer"],
        effective_at=RECOVERED,
    )
    assert result["completedAt"] == RECOVERED
    assert values["new"].cas_count == 1
    assert values["coordinator"].lifecycle()["status"] == "published_pending_activation"


@pytest.mark.parametrize("classification", ["proved_pre_cas_abort", "ambiguous_blocked"])
def test_recovery_never_infers_abort_or_resolves_ambiguity(tmp_path: Path, classification: str) -> None:
    values = publish_setup(tmp_path)
    with pytest.raises(AdoptionPublishCrash, match="publish_intent"):
        run_publish(values, crash_after="publish_intent")
    if classification == "ambiguous_blocked":
        values["new"].value["main"] = "9" * 40
        values["new"].value["refs"] = ["refs/heads/main"]
    recovery_request, recovery_operation = recovery_inputs(values, classification)
    with pytest.raises(AdoptionPublishError, match="signed adopt-cancel|ambiguity"):
        values["coordinator"].recover_publication(
            recovery_request=recovery_request,
            request=values["request"],
            package=values["package"],
            prepare_result=values["prepare_result"],
            approval_subject=values["approval_subject"],
            approval=values["approval"],
            approval_verification=values["approval_verification"],
            recovery_operation=recovery_operation,
            publish_operation=values["operation"],
            old_repository=values["old"],
            new_repository=values["new"],
            issuer=values["issuer"],
            effective_at=RECOVERED,
        )


@pytest.mark.parametrize("defect", ["old_main", "new_main", "object_format", "unexpected_ref"])
def test_publish_rejects_repository_substitution_and_ambiguity(tmp_path: Path, defect: str) -> None:
    values = publish_setup(tmp_path)
    if defect == "old_main":
        values["old"].value["main"] = "8" * 40
    elif defect == "new_main":
        values["new"].value["main"] = "9" * 40
    elif defect == "object_format":
        values["new"].value["objectFormat"] = "sha256"
    else:
        values["new"].value["refs"] = ["refs/heads/unexpected"]
    with pytest.raises(AdoptionPublishError, match="changed|ambiguous|format|unexpected"):
        run_publish(values)


@pytest.mark.parametrize(
    ("repository", "method", "message"),
    [
        ("old", "drain", "drain readback"),
        ("old", "prefence", "pre-fence readback"),
        ("new", "stage", "staging readback"),
        ("new", "create_main_from_absent", "zero-OID CAS readback"),
        ("new", "remove_staging", "staging removal readback"),
        ("old", "permanent_fence", "permanent-fence readback"),
    ],
)
def test_publish_rejects_silent_repository_mutation_failures(
    tmp_path: Path, repository: str, method: str, message: str,
) -> None:
    values = publish_setup(tmp_path)
    setattr(values[repository], method, lambda *_args: None)
    with pytest.raises(AdoptionPublishError, match=message):
        run_publish(values)


def test_publish_requires_approval_strictly_after_prepare(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    stale, stale_verification = FakeIssuer()(
        "bootstrap_adoption_approval",
        {
            "schema": "bootstrap-adoption-approval/v1",
            "approvalId": "stale-approval",
            "rootDigest": values["package"]["rootDigest"],
            "packageDigest": values["package"]["recordDigest"],
            "approvalSubjectDigest": values["approval_subject"]["recordDigest"],
            "action": "publish",
            "issuedAt": PREPARED,
            "expiresAt": "2026-07-16T12:10:00Z",
        },
    )
    request = deepcopy(values["request"])
    request.pop("recordDigest")
    request["approvalDigest"] = stale["recordDigest"]
    request["approvalVerificationDigest"] = stale_verification["recordDigest"]
    values["request"] = with_self_digest(request)
    values["approval"], values["approval_verification"] = stale, stale_verification
    verifier, _authority, tool, descriptor = values["chain"]
    records = [
        values["request"], values["package"], values["prepare_result"], values["approval_subject"],
        stale, stale_verification, values["foundation_authorized_head"],
        values["foundation_authorized_manifest"], values["repository_genesis"]["selectorHead"],
        values["repository_genesis"]["selectorVerification"],
        values["repository_genesis"]["profileHead"],
        values["repository_genesis"]["profileVerification"],
    ]
    values["operation"] = verified_operation(verifier, tool, descriptor, "adopt_publish", records)
    with pytest.raises(AdoptionPublishError, match="after package preparation"):
        run_publish(values)


def test_cancel_is_blocked_after_new_main_cas(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    with pytest.raises(AdoptionPublishCrash, match="new_main_created"):
        run_publish(values, crash_after="new_main_created")
    inputs = cancellation_inputs(values, expected_status="publishing", reason="proved_pre_cas_abort")
    with pytest.raises(AdoptionPublishError, match="cannot roll back"):
        run_cancel(values, inputs)


def test_cancel_requires_repository_disposition_readback(tmp_path: Path) -> None:
    values = publish_setup(tmp_path)
    values["old"].value.update({"drained": True, "fenced": True, "fenceMode": "prefenced"})
    values["old"].restore_access = lambda: None
    inputs = cancellation_inputs(values)
    with pytest.raises(AdoptionPublishError, match="fence-release readback"):
        run_cancel(values, inputs)
