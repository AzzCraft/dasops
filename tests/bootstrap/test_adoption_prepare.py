from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path

import pytest

from dasops.bootstrap.adoption_prepare import (
    AdoptionPrepareCoordinator,
    AdoptionPrepareCrash,
    AdoptionPrepareError,
)
from dasops.bootstrap.foundation_payload import write_prepared_package
from dasops.protected.canonical import canonical_bytes, semantic_digest, with_self_digest
from dasops.protected.state_store import atomic_write

from .test_authority import digest, verified_chain
from .test_legacy_claim import FakeIssuer, handoff_inputs, publish
from .test_registry import EFFECTIVE, verified_operation


class FakeRepository:
    def __init__(self, path: Path, *, main: str | None, refs=None, object_format="sha1", drained=False, fenced=False, fence_mode=None, mutate_after_first=False):
        self.value = {
            "path": str(path.resolve()),
            "objectFormat": object_format,
            "main": main,
            "refs": sorted(refs or []),
            "drained": drained,
            "fenced": fenced,
            "fenceMode": fence_mode or ("prefenced" if fenced else "open"),
        }
        self.calls = 0
        self.mutate_after_first = mutate_after_first

    def snapshot(self):
        self.calls += 1
        result = deepcopy(self.value)
        if self.mutate_after_first and self.calls > 1:
            result["refs"] = sorted([*result["refs"], "refs/heads/raced"])
        return result


class FakeSecretProvider:
    def __init__(self, path: Path):
        self.path = path
        self.calls = 0
        self.creations = 0
        self.token = b"A" * 32

    def prepare(self, request, *, recovery: bool):
        self.calls += 1
        token_hash = "sha256:" + hashlib.sha256(self.token).hexdigest()
        state = with_self_digest(
            {
                "schema": "bootstrap-adoption-private-state/v1",
                "operationId": request["operationId"],
                "packageId": request["packageId"],
                "tokenBase64": base64.urlsafe_b64encode(self.token).decode().rstrip("="),
                "tokenHash": token_hash,
                "keyEnvelopeDigest": digest("e"),
                "generation": 1,
                "status": "prepared",
                "createdAt": request["requestedAt"],
            }
        )
        encoded = canonical_bytes(state)
        if self.path.exists():
            assert recovery and self.path.read_bytes() == encoded
        else:
            assert not recovery
            self.creations += 1
            atomic_write(self.path, encoded, mode=0o600, create_only=True)


def claimed_handoff(
    tmp_path: Path,
    chain,
    *,
    candidate_commit: str = "b" * 40,
    candidate_tree: str = "c" * 40,
):
    values = publish(
        tmp_path,
        chain,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
    )
    registry, legacy, worker_lock, _adapter, candidate, publisher, issuer, publication, pub_verification, _request, _operation = values
    verifier, _authority, tool, descriptor = chain
    request, challenge, response, destination = handoff_inputs(registry, candidate, publication, worker_lock)
    handoff_operation = verified_operation(
        verifier,
        tool,
        descriptor,
        "handoff_claim",
        [request, candidate, publication, pub_verification, challenge],
    )
    handoff, handoff_verification = legacy.handoff_claim(
        request=request,
        candidate_result=candidate,
        publication_receipt=publication,
        publication_verification=pub_verification,
        challenge=challenge,
        response=response,
        operation=handoff_operation,
        publisher=publisher,
        issuer=issuer,
        effective_at=EFFECTIVE,
    )
    return registry, candidate, publication, pub_verification, handoff, handoff_verification, destination


def adoption_request(
    tmp_path: Path,
    registry,
    candidate,
    publication,
    pub_verification,
    handoff,
    handoff_verification,
    *,
    operation_id="adopt-prepare-001",
    package_id="package-001",
    requested_at=EFFECTIVE,
):
    current = registry.current()
    entry = registry.object(current["entryDigest"])
    private = tmp_path / "private-adoption" / f"{package_id}.json"
    old_path = tmp_path / "old-repo"
    new_path = tmp_path / "new-repo.git"
    worker_path = tmp_path / "foundation-worker"
    worker_path.mkdir(exist_ok=True)
    request = with_self_digest(
        {
            "schema": "bootstrap-adoption-prepare-request/v1",
            "operationId": operation_id,
            "packageId": package_id,
            "attemptId": current["attemptId"],
            "claimedHeadDigest": current["headDigest"],
            "rootDigest": entry["rootDigest"],
            "changeId": entry["changeId"],
            "taskId": entry["taskId"],
            "worker": entry["worker"],
            "oldRepositoryPath": str(old_path.resolve()),
            "newRepositoryPath": str(new_path.resolve()),
            "oldMain": candidate["candidateCommit"],
            "newMainExpectedAbsent": True,
            "objectFormat": "sha1",
            "allowedStagingNamespace": f"refs/das-bootstrap/{package_id}/",
            "publicationReceiptDigest": publication["recordDigest"],
            "publicationVerificationDigest": pub_verification["recordDigest"],
            "handoffReceiptDigest": handoff["recordDigest"],
            "handoffVerificationDigest": handoff_verification["recordDigest"],
            "legacyTokenHash": candidate["tokenHash"],
            "privateStatePath": str(private.resolve()),
            "packageLifetimeSeconds": 600 if requested_at == EFFECTIVE else 60,
            "requestedAt": requested_at,
        }
    )
    old = FakeRepository(old_path, main=candidate["candidateCommit"], refs=["refs/heads/main"])
    new = FakeRepository(new_path, main=None)
    secret = FakeSecretProvider(private)
    foundation_entry = {
        "path": "docs/example-recovery/tasks.md",
        "mode": "100644",
        "gitObjectId": "e" * 40,
        "size": len(b"candidate\n"),
        "contentSha256": hashlib.sha256(b"candidate\n").hexdigest(),
        "classification": "tracked_candidate",
    }
    foundation = with_self_digest(
        {
            "schema": "bootstrap-foundation-payload-manifest/v1",
            "manifestId": f"foundation-{package_id}",
            "workerRepositoryPath": str(worker_path.resolve()),
            "objectFormat": "sha1",
            "candidateCommit": "c" * 40,
            "candidateTree": "d" * 40,
            "candidateParent": candidate["candidateCommit"],
            "entries": [foundation_entry],
            "entryCount": 1,
            "totalBytes": foundation_entry["size"],
            "inventoryDigest": semantic_digest(
                {"schema": "bootstrap-foundation-payload-inventory/v1", "entries": [foundation_entry]}
            ),
            "createdAt": requested_at,
        }
    )
    claim_adoption = with_self_digest(
        {
            "schema": "bootstrap-claim-adoption-request/v1",
            "requestId": f"foundation-request-{package_id}",
            "packageId": package_id,
            "rootDigest": entry["rootDigest"],
            "attemptId": current["attemptId"],
            "changeId": entry["changeId"],
            "taskId": entry["taskId"],
            "worker": entry["worker"],
            "oldRepositoryPath": str(old_path.resolve()),
            "newRepositoryPath": str(new_path.resolve()),
            "workerRepositoryPath": str(worker_path.resolve()),
            "objectFormat": "sha1",
            "expectedOldMain": candidate["candidateCommit"],
            "expectedNewMainAbsent": True,
            "candidateCommit": foundation["candidateCommit"],
            "candidateTree": foundation["candidateTree"],
            "candidateParent": foundation["candidateParent"],
            "foundationPayloadManifestDigest": foundation["recordDigest"],
            "allowedStagingNamespace": request["allowedStagingNamespace"],
            "requestedAt": requested_at,
        }
    )
    prepared = write_prepared_package(
        prepared_directory=(tmp_path / f"foundation-package-{package_id}").resolve(),
        package_id=package_id,
        adoption_request=claim_adoption,
        payload_manifest=foundation,
        records={},
        manifest_id=f"prepared-{package_id}",
        created_at=requested_at,
    )
    return request, old, new, secret, claim_adoption, foundation, prepared


def setup_adoption(tmp_path: Path):
    chain = verified_chain()
    registry, candidate, publication, pub_verification, handoff, handoff_verification, _destination = claimed_handoff(tmp_path, chain)
    request, old, new, secret, claim_adoption, foundation, prepared = adoption_request(
        tmp_path,
        registry,
        candidate,
        publication,
        pub_verification,
        handoff,
        handoff_verification,
    )
    verifier, _authority, tool, descriptor = chain
    records = [
        request,
        candidate,
        publication,
        pub_verification,
        handoff,
        handoff_verification,
        claim_adoption,
        foundation,
        prepared,
    ]
    operation = verified_operation(verifier, tool, descriptor, "adopt_prepare", records)
    coordinator = AdoptionPrepareCoordinator(registry)
    return (
        chain, registry, coordinator, candidate, publication, pub_verification,
        handoff, handoff_verification, request, old, new, secret, operation,
        claim_adoption, foundation, prepared,
    )


def run_prepare(values, *, effective_at=EFFECTIVE, crash_after=None):
    (
        _chain, _registry, coordinator, candidate, publication, pub_verification,
        handoff, handoff_verification, request, old, new, secret, operation,
        claim_adoption, foundation, prepared,
    ) = values
    return coordinator.prepare(
        request=request,
        candidate_result=candidate,
        publication_receipt=publication,
        publication_verification=pub_verification,
        handoff_receipt=handoff,
        handoff_verification=handoff_verification,
        claim_adoption_request=claim_adoption,
        foundation_payload=foundation,
        prepared_package_manifest=prepared,
        operation=operation,
        old_repository=old,
        new_repository=new,
        secret_provider=secret,
        effective_at=effective_at,
        crash_after=crash_after,
    )


def test_prepare_builds_non_circular_package_subject_without_repo_mutation(tmp_path: Path) -> None:
    values = setup_adoption(tmp_path)
    (
        _chain, _registry, coordinator, candidate, _publication, _pubv, _handoff,
        _handv, request, old, new, secret, _operation, _claim, _foundation, _prepared,
    ) = values
    old_before, new_before = old.snapshot(), new.snapshot()
    package, subject, result = run_prepare(values)
    assert package["status"] == "awaiting_approval"
    assert subject["packageDigest"] == package["recordDigest"]
    assert result["packageDigest"] == package["recordDigest"]
    assert result["approvalSubjectDigest"] == subject["recordDigest"]
    assert package["legacyTokenHash"] == candidate["tokenHash"]
    assert package["adoptionTokenHash"] != package["legacyTokenHash"]
    assert package["candidateCommit"] == values[14]["candidateCommit"]
    assert package["candidateTree"] == values[14]["candidateTree"]
    assert package["candidateParent"] == package["oldMain"]
    assert package["preparedPackageManifestDigest"] == values[15]["recordDigest"]
    assert subject["candidateCommit"] == package["candidateCommit"]
    assert result["foundationPayloadManifestDigest"] == values[14]["recordDigest"]
    assert old.snapshot() == old_before and new.snapshot() == new_before
    assert coordinator.current_package() == package
    assert (Path(request["privateStatePath"]).stat().st_mode & 0o777) == 0o600
    shared = b"".join(path.read_bytes() for path in coordinator.root.rglob("*.json"))
    assert base64.urlsafe_b64encode(secret.token).rstrip(b"=") not in shared


@pytest.mark.parametrize("phase", ["prepare_intent", "secret_prepared", "package_built", "approval_subject_built", "completed"])
def test_prepare_recovers_every_response_loss_boundary_without_secret_regeneration(tmp_path: Path, phase: str) -> None:
    values = setup_adoption(tmp_path)
    secret = values[11]
    with pytest.raises(AdoptionPrepareCrash, match=phase):
        run_prepare(values, crash_after=phase)
    package, subject, result = run_prepare(values)
    assert package["status"] == "awaiting_approval" and subject["packageDigest"] == result["packageDigest"]
    assert secret.creations == 1


def test_one_live_package_blocks_replacement_even_after_expiry(tmp_path: Path) -> None:
    values = setup_adoption(tmp_path)
    run_prepare(values)
    (
        chain, registry, coordinator, candidate, publication, pubv, handoff, handv,
        _request, _old, _new, _secret, _operation, _claim, _foundation, _prepared,
    ) = values
    second, old, new, secret, claim_adoption, foundation, prepared = adoption_request(
        tmp_path,
        registry,
        candidate,
        publication,
        pubv,
        handoff,
        handv,
        operation_id="adopt-prepare-002",
        package_id="package-002",
        requested_at="2026-07-16T12:11:00Z",
    )
    verifier, _authority, tool, descriptor = chain
    operation = verified_operation(
        verifier,
        tool,
        descriptor,
        "adopt_prepare",
        [second, candidate, publication, pubv, handoff, handv, claim_adoption, foundation, prepared],
    )
    with pytest.raises(AdoptionPrepareError, match="remains live"):
        coordinator.prepare(
            request=second,
            candidate_result=candidate,
            publication_receipt=publication,
            publication_verification=pubv,
            handoff_receipt=handoff,
            handoff_verification=handv,
            claim_adoption_request=claim_adoption,
            foundation_payload=foundation,
            prepared_package_manifest=prepared,
            operation=operation,
            old_repository=old,
            new_repository=new,
            secret_provider=secret,
            effective_at="2026-07-16T12:11:00Z",
        )


@pytest.mark.parametrize("defect", ["new_main", "object_format", "extra_ref", "drained", "raced"])
def test_prepare_rejects_repository_precondition_and_mutation_defects(tmp_path: Path, defect: str) -> None:
    values = list(setup_adoption(tmp_path))
    old, new = values[9], values[10]
    if defect == "new_main":
        new.value["main"] = "9" * 40
    elif defect == "object_format":
        new.value["objectFormat"] = "sha256"
    elif defect == "extra_ref":
        new.value["refs"] = ["refs/heads/unexpected"]
    elif defect == "drained":
        old.value["drained"] = True
    else:
        new.mutate_after_first = True
    with pytest.raises(AdoptionPrepareError, match="precondition|formats|outside|drained|mutated"):
        run_prepare(tuple(values))


def test_prepare_rejects_failed_handoff_and_private_state_inside_authority(tmp_path: Path) -> None:
    values = list(setup_adoption(tmp_path))
    handoff_subject = {
        key: deepcopy(value)
        for key, value in values[6].items()
        if key not in {"recordDigest", "signatureSubjectDigest", "signatures"}
    }
    handoff_subject.update(
        {
            "outcome": "failed",
            "destinationLockPath": None,
            "destinationLockSha256": None,
            "ancestryVerified": None,
            "workerAcknowledged": None,
            "popVerified": None,
            "sourceDisposition": "retained",
            "failureReason": "candidate_ancestry_failed",
            "workAuthority": "none",
        }
    )
    values[6], values[7] = FakeIssuer()("bootstrap_handoff_receipt", handoff_subject)
    failed_request = deepcopy(values[8])
    failed_request.pop("recordDigest")
    failed_request["handoffReceiptDigest"] = values[6]["recordDigest"]
    failed_request["handoffVerificationDigest"] = values[7]["recordDigest"]
    values[8] = with_self_digest(failed_request)
    verifier, _authority, tool, descriptor = values[0]
    values[12] = verified_operation(
        verifier,
        tool,
        descriptor,
        "adopt_prepare",
        [values[8], values[3], values[4], values[5], values[6], values[7], *values[13:16]],
    )
    with pytest.raises(AdoptionPrepareError, match="acknowledged"):
        run_prepare(tuple(values))

    values = list(setup_adoption(tmp_path / "inside"))
    request = deepcopy(values[8])
    request.pop("recordDigest")
    request["privateStatePath"] = str((values[2].registry.root / "forbidden.json").resolve())
    values[8] = with_self_digest(request)
    verifier, _authority, tool, descriptor = values[0]
    values[12] = verified_operation(
        verifier,
        tool,
        descriptor,
        "adopt_prepare",
        [values[8], values[3], values[4], values[5], values[6], values[7], *values[13:16]],
    )
    with pytest.raises(AdoptionPrepareError, match="cannot enter"):
        run_prepare(tuple(values))
