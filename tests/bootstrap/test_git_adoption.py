from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from dasops.bootstrap.adoption_prepare import AdoptionPrepareCoordinator
from dasops.bootstrap.adoption_publish import AdoptionPublishCrash
from dasops.bootstrap.git_adoption import GitAdoptionError, GitAdoptionRepository
from dasops.bootstrap.foundation_payload import (
    build_claim_adoption_request,
    build_foundation_payload_manifest,
    write_prepared_package,
)
from dasops.protected.canonical import with_self_digest

from .test_adoption_prepare import FakeSecretProvider, claimed_handoff
from .test_adoption_publish import (
    PREPARED,
    REQUESTED,
    cancellation_inputs,
    publish_setup,
    run_cancel,
    run_publish,
)
from .test_authority import verified_chain
from .test_foundation_payload import git, worker_repository
from .test_registry import verified_operation


def repositories(tmp_path: Path):
    worker, parent, candidate = worker_repository(tmp_path)
    old = tmp_path / "old"
    subprocess.run(
        ["git", "clone", "--quiet", str(worker), str(old)],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    git(old, "reset", "--hard", parent)
    git(old, "branch", "-M", "main")
    new = tmp_path / "canonical.git"
    subprocess.run(
        ["git", "init", "--quiet", "--bare", str(new)],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    authority = (tmp_path / "authority").resolve()
    old_controller = GitAdoptionRepository(
        old.resolve(),
        role="old_bootstrap",
        authority_root=authority,
        effective_at=REQUESTED,
    )
    new_controller = GitAdoptionRepository(
        new.resolve(),
        role="new_canonical",
        authority_root=authority,
        effective_at=REQUESTED,
        candidate_source=worker,
    )
    return worker, parent, candidate, old_controller, new_controller


def real_adoption_values(tmp_path: Path):
    worker, parent, candidate = worker_repository(tmp_path)
    parent_tree = git(worker, "rev-parse", f"{parent}^{{tree}}")
    chain = verified_chain()
    (
        registry,
        candidate_result,
        publication,
        publication_verification,
        handoff,
        handoff_verification,
        _destination,
    ) = claimed_handoff(
        tmp_path,
        chain,
        candidate_commit=parent,
        candidate_tree=parent_tree,
    )

    old_path = tmp_path / "old-repo"
    subprocess.run(
        ["git", "clone", "--quiet", str(worker), str(old_path)],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    git(old_path, "reset", "--hard", parent)
    git(old_path, "branch", "-M", "main")
    new_path = tmp_path / "new-repo.git"
    subprocess.run(
        ["git", "init", "--quiet", "--bare", str(new_path)],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    git_authority = (tmp_path / "git-adoption-authority").resolve()
    old = GitAdoptionRepository(
        old_path.resolve(),
        role="old_bootstrap",
        authority_root=git_authority,
        effective_at=REQUESTED,
    )
    new = GitAdoptionRepository(
        new_path.resolve(),
        role="new_canonical",
        authority_root=git_authority,
        effective_at=REQUESTED,
        candidate_source=worker,
    )

    current = registry.current()
    entry = registry.object(current["entryDigest"])
    package_id = "real-git-package-001"
    namespace = f"refs/das-bootstrap/{package_id}/"
    foundation = build_foundation_payload_manifest(
        worker_repository=worker,
        candidate_commit=candidate,
        expected_parent=parent,
        manifest_id="real-git-foundation-001",
        created_at=PREPARED,
    )
    claim_adoption = build_claim_adoption_request(
        request_id="real-git-claim-adoption-001",
        package_id=package_id,
        root_digest=entry["rootDigest"],
        attempt_id=current["attemptId"],
        change_id=entry["changeId"],
        task_id=entry["taskId"],
        worker=entry["worker"],
        old_repository=str(old.path),
        new_repository=str(new.path),
        payload_manifest=foundation,
        allowed_staging_namespace=namespace,
        requested_at=PREPARED,
    )
    prepared = write_prepared_package(
        prepared_directory=(tmp_path / "real-git-prepared").resolve(),
        package_id=package_id,
        adoption_request=claim_adoption,
        payload_manifest=foundation,
        records={},
        manifest_id="real-git-prepared-001",
        created_at=PREPARED,
    )
    private = tmp_path / "private-adoption" / f"{package_id}.json"
    request = with_self_digest(
        {
            "schema": "bootstrap-adoption-prepare-request/v1",
            "operationId": "real-git-adopt-prepare-001",
            "packageId": package_id,
            "attemptId": current["attemptId"],
            "claimedHeadDigest": current["headDigest"],
            "rootDigest": entry["rootDigest"],
            "changeId": entry["changeId"],
            "taskId": entry["taskId"],
            "worker": entry["worker"],
            "oldRepositoryPath": str(old.path),
            "newRepositoryPath": str(new.path),
            "oldMain": parent,
            "newMainExpectedAbsent": True,
            "objectFormat": "sha1",
            "allowedStagingNamespace": namespace,
            "publicationReceiptDigest": publication["recordDigest"],
            "publicationVerificationDigest": publication_verification["recordDigest"],
            "handoffReceiptDigest": handoff["recordDigest"],
            "handoffVerificationDigest": handoff_verification["recordDigest"],
            "legacyTokenHash": candidate_result["tokenHash"],
            "privateStatePath": str(private.resolve()),
            "packageLifetimeSeconds": 600,
            "requestedAt": PREPARED,
        }
    )
    verifier, _authority, tool, descriptor = chain
    operation = verified_operation(
        verifier,
        tool,
        descriptor,
        "adopt_prepare",
        [
            request,
            candidate_result,
            publication,
            publication_verification,
            handoff,
            handoff_verification,
            claim_adoption,
            foundation,
            prepared,
        ],
    )
    return (
        chain,
        registry,
        AdoptionPrepareCoordinator(registry),
        candidate_result,
        publication,
        publication_verification,
        handoff,
        handoff_verification,
        request,
        old,
        new,
        FakeSecretProvider(private),
        operation,
        claim_adoption,
        foundation,
        prepared,
    )


def test_real_git_adoption_adapter_imports_and_zero_oid_publishes_exact_candidate(tmp_path: Path) -> None:
    _worker, parent, candidate, old, new = repositories(tmp_path)
    initial_old = old.snapshot()
    initial_new = new.snapshot()
    assert initial_old["main"] == parent
    assert initial_new["main"] is None
    assert initial_old["objectFormat"] == initial_new["objectFormat"] == "sha1"

    staging = "refs/das-bootstrap/package-001/candidate"
    with old.lock(), new.lock():
        old.drain()
        old.prefence()
        new.stage(staging, candidate)
        identity = new.candidate_identity(candidate)
        assert identity == {
            "commit": candidate,
            "tree": git(Path(_worker), "rev-parse", f"{candidate}^{{tree}}"),
            "parent": parent,
        }
        new.create_main_from_absent(candidate)
        new.remove_staging("refs/das-bootstrap/package-001/")
        old.permanent_fence()

    assert old.snapshot()["fenceMode"] == "permanent"
    assert old.snapshot()["main"] == parent
    assert new.snapshot()["main"] == candidate
    assert not any(ref.startswith("refs/das-bootstrap/") for ref in new.snapshot()["refs"])
    with old.lock(), pytest.raises(GitAdoptionError, match="cannot be reopened"):
        old.restore_access()


def test_protected_adoption_coordinator_publishes_real_git_candidate(tmp_path: Path) -> None:
    values = publish_setup(
        tmp_path,
        adoption_values=real_adoption_values(tmp_path),
        use_fake_controllers=False,
    )
    assert values["old"].snapshot()["fenceMode"] == "open"
    assert values["new"].snapshot()["main"] is None
    result, _verification = run_publish(values)
    assert result["newMain"] == values["package"]["candidateCommit"]
    assert values["old"].snapshot()["fenceMode"] == "permanent"
    assert values["old"].snapshot()["main"] == values["package"]["oldMain"]
    assert values["new"].snapshot()["main"] == values["package"]["candidateCommit"]
    assert not any(
        ref.startswith(values["package"]["allowedStagingNamespace"])
        for ref in values["new"].snapshot()["refs"]
    )


def test_protected_adoption_coordinator_recovers_real_git_post_cas_response_loss(tmp_path: Path) -> None:
    values = publish_setup(
        tmp_path,
        adoption_values=real_adoption_values(tmp_path),
        use_fake_controllers=False,
    )
    with pytest.raises(AdoptionPublishCrash, match="new_main_created"):
        run_publish(values, crash_after="new_main_created")
    assert values["old"].snapshot()["fenceMode"] == "prefenced"
    assert values["new"].snapshot()["main"] == values["package"]["candidateCommit"]
    result, _verification = run_publish(values)
    assert result["outcome"] == "published_pending_activation"
    assert values["old"].snapshot()["fenceMode"] == "permanent"


def test_protected_adoption_coordinator_cancels_real_git_pre_cas_package(tmp_path: Path) -> None:
    values = publish_setup(
        tmp_path,
        adoption_values=real_adoption_values(tmp_path),
        use_fake_controllers=False,
    )
    result, _verification = run_cancel(values, cancellation_inputs(values))
    assert result["outcome"] == "cancelled"
    assert values["old"].snapshot()["fenceMode"] == "open"
    assert values["new"].snapshot()["main"] is None
    assert values["new"].snapshot()["refs"] == []


def test_real_git_adoption_adapter_requires_lock_and_absent_main(tmp_path: Path) -> None:
    _worker, _parent, candidate, _old, new = repositories(tmp_path)
    staging = "refs/das-bootstrap/package-001/candidate"
    with pytest.raises(GitAdoptionError, match="exactly one endpoint lock"):
        new.stage(staging, candidate)
    with new.lock():
        new.stage(staging, candidate)
        new.create_main_from_absent(candidate)
        with pytest.raises(GitAdoptionError, match="already exists"):
            new.stage(staging, candidate)


def test_real_git_adoption_adapter_rejects_symlinked_repository(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _worker, _parent, _candidate, old, _new = repositories(source)
    link = tmp_path / "old-link"
    link.symlink_to(old.path)
    with pytest.raises(GitAdoptionError, match="non-symlink"):
        GitAdoptionRepository(
            link,
            role="old_bootstrap",
            authority_root=(tmp_path / "other-authority").resolve(),
            effective_at=REQUESTED,
        )
