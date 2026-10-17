from __future__ import annotations

from pathlib import Path
import os
import subprocess

import pytest

from dasops.bootstrap.git_claim import GitCanonicalClaimPublisher, GitClaimPublisherError

from .test_authority import verified_chain
from .test_foundation_payload import git, worker_repository
from .test_legacy_claim import publish


def publisher_repository(tmp_path: Path):
    worker, parent, candidate = worker_repository(tmp_path)
    repository = tmp_path / "bootstrap-repo"
    subprocess.run(
        ["git", "clone", "--quiet", str(worker), str(repository)],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    git(repository, "reset", "--hard", parent)
    git(repository, "branch", "-M", "main")
    publisher = GitCanonicalClaimPublisher(
        repository.resolve(),
        authority_root=(tmp_path / "claim-publisher-authority").resolve(),
    )
    return worker, repository, parent, candidate, publisher


def test_real_claim_publisher_exact_base_cas_and_readback(tmp_path: Path) -> None:
    _worker, _repository, parent, candidate, publisher = publisher_repository(tmp_path)
    assert publisher.head() == parent
    publisher.cas(old_commit=parent, new_commit=candidate)
    assert publisher.head() == candidate
    with pytest.raises(GitClaimPublisherError, match="changed before"):
        publisher.cas(old_commit=parent, new_commit=candidate)


def test_real_claim_publisher_rejects_wrong_ancestry_and_symlink(tmp_path: Path) -> None:
    _worker, repository, parent, _candidate, publisher = publisher_repository(tmp_path)
    tree = git(repository, "rev-parse", f"{parent}^{{tree}}")
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    wrong = subprocess.run(
        ["git", "-C", str(repository), "commit-tree", tree],
        input=b"orphan\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=True,
    ).stdout.decode().strip()
    with pytest.raises(GitClaimPublisherError, match="single-parent child"):
        publisher.cas(old_commit=parent, new_commit=wrong)

    link = tmp_path / "bootstrap-link"
    link.symlink_to(repository)
    with pytest.raises(GitClaimPublisherError, match="non-symlink"):
        GitCanonicalClaimPublisher(
            link,
            authority_root=(tmp_path / "other-authority").resolve(),
        )


def test_claim_coordinator_publishes_through_real_git_exact_base_cas(tmp_path: Path) -> None:
    worker, _repository, parent, candidate, publisher = publisher_repository(tmp_path)
    tree = git(worker, "rev-parse", f"{candidate}^{{tree}}")
    values = publish(
        tmp_path,
        verified_chain(),
        candidate_commit=candidate,
        candidate_tree=tree,
        base_commit=parent,
        claim_publisher=publisher,
    )
    registry, _coordinator, _lock, _adapter, result, selected, _issuer, receipt, _verification, _request, _operation = values
    assert selected is publisher
    assert publisher.head() == candidate == result["candidateCommit"]
    assert receipt["canonicalReadback"] == candidate
    assert registry.current()["state"] == "claimed"
