from __future__ import annotations

import base64
import os
from pathlib import Path
import subprocess

import pytest

from dasops.protected import with_self_digest
from dasops.protected.claim import (
    ProtectedClaimError,
    activate_claim,
    activation_response,
    claim_ready,
    issue_activation_challenge,
    read_worker_lock,
)
from dasops.protected.completion import abort_completion, prepare_completion, publish_completion
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.state_store import ProtectedStateStore


TASKS = """# Tasks

| Task ID | Title | Owner | Status | Depends on | Verify gate |
|---|---|---|---|---|---|
| T-001 | Foundation | - | DONE | - | `verify-one` |
| T-002 | Complete me | - | TODO | T-001 | `verify-two` |

### T-001: Foundation
- Owner: -
- Status: DONE

### T-002: Complete me
- Owner: -
- Status: TODO
"""


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def active_claim(tmp_path: Path) -> tuple[BareCanonicalRepo, ProtectedStateStore, Path]:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    run("git", "init", "-b", "main", cwd=source)
    run("git", "config", "user.name", "Test", cwd=source)
    run("git", "config", "user.email", "test@example.invalid", cwd=source)
    tasks = source / "openspec" / "changes" / "demo" / "tasks.md"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(TASKS, encoding="utf-8")
    (source / "app.txt").write_text("before\n", encoding="utf-8")
    (source / "unrelated.txt").write_text("unchanged\n", encoding="utf-8")
    run("git", "add", ".", cwd=source)
    run("git", "commit", "-m", "seed", cwd=source)
    bare = tmp_path / "canonical.git"
    run("git", "init", "--bare", str(bare))
    os.chmod(bare, 0o700)
    run("git", "push", str(bare), "main:main", cwd=source)
    run("git", f"--git-dir={bare}", "symbolic-ref", "HEAD", "refs/heads/main")
    repo = BareCanonicalRepo(bare)
    store = ProtectedStateStore(repo)
    store.initialize(
        {
            "schema": "protected-task-policy/v1",
            "policyId": "POLICY-COMPLETION-001",
            "canonicalRepoPath": str(repo.path),
            "canonicalRef": "refs/heads/main",
            "allowedOperations": ["activate", "claim", "complete"],
            "leaseSecondsMin": 60,
            "leaseSecondsMax": 3600,
            "toolDigests": {"dasops": "sha256:" + "a" * 64},
        }
    )
    worker_lock = tmp_path / "worker" / "T-002.lock"
    claim_ready(
        repo=repo,
        store=store,
        change_id="demo",
        owner="worker-01",
        worker_lock_path=worker_lock,
        idempotency_key="completion-claim-worker-0001",
    )
    challenge = issue_activation_challenge(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
    )
    lock = read_worker_lock(worker_lock, store)
    token = base64.urlsafe_b64decode(lock["tokenBase64"] + "=")
    activate_claim(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=activation_response(token, challenge),
    )
    return repo, store, worker_lock


def completion_authorization(store: ProtectedStateStore, worker_lock: Path) -> tuple[dict, bytes]:
    challenge = issue_activation_challenge(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        operation="completion_authorization",
    )
    lock = read_worker_lock(worker_lock, store)
    token = base64.urlsafe_b64decode(lock["tokenBase64"] + "=")
    return challenge, activation_response(token, challenge)


def verification_for(request: dict) -> dict:
    return with_self_digest(
        {
            "schema": "protected-completion-verification/v1",
            "requestDigest": request["recordDigest"],
            "candidateCommit": request["candidateCommit"],
            "profileId": "TEST-COMPLETION-PROFILE-1",
            "outcome": "passed",
            "reportDigest": "sha256:" + "c" * 64,
            "verifierId": "external-test-verifier",
            "verifiedAt": "2026-07-16T10:00:00Z",
        }
    )


def approval_for(request: dict, action: str, canonical_head: str, verification_digest: str | None) -> dict:
    return with_self_digest(
        {
            "schema": "protected-completion-approval/v1",
            "approvalId": f"APPROVAL-{action.upper()}-0001",
            "authorityRef": "test-completion-root/epoch-1",
            "approvalSetDigest": "sha256:" + "d" * 64,
            "action": action,
            "requestDigest": request["recordDigest"],
            "candidateCommit": request["candidateCommit"],
            "canonicalHead": canonical_head,
            "verificationDigest": verification_digest,
            "requiredRoles": ["reviewer", "task_governance", "verifier"],
            "issuedAt": "2020-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
        }
    )


def role_verifier(_approval: dict, _expected: dict) -> dict[str, str]:
    return {
        "reviewer": "reviewer-identity",
        "task_governance": "governance-identity",
        "verifier": "verifier-identity",
    }


def prepare(repo: BareCanonicalRepo, store: ProtectedStateStore, worker_lock: Path, key: str) -> dict:
    challenge, response = completion_authorization(store, worker_lock)
    return prepare_completion(
        repo=repo,
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        idempotency_key=key,
        changes={"app.txt": (b"after\n", None)},
    )


def test_prepare_does_not_publish_and_publish_requires_external_review_and_verification(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    base = repo.head()
    request = prepare(repo, store, worker_lock, "completion-prepare-publish-0001")
    assert repo.head() == base
    assert request["changedPaths"] == ["app.txt", "openspec/changes/demo/tasks.md"]
    assert repo._run("rev-parse", f"{request['candidateCommit']}^").stdout.decode().strip() == base
    assert repo._run("diff", "--name-only", base, request["candidateCommit"]).stdout.decode().splitlines() == request["changedPaths"]
    assert store.read_state("demo", "T-002")["status"] == "completion_pending"
    assert read_worker_lock(worker_lock, store)["status"] == "completion_pending"
    verification = verification_for(request)
    approval = approval_for(request, "publish", base, verification["recordDigest"])
    with pytest.raises(ProtectedClaimError, match="independent.*verifier"):
        publish_completion(
            repo=repo,
            store=store,
            operation_id=request["operationId"],
            approval=approval,
            verification=verification,
            approval_verifier=None,
        )
    assert repo.head() == base
    result = publish_completion(
        repo=repo,
        store=store,
        operation_id=request["operationId"],
        approval=approval,
        verification=verification,
        approval_verifier=role_verifier,
    )
    assert result["outcome"] == "published"
    assert repo.head() == request["candidateCommit"]
    assert repo.read_path(repo.head(), "app.txt") == b"after\n"
    tasks = repo.read_path(repo.head(), "openspec/changes/demo/tasks.md").decode()
    assert "| T-002 | Complete me | worker-01 | DONE |" in tasks
    assert "- Status: DONE" in tasks
    assert store.read_state("demo", "T-002")["status"] == "completed"
    assert not worker_lock.exists()


def test_publish_retry_recovers_lost_response_after_exact_base_cas(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    request = prepare(repo, store, worker_lock, "completion-lost-response-0001")
    verification = verification_for(request)
    approval = approval_for(request, "publish", request["baseCommit"], verification["recordDigest"])
    original_write_state = store.write_state
    crashed = False

    def crash_once(value: dict):
        nonlocal crashed
        if value["status"] == "completed" and not crashed:
            crashed = True
            raise RuntimeError("simulated loss after completion CAS")
        return original_write_state(value)

    store.write_state = crash_once  # type: ignore[method-assign]
    kwargs = dict(
        repo=repo,
        store=store,
        operation_id=request["operationId"],
        approval=approval,
        verification=verification,
        approval_verifier=role_verifier,
    )
    with pytest.raises(RuntimeError, match="simulated loss"):
        publish_completion(**kwargs)
    assert repo.head() == request["candidateCommit"]
    assert store.read_state("demo", "T-002")["status"] == "completion_pending"
    store.write_state = original_write_state  # type: ignore[method-assign]
    kwargs["approval_verifier"] = None
    result = publish_completion(**kwargs)
    assert result["outcome"] == "published"
    assert store.read_state("demo", "T-002")["status"] == "completed"


def test_abort_is_no_cas_restores_active_and_consumed_challenge_cannot_prepare_again(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    base = repo.head()
    challenge, response = completion_authorization(store, worker_lock)
    common = dict(
        repo=repo,
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        changes={"app.txt": (b"after\n", None)},
    )
    request = prepare_completion(**common, idempotency_key="completion-abort-0001")
    approval = approval_for(request, "abort", base, None)
    result = abort_completion(
        repo=repo,
        store=store,
        operation_id=request["operationId"],
        approval=approval,
        approval_verifier=role_verifier,
    )
    assert result["outcome"] == "aborted_pre_cas"
    assert repo.head() == base
    assert store.read_state("demo", "T-002")["status"] == "active"
    assert read_worker_lock(worker_lock, store)["status"] == "active"
    with pytest.raises(ProtectedClaimError, match="already consumed"):
        prepare_completion(**common, idempotency_key="completion-abort-replay-0002")
    second_challenge, second_response = completion_authorization(store, worker_lock)
    second = prepare_completion(
        **{**common, "challenge_id": second_challenge["challengeId"], "response": second_response},
        idempotency_key="completion-after-abort-0003",
    )
    assert second["operationId"] != request["operationId"]
    assert repo.head() == base


def test_publish_base_drift_is_fenced_and_fresh_abort_binds_current_head(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    request = prepare(repo, store, worker_lock, "completion-drift-0001")
    drift, _tree = repo.build_single_path_commit(
        base_commit=request["baseCommit"],
        path="unrelated.txt",
        content=b"other task changed this\n",
        message="test: unrelated canonical change",
        timestamp="2026-07-16T10:30:00Z",
        scratch_root=store.scratch_root,
    )
    repo.cas(old_commit=request["baseCommit"], new_commit=drift)
    verification = verification_for(request)
    publish_approval = approval_for(request, "publish", request["baseCommit"], verification["recordDigest"])
    with pytest.raises(ProtectedClaimError, match="canonical ref drift"):
        publish_completion(
            repo=repo,
            store=store,
            operation_id=request["operationId"],
            approval=publish_approval,
            verification=verification,
            approval_verifier=role_verifier,
        )
    abort_approval = approval_for(request, "abort", drift, None)
    result = abort_completion(
        repo=repo,
        store=store,
        operation_id=request["operationId"],
        approval=abort_approval,
        approval_verifier=role_verifier,
    )
    assert result["outcome"] == "aborted_pre_cas"
    assert result["canonicalReadback"] == drift == repo.head()
    assert store.read_state("demo", "T-002")["canonicalCommit"] == drift
    assert read_worker_lock(worker_lock, store)["candidateCommit"] == drift


def test_prepare_retry_recovers_accepted_challenge_without_reproving_token(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    challenge, response = completion_authorization(store, worker_lock)
    original_builder = repo.build_path_changes_commit
    crashed = False

    def crash_once(**kwargs):
        nonlocal crashed
        if not crashed:
            crashed = True
            raise RuntimeError("simulated loss after challenge consumption")
        return original_builder(**kwargs)

    repo.build_path_changes_commit = crash_once  # type: ignore[method-assign]
    kwargs = dict(
        repo=repo,
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        idempotency_key="completion-consumption-recovery-0001",
        changes={"app.txt": (b"after\n", None)},
    )
    with pytest.raises(RuntimeError, match="simulated loss"):
        prepare_completion(**kwargs)
    repo.build_path_changes_commit = original_builder  # type: ignore[method-assign]
    kwargs["response"] = b"not-the-original-accepted-proof"
    request = prepare_completion(**kwargs)
    consumption = store.read_receipt(
        store.read_state("demo", "T-002")["operationId"],
        f"challenge-{challenge['challengeId']}",
    )
    assert consumption is not None
    assert request["authorizationResponseDigest"] == consumption["authorizationResponseDigest"]
    assert store.read_state("demo", "T-002")["status"] == "completion_pending"
