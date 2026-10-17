from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from dasops.protected import with_self_digest
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.routing import ProtectedRouteError, abort_route, prepare_route, publish_route
from dasops.protected.state_store import ProtectedStateStore


SOURCES = ("S-001", "S-002", "S-003")
TARGETS = tuple(f"T-{index:03d}" for index in range(1, 12))


def tasks_text(*, incomplete_source: bool = False) -> str:
    rows = [
        "# Tasks",
        "",
        "| Task ID | Title | Owner | Status | Depends on | Verify gate |",
        "|---|---|---|---|---|---|",
    ]
    for task_id in SOURCES:
        status = "TODO" if incomplete_source and task_id == "S-003" else "DONE"
        rows.append(f"| {task_id} | Source {task_id} | - | {status} | - | `verify-source` |")
    for task_id in TARGETS:
        rows.append(
            f"| {task_id} | Target {task_id} | - | BLOCKED | {','.join(SOURCES)} | `verify-target` |"
        )
    rows.append("")
    for task_id in (*SOURCES, *TARGETS):
        status = "BLOCKED" if task_id in TARGETS else (
            "TODO" if incomplete_source and task_id == "S-003" else "DONE"
        )
        rows.extend([f"### {task_id}: Task", "- Owner: -", f"- Status: {status}", ""])
    return "\n".join(rows)


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def initialized(tmp_path: Path, *, incomplete_source: bool = False) -> tuple[BareCanonicalRepo, ProtectedStateStore]:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    run("git", "init", "-b", "main", cwd=source)
    run("git", "config", "user.name", "Test", cwd=source)
    run("git", "config", "user.email", "test@example.invalid", cwd=source)
    tasks = source / "openspec" / "changes" / "demo" / "tasks.md"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(tasks_text(incomplete_source=incomplete_source), encoding="utf-8")
    (source / "unrelated.txt").write_text("before\n", encoding="utf-8")
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
            "policyId": "POLICY-ROUTE-001",
            "canonicalRepoPath": str(repo.path),
            "canonicalRef": "refs/heads/main",
            "allowedOperations": ["route_abort", "route_prepare", "route_publish"],
            "leaseSecondsMin": 60,
            "leaseSecondsMax": 3600,
            "toolDigests": {"dasops": "sha256:" + "a" * 64},
        }
    )
    return repo, store


def receipts() -> dict[str, dict]:
    return {
        task_id: with_self_digest(
            {
                "schema": "test-source-result/v1",
                "taskId": task_id,
                "outcome": "passed",
            }
        )
        for task_id in SOURCES
    }


def request_for(repo: BareCanonicalRepo, source_receipts: dict[str, dict], request_id: str = "route-001") -> dict:
    return with_self_digest(
        {
            "schema": "protected-route-request/v1",
            "requestId": request_id,
            "changeId": "demo",
            "baseCommit": repo.head(),
            "sourceResults": [
                {"taskId": task_id, "resultDigest": source_receipts[task_id]["recordDigest"]}
                for task_id in SOURCES
            ],
            "targetTransitions": [
                {"taskId": task_id, "fromStatus": "BLOCKED", "toStatus": "TODO", "owner": "-"}
                for task_id in TARGETS
            ],
        }
    )


def approval_for(request: dict, prepared: dict, action: str, head: str) -> dict:
    return with_self_digest(
        {
            "schema": "protected-route-approval/v1",
            "approvalId": f"ROUTE-{action.upper()}-001",
            "authorityRef": "test-route-root/epoch-1",
            "approvalSetDigest": "sha256:" + "b" * 64,
            "action": action,
            "requestDigest": request["recordDigest"],
            "candidateCommit": prepared["candidateCommit"],
            "canonicalHead": head,
            "requiredRoles": ["task_governance", "verifier"],
            "issuedAt": "2020-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
        }
    )


def role_verifier(_approval: dict, _expected: dict) -> dict[str, str]:
    return {"task_governance": "governance-identity", "verifier": "verifier-identity"}


def test_eleven_target_route_prepares_without_cas_and_publishes_atomically(tmp_path: Path) -> None:
    repo, store = initialized(tmp_path)
    source_receipts = receipts()
    request = request_for(repo, source_receipts)
    base = repo.head()
    prepared = prepare_route(repo=repo, store=store, request=request, source_receipts=source_receipts)
    assert prepared["outcome"] == "prepared"
    assert repo.head() == base
    assert repo._run("rev-parse", f"{prepared['candidateCommit']}^").stdout.decode().strip() == base
    assert repo._run("diff", "--name-only", base, prepared["candidateCommit"]).stdout.decode().splitlines() == [
        "openspec/changes/demo/tasks.md"
    ]
    candidate_tasks = repo.read_path(prepared["candidateCommit"], "openspec/changes/demo/tasks.md").decode()
    for task_id in TARGETS:
        assert f"| {task_id} | Target {task_id} | - | TODO |" in candidate_tasks
    approval = approval_for(request, prepared, "publish", base)
    with pytest.raises(ProtectedRouteError, match="independent.*verifier"):
        publish_route(
            repo=repo,
            store=store,
            request_id=request["requestId"],
            approval=approval,
            approval_verifier=None,
        )
    result = publish_route(
        repo=repo,
        store=store,
        request_id=request["requestId"],
        approval=approval,
        approval_verifier=role_verifier,
    )
    assert result["outcome"] == "published"
    assert repo.head() == prepared["candidateCommit"]


@pytest.mark.parametrize("mutation", ["missing_receipt", "extra_receipt", "reordered_sources", "missing_source_row"])
def test_route_denominator_and_order_fail_closed(tmp_path: Path, mutation: str) -> None:
    repo, store = initialized(tmp_path, incomplete_source=mutation == "missing_source_row")
    source_receipts = receipts()
    request = request_for(repo, source_receipts, request_id=f"route-{mutation}")
    if mutation == "missing_receipt":
        source_receipts.pop("S-003")
    elif mutation == "extra_receipt":
        source_receipts["S-999"] = with_self_digest(
            {"schema": "test-source-result/v1", "taskId": "S-999", "outcome": "passed"}
        )
    elif mutation == "reordered_sources":
        subject = dict(request)
        subject.pop("recordDigest")
        subject["sourceResults"] = list(reversed(subject["sourceResults"]))
        request = with_self_digest(subject)
    base = repo.head()
    with pytest.raises(ProtectedRouteError):
        prepare_route(repo=repo, store=store, request=request, source_receipts=source_receipts)
    assert repo.head() == base
    assert store.read_receipt(request["requestId"], "route-prepared") is None


def test_route_publish_retry_recovers_response_loss_after_cas(tmp_path: Path) -> None:
    repo, store = initialized(tmp_path)
    source_receipts = receipts()
    request = request_for(repo, source_receipts, request_id="route-lost-response")
    prepared = prepare_route(repo=repo, store=store, request=request, source_receipts=source_receipts)
    approval = approval_for(request, prepared, "publish", request["baseCommit"])
    original_write_receipt = store.write_receipt
    crashed = False

    def crash_once(operation_id: str, kind: str, value: dict):
        nonlocal crashed
        if kind == "route-result" and not crashed:
            crashed = True
            raise RuntimeError("simulated route response loss")
        return original_write_receipt(operation_id, kind, value)

    store.write_receipt = crash_once  # type: ignore[method-assign]
    kwargs = dict(
        repo=repo,
        store=store,
        request_id=request["requestId"],
        approval=approval,
        approval_verifier=role_verifier,
    )
    with pytest.raises(RuntimeError, match="simulated route response loss"):
        publish_route(**kwargs)
    assert repo.head() == prepared["candidateCommit"]
    store.write_receipt = original_write_receipt  # type: ignore[method-assign]
    kwargs["approval_verifier"] = None
    result = publish_route(**kwargs)
    assert result["outcome"] == "published"
    assert result["canonicalReadback"] == prepared["candidateCommit"]


def test_route_base_drift_blocks_publish_and_fresh_abort_is_no_cas(tmp_path: Path) -> None:
    repo, store = initialized(tmp_path)
    source_receipts = receipts()
    request = request_for(repo, source_receipts, request_id="route-drift")
    prepared = prepare_route(repo=repo, store=store, request=request, source_receipts=source_receipts)
    drift, _tree = repo.build_single_path_commit(
        base_commit=request["baseCommit"],
        path="unrelated.txt",
        content=b"changed elsewhere\n",
        message="test: unrelated route drift",
        timestamp="2026-07-16T10:45:00Z",
        scratch_root=store.scratch_root,
    )
    repo.cas(old_commit=request["baseCommit"], new_commit=drift)
    publish_approval = approval_for(request, prepared, "publish", request["baseCommit"])
    with pytest.raises(ProtectedRouteError, match="canonical ref drift"):
        publish_route(
            repo=repo,
            store=store,
            request_id=request["requestId"],
            approval=publish_approval,
            approval_verifier=role_verifier,
        )
    abort_approval = approval_for(request, prepared, "abort", drift)
    result = abort_route(
        repo=repo,
        store=store,
        request_id=request["requestId"],
        approval=abort_approval,
        approval_verifier=role_verifier,
    )
    assert result["outcome"] == "aborted_pre_cas"
    assert result["canonicalReadback"] == drift == repo.head()


def test_route_prepare_retry_rebuilds_exact_candidate_after_receipt_loss(tmp_path: Path) -> None:
    repo, store = initialized(tmp_path)
    source_receipts = receipts()
    request = request_for(repo, source_receipts, request_id="route-prepare-recovery")
    original_write_receipt = store.write_receipt
    crashed = False

    def crash_once(operation_id: str, kind: str, value: dict):
        nonlocal crashed
        if kind == "route-prepared" and not crashed:
            crashed = True
            raise RuntimeError("simulated prepared receipt loss")
        return original_write_receipt(operation_id, kind, value)

    store.write_receipt = crash_once  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="simulated prepared receipt loss"):
        prepare_route(repo=repo, store=store, request=request, source_receipts=source_receipts)
    intent = store.read_receipt(request["requestId"], "route-prepare-intent")
    assert intent is not None
    assert store.read_receipt(request["requestId"], "route-request") is not None
    store.write_receipt = original_write_receipt  # type: ignore[method-assign]
    prepared = prepare_route(repo=repo, store=store, request=request, source_receipts=source_receipts)
    expected, _tree = repo.build_single_path_commit(
        base_commit=request["baseCommit"],
        path="openspec/changes/demo/tasks.md",
        content=repo.read_path(prepared["candidateCommit"], "openspec/changes/demo/tasks.md"),
        message=f"chore(tasks): protected route {request['requestId']}",
        timestamp=intent["preparedAt"],
        scratch_root=store.scratch_root,
    )
    assert prepared["candidateCommit"] == expected
    assert repo.head() == request["baseCommit"]
