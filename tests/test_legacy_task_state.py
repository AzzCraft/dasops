"""Behavioral regressions for cooperative state transitions, not protected auth."""
import json
import multiprocessing
import shlex
import sys
from pathlib import Path

import pytest

from dasops import legacy_task_state as state
from dasops.locks import (claim_task, claim_ready_task, complete_task, inspect_lock,
                          read_lock, reclaim_lock, release_task, renew_lock)
from dasops.scaffold import list_tasks


@pytest.mark.parametrize("transition", ["claim", "release"])
def test_inspect_existence_matches_snapshot_after_waiting_for_writer(tmp_path, monkeypatch, transition):
    from contextlib import contextmanager
    from dasops import __main__ as cli

    project(tmp_path)
    if transition == "release":
        claim(tmp_path)
    original_guard = state.guard
    changed = False

    @contextmanager
    def writer_before_reader(change, *, write=False):
        nonlocal changed
        if not write and not changed:
            changed = True
            if transition == "claim":
                claim(tmp_path)
            else:
                release_task(repo_root=tmp_path, change_id="sample", task_id="T-167", owner="worker-a")
        with original_guard(change, write=write):
            yield

    monkeypatch.setattr(state, "guard", writer_before_reader)
    # Force the writer between the caller's initial stat and guarded snapshot.
    # The public CLI uses this same inspector; no scheduling sleeps are needed.
    result = cli.inspect_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", expect_owner="worker-a")
    assert changed and result["valid"] is True
    assert result["exists"] is (transition == "claim")
    assert (result["lock"] is not None) is result["exists"]
    assert result["ownerMatches"] is result["exists"]


def test_worker_hints_refuse_pending_and_inconsistent_state(tmp_path):
    from dasops.scaffold import read_task_hints
    change = project(tmp_path)
    claim(tmp_path)
    pending = change / ".dasops-local/pending.json"
    pending.write_text("{}")
    before = (change / "tasks.md").read_bytes()
    with pytest.raises(SystemExit, match="recovery_required"):
        read_task_hints(repo_root=tmp_path, change_id="sample", task_id="T-167")
    assert pending.read_text() == "{}" and (change / "tasks.md").read_bytes() == before
    pending.unlink()
    (change / "tasks.md").write_bytes(before.replace(b"worker-a", b"other-worker"))
    with pytest.raises(SystemExit, match="inconsistent_task_state"):
        read_task_hints(repo_root=tmp_path, change_id="sample", task_id="T-167")


@pytest.mark.parametrize("command", ["claim-task", "claim-ready"])
def test_cli_claim_returns_its_committed_snapshot(tmp_path, monkeypatch, capsys, command):
    from dasops import __main__ as cli
    project(tmp_path)
    monkeypatch.setattr(cli, "_resolve_repo_root", lambda path: tmp_path)
    name = "claim_task_with_result" if command == "claim-task" else "claim_ready_task_with_result"
    operation = getattr(cli, name)
    def take_over_after_commit(**kwargs):
        result = operation(**kwargs)
        reclaim_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", new_owner="worker-b", reason="synthetic concurrent takeover", force=True)
        return result
    monkeypatch.setattr(cli, name, take_over_after_commit)
    argv = [command, "--repo-root", str(tmp_path), "--change-id", "sample", "--owner", "worker-a", "--json"]
    if command == "claim-task": argv += ["--task-id", "T-167"]
    assert cli.main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["owner"] == "worker-a" and result["status"] == "IN_PROGRESS"
    assert read_lock(tmp_path / "openspec/changes/sample/task_locks/T-167.lock").owner == "worker-b"


def test_cli_claim_json_preserves_corruption_failure(tmp_path, monkeypatch, capsys):
    from dasops import __main__ as cli
    change = project(tmp_path)
    (change / "task_locks").mkdir()
    (change / "task_locks/T-167.lock").write_text("owner: [broken")
    monkeypatch.setattr(cli, "_resolve_repo_root", lambda path: tmp_path)
    assert cli.main(["claim-task", "--repo-root", str(tmp_path), "--change-id", "sample", "--task-id", "T-167", "--owner", "worker-a", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False and "invalid_lock" in result["message"]
    assert result["currentOwner"] is None


def project(tmp_path, gate=None):
    change = tmp_path / "openspec/changes/sample"
    change.mkdir(parents=True)
    gate = gate or f'{shlex.quote(sys.executable)} -c "pass"'
    (change / "tasks.md").write_text(
        "| Task ID | Title | Owner | Status | Depends On | Verify Gate |\n"
        "|---|---|---|---|---|---|\n"
        f"| T-167 | first | - | TODO | - | `{gate}` |\n"
        f"| T-168 | second | - | TODO | - | `{gate}` |\n")
    return change


def claim(root, task="T-167", owner="worker-a"):
    return claim_task(repo_root=root, change_id="sample", task_id=task, owner=owner)


def _claim_child(root, task, owner, entered, release, started, queue):
    original = state._install
    if entered is not None:
        def pause(path, data):
            if path.name == "pending.json":
                entered.set()
                if not release.wait(10):
                    raise RuntimeError("test barrier timeout")
            return original(path, data)
        state._install = pause
    started.set()
    try:
        claim(Path(root), task, owner)
        queue.put((owner, "ok"))
    except SystemExit as exc:
        queue.put((owner, str(exc)))


@pytest.mark.parametrize("same_task", [True, False])
def test_overlapping_claims_preserve_the_entire_index(tmp_path, same_task):
    change = project(tmp_path)
    ctx = multiprocessing.get_context("fork")
    entered, release, started_a, started_b = [ctx.Event() for _ in range(4)]
    queue = ctx.Queue()
    a = ctx.Process(target=_claim_child, args=(str(tmp_path), "T-167", "worker-a", entered, release, started_a, queue))
    b = ctx.Process(target=_claim_child, args=(str(tmp_path), "T-167" if same_task else "T-168", "worker-b", None, release, started_b, queue))
    try:
        a.start()
        assert entered.wait(10)
        b.start()
        assert started_b.wait(10)
        release.set()
        a.join(10)
        b.join(10)
        assert a.exitcode == b.exitcode == 0
        outcomes = dict(queue.get(timeout=2) for _ in range(2))
        assert outcomes["worker-a"] == "ok"
        assert (outcomes["worker-b"] == "ok") is not same_task
        rows = list_tasks(repo_root=tmp_path, change_id="sample")
        assert read_lock(change / "task_locks/T-167.lock").owner == "worker-a"
        if not same_task:
            assert read_lock(change / "task_locks/T-168.lock").owner == "worker-b"
        assert len(rows) == 2
    finally:
        release.set()
        for p in (a, b):
            if p.is_alive():
                p.terminate()
            if p.pid:
                p.join(2)
        queue.close()
        queue.join_thread()


@pytest.mark.parametrize("entry", [claim_task, claim_ready_task])
def test_corrupt_lock_is_visible_and_no_new_state_is_committed(tmp_path, entry):
    change = project(tmp_path)
    (change / "task_locks").mkdir()
    lock = change / "task_locks/T-167.lock"
    lock.write_text("owner: [broken")
    before = (change / "tasks.md").read_bytes()
    kwargs = dict(repo_root=tmp_path, change_id="sample", owner="worker-a")
    if entry is claim_task:
        kwargs["task_id"] = "T-167"
    with pytest.raises(SystemExit, match="invalid_lock"):
        entry(**kwargs)
    assert (change / "tasks.md").read_bytes() == before
    assert lock.read_text() == "owner: [broken"
    result = inspect_lock(repo_root=tmp_path, change_id="sample", task_id="T-167")
    assert result["exists"] is True and result["valid"] is False
    assert result["error"] == "invalid_lock"


@pytest.mark.parametrize("boundary", ["before-pending", "before-tasks", "before-lock", "after-pair"])
def test_fixed_pair_failure_and_exact_recovery(tmp_path, monkeypatch, boundary):
    change = project(tmp_path)
    before = (change / "tasks.md").read_bytes()
    original, unlink = state._install, Path.unlink
    def install(path, data):
        if ((boundary == "before-pending" and path.name == "pending.json") or
            (boundary == "before-tasks" and path.name == "tasks.md") or
            (boundary == "before-lock" and path.suffix == ".lock")):
            raise OSError("synthetic owned write failure")
        return original(path, data)
    def remove(path, *args, **kwargs):
        if boundary == "after-pair" and path.name == "pending.json":
            raise OSError("synthetic cleanup failure")
        return unlink(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(state, "_install", install)
        patch.setattr(Path, "unlink", remove)
        with pytest.raises((OSError, SystemExit)):
            claim(tmp_path)
    pending = change / ".dasops-local/pending.json"
    if boundary == "before-pending":
        assert not pending.exists()
        assert (change / "tasks.md").read_bytes() == before
        assert not (change / "task_locks/T-167.lock").exists()
        return
    recorded = json.loads(pending.read_bytes())
    with pytest.raises(SystemExit, match="recovery_required"):
        list_tasks(repo_root=tmp_path, change_id="sample")
    with state.guard(change, write=True):
        pass
    assert not pending.exists()
    import base64
    for path, image in zip([change / "tasks.md", change / "task_locks/T-167.lock"], recorded["targets"]):
        assert path.read_bytes() == base64.b64decode(image["after"]["data"])


def test_recovery_conflict_preserves_all_evidence(tmp_path, monkeypatch):
    change = project(tmp_path)
    original = state._install
    def fail(path, data):
        if path.name == "tasks.md":
            raise OSError("synthetic failure")
        return original(path, data)
    with monkeypatch.context() as patch:
        patch.setattr(state, "_install", fail)
        with pytest.raises(SystemExit, match="recovery_required"):
            claim(tmp_path)
    pending = change / ".dasops-local/pending.json"
    evidence = pending.read_bytes()
    (change / "tasks.md").write_text("manual third state")
    with pytest.raises(SystemExit, match="recovery_conflict"):
        with state.guard(change, write=True):
            pass
    assert (change / "tasks.md").read_text() == "manual third state"
    assert pending.read_bytes() == evidence
    assert not (change / "task_locks/T-167.lock").exists()


def _die_after_first_target(root):
    import os
    original = state._install
    def install(path, data):
        if path.suffix == ".lock":
            os._exit(23)
        return original(path, data)
    state._install = install
    claim(Path(root))


def _recover_in_new_process(change):
    with state.guard(Path(change), write=True):
        pass


def test_actual_process_exit_recovers_in_a_new_process(tmp_path):
    change = project(tmp_path)
    ctx = multiprocessing.get_context("fork")
    child = ctx.Process(target=_die_after_first_target, args=(str(tmp_path),))
    child.start()
    child.join(10)
    assert child.exitcode == 23
    pending = json.loads((change / ".dasops-local/pending.json").read_bytes())
    recovery = ctx.Process(target=_recover_in_new_process, args=(str(change),))
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == 0
    import base64
    assert (change / "task_locks/T-167.lock").read_bytes() == base64.b64decode(pending["targets"][1]["after"]["data"])


def test_release_delete_interruption_is_recoverable(tmp_path, monkeypatch):
    change = project(tmp_path)
    path = claim(tmp_path)
    original = state._install
    def fail(path, data):
        if path.suffix == ".lock":
            raise OSError("synthetic lock deletion failure")
        return original(path, data)
    with monkeypatch.context() as patch:
        patch.setattr(state, "_install", fail)
        with pytest.raises(SystemExit, match="recovery_required"):
            release_task(repo_root=tmp_path, change_id="sample", task_id="T-167", owner="worker-a")
    with state.guard(change, write=True):
        pass
    assert not path.exists()
    assert "| T-167 | first | worker-a | TODO |" in (change / "tasks.md").read_text()


def test_done_dependency_and_duplicate_or_misbound_state(tmp_path):
    change = project(tmp_path)
    text = (change / "tasks.md").read_text().replace("| T-168 | second | - | TODO | - |", "| T-168 | second | - | TODO | T-167 |")
    (change / "tasks.md").write_text(text)
    path = claim_ready_task(repo_root=tmp_path, change_id="sample", owner="worker-a")
    assert path.stem == "T-167"
    assert claim_ready_task(repo_root=tmp_path, change_id="sample", owner="worker-b") is None
    complete_task(repo_root=tmp_path, change_id="sample", task_id="T-167", owner="worker-a")
    assert claim_ready_task(repo_root=tmp_path, change_id="sample", owner="worker-b").stem == "T-168"
    content = path.read_text()
    path.write_text(content.replace("taskId: T-167", "taskId: T-168"))
    with pytest.raises(SystemExit, match="invalid_lock"):
        read_lock(path)


def test_reclaim_history_survives_renew_and_old_token_cannot_write(tmp_path):
    project(tmp_path)
    path = claim(tmp_path)
    old = read_lock(path)
    reclaim_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", new_owner="worker-b", reason="synthetic handoff", force=True)
    current = read_lock(path)
    for _ in range(2):
        renew_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", owner="worker-b", lock_token=current.lock_token)
        assert read_lock(path).audit_history == current.audit_history
    with pytest.raises(SystemExit, match="identity_mismatch"):
        renew_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", owner="worker-a", lock_token=old.lock_token)
    with pytest.raises(SystemExit, match="invalid_release_status"):
        release_task(repo_root=tmp_path, change_id="sample", task_id="T-167", owner="worker-b", status="IN_PROGRESS")


@pytest.mark.parametrize("owner", ["worker | DONE", "worker\nother", " worker", "-"])
def test_invalid_owner_never_commits_a_broken_markdown_pair(tmp_path, owner):
    change = project(tmp_path)
    before = (change / "tasks.md").read_bytes()
    with pytest.raises(SystemExit, match="invalid_owner"):
        claim(tmp_path, owner=owner)
    assert (change / "tasks.md").read_bytes() == before
    assert not (change / "task_locks/T-167.lock").exists()


@pytest.mark.parametrize("task", ["T-167", "T-168"])
@pytest.mark.parametrize("force", [True, False])
def test_completion_policy_is_independent_of_id_and_force(tmp_path, task, force):
    change = project(tmp_path, f'{shlex.quote(sys.executable)} -c "raise SystemExit(7)"')
    before = (change / "tasks.md").read_bytes()
    with pytest.raises(SystemExit, match="verification_failed_exit_7"):
        complete_task(repo_root=tmp_path, change_id="sample", task_id=task, owner="worker-a", force=force)
    assert (change / "tasks.md").read_bytes() == before
    with pytest.raises(SystemExit, match="requires_reason"):
        complete_task(repo_root=tmp_path, change_id="sample", task_id=task, owner="worker-a", record_only=True)
    path = complete_task(repo_root=tmp_path, change_id="sample", task_id=task, owner="worker-a", record_only=True, reason="historical status import")
    lock = read_lock(path)
    assert lock.status == "DONE"
    assert lock.audit_history[-1]["verification"] == "not_run"


@pytest.mark.parametrize("takeover", [False, True])
def test_completion_runs_outside_guard_and_rechecks_current_subject(tmp_path, takeover):
    change = project(tmp_path)
    lock = read_lock(claim(tmp_path))
    gate = tmp_path / "gate.py"
    module_root = str(Path(__file__).resolve().parents[1])
    action = ("reclaim_lock(repo_root=root,change_id='sample',task_id='T-167',new_owner='worker-b',reason='handoff',force=True)" if takeover else
              f"renew_lock(repo_root=root,change_id='sample',task_id='T-167',owner='worker-a',lock_token={lock.lock_token!r})\nclaim_task(repo_root=root,change_id='sample',task_id='T-168',owner='worker-other')")
    gate.write_text(f"import sys\nsys.path.insert(0,{module_root!r})\nfrom pathlib import Path\nfrom dasops.locks import *\nroot=Path({str(tmp_path)!r})\n{action}\n")
    source = (change / "tasks.md").read_text()
    source = source.replace(f'`{shlex.quote(sys.executable)} -c "pass"`', f"`{shlex.quote(sys.executable)} {shlex.quote(str(gate))}`", 1)
    (change / "tasks.md").write_text(source)
    kwargs = dict(repo_root=tmp_path, change_id="sample", task_id="T-167", owner="worker-a")
    if takeover:
        with pytest.raises(SystemExit):
            complete_task(**kwargs)
        assert read_lock(change / "task_locks/T-167.lock").owner == "worker-b"
    else:
        complete_task(**kwargs)
        assert read_lock(change / "task_locks/T-167.lock").status == "DONE"
        assert read_lock(change / "task_locks/T-168.lock").owner == "worker-other"
