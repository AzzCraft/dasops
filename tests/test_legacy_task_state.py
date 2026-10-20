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


@pytest.mark.parametrize("owner,force", [("worker-a", False), ("worker-a", True), ("worker-b", False), ("worker-b", True)])
def test_stale_claim_requires_explicit_reclaim(tmp_path, owner, force):
    import yaml
    change = project(tmp_path)
    path = claim(tmp_path)
    record = yaml.safe_load(path.read_text())
    for key in ("claimedAt", "updatedAt", "heartbeatAt"):
        record[key] = "2000-01-01T00:00:00+00:00"
    path.write_text(yaml.safe_dump(record))
    before = path.read_bytes(), (change / "tasks.md").read_bytes()
    with pytest.raises(state.StateError, match="stale_lock_requires_reclaim"):
        claim_task(repo_root=tmp_path, change_id="sample", task_id="T-167", owner=owner, force=force)
    assert before == (path.read_bytes(), (change / "tasks.md").read_bytes())
    reclaim_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", new_owner=owner, reason="abandoned attempt")
    fresh = read_lock(path)
    assert fresh.lock_token != record["lockToken"] and fresh.version > record["version"]
    with pytest.raises(SystemExit):
        renew_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", owner=owner, lock_token=record["lockToken"])


def test_fresh_same_owner_claim_is_write_free(tmp_path, monkeypatch):
    project(tmp_path)
    path = claim(tmp_path)
    before = path.read_bytes(), path.stat().st_mtime_ns
    monkeypatch.setattr(state, "commit", lambda *a, **kw: pytest.fail("idempotent claim wrote state"))
    assert claim(tmp_path) == path
    assert before == (path.read_bytes(), path.stat().st_mtime_ns)


@pytest.mark.parametrize("defect", ["active", "done", "todo", "stale", "owner", "pending", "corrupt", "inconsistent", "prompt-failure"])
def test_actual_worker_precheck_never_starts_on_refusal(tmp_path, defect):
    import os
    import subprocess
    import yaml
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    change = project(tmp_path)
    path = claim(tmp_path)
    record = yaml.safe_load(path.read_text())
    if defect in {"done", "todo"}:
        record["status"] = defect.upper()
        (change / "tasks.md").write_text((change / "tasks.md").read_text().replace("IN_PROGRESS", defect.upper()))
    if defect == "stale":
        for key in ("claimedAt", "updatedAt", "heartbeatAt"):
            record[key] = "2000-01-01T00:00:00+00:00"
    path.write_text(yaml.safe_dump(record))
    if defect == "pending": (change / ".dasops-local/pending.json").write_text("{}")
    if defect == "corrupt": path.write_text("owner: [broken")
    if defect == "inconsistent": (change / "tasks.md").write_text((change / "tasks.md").read_text().replace("worker-a", "other"))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # Only prompt and the model are controlled substitutes; lock-status runs the
    # actual public CLI against the actual managed task/lock files.
    shim = bindir / "dasops"
    shim.write_text(f'#!{sys.executable}\nimport sys\nif sys.argv[1] == "prompt":\n print("complete prompt")\n sys.exit({1 if defect == "prompt-failure" else 0})\nfrom dasops.__main__ import main\nsys.exit(main())\n')
    shim.chmod(0o700)
    worker = bindir / "codex"
    worker.write_text(f'#!{sys.executable}\nimport sys\nfrom pathlib import Path\nPath("worker-started").write_text(sys.stdin.read())\n')
    worker.chmod(0o700)
    temps = tmp_path / "temps"
    temps.mkdir()
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
               PYTHONPATH=str(Path(__file__).resolve().parents[1]), TMPDIR=str(temps))
    script = Path(__file__).resolve().parents[1] / "templates/das-product/scripts/run_worker_codex.sh"
    before = path.read_bytes(), (change / "tasks.md").read_bytes()
    result = subprocess.run(["bash", str(script), "sample", "T-167", "worker-b" if defect == "owner" else "worker-a"], cwd=tmp_path, env=env, text=True, capture_output=True)
    assert (result.returncode == 0) == (defect == "active"), result.stdout + result.stderr
    assert (tmp_path / "worker-started").exists() == (defect == "active")
    assert before == (path.read_bytes(), (change / "tasks.md").read_bytes())
    if defect != "active":
        reason = {"done": "lock_not_in_progress", "todo": "lock_not_in_progress",
                  "stale": "stale_lock_requires_reclaim", "owner": "owner_mismatch",
                  "pending": "recovery_required", "corrupt": "invalid_lock",
                  "inconsistent": "inconsistent_task_state", "prompt-failure": "prompt generation failed"}[defect]
        assert reason in result.stderr
    else:
        assert (tmp_path / "worker-started").read_text() == "complete prompt\n"
    assert not list(temps.iterdir())
    assert record["lockToken"] not in result.stdout + result.stderr
    if defect in {"done", "todo", "stale"}:
        assert inspect_lock(repo_root=tmp_path, change_id="sample", task_id="T-167")["valid"] is True


def test_active_check_requires_owner(tmp_path):
    project(tmp_path)
    claim(tmp_path)
    assert inspect_lock(repo_root=tmp_path, change_id="sample", task_id="T-167", require_active=True)["error"] == "active_check_requires_owner"


def _die_during_completion(root):
    import os
    original = state._install
    def install(path, data):
        if path.suffix == ".lock": os._exit(24)
        return original(path, data)
    state._install = install
    complete_task(repo_root=Path(root), change_id="sample", task_id="T-167", owner="worker-a")


def test_all_status_readers_refuse_partial_completion(tmp_path, monkeypatch):
    from dasops import tasks
    from dasops.scaffold import read_task_hints
    change = project(tmp_path)
    claim(tmp_path)
    ctx = multiprocessing.get_context("fork")
    child = ctx.Process(target=_die_during_completion, args=(str(tmp_path),))
    child.start(); child.join(10)
    assert child.exitcode == 24
    artifacts = [tasks.Artifact("tasks", "tasks.md", [])]
    monkeypatch.setattr(tasks, "read_schema", lambda root: artifacts)
    pending = change / ".dasops-local/pending.json"
    before = pending.read_bytes(), (change / "tasks.md").read_bytes()
    for reader in [lambda: tasks.task_index_is_complete(change / "tasks.md"),
                   lambda: tasks.artifact_status(change, artifacts),
                   lambda: tasks.print_status(tmp_path, "sample"),
                   lambda: list_tasks(repo_root=tmp_path, change_id="sample"),
                   lambda: read_task_hints(repo_root=tmp_path, change_id="sample", task_id="T-167")]:
        with pytest.raises(state.StateError, match="recovery_required"): reader()
    assert inspect_lock(repo_root=tmp_path, change_id="sample", task_id="T-167")["error"] == "recovery_required"
    assert before == (pending.read_bytes(), (change / "tasks.md").read_bytes())
    with state.guard(change, write=True): pass
    assert not pending.exists()
    assert list_tasks(repo_root=tmp_path, change_id="sample")[0]["status"] == "DONE"
    assert tasks.artifact_status(change, artifacts) == {"tasks": "BLOCKED"}  # T-168 remains TODO.


def test_status_missing_tasks_allowed_only_without_locks(tmp_path):
    from dasops.tasks import Artifact, artifact_status, task_index_is_complete
    change = project(tmp_path)
    (change / "tasks.md").unlink()
    assert artifact_status(change, [Artifact("tasks", "tasks.md", [])]) == {"tasks": "READY"}
    assert task_index_is_complete(change / "tasks.md") is False
    (change / "task_locks").mkdir()
    (change / "task_locks/T-167.lock").write_text("{}")
    with pytest.raises(state.StateError, match="missing_tasks_with_locks"):
        artifact_status(change, [])


@pytest.mark.parametrize("failed_directory", [".dasops-local", "sample"])
def test_recovery_retry_syncs_journal_before_any_target(tmp_path, monkeypatch, failed_directory):
    change = project(tmp_path)
    # Readers can pre-create this directory without syncing its parent.
    with state.guard(change): pass
    original = state._sync_dir
    def fail_after_pending_rename(path):
        if path.name == ".dasops-local" and (path / "pending.json").exists():
            raise OSError("injected pending directory fsync failure")
        return original(path)
    before = (change / "tasks.md").read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(state, "_sync_dir", fail_after_pending_rename)
        with pytest.raises(state.StateError, match="recovery_required"): claim(tmp_path)
    pending = change / ".dasops-local/pending.json"
    journal = pending.read_bytes()
    events = []
    def fail_barrier(path):
        events.append(path.name)
        if path.name == failed_directory: raise OSError("injected retry barrier failure")
        return original(path)
    with monkeypatch.context() as patch:
        patch.setattr(state, "_sync_dir", fail_barrier)
        patch.setattr(state, "_install", lambda *args: pytest.fail("target changed before durable journal"))
        with pytest.raises(state.StateError, match="recovery_required"):
            with state.guard(change, write=True): pass
    assert events == ([".dasops-local"] if failed_directory == ".dasops-local" else [".dasops-local", "sample"])
    assert pending.read_bytes() == journal and (change / "tasks.md").read_bytes() == before
    assert not (change / "task_locks/T-167.lock").exists()
    with state.guard(change, write=True): pass
    assert not pending.exists() and read_lock(change / "task_locks/T-167.lock") is not None


def test_status_display_uses_one_guarded_read(tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager
    from dasops import tasks
    change = project(tmp_path)
    claim(tmp_path)
    artifact = tasks.Artifact("tasks", "tasks.md", [])
    monkeypatch.setattr(tasks, "read_schema", lambda root: [artifact])
    original_guard, original_read = state.guard, state.read_bytes
    counts = {"guards": 0, "tasks": 0}
    @contextmanager
    def observe_guard(path, **kwargs):
        counts["guards"] += 1
        with original_guard(path, **kwargs): yield
    def observe_read(path):
        if path == change / "tasks.md": counts["tasks"] += 1
        return original_read(path)
    monkeypatch.setattr(state, "guard", observe_guard)
    monkeypatch.setattr(state, "read_bytes", observe_read)
    tasks.print_status(tmp_path, "sample")
    assert "BLOCKED" in capsys.readouterr().out
    assert counts == {"guards": 1, "tasks": 1}


@pytest.mark.parametrize("defect", ["corrupt", "inconsistent"])
def test_status_refuses_bad_lock_snapshot(tmp_path, defect):
    from dasops.tasks import task_index_is_complete
    change = project(tmp_path)
    path = claim(tmp_path)
    if defect == "corrupt": path.write_text("owner: [broken")
    else: (change / "tasks.md").write_text((change / "tasks.md").read_text().replace("worker-a", "other"))
    with pytest.raises(state.StateError, match="invalid_lock|inconsistent_task_state"):
        task_index_is_complete(change / "tasks.md")


def test_recovery_pending_file_fsync_failure_precedes_targets(tmp_path, monkeypatch):
    import os
    change = project(tmp_path)
    original = state._install
    def leave_pending(path, data):
        if path.name == "tasks.md": raise OSError("injected first target failure")
        return original(path, data)
    with monkeypatch.context() as patch:
        patch.setattr(state, "_install", leave_pending)
        with pytest.raises(state.StateError): claim(tmp_path)
    pending = change / ".dasops-local/pending.json"
    before = pending.read_bytes(), (change / "tasks.md").read_bytes()
    inode = pending.stat().st_ino
    sync = os.fsync
    def fail_pending_sync(fd):
        if os.fstat(fd).st_ino == inode: raise OSError("injected pending file fsync failure")
        sync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_pending_sync)
        patch.setattr(state, "_install", lambda *args: pytest.fail("target changed before pending fsync"))
        with pytest.raises(state.StateError, match="recovery_required"):
            with state.guard(change, write=True): pass
    assert before == (pending.read_bytes(), (change / "tasks.md").read_bytes())
