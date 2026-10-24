import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from dasops.vendor import SUPPORTED_PUBLIC_TIERS, build_install_cadence_command
from tests.test_template_verify_frontend import copy_template_repo, seed_frontend_evidence


def test_generated_verifier_releases_state_guard_before_cadence(tmp_path):
    from dasops.locks import claim_task, complete_task, read_lock

    repo = copy_template_repo(str(tmp_path))
    change = repo / "openspec/changes/heartbeat"
    change.mkdir()
    (change / "tasks.md").write_text(
        "| Task ID | Title | Owner | Status | Depends on | Verify gate |\n"
        "|---|---|---|---|---|---|\n"
        "| T-001 | Review | - | TODO | - | `./scripts/verify` |\n"
        "| T-002 | Independent | - | TODO | - | `./scripts/verify` |\n")
    path = claim_task(repo_root=repo, change_id="heartbeat", task_id="T-001", owner="worker-a")
    token = read_lock(path).lock_token
    (repo / "vendor/cadence").mkdir()
    # This controlled child substitutes the external Cadence command only.
    # Probe nonblocking first so a regression cannot hang the test for 900s.
    (repo / "cadencew").write_text(
        f"#!{sys.executable}\n"
        "import fcntl, sys\nfrom pathlib import Path\n"
        "root = Path.cwd()\n"
        "with (root / 'openspec/changes/heartbeat/.dasops-local/coordination.guard').open('r+b') as guard:\n"
        "    fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})\n"
        "from dasops.locks import renew_lock, claim_task\n"
        f"renew_lock(repo_root=root, change_id='heartbeat', task_id='T-001', owner='worker-a', lock_token={token!r})\n"
        "claim_task(repo_root=root, change_id='heartbeat', task_id='T-002', owner='worker-b')\n")
    complete_task(repo_root=repo, change_id="heartbeat", task_id="T-001", owner="worker-a")
    assert read_lock(path).status == "DONE"
    assert read_lock(change / "task_locks/T-002.lock").owner == "worker-b"


@pytest.mark.parametrize("defect", ["owner-drift", "missing-lock", "misbound-id", "duplicate-task", "duplicate-key", "boolean-lease", "missing-index"])
def test_template_verifier_rejects_inconsistent_task_snapshot(tmp_path, defect):
    from dasops.locks import claim_task, complete_task

    repo = copy_template_repo(str(tmp_path))
    change = repo / "openspec/changes/recheck"
    change.mkdir()
    tasks = change / "tasks.md"
    tasks.write_text("| Task ID | Title | Owner | Status | Depends on | Verify gate |\n"
                     "|---|---|---|---|---|---|\n"
                     "| T-001 | Review | - | TODO | - | `./scripts/verify` |\n")
    lock = claim_task(repo_root=repo, change_id="recheck", task_id="T-001", owner="worker-a")
    task_bytes, lock_bytes = tasks.read_bytes(), lock.read_bytes()
    if defect == "owner-drift": tasks.write_bytes(task_bytes.replace(b"worker-a", b"worker-b"))
    elif defect == "missing-lock": lock.unlink()
    elif defect == "misbound-id": lock.write_bytes(lock_bytes.replace(b"taskId: T-001", b"taskId: T-002"))
    elif defect == "duplicate-task": tasks.write_bytes(task_bytes + task_bytes.splitlines(keepends=True)[-1])
    elif defect == "duplicate-key": lock.write_bytes(lock_bytes + b"owner: worker-a\n")
    elif defect == "missing-index": tasks.unlink()
    else: lock.write_bytes(lock_bytes.replace(b"leaseSeconds: 3600", b"leaseSeconds: true"))
    before = (tasks.read_bytes() if tasks.exists() else None, lock.read_bytes() if lock.exists() else None)
    result = subprocess.run(["bash", "scripts/verify"], cwd=repo, text=True, capture_output=True)
    assert result.returncode != 0 and "[FAIL]" in result.stdout, result.stdout + result.stderr
    assert (tasks.read_bytes() if tasks.exists() else None, lock.read_bytes() if lock.exists() else None) == before
    # Restore the legitimate snapshot, then exercise the real completion gate.
    tasks.write_bytes(task_bytes)
    lock.write_bytes(lock_bytes)
    complete_task(repo_root=repo, change_id="recheck", task_id="T-001", owner="worker-a")
    # Historical DONE rows need not retain a lock.
    lock.unlink()
    result = subprocess.run(["bash", "scripts/verify"], cwd=repo, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("enabled", [False, True, "true"])
def test_main_frontend_selection_is_explicit_and_helper_runs_once(tmp_path, enabled):
    repo = copy_template_repo(str(tmp_path))
    config = yaml.safe_load((repo / "cadence.yaml").read_text())
    config["ui"]["enabled"] = enabled
    (repo / "cadence.yaml").write_text(yaml.safe_dump(config))
    run = subprocess.run(["bash", "scripts/verify"], cwd=repo, text=True, capture_output=True)
    if enabled is False:
        assert run.returncode == 0, run.stderr
        assert "frontend evidence not applicable" in run.stdout
    else:
        assert run.returncode != 0
        assert ("ui.enabled must be boolean" if isinstance(enabled, str) else "missing frontend evidence file") in run.stdout + run.stderr
    if enabled is True:
        seed_frontend_evidence(repo, visual_matrix_text='{"viewports":["desktop"],"themes":["light"],"locales":["en"]}')
        run = subprocess.run(["bash", "scripts/verify-frontend"], cwd=repo, text=True, capture_output=True)
        assert run.returncode == 0, run.stderr
        assert run.stdout.count("matrix structure and file presence only") == 1
    (repo / "openspec/changes/broken/.dasops-local").mkdir(parents=True)
    (repo / "openspec/changes/broken/tasks.md").write_text("fixture")
    (repo / "openspec/changes/broken/.dasops-local/pending.json").write_text("{}")
    run = subprocess.run(["bash", "scripts/verify"], cwd=repo, text=True, capture_output=True)
    assert run.returncode != 0 and "recovery_required" in run.stdout + run.stderr


def test_vendor_public_tiers_and_source_validation(tmp_path):
    for tier in ["pro", "enterprise", "unknown"]:
        with pytest.raises(ValueError, match="only tier=oss"):
            build_install_cadence_command(tier=tier, git_base="https://github.com/AzzCraft")
    with pytest.raises(ValueError):
        build_install_cadence_command(tier="oss")
    with pytest.raises(ValueError):
        build_install_cadence_command(tier="oss", from_suite=str(tmp_path / "missing"))
    assert SUPPORTED_PUBLIC_TIERS == ("oss",)
    command = build_install_cadence_command(tier="oss", git_base="https://github.com/AzzCraft")
    assert command[-2:] == ["--git-base", "https://github.com/AzzCraft"]
    script = Path(__file__).resolve().parents[1] / "templates/das-product/scripts/install_cadence_vendor.sh"
    run = subprocess.run(["bash", str(script), "--tier", "pro"], capture_output=True, text=True)
    assert run.returncode == 2 and "Invalid --tier" in run.stderr


@pytest.mark.parametrize("valid_source", [False, True])
@pytest.mark.parametrize("creation_failure", [None, "nonempty", "git-failure"])
def test_gui_preflights_source_and_retains_created_product_on_install_failure(tmp_path, monkeypatch, valid_source, creation_failure):
    product = tmp_path / "product"
    errors, created = [], []
    class UI:
        def text_input(self, label, value="", **kwargs):
            if label == "Product repo output directory": return str(product)
            if label == "Git base": return "https://github.com/AzzCraft" if valid_source else ""
            return value
        def checkbox(self, label, value=False, **kwargs):
            return True if label == "Install Cadence under vendor/cadence" else value
        def file_uploader(self, *args, **kwargs): return SimpleNamespace(getvalue=lambda: b"# Synthetic input\n")
        def selectbox(self, label, options, **kwargs):
            if label == "DAS Standard release":
                assert options == ["1.4.0", "1.5.0-beta.1"]
                return "1.4.0"  # Keep this legacy install-failure regression on its original path.
            assert label == "Cadence tier"
            assert options == ["oss"]
            return options[0]
        def radio(self, *args, **kwargs): return "Clone from Git base"
        def button(self, *args, **kwargs): return True
        def error(self, text): errors.append(text)
        def __getattr__(self, name): return lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "streamlit", UI())
    path = Path(__file__).resolve().parents[1] / "gui/app.py"
    spec = importlib.util.spec_from_file_location("review_gui", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def create(**kwargs):
        if creation_failure == "nonempty": raise SystemExit("Destination is not empty")
        if creation_failure == "git-failure": raise RuntimeError("Git bootstrap failed; product creation is incomplete")
        product.mkdir()
        created.append(product)
        return product
    monkeypatch.setattr(module, "create_product_repo", create)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="synthetic installer failure"))
    module.main()
    if valid_source and creation_failure:
        assert not product.exists() and errors
        assert any(("not empty" if creation_failure == "nonempty" else "incomplete") in message for message in errors)
    elif valid_source:
        assert product.is_dir() and created == [product]
        assert any("was created" in error and "installation failed" in error for error in errors)
    else:
        assert not product.exists() and not created and errors

@pytest.mark.parametrize("defect", ["tasks-link", "lock-link", "owner", "zero-lease", "string-lease"])
def test_doctor_and_product_verify_refuse_same_invalid_state(tmp_path, defect):
    from dasops.locks import claim_task, inspect_lock
    from dasops.doctor import run_doctor as doctor
    repo = copy_template_repo(str(tmp_path))
    change = repo / "openspec/changes/consistent"
    change.mkdir()
    tasks = change / "tasks.md"
    tasks.write_text("| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n| T-1 | Work | - | TODO | - | python3 -V |\n")
    lock = claim_task(repo_root=repo, change_id="consistent", task_id="T-1", owner="alice")
    before_tasks, before_lock = tasks.read_bytes(), lock.read_bytes()
    assert not doctor(repo_root=repo).problems
    control = subprocess.run(["bash", "scripts/verify"], cwd=repo, text=True, capture_output=True)
    assert control.returncode == 0, control.stdout + control.stderr
    if defect.endswith("-link"):
        path = tasks if defect == "tasks-link" else lock
        outside = tmp_path / "original-state"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
    elif defect == "owner":
        tasks.write_bytes(before_tasks.replace(b"alice", b"bob"))
    else:
        payload = yaml.safe_load(before_lock)
        payload["leaseSeconds"] = 0 if defect == "zero-lease" else "sixty"
        lock.write_text(yaml.safe_dump(payload))
    snapshot = tasks.read_bytes(), lock.read_bytes()
    report = doctor(repo_root=repo)
    assert report.problems, report
    status = inspect_lock(repo_root=repo, change_id="consistent", task_id="T-1", expect_owner="alice")
    assert not status["valid"]
    result = subprocess.run(["bash", "scripts/verify"], cwd=repo, text=True, capture_output=True)
    assert result.returncode and "[FAIL]" in result.stdout, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert snapshot == (tasks.read_bytes(), lock.read_bytes())
    if defect.endswith("-link"):
        assert outside.read_bytes() == (before_tasks if defect == "tasks-link" else before_lock)


def test_generated_verifier_executes_local_schemas_and_rejects_bad_yaml(tmp_path):
    from dasops.doctor import run_doctor as doctor
    repo = copy_template_repo(str(tmp_path))
    def verify(*args):
        return subprocess.run(["bash", "scripts/verify", *args], cwd=repo, text=True, capture_output=True)
    assert verify().returncode == 0
    tooling = repo / "tooling_lock.json"
    original = tooling.read_text()
    data = json.loads(original)
    data["schemaVersion"] = 7
    tooling.write_text(json.dumps(data))
    assert verify().returncode != 0
    assert doctor(repo_root=repo).problems
    tooling.write_text(original)
    config = repo / "openspec/config.yaml"
    original_config = config.read_text()
    config.write_text("context: [broken\n# STANDARD_REF.md\n")
    result = verify()
    assert result.returncode and "invalid YAML" in result.stdout
    config.write_text(original_config)
    seed_frontend_evidence(repo, visual_matrix_text='{"viewports":["desktop"],"themes":["dark"],"locales":["en"]}')
    assert verify("--frontend").returncode == 0
    schema_path = repo / "openspec/schemas/das-standard/visual_matrix.schema.json"
    schema = json.loads(schema_path.read_text())
    schema["properties"]["themes"]["items"]["enum"] = ["light"]
    schema_path.write_text(json.dumps(schema))
    result = verify("--frontend")
    assert result.returncode and "schema validation failed" in result.stderr
    matrix = repo / "artifacts/frontend/visualMatrix.json"
    matrix.write_text(matrix.read_text().replace('"dark"', '"light"'))
    assert verify("--frontend").returncode == 0
    baseline = repo / "artifacts/frontend/baseline"
    (baseline / "baseline.txt").unlink()
    (baseline / "empty").mkdir()
    result = verify("--frontend")
    assert result.returncode and "ordinary evidence file" in result.stderr

@pytest.mark.parametrize("worktree_mode", [False, True])
def test_start_task_preflight_and_safe_failure_recovery(tmp_path, monkeypatch, capsys, worktree_mode):
    from dasops import __main__ as cli
    from dasops import legacy_task_state as state
    repo = copy_template_repo(str(tmp_path))
    change = repo / "openspec/changes/start"
    change.mkdir()
    tasks = change / "tasks.md"
    tasks.write_text("| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n| T-1 | Start | bob | TODO | - | python3 -V |\n")
    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()
    git("add", "-A")
    git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "Task fixture")
    head, branch = git("rev-parse", "HEAD"), git("branch", "--show-current")
    work = tmp_path / "started"
    args = ["start-task", "--repo-root", str(repo), "--change-id", "start", "--task-id", "T-1", "--owner", "alice", "--branch", "feat/start", "--base", head, "--json"]
    args += ["--worktree", str(work)] if worktree_mode else ["--no-worktree"]
    monkeypatch.setattr(sys, "argv", ["dasops", *args])
    with pytest.raises(SystemExit, match="owner_mismatch"):
        cli.main()
    assert git("branch", "--show-current") == branch
    assert "feat/start" not in git("branch", "--list")
    args[args.index("alice")] = "bob"
    monkeypatch.setattr(sys, "argv", ["dasops", *args])
    def refused(**kwargs):
        raise state.StateError("concurrent_refusal")
    monkeypatch.setattr(cli, "claim_task", refused)
    assert cli.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert result["checkoutRestored"] and result["branchRemoved"] and not result["recoveryRequired"]
    assert git("branch", "--show-current") == branch and git("rev-parse", "HEAD") == head
    def interrupted(**kwargs):
        pending = kwargs["repo_root"] / "openspec/changes/start/.dasops-local/pending.json"
        pending.parent.mkdir(parents=True, exist_ok=True)
        pending.write_text('{"retained":"recovery fixture"}')
        raise state.StateError("recovery_required")
    monkeypatch.setattr(cli, "claim_task", interrupted)
    assert cli.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert not result["checkoutRestored"] and not result["branchRemoved"] and result["recoveryRequired"]
    retained = Path(result["retainedWorktree"])
    assert (retained / "openspec/changes/start/.dasops-local/pending.json").is_file()


def test_completion_failure_retains_bounded_diagnostics_and_state(tmp_path, monkeypatch, capsys):
    from dasops import __main__ as cli
    from dasops.locks import claim_task
    repo=copy_template_repo(str(tmp_path))
    change=repo/'openspec/changes/diagnostic'
    change.mkdir()
    tasks=change/'tasks.md'
    tasks.write_text('| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n| T-1 | Failure | - | TODO | - | python3 gate.py |\n')
    (repo/'gate.py').write_text("import sys\nprint('checking arithmetic fixture')\nsys.stderr.write('x'*10000+'expected total 2 but got 3')\nsys.exit(7)\n")
    lock=claim_task(repo_root=repo,change_id='diagnostic',task_id='T-1',owner='alice')
    before=tasks.read_bytes(),lock.read_bytes()
    monkeypatch.setattr(sys,'argv',['dasops','complete-task','--repo-root',str(repo),'--change-id','diagnostic','--task-id','T-1','--owner','alice','--json'])
    assert cli.main()==1
    result=json.loads(capsys.readouterr().out)
    assert result['exitCode']==7 and result['completionWritten'] is False
    assert 'checking arithmetic fixture' in result['stdout']
    assert result['stderr'].endswith('expected total 2 but got 3') and len(result['stderr'])<=8192
    assert before==(tasks.read_bytes(),lock.read_bytes())
    (repo/'gate.py').write_text('print("fixed")\n')
    assert cli.main()==0
    assert json.loads(capsys.readouterr().out)['status']=='DONE'


def test_registered_nested_worktree_is_not_a_stray_task_tree(tmp_path):
    from dasops.doctor import run_doctor
    repo=copy_template_repo(str(tmp_path))
    work=repo/'.worktrees/worker/task'
    result=subprocess.run(['git','worktree','add','-b','fixture-worktree',str(work),'HEAD'],cwd=repo,text=True,capture_output=True)
    assert result.returncode==0,result.stderr
    change=work/'openspec/changes/worker'
    change.mkdir()
    (change/'tasks.md').write_text('worker worktree only\n')
    assert not run_doctor(repo).problems
    result=subprocess.run(['bash','scripts/verify'],cwd=repo,text=True,capture_output=True)
    assert result.returncode==0,result.stdout+result.stderr
    stray=repo/'scratch/tasks.md';stray.parent.mkdir();stray.write_text('unregistered\n')
    assert any('stray tasks' in problem for problem in run_doctor(repo).problems)
    result=subprocess.run(['bash','scripts/verify'],cwd=repo,text=True,capture_output=True)
    assert result.returncode and 'stray tasks' in result.stdout


def test_reviewed_ids_drafts_owner_and_task_columns(tmp_path, capsys):
    from dasops.__main__ import main, _make_change_id
    from dasops.commands.create import create_change
    from dasops.tasks import _text_is_draft, parse_tasks_index
    from dasops.locks import read_lock
    for invalid in ('..', '../escape', 'a/b', 'a\\b', 'a\nb'):
        with pytest.raises(ValueError):
            create_change(tmp_path, invalid)
    assert not (tmp_path / 'changes').exists()
    assert create_change(tmp_path, '合法 空格').ok
    assert len({_make_change_id('相同意图') for _ in range(30)}) == 30
    for text in ('<https://example.org/docs>', '<mailto:reader@example.org>', '`<!-- DASOPS:DRAFT -->`', '```md\n<!-- DASOPS:DRAFT -->\n```'):
        assert not _text_is_draft(text)
    assert _text_is_draft('<!-- DASOPS:DRAFT -->') and _text_is_draft('<replace me>')
    (tmp_path / 'product').mkdir()
    repo = copy_template_repo(str(tmp_path / 'product'))
    change = repo / 'openspec/changes/合法 空格'
    change.mkdir()
    tasks = change / 'tasks.md'
    header = '| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n'
    example = '```md\n' + header + '| example | ignored | - | TODO | - | false |\n```\n'
    tasks.write_text(example + header + '| 任务 一 | left \\| right | - | TODO | - | `python3 -c "pass"` |\n'
                     '| 任务 二 | dependent | - | TODO | "任务 一" | `python3 -c "pass"` |\n')
    def cli(*args):
        result = main([args[0], '--repo-root', str(repo), *args[1:]])
        capsys.readouterr()
        return result
    assert cli('claim-task', '--change-id', change.name, '--task-id', '任务 一', '--owner', 'Worker A') == 0
    lock_path = change / 'task_locks/任务 一.lock'
    assert cli('renew-lock', '--change-id', change.name, '--task-id', '任务 一', '--owner', 'Worker A', '--lock-token', read_lock(lock_path).lock_token) == 0
    assert cli('reclaim-lock', '--change-id', change.name, '--task-id', '任务 一', '--new-owner', 'Worker B', '--reason', 'review', '--force') == 0
    assert cli('renew-lock', '--change-id', change.name, '--task-id', '任务 一', '--owner', 'Worker B', '--lock-token', read_lock(lock_path).lock_token) == 0
    assert cli('complete-task', '--change-id', change.name, '--task-id', '任务 一', '--owner', 'Worker B') == 0
    assert cli('claim-task', '--change-id', change.name, '--task-id', '任务 二', '--owner', 'Worker C') == 0
    rows = parse_tasks_index(tasks.read_text())
    assert len(rows) == 2 and rows[0].status == 'DONE' and rows[0].title == 'left \\| right'
    assert rows[1].owner == 'Worker-C' and tasks.read_text().startswith(example)


def test_factory_git_failure_does_not_publish_success_or_new_destination(tmp_path, monkeypatch):
    from dasops import repo_factory
    factory = Path(__file__).resolve().parents[1]
    master, ui = tmp_path / 'master.md', tmp_path / 'ui.md'
    master.write_text('# Master\n'); ui.write_text('# UI\n')
    destination = tmp_path / 'new-product'
    original_run = subprocess.run
    def failing_commit(cmd, *args, **kwargs):
        if cmd[0] == 'git' and 'commit' in cmd:
            raise subprocess.CalledProcessError(1, cmd, output='synthetic commit failure')
        return original_run(cmd, *args, **kwargs)
    monkeypatch.setattr(repo_factory.subprocess, 'run', failing_commit)
    with pytest.raises(RuntimeError, match='Git bootstrap failed'):
        repo_factory.create_product_repo(factory_root=factory, dest_dir=destination, master_doc_path=master, ui_spec_path=ui)
    assert not destination.exists()
    assert master.read_text() == '# Master\n' and ui.read_text() == '# UI\n'


@pytest.mark.parametrize('dependencies', [('missing', '-'), ('A', '-'), ('B', 'A')])
def test_invalid_task_dependency_graph_is_rejected(dependencies):
    from dasops.tasks import parse_tasks_index
    text = '| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n'
    text += f'| A | first | - | TODO | {dependencies[0]} | true |\n| B | second | - | TODO | {dependencies[1]} | true |\n'
    with pytest.raises(ValueError, match='Invalid task graph'): parse_tasks_index(text)
    # A separate explicit DAG is the control, rather than repairing a malformed graph heuristically.
    legal = '| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n| A | first | - | DONE | - | true |\n| B | second | - | TODO | A | true |\n'
    assert len(parse_tasks_index(legal)) == 2


def test_document_import_and_adoption_output_conflicts_preserve_inputs(tmp_path):
    from dasops.repo_factory import init_repo
    from dasops.adopt import adopt_report
    docs = tmp_path / 'docs'; docs.mkdir()
    (docs / 'master_doc.md').write_bytes(b'original master')
    (docs / 'ui_spec.md').mkdir()
    with pytest.raises(ValueError, match='conflict'):
        init_repo(tmp_path, master_doc_bytes=b'new', ui_spec_bytes=b'new')
    assert (docs / 'master_doc.md').read_bytes() == b'original master'
    evidence_dir = tmp_path / '.dasops'; evidence_dir.mkdir()
    external = tmp_path / 'external'; external.write_bytes(b'keep')
    (evidence_dir / 'adoption_evidence.json').symlink_to(external)
    result = adopt_report(tmp_path)
    assert result['ok'] is False
    assert external.read_bytes() == b'keep'
    assert not (tmp_path/'cadence.yaml').exists()


def test_existing_git_scaffold_preserves_index_and_records_new_baseline(tmp_path):
    from dasops.repo_factory import create_product_repo_from_template
    root = Path(__file__).resolve().parents[1]
    master, ui = tmp_path/'master.md', tmp_path/'ui.md'
    master.write_text('# Master\n'); ui.write_text('# UI\n')
    product = tmp_path/'product'
    args = dict(template_dir=root/'templates/das-product', dest_dir=product, master_doc_path=master, ui_spec_path=ui)
    create_product_repo_from_template(**args)
    user = product/'user.txt'; user.write_text('staged user content')
    subprocess.run(['git','add','user.txt'],cwd=product,check=True)
    before = subprocess.check_output(['git','write-tree'],cwd=product)
    master.write_text('# Changed master\n')
    with pytest.raises(RuntimeError, match='staged user'):
        create_product_repo_from_template(**args, overwrite=True)
    assert subprocess.check_output(['git','write-tree'],cwd=product) == before
    assert (product/'docs/master_doc.md').read_text() == '# Master\n'
    subprocess.run(['git','reset','--','user.txt'],cwd=product,check=True,capture_output=True)
    create_product_repo_from_template(**args, overwrite=True)
    pin = json.loads((product/'tooling_lock.json').read_text())['sourceOfTruth']['pinValue']
    assert subprocess.check_output(['git','show',pin+':docs/master_doc.md'],cwd=product).decode() == '# Changed master\n'
    assert subprocess.run(['git','ls-files','--error-unmatch','user.txt'],cwd=product,capture_output=True).returncode != 0
    assert user.read_text() == 'staged user content'


def test_default_branch_handles_business_ids_and_scaffold_trace(tmp_path):
    import os
    from dasops.repo_factory import create_product_repo_from_template
    from dasops.adopt import trace_check
    from dasops.__main__ import _branch_id
    root = Path(__file__).resolve().parents[1]
    master, ui = tmp_path/'master.md', tmp_path/'ui.md'
    master.write_text('# Master\n'); ui.write_text('# UI\n')
    product = tmp_path/'product'
    create_product_repo_from_template(template_dir=root/'templates/das-product',dest_dir=product,master_doc_path=master,ui_spec_path=ui)
    assert trace_check(product) == []
    (product/'VERSION').write_text('0.1.1\n')
    assert any('0.1.1' in issue for issue in trace_check(product))
    (product/'VERSION').write_text('0.1.0\n')
    change = product/'openspec/changes/release work'; change.mkdir()
    (change/'tasks.md').write_text('| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n| build app | Build | - | TODO | - | true |\n\n### build app: Build\n- Owner: -\n- Status: TODO\n- Branch: -\n')
    subprocess.run(['git','add','openspec'],cwd=product,check=True)
    subprocess.run(['git','-c','user.name=TEST','-c','user.email=test@example.invalid','commit','-m','TEST task'],cwd=product,check=True,capture_output=True)
    env = dict(os.environ, PYTHONPATH=str(root))
    result = subprocess.run([sys.executable,'-m','dasops','start-task','--change-id','release work','--task-id','build app','--owner','TEST','--no-worktree','--json'],cwd=product,env=env,text=True,capture_output=True)
    assert result.returncode == 0, result.stderr + result.stdout
    value = json.loads(result.stdout)
    assert value['branch'].startswith('feat/release%20work/build%20app-')
    assert _branch_id('build app') != _branch_id('build%20app')


def test_generated_verify_and_doctor_share_dependency_rejection(tmp_path):
    from dasops.doctor import run_doctor
    product = copy_template_repo(str(tmp_path))
    positive = subprocess.run(['bash','scripts/verify'],cwd=product,text=True,capture_output=True)
    assert positive.returncode == 0, positive.stdout + positive.stderr
    change = product/'openspec/changes/graph'; change.mkdir(); (change/'task_locks').mkdir()
    (change/'tasks.md').write_text('| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n| A | first | - | TODO | missing | true |\n')
    negative = subprocess.run(['bash','scripts/verify'],cwd=product,text=True,capture_output=True)
    assert negative.returncode != 0 and 'unknown dependency' in negative.stdout + negative.stderr
    assert any('unknown dependency' in issue for issue in run_doctor(product).problems)
