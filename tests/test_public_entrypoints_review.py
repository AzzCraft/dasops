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
def test_gui_preflights_source_and_retains_created_product_on_install_failure(tmp_path, monkeypatch, valid_source):
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
        product.mkdir()
        created.append(product)
        return product
    monkeypatch.setattr(module, "create_product_repo", create)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="synthetic installer failure"))
    module.main()
    if valid_source:
        assert product.is_dir() and created == [product]
        assert any("was created" in error and "installation failed" in error for error in errors)
    else:
        assert not product.exists() and not created and errors
