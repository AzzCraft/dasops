from __future__ import annotations

import json
import pytest
import shlex
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_verify_runs_the_complete_bounded_pytest_collection() -> None:
    script = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
    manifest = json.loads((ROOT / "tests" / "verification_manifest.json").read_text(encoding="utf-8"))

    assert manifest["minimumCollectedTests"] >= 460
    assert manifest["publicTestPaths"]
    assert "tests/bootstrap/test_registry.py" in manifest["publicTestPaths"]
    assert "tests/protected/test_release_candidate.py" not in manifest["publicTestPaths"]
    assert "tests/protected" not in manifest["publicTestPaths"]
    assert "python3 -m unittest discover" not in script
    assert "python3 -m pytest --collect-only" in script
    assert "--timeout=90" in script
    assert "timeout --preserve-status 30m" in script
    assert "pytest collection fell below the required floor" in script
    invocations = [shlex.split(line) for line in script.replace('\\\n', ' ').splitlines()
                   if 'python3 -m pytest' in line]
    assert len(invocations) == 2
    for argv in invocations:
        assert any(argv[i:i + 2] == ['-p', 'timeout'] for i in range(len(argv))), 'collection and execution both need the timeout entry point'
    assert '"${public_test_paths[@]}"' in script


def test_verify_ci_uses_the_pinned_verification_lock_and_security_audits() -> None:
    workflow = (ROOT / ".github" / "workflows" / "verify.yml").read_text(encoding="utf-8")

    assert "-r requirements-verify.txt" in workflow
    assert "-r requirements.txt" not in workflow
    requirements = (ROOT / "requirements-verify.txt").read_text(encoding="utf-8")
    assert "rfc3339-validator==0.1.4" in requirements
    assert "setuptools==83.0.0" in requirements
    assert "wheel==0.46.2" in requirements
    assert "pip-audit --progress-spinner off --strict -r requirements-verify.txt" in workflow
    assert "bandit -q -lll -r dasops" in workflow


def test_direct_verify_bootstraps_the_exact_lock_when_the_host_lacks_verification_dependencies() -> None:
    script = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")

    assert "DASOPS_VERIFY_ENV_READY" in script
    assert "python3 -m venv" in script
    assert "-r requirements-verify.txt" in script
    assert "pytest_timeout" in script
    assert 'PATH="$verify_environment/bin:$PATH" bash "$0" "$@"' in script


def test_optional_public_gui_has_an_immutable_direct_dependency() -> None:
    requirements = (ROOT / "requirements-gui.txt").read_text(encoding="utf-8")
    assert "streamlit==" in requirements
    assert ">=" not in requirements


def test_final_task_verify_gate_never_uses_a_shell() -> None:
    source = (ROOT / "dasops" / "__main__.py").read_text(encoding="utf-8")
    assert "argv = shlex.split(command, posix=True)" in source
    assert "shell=True" not in source


@pytest.mark.parametrize('autoload', [True, False])
def test_explicit_timeout_entry_works_with_and_without_autoload(tmp_path, autoload):
    import os
    import subprocess
    import sys
    sample = tmp_path / 'timeout-control'; sample.mkdir()
    case = sample / 'test_control.py'
    case.write_text('import time\ndef test_fast():\n assert True\ndef test_slow():\n time.sleep(1)\n')
    env = {**os.environ, 'PYTEST_ADDOPTS': '', 'PYTHONDONTWRITEBYTECODE': '1'}
    if autoload: env.pop('PYTEST_DISABLE_PLUGIN_AUTOLOAD', None)
    else: env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    # Exercise the options in the shipped verifier, shortening only the deadline.
    script = (ROOT / 'scripts/verify').read_text().replace('\\\n', ' ')
    argv = shlex.split(next(line for line in script.splitlines() if line.startswith('timeout --preserve-status')))
    options = argv[argv.index('pytest') + 1:-1]  # replace only the manifest's path array
    options = ['--timeout=0.1' if arg == '--timeout=90' else arg for arg in options]
    command = [sys.executable, '-B', '-m', 'pytest', *options,
               '--confcutdir', str(sample), str(case)]
    slow = subprocess.run([*command, '--basetemp', str(tmp_path / 'slow-run')], cwd=sample,
                          env=env, capture_output=True, text=True, timeout=15)
    assert slow.returncode == 1 and 'Timeout' in slow.stdout and '1 failed, 1 passed' in slow.stdout, slow.stdout + slow.stderr
    case.write_text('def test_fast():\n assert True\ndef test_slow():\n assert True\n')
    fast = subprocess.run([*command, '--basetemp', str(tmp_path / 'fast-run')], cwd=sample,
                          env=env, capture_output=True, text=True, timeout=15)
    assert fast.returncode == 0 and '2 passed' in fast.stdout, fast.stdout + fast.stderr
