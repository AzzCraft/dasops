from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
DASOPS_ROOT = REPO_ROOT / "dasops"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(DASOPS_ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run(args: list[str], *, cwd: Path, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60, env=_env())
    assert proc.returncode in ok, proc.stdout + proc.stderr
    return proc


def _write_change(repo: Path) -> None:
    change = repo / "openspec" / "changes" / "lock-smoke"
    (change / "task_locks").mkdir(parents=True)
    (change / "tasks.md").write_text(
        "\n".join(
            [
                "# Tasks",
                "",
                "| Task ID | Title | Owner | Status | Depends on | Verify gate |",
                "| --- | --- | --- | --- | --- | --- |",
                "| T-001 | Lock smoke | - | TODO | - | `python3 -m pytest` |",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _lock_path(repo: Path) -> Path:
    return repo / "openspec" / "changes" / "lock-smoke" / "task_locks" / "T-001.lock"


def test_ops_003_competing_claims_produce_single_owner_and_loser_diagnostics(tmp_path: Path) -> None:
    _write_change(tmp_path)

    first = _run(
        [
            sys.executable,
            "-m",
            "dasops",
            "claim-task",
            "--change-id",
            "lock-smoke",
            "--task-id",
            "T-001",
            "--owner",
            "worker-a",
            "--json",
        ],
        cwd=tmp_path,
    )
    assert json.loads(first.stdout)["owner"] == "worker-a"

    second = _run(
        [
            sys.executable,
            "-m",
            "dasops",
            "claim-task",
            "--change-id",
            "lock-smoke",
            "--task-id",
            "T-001",
            "--owner",
            "worker-b",
            "--json",
        ],
        cwd=tmp_path,
        ok=(1,),
    )

    output = second.stdout + second.stderr
    assert "OPS-003" in output
    assert "T-001" in output
    assert "worker-a" in output
    assert "worker-b" in output
    lock = yaml.safe_load(_lock_path(tmp_path).read_text(encoding="utf-8"))
    assert lock["owner"] == "worker-a"


def test_ops_003_stale_reclaim_rotates_token_and_writes_audit_history(tmp_path: Path) -> None:
    _write_change(tmp_path)
    _run(
        [
            sys.executable,
            "-m",
            "dasops",
            "claim-task",
            "--change-id",
            "lock-smoke",
            "--task-id",
            "T-001",
            "--owner",
            "worker-a",
            "--json",
        ],
        cwd=tmp_path,
    )
    lock_path = _lock_path(tmp_path)
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    original_token = lock["lockToken"]
    old = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    lock["claimedAt"] = old
    lock["heartbeatAt"] = old
    lock["updatedAt"] = old
    lock["leaseSeconds"] = 60
    lock_path.write_text(yaml.safe_dump(lock, sort_keys=False), encoding="utf-8")

    proc = _run(
        [
            sys.executable,
            "-m",
            "dasops",
            "reclaim-lock",
            "--change-id",
            "lock-smoke",
            "--task-id",
            "T-001",
            "--new-owner",
            "worker-b",
            "--reason",
            "lease expired in OPS-003 fixture",
            "--json",
        ],
        cwd=tmp_path,
    )

    payload = json.loads(proc.stdout)
    assert payload["task"] == "OPS-003"
    assert payload["previousOwner"] == "worker-a"
    assert payload["newOwner"] == "worker-b"
    assert payload["oldToken"] == original_token
    assert payload["newToken"] != original_token
    reclaimed = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    assert reclaimed["owner"] == "worker-b"
    assert reclaimed["lockToken"] == payload["newToken"]
    assert reclaimed["auditHistory"][-1]["reason"] == "lease expired in OPS-003 fixture"
    assert reclaimed["auditHistory"][-1]["fromOwner"] == "worker-a"
    assert reclaimed["auditHistory"][-1]["toOwner"] == "worker-b"
