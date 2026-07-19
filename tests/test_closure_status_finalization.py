"""Regression coverage for final OpenSpec closure status semantics."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHANGE_ID = "v10-6-commercial-ga-closure"
CHANGE_REL = Path("openspec") / "changes" / CHANGE_ID
SCHEMA_REL = Path("openspec") / "schemas" / "das-standard" / "schema.yaml"


def _write_fixture_repo(tmp_path: Path, *, complete_tasks: bool) -> Path:
    repo = tmp_path / "repo"
    change_dir = repo / CHANGE_REL
    schema_path = repo / SCHEMA_REL
    change_dir.mkdir(parents=True)
    schema_path.parent.mkdir(parents=True)
    schema_path.write_text((REPO_ROOT / SCHEMA_REL).read_text(encoding="utf-8"), encoding="utf-8")

    for name in ("contracts_plan.md", "master_doc_delta.md", "verification_plan.md", "tasks.md"):
        text = (REPO_ROOT / CHANGE_REL / name).read_text(encoding="utf-8")
        if name == "tasks.md":
            text = _mark_all_tasks_done(text)
            if not complete_tasks:
                text = _set_task_status(text, "T-040", "worker-1", "TODO")
        (change_dir / name).write_text(text, encoding="utf-8")
    return repo


def _mark_all_tasks_done(tasks_md: str) -> str:
    lines: list[str] = []
    for raw in tasks_md.splitlines():
        stripped = raw.strip()
        if stripped.startswith("| T-"):
            parts = [part.strip() for part in stripped.strip("|").split("|")]
            if len(parts) >= 4:
                parts[2] = "worker-1"
                parts[3] = "DONE"
                raw = "| " + " | ".join(parts) + " |"
        elif stripped.startswith("- Owner:"):
            raw = "- Owner: worker-1"
        elif stripped.startswith("- Status:"):
            raw = "- Status: DONE"
        lines.append(raw)
    return "\n".join(lines) + "\n"


def _set_task_status(tasks_md: str, task_id: str, owner: str, status: str) -> str:
    lines: list[str] = []
    in_section = False
    for raw in tasks_md.splitlines():
        stripped = raw.strip()
        if stripped.startswith("| " + task_id + " "):
            parts = [part.strip() for part in stripped.strip("|").split("|")]
            if len(parts) >= 4:
                parts[2] = owner
                parts[3] = status
                raw = "| " + " | ".join(parts) + " |"
        elif stripped.startswith("### "):
            in_section = stripped.startswith("### " + task_id + ":") or stripped == "### " + task_id
        elif in_section and stripped.startswith("- Owner:"):
            raw = f"- Owner: {owner}"
        elif in_section and stripped.startswith("- Status:"):
            raw = f"- Status: {status}"
        lines.append(raw)
    return "\n".join(lines) + "\n"


def _run_status(repo: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "dasops")
    return subprocess.run(
        [sys.executable, "-m", "dasops", "status", "--id", CHANGE_ID],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def test_unfinished_execution_tasks_keep_execution_plan_blocked(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, complete_tasks=False)

    proc = _run_status(repo)

    assert proc.returncode == 0, proc.stderr
    assert "tasks.md" in proc.stdout
    assert "execution-plan    BLOCKED" in proc.stdout


def test_completed_closure_status_ignores_stale_draft_markers(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, complete_tasks=True)

    proc = _run_status(repo)

    assert proc.returncode == 0, proc.stderr
    assert "contracts_plan.md" in proc.stdout
    assert "tasks.md" in proc.stdout
    assert "contracts         DONE" in proc.stdout, proc.stdout
    assert "execution-plan    DONE" in proc.stdout, proc.stdout
    assert "BLOCKED (draft)" not in proc.stdout
