from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests._root_contract import repository_root_for_test_file


REPO_ROOT = repository_root_for_test_file(__file__)
DASOPS_ROOT = REPO_ROOT


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(DASOPS_ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run(args: list[str], *, cwd: Path = REPO_ROOT, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60, env=_env())
    assert proc.returncode in ok, proc.stdout + proc.stderr
    return proc


def _run_json(args: list[str], *, cwd: Path = REPO_ROOT, ok: tuple[int, ...] = (0,)) -> dict[str, object]:
    proc = _run(args, cwd=cwd, ok=ok)
    return json.loads(proc.stdout)


def _seed_legacy_repo(root: Path) -> None:
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "master_doc.md").write_text(
        "# Legacy Product\n\nSee [old standard](../standard-v1.4.0/SPECIFICATION.md).\n",
        encoding="utf-8",
    )
    (root / "docs" / "ui_spec.md").write_text("# UI Spec\n", encoding="utf-8")
    (root / "README.md").write_text("# Legacy Product\n", encoding="utf-8")
    (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0.0\n", encoding="utf-8")


def test_ops_002_adopt_normalize_trace_pipeline_yields_verifiable_repo(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    _seed_legacy_repo(legacy)

    audit = _run_json([sys.executable, "-m", "dasops", "audit-repo", str(legacy), "--json"], ok=(1,))
    assert audit["task"] == "OPS-002"
    assert audit["ok"] is False
    assert "scripts/verify" in "\n".join(audit["missingArtifacts"])

    adopted = _run_json([sys.executable, "-m", "dasops", "adopt-repo", str(legacy), "--json"])
    assert adopted["task"] == "OPS-002"
    assert "scripts/verify" in "\n".join(adopted["repairedArtifacts"])

    normalized = _run_json([sys.executable, "-m", "dasops", "normalize-repo", str(legacy), "--json"])
    assert normalized["task"] == "OPS-002"
    assert normalized["docLinkRepairs"]
    assert "../standard/SPECIFICATION.md" in (legacy / "docs" / "master_doc.md").read_text(encoding="utf-8")

    trace = _run_json([sys.executable, "-m", "dasops", "trace-check", str(legacy), "--json"])
    assert trace["task"] == "OPS-002"
    assert trace["ok"] is True
    assert {"requirements", "tasks", "verify", "evidence"} <= set(trace["kinds"])
    assert any(edge["from"] == "requirements" and edge["to"] == "tasks" for edge in trace["relations"])

    verify = _run(["bash", "scripts/verify"], cwd=legacy)
    assert verify.returncode == 0


def test_ops_002_failure_output_names_missing_artifact_and_command(tmp_path: Path) -> None:
    legacy = tmp_path / "broken"
    legacy.mkdir()

    proc = _run(
        [sys.executable, "-m", "dasops", "trace-check", str(legacy), "--json"],
        ok=(1,),
    )

    output = proc.stdout + proc.stderr
    assert "OPS-002" in output
    assert "trace-check" in output
    assert "docs/master_doc.md" in output
