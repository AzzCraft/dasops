"""Regression coverage for root OpenSpec status schema handling."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[2]
CHANGE_ID = "v10-6-commercial-ga-closure"
SCHEMA_REL = "openspec/schemas/das-standard/schema.yaml"
STATUS_COMMAND = f"PYTHONPATH=dasops python3 -m dasops status --id {CHANGE_ID}"


class StatusSchemaContractTests(unittest.TestCase):
    def _run_status_without_root_schema(self) -> subprocess.CompletedProcess[str]:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            change_dir = repo / "openspec" / "changes" / CHANGE_ID
            change_dir.mkdir(parents=True)
            (change_dir / "tasks.md").write_text(
                "# Tasks\n\n"
                "| Task ID | Title | Owner | Status | Depends on | Verify gate |\n"
                "|---|---|---|---|---|---|\n"
                "| T-001 | Example | - | TODO | - | `python3 -m pytest` |\n",
                encoding="utf-8",
            )

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

    def test_status_command_does_not_crash_when_root_schema_is_missing(self) -> None:
        proc = self._run_status_without_root_schema()

        self.assertEqual(
            proc.returncode,
            0,
            (
                f"{STATUS_COMMAND} must not fail with FileNotFoundError when "
                f"{SCHEMA_REL} is missing.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            ),
        )
        self.assertNotIn("FileNotFoundError", proc.stderr)
        self.assertIn(f"Change: {CHANGE_ID}", proc.stdout)


if __name__ == "__main__":
    unittest.main()
