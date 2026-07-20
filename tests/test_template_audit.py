from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from tests._root_contract import repository_root_for_test_file

from dasops.template_audit import run_template_audit


REPO_ROOT = repository_root_for_test_file(__file__)


class TemplateAuditTests(unittest.TestCase):
    def test_factory_template_audit_passes_on_current_repo(self) -> None:
        report = run_template_audit(REPO_ROOT)
        self.assertEqual(report.problems, [], report.problems)
        self.assertEqual(report.structured_artifacts, {})

    def test_template_audit_detects_missing_fail_closed_script(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            (scratch / "templates" / "das-product" / "scripts" / "verify-backend").write_text(
                "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
            )
            report = run_template_audit(scratch)
            self.assertTrue(any(item.code == "verify_script_not_fail_closed" for item in report.problem_details))

    def test_template_audit_detects_missing_verify_guardrail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            script = scratch / "templates" / "das-product" / "scripts" / "verify"
            script.write_text(
                script.read_text(encoding="utf-8").replace("check_stale_lock_semantics", "check_removed_stale_semantics"),
                encoding="utf-8",
            )
            report = run_template_audit(scratch)
            self.assertTrue(any(item.code == "verify_guardrail_missing" for item in report.problem_details))

    def test_template_audit_detects_unsupported_command_hint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            readme = scratch / "templates" / "das-product" / "README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\npython3 scaffold.py\n", encoding="utf-8")
            report = run_template_audit(scratch)
            self.assertTrue(any(item.code == "unsupported_command_hint" for item in report.problem_details))

    def test_template_audit_detects_orchestrator_status_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            prompt = scratch / "templates" / "das-product" / "prompts" / "orchestrator.md"
            prompt.write_text(
                prompt.read_text(encoding="utf-8").replace(
                    "Status values are limited to: `TODO`, `IN_PROGRESS`, `DONE`, `BLOCKED`, `PROPOSED`.",
                    "Status values are limited to: `TODO`, `IN_PROGRESS`, `DONE`.",
                ),
                encoding="utf-8",
            )
            report = run_template_audit(scratch)
            self.assertTrue(any(item.code == "command_parity_mismatch" for item in report.problem_details))

    def test_template_audit_detects_frontend_evidence_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            script = scratch / "templates" / "das-product" / "scripts" / "verify-frontend"
            script.write_text(
                script.read_text(encoding="utf-8").replace("artifacts/frontend/visualMatrix.json", "artifacts/frontend/visual-drift.json"),
                encoding="utf-8",
            )
            report = run_template_audit(scratch)
            self.assertTrue(any(item.code == "frontend_evidence_contract_mismatch" for item in report.problem_details))


if __name__ == "__main__":
    unittest.main()
