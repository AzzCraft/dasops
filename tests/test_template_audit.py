from __future__ import annotations

import json
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
        self.assertEqual(report.problems, [], f"unexpected template audit problems: {report.problems}")
        payload = report.to_payload()
        self.assertIn("problemDetails", payload)
        self.assertIn("commandParityChecks", payload)
        self.assertIn("frontendEvidenceContract", payload)
        self.assertIn("unsupportedHints", payload)

    def test_template_audit_detects_missing_fail_closed_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            (scratch / "templates" / "das-product" / "scripts" / "verify-backend").write_text(
                "#!/usr/bin/env bash\nexit 0\n",
                encoding="utf-8",
            )
            report = run_template_audit(scratch)
            self.assertTrue(
                any("verify gate does not declare fail-closed behavior" in item for item in report.problems),
                report.problems,
            )
            self.assertTrue(
                any(item.code == "verify_script_not_fail_closed" for item in report.problem_details),
                report.problem_details,
            )

    def test_template_audit_detects_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            tooling_lock = scratch / "templates" / "das-product" / "tooling_lock.json"
            payload = json.loads(tooling_lock.read_text(encoding="utf-8"))
            payload["toolchain"] = {"name": "python3"}
            tooling_lock.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            report = run_template_audit(scratch)
            self.assertTrue(
                any(item.code == "structured_artifact_shape_drift" for item in report.problem_details),
                report.problem_details,
            )

    def test_template_audit_detects_missing_tooling_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            tooling_lock = scratch / "templates" / "das-product" / "tooling_lock.json"
            payload = json.loads(tooling_lock.read_text(encoding="utf-8"))
            payload.pop("suiteLockRef", None)
            tooling_lock.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            report = run_template_audit(scratch)
            self.assertTrue(
                any(item.code == "structured_artifact_missing_key" and "suiteLockRef" in item.message for item in report.problem_details),
                report.problem_details,
            )

    def test_template_audit_detects_missing_verify_guardrail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            verify_script = scratch / "templates" / "das-product" / "scripts" / "verify"
            verify_script.write_text(
                verify_script.read_text(encoding="utf-8").replace("check_stale_lock_semantics", "check_removed_stale_semantics"),
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(item.code == "verify_guardrail_missing" for item in report.problem_details),
                report.problem_details,
            )

    def test_template_audit_detects_unsupported_command_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            readme = scratch / "templates" / "das-product" / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8") + "\nLegacy bootstrap: python scaffold.py\n",
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(item.code == "unsupported_command_hint" for item in report.problem_details),
                report.problem_details,
            )

    def test_template_audit_detects_orchestrator_status_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
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
            self.assertTrue(
                any(item.code == "command_parity_mismatch" for item in report.problem_details),
                report.problem_details,
            )

    def test_template_audit_detects_missing_visual_regression_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            manual = scratch / "templates" / "das-product" / "docs" / "USER_MANUAL.md"
            manual.write_text(
                manual.read_text(encoding="utf-8").replace("baseline ratchet", "baseline-rule"),
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(
                    item.code == "command_parity_mismatch"
                    and "baseline ratchet" in item.message
                    for item in report.problem_details
                ),
                report.problem_details,
            )

    def test_template_audit_detects_missing_cadence_clone_mode_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            vendor_readme = scratch / "templates" / "das-product" / "vendor" / "README.md"
            vendor_readme.write_text(
                vendor_readme.read_text(encoding="utf-8").replace(
                    "./scripts/install_cadence_vendor.sh --tier oss --git-base https://github.com/<org>",
                    "./scripts/install_cadence_vendor.sh --from-suite <path> --tier oss",
                ),
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(
                    item.code == "command_parity_mismatch"
                    and "install_cadence_vendor.sh --tier oss --git-base https://github.com/<org>" in item.message
                    for item in report.problem_details
                ),
                report.problem_details,
            )

    def test_template_audit_detects_missing_cadence_runtime_exec_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            manual = scratch / "templates" / "das-product" / "docs" / "USER_MANUAL.md"
            manual.write_text(
                manual.read_text(encoding="utf-8").replace(
                    "Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof.\n\n",
                    "",
                ),
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(
                    item.code == "command_parity_mismatch"
                    and "mode=runtime-exec" in item.message
                    for item in report.problem_details
                ),
                report.problem_details,
            )

    def test_template_audit_detects_missing_gui_runtime_exec_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            gui = scratch / "gui" / "app.py"
            gui.write_text(
                gui.read_text(encoding="utf-8").replace(
                    "- Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof.\"",
                    "\"",
                ),
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(
                    item.code == "command_parity_mismatch"
                    and "CADENCE_SANDBOX_CONTAINER_ADAPTER" in item.message
                    for item in report.problem_details
                ),
                report.problem_details,
            )

    def test_template_audit_detects_frontend_evidence_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            verify_frontend = scratch / "templates" / "das-product" / "scripts" / "verify-frontend"
            verify_frontend.write_text(
                verify_frontend.read_text(encoding="utf-8").replace(
                    "artifacts/frontend/visualMatrix.json",
                    "artifacts/frontend/visual-drift.json",
                ),
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(item.code == "frontend_evidence_contract_mismatch" for item in report.problem_details),
                report.problem_details,
            )

    def test_template_audit_detects_frontend_runtime_semantics_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            verify_frontend = scratch / "templates" / "das-product" / "scripts" / "verify_frontend_evidence.py"
            verify_frontend.write_text(
                verify_frontend.read_text(encoding="utf-8").replace(
                    "json.loads",
                    "json.dumps",
                ),
                encoding="utf-8",
            )

            report = run_template_audit(scratch)
            self.assertTrue(
                any(item.code == "frontend_evidence_runtime_mismatch" for item in report.problem_details),
                report.problem_details,
            )


if __name__ == "__main__":
    unittest.main()
