"""Integration tests for dasops end-to-end workflows."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

DASOPS_ROOT = Path(__file__).resolve().parents[2]


class TestCreateAndVerify(unittest.TestCase):
    """Test: create product repo → run verify → expect pass."""

    def test_create_product_repo_and_verify(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test-product"
            master_doc = DASOPS_ROOT / "templates" / "das-product" / "docs" / "master_doc.md"
            ui_spec = DASOPS_ROOT / "templates" / "das-product" / "docs" / "ui_spec.md"

            # Create placeholder docs if they don't exist
            if not master_doc.exists():
                master_doc.parent.mkdir(parents=True, exist_ok=True)
                master_doc.write_text("# Master Doc\nPlaceholder.\n")
            if not ui_spec.exists():
                ui_spec.parent.mkdir(parents=True, exist_ok=True)
                ui_spec.write_text("# UI Spec\nPlaceholder.\n")

            result = subprocess.run(
                [
                    "python3", "-m", "dasops", "create",
                    "--dest", str(dest),
                    "--master-doc", str(master_doc),
                    "--ui-spec", str(ui_spec),
                    "--no-git",
                ],
                cwd=str(DASOPS_ROOT),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"create failed: {result.stdout}\n{result.stderr}")
            self.assertTrue(dest.exists())
            self.assertTrue((dest / "STANDARD_REF.md").exists())
            self.assertFalse((dest / "cadence.yaml").exists())


class TestDoctorOnFactory(unittest.TestCase):
    """Test: run doctor on the factory repo itself."""

    def test_doctor_factory(self):
        result = subprocess.run(
            ["python3", "-m", "dasops", "doctor", "--repo-root", str(DASOPS_ROOT)],
            cwd=str(DASOPS_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertIn("Result:", result.stdout)


class TestTrace(unittest.TestCase):
    """Test: trace module checks VERSION vs CHANGELOG."""

    def test_trace_check_factory(self):
        from dasops.trace import check_trace

        findings = check_trace(DASOPS_ROOT)
        # Factory should have VERSION in CHANGELOG
        self.assertEqual(findings, [], f"Trace findings: {findings}")


class TestCreateAuditClean(unittest.TestCase):
    """Test: create product repo → audit → expect zero findings."""

    def test_created_repo_passes_audit(self):
        from dasops.adopt import audit_repo

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "audit-test-product"
            master_doc = DASOPS_ROOT / "templates" / "das-product" / "docs" / "master_doc.md"
            ui_spec = DASOPS_ROOT / "templates" / "das-product" / "docs" / "ui_spec.md"

            # Create placeholder docs if they don't exist
            if not master_doc.exists():
                master_doc.parent.mkdir(parents=True, exist_ok=True)
                master_doc.write_text("# Master Doc\nPlaceholder.\n")
            if not ui_spec.exists():
                ui_spec.parent.mkdir(parents=True, exist_ok=True)
                ui_spec.write_text("# UI Spec\nPlaceholder.\n")

            result = subprocess.run(
                [
                    "python3", "-m", "dasops", "create",
                    "--dest", str(dest),
                    "--master-doc", str(master_doc),
                    "--ui-spec", str(ui_spec),
                    "--no-git",
                ],
                cwd=str(DASOPS_ROOT),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"create failed: {result.stdout}\n{result.stderr}")

            # The created repo should pass audit with zero findings
            audit_result = audit_repo(dest)
            self.assertEqual(
                len(audit_result.findings), 0,
                f"generated repo has audit findings: {audit_result.findings}",
            )


if __name__ == "__main__":
    unittest.main()
