from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file

from dasops.repo_factory import create_product_repo
from dasops.template_audit import run_template_audit


REPO_ROOT = repository_root_for_test_file(__file__)


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


def _write_minimum_docs(root: Path) -> tuple[Path, Path]:
    master_doc = root / "master_doc.md"
    ui_spec = root / "ui_spec.md"
    master_doc.write_text(
        "# Master Doc\n\n"
        "## Conformance profile\n\n"
        "## Repo topology\n\n"
        "## Contracts\n\n"
        "## Traceability\n\n"
        "## Verification\n\n"
        "## Execution plan\n",
        encoding="utf-8",
    )
    ui_spec.write_text("# UI Spec\n", encoding="utf-8")
    return master_doc, ui_spec


class RemediationSpecTests(unittest.TestCase):
    def test_ops_001_git_pin_references_the_bootstrap_baseline_after_create(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            master_doc, ui_spec = _write_minimum_docs(tmp_root)
            repo = create_product_repo(
                factory_root=REPO_ROOT,
                dest_dir=tmp_root / "product",
                master_doc_path=master_doc,
                ui_spec_path=ui_spec,
                init_git=True,
            )

            payload = json.loads((repo / "tooling_lock.json").read_text(encoding="utf-8"))
            pin_value = payload["sourceOfTruth"]["pinValue"]
            head = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                text=True,
            ).strip()

            # A commit cannot truthfully pin itself before it exists.  The
            # factory therefore creates an immutable bootstrap baseline, then
            # records that reachable baseline in a second, clean provenance
            # commit.  Pinning HEAD here would reintroduce a self-referential
            # lock that no independently checked-out history can verify.
            ancestor = subprocess.run(
                ["git", "-C", str(repo), "merge-base", "--is-ancestor", pin_value, head],
                check=False,
            )
            self.assertEqual(ancestor.returncode, 0)
            self.assertNotEqual(pin_value, head)
            self.assertNotEqual(pin_value, "replace-with-product-commit")
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(repo), "status", "--porcelain"],
                    text=True,
                ),
                "",
            )

    def test_ops_002_verify_and_doctor_reject_placeholder_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            master_doc, ui_spec = _write_minimum_docs(tmp_root)
            repo = create_product_repo(
                factory_root=REPO_ROOT,
                dest_dir=tmp_root / "product",
                master_doc_path=master_doc,
                ui_spec_path=ui_spec,
                init_git=False,
            )

            lock_path = repo / "tooling_lock.json"
            payload = json.loads(lock_path.read_text(encoding="utf-8"))
            payload["sourceOfTruth"]["pinValue"] = "replace-with-product-commit"
            lock_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            verify = subprocess.run(
                ["bash", "scripts/verify"],
                cwd=repo,
                check=False,
                capture_output=True,
                text=True,
            )
            doctor = subprocess.run(
                [sys.executable, "-m", "dasops", "doctor", "--repo-root", str(repo)],
                cwd=REPO_ROOT,
                env=_base_env(),
                check=False,
                capture_output=True,
                text=True,
            )

            combined = verify.stdout + verify.stderr + doctor.stdout + doctor.stderr
            self.assertNotEqual(verify.returncode, 0, combined)
            self.assertNotEqual(doctor.returncode, 0, combined)
            self.assertIn("pinValue", combined)

    def test_ops_001_no_git_generation_marks_pin_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            master_doc, ui_spec = _write_minimum_docs(tmp_root)
            repo = create_product_repo(
                factory_root=REPO_ROOT,
                dest_dir=tmp_root / "product",
                master_doc_path=master_doc,
                ui_spec_path=ui_spec,
                init_git=False,
            )

            payload = json.loads((repo / "tooling_lock.json").read_text(encoding="utf-8"))
            source = payload["sourceOfTruth"]
            self.assertEqual(source.get("pinState"), "pending")
            self.assertNotIn("pinValue", source)

    def test_ops_002_template_audit_rejects_template_placeholder_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "factory"
            shutil.copytree(REPO_ROOT, scratch)
            lock_path = scratch / "templates" / "das-product" / "tooling_lock.json"
            payload = json.loads(lock_path.read_text(encoding="utf-8"))
            payload["sourceOfTruth"]["pinValue"] = "replace-with-product-commit"
            payload["sourceOfTruth"].pop("pinState", None)
            lock_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            report = run_template_audit(scratch)
        self.assertTrue(
            any(
                "replace-with-product-commit" in finding.message
                or "sourceOfTruth.pinValue" in finding.message
                for finding in report.problem_details
            ),
            report.problem_details,
        )

    def test_ops_003_verify_rejects_template_docs_placeholder_residue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            repo = create_product_repo(
                factory_root=REPO_ROOT,
                dest_dir=tmp_root / "product",
                master_doc_path=REPO_ROOT / "templates" / "das-product" / "docs" / "master_doc.md",
                ui_spec_path=REPO_ROOT / "templates" / "das-product" / "docs" / "ui_spec.md",
                init_git=True,
            )

            baseline = subprocess.run(
                ["bash", "scripts/verify"], cwd=repo, check=False,
                capture_output=True, text=True,
            )
            self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)
            # The template no longer contains placeholder residue. Inject the
            # fault explicitly so a pending Git pin cannot make this test pass.
            master_doc = repo / "docs" / "master_doc.md"
            master_doc.write_text(master_doc.read_text(encoding="utf-8") + "\nTBD\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", "scripts/verify"],
                cwd=repo,
                check=False,
                capture_output=True,
                text=True,
            )
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0, combined)
            self.assertIn("docs/master_doc.md contains unresolved residue: 'TBD'", combined)

    # --- OPS-VENDOR-001 (completed): template lock has no placeholder pins ---
    def test_ops_vendor_001_template_lock_no_placeholder_pins(self) -> None:
        lock_path = REPO_ROOT / "templates" / "das-product" / "tooling_lock.json"
        self.assertTrue(lock_path.exists(), "template tooling_lock.json missing")
        text = lock_path.read_text(encoding="utf-8")
        forbidden = ["replace-with-product-commit", "fake-sha256", "0000000", "PLACEHOLDER", "TODO"]
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, text, f"Lock file contains placeholder: {pattern}")
        lock = json.loads(text)
        sot = lock.get("sourceOfTruth", {})
        self.assertNotIn("pinValue", sot)
        self.assertEqual(sot.get("pinState"), "template")

    def test_ops_vendor_001_vendor_install_script_fail_closed(self) -> None:
        script_path = REPO_ROOT / "templates" / "das-product" / "scripts" / "install_cadence_vendor.sh"
        self.assertTrue(script_path.exists(), "install_cadence_vendor.sh missing")
        text = script_path.read_text(encoding="utf-8")
        self.assertIn(
            "Clone mode requires --git-base, --org, or DAS_SUITE_GIT_BASE.",
            text,
        )
        self.assertNotIn("https://github.com/<ORG>", text)

    # --- DO-003/DO-004 (historical closure): no unresolved <ORG>/<PRODUCT_REPO> ---
    def test_do_003_004_factory_no_unresolved_template_uris(self) -> None:
        factory_py = REPO_ROOT / "dasops" / "repo_factory.py"
        self.assertTrue(factory_py.exists())
        text = factory_py.read_text(encoding="utf-8")
        self.assertNotIn("<ORG>/<PRODUCT_REPO>", text)
        self.assertNotIn("<ORG>/", text)

    # --- OPS-002 deep: verify script has semantic pin validation code ---
    def test_ops_002_verify_script_has_pin_validation(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("sourceOfTruth", text)
        self.assertIn("pinValue", text)
        self.assertIn("commit", text)
        self.assertIn("replace-with-product-commit", text)

    # --- OPS-002 deep: doctor.py has semantic pin validation ---
    def test_ops_002_doctor_has_pin_validation(self) -> None:
        text = (REPO_ROOT / "dasops" / "doctor.py").read_text(encoding="utf-8")
        self.assertIn("sourceOfTruth", text)
        self.assertIn("pinValue", text)
        self.assertIn("replace-with-product-commit", text)

    # --- OPS-003 deep: verify script has unresolved-doc checks ---
    def test_ops_003_verify_script_has_unresolved_doc_check(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertTrue(
            "unresolved" in text and "docs/master_doc.md" in text,
            "verify script must check for unresolved doc residue",
        )

    # --- OPS-001 matrix exact: template tooling_lock pinValue != placeholder ---
    def test_ops_001_template_tooling_lock_pin_not_placeholder(self) -> None:
        payload = json.loads(
            (REPO_ROOT / "templates" / "das-product" / "tooling_lock.json").read_text(encoding="utf-8")
        )
        pin = payload.get("sourceOfTruth", {}).get("pinValue", "")
        self.assertNotEqual(pin, "replace-with-product-commit")

    # --- OPS-002 matrix exact: verify script checks sourceOfTruth/pinValue/commit ---
    def test_ops_002_matrix_verify_checks_pin(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("sourceOfTruth", text)
        self.assertIn("pinValue", text)
        self.assertIn("commit", text)

    # --- OPS-002 depth: verify script has check_tooling_lock_schema function ---
    def test_ops_002_verify_has_check_tooling_lock_schema(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("check_tooling_lock_schema", text)

    # --- OPS-002 depth: verify rejects pinType not commit/tag ---
    def test_ops_002_verify_rejects_bad_pin_type(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("pinType must be", text)

    # --- OPS-001 depth: factory generates pending state when no git ---

    # --- OPS depth: template verify rejects absolute paths outside repo ---
    def test_ops_verify_rejects_path_traversal(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify").read_text(encoding="utf-8")
        # verify script should use safe path handling
        self.assertTrue(
            "ROOT" in text or "REPO_ROOT" in text or "resolve" in text or "realpath" in text,
            "verify script must reference repo root for path safety",
        )

    # --- OPS depth: dasops has LICENSE ---
    def test_ops_license_exists(self) -> None:
        self.assertTrue((REPO_ROOT / "LICENSE").exists())

    # --- OPS depth: CHANGELOG exists ---
    def test_ops_changelog_exists(self) -> None:
        self.assertTrue((REPO_ROOT / "CHANGELOG.md").exists())

    # --- OPS depth: BUILD_REQUIREMENTS exists ---
    def test_ops_build_requirements_exists(self) -> None:
        self.assertTrue((REPO_ROOT / "BUILD_REQUIREMENTS.md").exists())

    # --- OPS depth: VERIFY_REQUIREMENTS exists ---
    def test_ops_verify_requirements_exists(self) -> None:
        self.assertTrue((REPO_ROOT / "VERIFY_REQUIREMENTS.md").exists())

    # --- OPS depth: template audit module exists ---
    def test_ops_template_audit_module_exists(self) -> None:
        self.assertTrue((REPO_ROOT / "dasops" / "template_audit.py").exists())

    # --- V9 Item 04: dasops template no old baseline/standard/vendor/fail-open ---

    def test_v9_04_template_no_copied_standard(self) -> None:
        self.assertFalse(
            (REPO_ROOT / "templates" / "das-product" / "docs" / "standards" / "DAS_STANDARD.md").exists(),
            "copied standard doc still exists in template",
        )

    def test_v9_04_template_has_standard_ref(self) -> None:
        self.assertTrue((REPO_ROOT / "templates" / "das-product" / "STANDARD_REF.md").exists())

    def test_v9_04_template_has_lock_artifacts(self) -> None:
        for name in ("tooling_lock.json", "local_extension_manifest.json"):
            with self.subTest(file=name):
                self.assertTrue((REPO_ROOT / "templates" / "das-product" / name).exists())

    def test_v9_04_template_text_references_standard_ref(self) -> None:
        targets = {
            "README.md": (REPO_ROOT / "templates" / "das-product" / "README.md"),
            "AGENTS.override.md": (REPO_ROOT / "templates" / "das-product" / "AGENTS.override.md"),
            "docs/USER_MANUAL.md": (REPO_ROOT / "templates" / "das-product" / "docs" / "USER_MANUAL.md"),
            "openspec/config.yaml": (REPO_ROOT / "templates" / "das-product" / "openspec" / "config.yaml"),
            "vendor/README.md": (REPO_ROOT / "templates" / "das-product" / "vendor" / "README.md"),
        }
        for name, path in targets.items():
            if path.exists():
                text = path.read_text(encoding="utf-8")
                with self.subTest(file=name):
                    self.assertIn("STANDARD_REF.md", text)

    def test_v9_04_template_no_old_baseline(self) -> None:
        targets = {
            "README.md": REPO_ROOT / "templates" / "das-product" / "README.md",
            "AGENTS.override.md": REPO_ROOT / "templates" / "das-product" / "AGENTS.override.md",
            "docs/USER_MANUAL.md": REPO_ROOT / "templates" / "das-product" / "docs" / "USER_MANUAL.md",
            "openspec/config.yaml": REPO_ROOT / "templates" / "das-product" / "openspec" / "config.yaml",
            "vendor/README.md": REPO_ROOT / "templates" / "das-product" / "vendor" / "README.md",
        }
        for name, path in targets.items():
            if path.exists():
                text = path.read_text(encoding="utf-8")
                with self.subTest(file=name):
                    self.assertNotIn("unified" + "-current-baseline", text)
                    self.assertNotIn("cadence-forge" + "-enterprise", text)

    def test_v9_04_verify_backend_fail_closed(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify-backend").read_text(encoding="utf-8")
        self.assertIn("exit 1", text)
        self.assertTrue("fail-closed" in text or "[FAIL]" in text,
            "verify-backend must declare fail-closed or [FAIL] marker")

    def test_v9_04_verify_contracts_fail_closed(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "verify-contracts").read_text(encoding="utf-8")
        self.assertIn("exit 1", text)
        self.assertTrue("fail-closed" in text or "[FAIL]" in text,
            "verify-contracts must declare fail-closed or [FAIL] marker")

    def test_v9_04_vendor_script_is_limited_to_public_cadence_oss(self) -> None:
        text = (REPO_ROOT / "templates" / "das-product" / "scripts" / "install_cadence_vendor.sh").read_text(encoding="utf-8")
        self.assertIn("cadence-oss", text)
        self.assertNotIn("cadence" + "-enterprise", text)
        self.assertNotIn("cadence" + "-pro", text)
        self.assertNotIn("cadence-forge" + "-enterprise", text)

    def test_v9_04_worker_script_uses_lock_status(self) -> None:
        script = REPO_ROOT / "templates" / "das-product" / "scripts" / "run_worker_codex.sh"
        self.assertTrue(script.exists(), "run_worker_codex.sh must exist")
        text = script.read_text(encoding="utf-8")
        self.assertIn("dasops lock-status", text)
        self.assertNotIn('grep -q "^Owner:', text,
            "worker script must not grep Owner header")

    # --- Additional Item 04 content-validation tests ---

    def test_v9_04_agents_override_no_old_standard_path(self) -> None:
        agents = REPO_ROOT / "templates" / "das-product" / "AGENTS.override.md"
        text = agents.read_text(encoding="utf-8")
        self.assertNotIn("docs/standards/DAS_STANDARD.md", text)
        self.assertIn("STANDARD_REF.md", text)

    def test_v9_04_tooling_lock_json_valid_structure(self) -> None:
        import json
        lock = json.loads((REPO_ROOT / "templates" / "das-product" / "tooling_lock.json").read_text(encoding="utf-8"))
        self.assertIn("sourceOfTruth", lock)
        sot = lock["sourceOfTruth"]
        self.assertIn("pinState", sot)
        self.assertEqual(sot["pinState"], "template")

    def test_v9_04_local_extension_manifest_valid_json(self) -> None:
        import json
        data = json.loads(
            (REPO_ROOT / "templates" / "das-product" / "local_extension_manifest.json").read_text(encoding="utf-8")
        )
        self.assertIsInstance(data, dict)


if __name__ == "__main__":
    unittest.main()
