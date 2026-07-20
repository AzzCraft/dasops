"""Release regressions for the truthful standalone product scaffold."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from tests._root_contract import repository_root_for_test_file

from dasops.repo_factory import create_product_repo
from dasops.template_audit import run_template_audit


REPO_ROOT = repository_root_for_test_file(__file__)


def _write_minimum_docs(root: Path) -> tuple[Path, Path]:
    master_doc = root / "master_doc.md"
    ui_spec = root / "ui_spec.md"
    master_doc.write_text(
        "# Master Doc\n\n## Conformance profile\n\n## Repo topology\n\n"
        "## Contracts\n\n## Traceability\n\n## Verification\n\n## Execution plan\n",
        encoding="utf-8",
    )
    ui_spec.write_text("# UI Spec\n", encoding="utf-8")
    return master_doc, ui_spec


class RemediationSpecTests(unittest.TestCase):
    def test_scaffold_is_standalone_and_does_not_invent_governed_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            master_doc, ui_spec = _write_minimum_docs(root)
            repo = create_product_repo(
                factory_root=REPO_ROOT,
                dest_dir=root / "product",
                master_doc_path=master_doc,
                ui_spec_path=ui_spec,
                init_git=True,
            )
            for rel in ("cadence.yaml", "cadencew", "tooling_lock.json", "local_extension_manifest.json"):
                self.assertFalse((repo / rel).exists(), rel)
            verify = subprocess.run(
                ["bash", "scripts/verify"], cwd=repo, text=True, capture_output=True, check=False
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            status = subprocess.run(
                ["git", "status", "--porcelain"], cwd=repo, text=True, capture_output=True, check=True
            )
            self.assertEqual(status.stdout, "")

    def test_template_audit_confirms_no_governed_closure_placeholder(self) -> None:
        report = run_template_audit(REPO_ROOT)
        self.assertEqual(report.problems, [], report.problems)
        template = REPO_ROOT / "templates" / "das-product"
        self.assertFalse((template / "tooling_lock.json").exists())
        self.assertFalse((template / "local_extension_manifest.json").exists())

    def test_public_template_excludes_internal_and_commercial_release_terms(self) -> None:
        forbidden = ("release-inputs/commercial", "cadence-forge-enterprise", "DAS_L2_v10_")
        for path in (REPO_ROOT / "templates" / "das-product").rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for term in forbidden:
                self.assertNotIn(term, text, f"{path}: {term}")


if __name__ == "__main__":
    unittest.main()
