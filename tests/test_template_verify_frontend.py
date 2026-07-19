from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file

from dasops.repo_factory import create_product_repo

REPO_ROOT = repository_root_for_test_file(__file__)
TEMPLATE_ROOT = REPO_ROOT / "templates" / "das-product"


def copy_template_repo(tmp_dir: str) -> Path:
    tmp_root = Path(tmp_dir)
    master_doc = tmp_root / "master_doc.md"
    ui_spec = tmp_root / "ui_spec.md"
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
    return create_product_repo(
        factory_root=REPO_ROOT,
        dest_dir=tmp_root / "repo",
        master_doc_path=master_doc,
        ui_spec_path=ui_spec,
        init_git=True,
    )


def run_verify_frontend(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "./scripts/verify-frontend"],
        cwd=repo,
        text=True,
        capture_output=True,
    )


def seed_frontend_evidence(repo: Path, *, visual_matrix_text: str) -> None:
    frontend_root = repo / "artifacts" / "frontend"
    baseline = frontend_root / "baseline"
    screenshots = frontend_root / "screenshots"
    baseline.mkdir(parents=True, exist_ok=True)
    screenshots.mkdir(parents=True, exist_ok=True)
    (frontend_root / "visualMatrix.json").write_text(visual_matrix_text, encoding="utf-8")
    (baseline / "baseline.txt").write_text("baseline\n", encoding="utf-8")
    (screenshots / "screen.txt").write_text("capture\n", encoding="utf-8")


class TemplateVerifyFrontendTests(unittest.TestCase):
    def test_verify_frontend_fails_when_artifacts_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = copy_template_repo(tmp_dir)
            result = run_verify_frontend(repo)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("missing frontend evidence file", result.stderr or result.stdout)

    def test_verify_frontend_fails_when_visual_matrix_is_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = copy_template_repo(tmp_dir)
            seed_frontend_evidence(repo, visual_matrix_text="{not-json}")
            result = run_verify_frontend(repo)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("invalid visualMatrix.json", result.stderr or result.stdout)

    def test_verify_frontend_fails_when_visual_matrix_shape_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = copy_template_repo(tmp_dir)
            seed_frontend_evidence(repo, visual_matrix_text='{"viewports":["desktop"],"themes":["light"]}')
            result = run_verify_frontend(repo)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("visualMatrix must contain exactly these keys", result.stderr or result.stdout)

    def test_verify_frontend_passes_with_governed_visual_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = copy_template_repo(tmp_dir)
            seed_frontend_evidence(repo, visual_matrix_text='{"viewports":["desktop"],"themes":["light"],"locales":["en-US"]}')
            result = run_verify_frontend(repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("frontend evidence artifacts are present and non-empty", result.stdout)


if __name__ == "__main__":
    unittest.main()
