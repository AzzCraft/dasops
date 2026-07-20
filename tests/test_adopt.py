"""Tests for dasops.adopt module."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


from dasops.adopt import REQUIRED_PATHS, audit_repo, normalize_repo, repair_doc_links, trace_check


class TestAuditRepo(unittest.TestCase):
    def test_empty_repo_finds_all_missing(self):
        with TemporaryDirectory() as tmp:
            result = audit_repo(Path(tmp))
            # A standalone DAS/OpenSpec baseline reports every required path.
            self.assertGreaterEqual(len(result.findings), len(REQUIRED_PATHS))

    def test_compliant_repo_has_no_findings(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, kind in REQUIRED_PATHS.items():
                target = root / rel
                if kind == "dir":
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("")
            result = audit_repo(root)
            self.assertEqual(result.findings, [])

    def test_dir_as_file_reported(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, kind in REQUIRED_PATHS.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("")  # everything as file
            result = audit_repo(root)
            self.assertTrue(any("must be a directory" in f for f in result.findings))


class TestNormalizeRepo(unittest.TestCase):
    def test_seeds_only_safe_baseline_files_without_overwriting_user_content(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Owner README\n", encoding="utf-8")
            result = normalize_repo(root)
            self.assertGreater(len(result.findings), 0)
            self.assertIn("created openspec/changes directory", result.repaired)
            self.assertIn("created scripts/verify", result.repaired)
            self.assertEqual((root / "README.md").read_text(encoding="utf-8"), "# Owner README\n")
            self.assertIn("UNLICENSED", (root / "LICENSE").read_text(encoding="utf-8"))

    def test_creates_a_fail_closed_verify_script(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            normalize_repo(root)
            verify = root / "scripts" / "verify"
            self.assertTrue(verify.exists())
            self.assertTrue(verify.stat().st_mode & 0o111)
            self.assertIn("missing required artifact", verify.read_text(encoding="utf-8"))


class TestRepairDocLinks(unittest.TestCase):
    def test_no_docs_dir_returns_empty(self):
        with TemporaryDirectory() as tmp:
            broken = repair_doc_links(Path(tmp))
            self.assertEqual(broken, [])

    def test_detects_broken_link(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            (docs / "test.md").write_text("[link](nonexistent.md)\n")
            broken = repair_doc_links(root)
            self.assertEqual(len(broken), 1)
            self.assertIn("nonexistent.md", broken[0])

    def test_ignores_http_links(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            (docs / "test.md").write_text("[link](https://example.com)\n")
            broken = repair_doc_links(root)
            self.assertEqual(broken, [])


class TestTraceCheck(unittest.TestCase):
    def test_missing_version_reported(self):
        with TemporaryDirectory() as tmp:
            issues = trace_check(Path(tmp))
            self.assertTrue(any("VERSION" in i for i in issues))

    def test_empty_version_reported(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("")
            issues = trace_check(root)
            self.assertTrue(any("empty" in i for i in issues))

    def test_version_changelog_mismatch(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("2.0.0")
            (root / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0.0\n")
            issues = trace_check(root)
            self.assertTrue(any("2.0.0" in i for i in issues))

    def test_consistent_version_no_issues(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("1.0.0")
            (root / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0.0\n- init\n")
            issues = trace_check(root)
            self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
