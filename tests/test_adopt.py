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
            # Should report every REQUIRED_PATHS entry + cadence config missing
            self.assertGreaterEqual(len(result.findings), len(REQUIRED_PATHS))
            self.assertTrue(any("cadence.yaml" in f for f in result.findings))

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
            (root / "cadence.yaml").write_text("")
            result = audit_repo(root)
            self.assertEqual(result.findings, [])

    def test_dir_as_file_reported(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, kind in REQUIRED_PATHS.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("")  # everything as file
            (root / "cadence.yaml").write_text("")
            result = audit_repo(root)
            self.assertTrue(any("must be a directory" in f for f in result.findings))


class TestNormalizeRepo(unittest.TestCase):
    def test_does_not_synthesize_compliance_files(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cadence.yaml").write_text("")
            result = normalize_repo(root)
            self.assertGreater(len(result.findings), 0)
            self.assertEqual(result.repaired, ["created openspec/changes directory"])
            for rel in REQUIRED_PATHS:
                if rel == "openspec/changes":
                    self.assertTrue((root / rel).is_dir())
                else:
                    self.assertFalse((root / rel).exists(), f"{rel} must require user-authored content")

    def test_does_not_create_a_noop_verify_script(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cadence.yaml").write_text("")
            normalize_repo(root)
            verify = root / "scripts" / "verify"
            self.assertFalse(verify.exists())


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
