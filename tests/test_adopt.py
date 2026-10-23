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
    def test_evidence_hardlink_refuses_before_any_repair(self):
        import os
        from dasops.adopt import adopt_report, normalize_report
        for command in (normalize_report, adopt_report):
            with self.subTest(command=command.__name__), TemporaryDirectory() as tmp:
                root = Path(tmp) / 'product'
                (root / '.dasops').mkdir(parents=True)
                other = Path(tmp) / 'preserve.txt'
                other.write_bytes(b'irreplaceable')
                evidence = root / '.dasops/adoption_evidence.json'
                os.link(other, evidence)
                before = sorted(p.relative_to(root) for p in root.rglob('*'))
                result = command(root)
                self.assertFalse(result['ok'])
                self.assertTrue(any('hard link' in f for f in result['findings']))
                self.assertEqual(other.read_bytes(), b'irreplaceable')
                self.assertEqual(evidence.read_bytes(), b'irreplaceable')
                self.assertEqual(before, sorted(p.relative_to(root) for p in root.rglob('*')))
                evidence.unlink()
                evidence.write_bytes(b'old evidence')
                self.assertTrue(adopt_report(root)['ok'])
                self.assertEqual(other.read_bytes(), b'irreplaceable')
                self.assertIn('adopted', evidence.read_text())

    def test_conflicts_refuse_both_commands_without_writing(self):
        from dasops.__main__ import main
        from contextlib import redirect_stdout
        import io
        import json
        for command in ("normalize-repo", "adopt-repo"):
            for rel in ("openspec/changes", "docs", "scripts", "README.md"):
                with self.subTest(command=command, conflict=rel), TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    sentinel = root / rel
                    sentinel.parent.mkdir(parents=True, exist_ok=True)
                    if rel == "README.md":
                        sentinel.mkdir()
                    else:
                        sentinel.write_bytes(b"irreplaceable")
                    before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
                    inode = sentinel.stat().st_ino
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = main([command, str(root), "--json"])
                    payload = json.loads(output.getvalue())
                    self.assertNotEqual(code, 0)
                    self.assertFalse(payload["ok"])
                    self.assertTrue(any(rel in f for f in payload["findings"]))
                    self.assertEqual(sentinel.stat().st_ino, inode)
                    if sentinel.is_file():
                        self.assertEqual(sentinel.read_bytes(), b"irreplaceable")
                    self.assertEqual(before, sorted(str(p.relative_to(root)) for p in root.rglob("*")))

    def test_creates_missing_files(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cadence.yaml").write_text("")
            result = normalize_repo(root)
            self.assertGreater(len(result.repaired), 0)
            # After normalization, all required paths should exist
            for rel in REQUIRED_PATHS:
                self.assertTrue((root / rel).exists(), f"{rel} should exist after normalize")

    def test_verify_script_is_executable(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cadence.yaml").write_text("")
            normalize_repo(root)
            verify = root / "scripts" / "verify"
            self.assertTrue(verify.exists())
            import os
            self.assertTrue(os.access(verify, os.X_OK))


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


def test_trace_rejects_type_conflict_and_version_substrings(tmp_path):
    from dasops.adopt import trace_report
    normalize_repo(tmp_path)
    (tmp_path / 'VERSION').write_text('1.0.0')
    for version, ok in [('11.0.0', False), ('1.0.0-beta.1', False), ('1.0.0', True)]:
        (tmp_path / 'CHANGELOG.md').write_text(f'## {version}\n')
        assert trace_report(tmp_path)['ok'] is ok
    (tmp_path / 'LICENSE').unlink()
    (tmp_path / 'LICENSE').mkdir()
    assert not trace_report(tmp_path)['ok']


def test_link_repair_preserves_valid_history_and_requires_real_destination(tmp_path):
    from dasops.repair_doc_links import repair_tree
    docs = tmp_path / 'docs'; docs.mkdir()
    link = docs / 'guide.md'
    link.write_text('[spec](../standard-v1.4.0/SPECIFICATION.md)')
    before = link.read_bytes()
    assert repair_tree(tmp_path).edits == 0
    current = tmp_path / 'standard'; current.mkdir()
    (current / 'SPECIFICATION.md').write_text('current')
    historical = tmp_path / 'standard-v1.4.0'; historical.mkdir()
    (historical / 'SPECIFICATION.md').write_text('historical')
    assert repair_tree(tmp_path).edits == 0 and link.read_bytes() == before
    (historical / 'SPECIFICATION.md').unlink()
    assert repair_tree(tmp_path).edits == 1
    assert '../standard/SPECIFICATION.md' in link.read_text()
    assert repair_tree(tmp_path).edits == 0
