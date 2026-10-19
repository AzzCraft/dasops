"""Golden tests for dasops task parsing, lock schema, and adopt flow."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from dasops.adopt import audit_repo, normalize_repo, repair_doc_links, trace_check
from dasops.locks import is_stale, read_lock
from dasops.legacy_task_state import StateError
from dasops.tasks import extract_task_verify_cmds, parse_tasks_index


GOLDEN_ROOT = Path(__file__).resolve().parent / "golden"
ALLOWED_TASK_STATUSES = {"TODO", "IN_PROGRESS", "DONE", "BLOCKED", "PROPOSED"}


def lint_task_rows(rows) -> list[str]:
    issues: list[str] = []
    for row in rows:
        if not row.verify_gate.strip():
            issues.append(f"{row.task_id}: missing verify gate")
        if row.status.strip() not in ALLOWED_TASK_STATUSES:
            issues.append(f"{row.task_id}: invalid status {row.status!r}")
    return issues


class LockSchemaGoldenTests(unittest.TestCase):
    """Verify lock file schema expectations."""

    def read_fixture(self, path: Path):
        # Corpus filenames describe cases; operational filenames bind task IDs.
        raw = path.read_bytes()
        task_id = yaml.safe_load(raw)["taskId"]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / f"{task_id}.lock"
            target.write_bytes(raw)
            return read_lock(target)

    def test_valid_lock_corpus_round_trips_into_structured_lock(self) -> None:
        valid_locks = sorted((GOLDEN_ROOT / "locks" / "valid").glob("*.lock"))
        self.assertGreaterEqual(len(valid_locks), 3, "expected expanded valid lock corpus")
        for path in valid_locks:
            lock = self.read_fixture(path)
            self.assertIsNotNone(lock, f"expected valid lock: {path.name}")
            # The descriptive corpus name must not bypass operational binding.
            with self.assertRaisesRegex(StateError, "invalid_lock"):
                read_lock(path)

    def test_invalid_lock_corpus_is_rejected(self) -> None:
        invalid_locks = sorted((GOLDEN_ROOT / "locks" / "invalid").glob("*.lock"))
        self.assertGreaterEqual(len(invalid_locks), 4, "expected expanded invalid lock corpus")
        for path in invalid_locks:
            with self.subTest(fixture=path.name):
                with self.assertRaisesRegex(StateError, "invalid_lock"):
                    self.read_fixture(path)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(read_lock(Path(tmp) / "missing.lock"))

    def test_stale_and_reclaim_fixtures_capture_lifecycle_semantics(self) -> None:
        stale_lock = self.read_fixture(GOLDEN_ROOT / "locks" / "valid" / "stale.lock")
        self.assertIsNotNone(stale_lock)
        self.assertTrue(is_stale(stale_lock), "stale fixture should be stale")

        reclaimed = self.read_fixture(GOLDEN_ROOT / "locks" / "valid" / "reclaimed.lock")
        self.assertIsNotNone(reclaimed)
        self.assertGreaterEqual(reclaimed.version, 2, "reclaimed lock should bump lock version")


class TaskCorpusGoldenTests(unittest.TestCase):
    """Verify task index parsing against realistic markdown corpus."""

    def test_valid_task_markdown_yields_task_rows_and_verify_gate(self) -> None:
        valid_docs = sorted((GOLDEN_ROOT / "tasks" / "valid").glob("*.tasks.md"))
        self.assertGreaterEqual(len(valid_docs), 3, "expected expanded valid task corpus")
        for path in valid_docs:
            task_doc = path.read_text(encoding="utf-8")
            rows = parse_tasks_index(task_doc)
            self.assertTrue(rows, f"expected rows in valid task doc: {path.name}")
            self.assertEqual(lint_task_rows(rows), [], f"unexpected row drift in {path.name}")

        basic_doc = (GOLDEN_ROOT / "tasks" / "valid" / "basic.tasks.md").read_text(encoding="utf-8")
        self.assertEqual(extract_task_verify_cmds(basic_doc, "T-001"), ["./scripts/verify"])

    def test_invalid_task_markdown_without_index_table_yields_no_rows(self) -> None:
        task_doc = (GOLDEN_ROOT / "tasks" / "invalid" / "no_table.tasks.md").read_text(encoding="utf-8")
        self.assertEqual(parse_tasks_index(task_doc), [])
        self.assertEqual(extract_task_verify_cmds(task_doc, "T-001"), [])

    def test_invalid_task_corpus_catches_column_and_status_drift(self) -> None:
        missing_verify = (GOLDEN_ROOT / "tasks" / "invalid" / "missing_verify_column.tasks.md").read_text(encoding="utf-8")
        missing_rows = parse_tasks_index(missing_verify)
        self.assertTrue(missing_rows)
        self.assertIn("T-030: missing verify gate", lint_task_rows(missing_rows))

        invalid_status = (GOLDEN_ROOT / "tasks" / "invalid" / "invalid_status.tasks.md").read_text(encoding="utf-8")
        status_rows = parse_tasks_index(invalid_status)
        self.assertTrue(status_rows)
        self.assertIn("T-031: invalid status 'RUNNING'", lint_task_rows(status_rows))


class AdoptFlowGoldenTests(unittest.TestCase):
    """Verify the adopt/normalize/repair/trace pipeline."""

    def test_audit_finds_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            result = audit_repo(repo)
            # Should find many missing files
            self.assertGreater(len(result.findings), 5)

    def test_audit_clean_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            # Create all required files
            for rel in [
                "docs/master_doc.md", "docs/ui_spec.md",
                "VERSION", "CHANGELOG.md",
                "README.md", "scripts/verify", "BUILD_REQUIREMENTS.md",
                "VERIFY_REQUIREMENTS.md", "NOTICE", "LICENSE",
            ]:
                p = repo / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("placeholder\n")
            (repo / "openspec" / "changes").mkdir(parents=True, exist_ok=True)
            (repo / "cadence.yaml").write_text("projectId: test\n")
            result = audit_repo(repo)
            self.assertEqual(len(result.findings), 0, f"unexpected findings: {result.findings}")

    def test_normalize_creates_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            result = normalize_repo(repo)
            self.assertGreater(len(result.repaired), 0)
            # After normalize, files should exist
            self.assertTrue((repo / "VERSION").exists())
            self.assertTrue((repo / "README.md").exists())
            self.assertTrue((repo / "openspec" / "changes").is_dir())

    def test_repair_doc_links_empty_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            broken = repair_doc_links(repo)
            self.assertEqual(len(broken), 0)

    def test_repair_doc_links_finds_broken(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            docs = repo / "docs"
            docs.mkdir()
            (docs / "index.md").write_text("See [guide](nonexistent.md) for details.\n")
            broken = repair_doc_links(repo)
            self.assertEqual(len(broken), 1)
            self.assertIn("nonexistent.md", broken[0])

    def test_trace_check_missing_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            issues = trace_check(repo)
            self.assertTrue(any("VERSION" in i for i in issues))

    def test_trace_check_version_not_in_changelog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "VERSION").write_text("2.0.0\n")
            (repo / "CHANGELOG.md").write_text("# Changelog\n## 1.0.0\n- initial\n")
            issues = trace_check(repo)
            self.assertTrue(any("CHANGELOG" in i for i in issues))

    def test_valid_lock_fixture_is_well_formed_yaml(self) -> None:
        data = yaml.safe_load((GOLDEN_ROOT / "locks" / "valid" / "basic.lock").read_text(encoding="utf-8"))
        self.assertEqual(data["taskId"], "T-001")
        self.assertEqual(data["leaseSeconds"], 3600)


if __name__ == "__main__":
    unittest.main()
