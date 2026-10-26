"""Tests for dasops.tasks module."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from dasops.tasks import (
    Artifact,
    TaskRow,
    artifact_status,
    extract_task_branch,
    extract_task_owner_status,
    extract_task_verify_cmds,
    file_is_draft,
    find_task_section,
    index_rows_by_id,
    is_unassigned_owner,
    parse_tasks_index,
    split_deps,
    update_task_details_section,
    update_task_index_table,
    update_tasks_md_text,
)

# ---------------------------------------------------------------------------
# Sample Markdown
# ---------------------------------------------------------------------------

SAMPLE_TASKS_MD = """\
# Tasks

| Task ID | Title | Owner | Status | Depends On | Verify Gate |
| ------- | ----- | ----- | ------ | ---------- | ----------- |
| T-001   | First task  | alice | TODO   | -          | scripts/verify |
| T-002   | Second task | bob   | IN_PROGRESS | T-001 | scripts/verify |
| T-003   | Third task  | -     | TODO   | T-001, T-002 | scripts/verify |

### T-001

- Owner: alice
- Status: TODO
- Branch: `feature/first`
- Verification: `scripts/verify`

### T-002

- Owner: bob
- Status: IN_PROGRESS
- Branch: `feature/second`
- Verification:
  - `scripts/verify --task T-002`

### T-003

- Owner: -
- Status: TODO
"""


# ---------------------------------------------------------------------------
# parse_tasks_index
# ---------------------------------------------------------------------------


class TestParseTasksIndex(unittest.TestCase):
    def test_parses_all_rows(self):
        rows = parse_tasks_index(SAMPLE_TASKS_MD)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0].task_id, "T-001")
        self.assertEqual(rows[0].owner, "alice")
        self.assertEqual(rows[0].status, "TODO")

    def test_second_row_depends(self):
        rows = parse_tasks_index(SAMPLE_TASKS_MD)
        self.assertEqual(rows[1].depends_on, "T-001")

    def test_third_row_multi_deps(self):
        rows = parse_tasks_index(SAMPLE_TASKS_MD)
        self.assertEqual(rows[2].depends_on, "T-001, T-002")

    def test_empty_string(self):
        rows = parse_tasks_index("")
        self.assertEqual(rows, [])

    def test_no_table(self):
        rows = parse_tasks_index("# Tasks\n\nSome text but no table.\n")
        self.assertEqual(rows, [])

    def test_short_row_rejected(self):
        md = """\
| Task ID | Title | Owner | Status | Depends On | Verify Gate |
| ------- | ----- | ----- | ------ | ---------- | ----------- |
| T-X | Short |
"""
        with self.assertRaisesRegex(ValueError, "six columns"):
            parse_tasks_index(md)

    def test_malformed_header_is_not_an_absent_index(self):
        header = '| Task ID | Title | Owner | Status | Depends On | Verify Gate |\n|---|---|---|---|---|---|\n'
        for column in ('Owner', 'Status', 'Title', 'Depends On', 'Verify Gate'):
            malformed = header.replace(column, 'Wrong column') + '| A | work | - | TODO | - | true |\n'
            with self.subTest(column=column), self.assertRaisesRegex(ValueError, 'columns.*line 1'):
                parse_tasks_index(malformed)

    def test_header_label_can_still_be_a_task_id(self):
        text = ('| Task ID | Title | Owner | Status | Depends On | Verify Gate |\n'
                '|---|---|---|---|---|---|\n| Task ID | work | worker | DONE | - | true |\n')
        rows = parse_tasks_index(text)
        self.assertEqual([(row.task_id, row.status) for row in rows], [('Task ID', 'DONE')])

    def test_separator_like_task_id_is_not_discarded(self):
        text = ('| Task ID | Title | Owner | Status | Depends On | Verify Gate |\n'
                '|---|---|---|---|---|---|\n| ---A | pending | - | TODO | - | true |\n'
                '| B | finished | worker | DONE | - | true |\n')
        rows = parse_tasks_index(text)
        self.assertEqual([(row.task_id, row.status) for row in rows], [('---A', 'TODO'), ('B', 'DONE')])
        with TemporaryDirectory() as temp:
            change = Path(temp);path = change/'tasks.md';path.write_text(text)
            self.assertEqual(artifact_status(change, [Artifact('execution-plan', 'tasks.md', [])]),
                             {'execution-plan': 'BLOCKED'})
            self.assertEqual(path.read_text(), text)

    def test_malformed_index_cannot_hide_behind_a_done_index(self):
        header = '| Task ID | Title | Owner | Status | Depends On | Verify Gate |\n|---|---|---|---|---|---|\n'
        bad = header.replace('Owner', 'Wrong column')+'| A | unfinished | - | TODO | - | true |\n'
        done = header+'| B | finished | worker | DONE | - | true |\n'
        for text in (bad+'\n'+done, done+'\n'+bad):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'ambiguous'):
                parse_tasks_index(text)
            with TemporaryDirectory() as temp:
                change = Path(temp)
                path = change/'tasks.md';path.write_text(text)
                with self.assertRaisesRegex(SystemExit, 'ambiguous'):
                    artifact_status(change, [Artifact('execution-plan', 'tasks.md', [])])
                self.assertEqual(path.read_text(), text)


# ---------------------------------------------------------------------------
# find_task_section
# ---------------------------------------------------------------------------


class TestFindTaskSection(unittest.TestCase):
    def test_space_containing_indexed_id_does_not_match_shorter_task(self):
        header = "| Task ID | Title | Owner | Status | Depends on | Verify gate |\n|---|---|---|---|---|---|\n"
        text = (header + "| build | short | - | TODO | - | true |\n"
                "| build app | long | - | TODO | - | true |\n\n"
                "### build app: Long task\n- Owner: long-owner\n- Status: TODO\n- Branch: `long`\n\n"
                "### build: Short task\n- Owner: short-owner\n- Status: TODO\n- Branch: `short`\n")
        self.assertEqual(extract_task_branch(text, "build"), "short")
        self.assertEqual(extract_task_branch(text, "build app"), "long")
        updated, changed = update_tasks_md_text(text, "build", "new-short", "IN_PROGRESS")
        self.assertTrue(changed)
        self.assertIn("### build app: Long task\n- Owner: long-owner\n- Status: TODO", updated)
        self.assertIn("### build: Short task\n- Owner: new-short\n- Status: IN_PROGRESS", updated)

    def test_finds_section(self):
        lines = SAMPLE_TASKS_MD.splitlines(keepends=True)
        result = find_task_section(lines, "T-001")
        self.assertIsNotNone(result)
        start, end = result
        self.assertIn("T-001", lines[start])

    def test_missing_section(self):
        lines = SAMPLE_TASKS_MD.splitlines(keepends=True)
        result = find_task_section(lines, "T-999")
        self.assertIsNone(result)

    def test_section_boundaries(self):
        lines = SAMPLE_TASKS_MD.splitlines(keepends=True)
        start, end = find_task_section(lines, "T-002")
        # T-003 starts after T-002 section
        self.assertIn("T-003", lines[end])


# ---------------------------------------------------------------------------
# extract_task_branch
# ---------------------------------------------------------------------------


class TestExtractTaskBranch(unittest.TestCase):
    def test_branch_backtick(self):
        branch = extract_task_branch(SAMPLE_TASKS_MD, "T-001")
        self.assertEqual(branch, "feature/first")

    def test_branch_not_found(self):
        branch = extract_task_branch(SAMPLE_TASKS_MD, "T-003")
        self.assertEqual(branch, "")

    def test_nonexistent_task(self):
        branch = extract_task_branch(SAMPLE_TASKS_MD, "T-999")
        self.assertEqual(branch, "")


# ---------------------------------------------------------------------------
# extract_task_verify_cmds
# ---------------------------------------------------------------------------


class TestExtractTaskVerifyCmds(unittest.TestCase):
    def test_inline_verify(self):
        cmds = extract_task_verify_cmds(SAMPLE_TASKS_MD, "T-001")
        self.assertIn("scripts/verify", cmds)

    def test_multi_line_verify(self):
        cmds = extract_task_verify_cmds(SAMPLE_TASKS_MD, "T-002")
        self.assertIn("scripts/verify --task T-002", cmds)

    def test_no_verify_section(self):
        cmds = extract_task_verify_cmds(SAMPLE_TASKS_MD, "T-003")
        self.assertEqual(cmds, [])

    def test_missing_task(self):
        cmds = extract_task_verify_cmds(SAMPLE_TASKS_MD, "T-999")
        self.assertEqual(cmds, [])


# ---------------------------------------------------------------------------
# is_unassigned_owner
# ---------------------------------------------------------------------------


class TestIsUnassignedOwner(unittest.TestCase):
    def test_empty_string(self):
        self.assertTrue(is_unassigned_owner(""))

    def test_dash(self):
        self.assertTrue(is_unassigned_owner("-"))

    def test_tbd(self):
        self.assertTrue(is_unassigned_owner("TBD"))
        self.assertTrue(is_unassigned_owner("tbd"))

    def test_unassigned(self):
        self.assertTrue(is_unassigned_owner("unassigned"))

    def test_none_string(self):
        self.assertTrue(is_unassigned_owner("none"))

    def test_angle_bracket_placeholder(self):
        self.assertTrue(is_unassigned_owner("<Worker-1>"))

    def test_real_owner(self):
        self.assertFalse(is_unassigned_owner("alice"))

    def test_none_value(self):
        self.assertTrue(is_unassigned_owner(None))


# ---------------------------------------------------------------------------
# extract_task_owner_status
# ---------------------------------------------------------------------------


class TestExtractTaskOwnerStatus(unittest.TestCase):
    def test_from_table(self):
        owner, status = extract_task_owner_status(SAMPLE_TASKS_MD, "T-001")
        self.assertEqual(owner, "alice")
        self.assertEqual(status, "TODO")

    def test_in_progress(self):
        owner, status = extract_task_owner_status(SAMPLE_TASKS_MD, "T-002")
        self.assertEqual(owner, "bob")
        self.assertEqual(status, "IN_PROGRESS")

    def test_missing_task(self):
        owner, status = extract_task_owner_status(SAMPLE_TASKS_MD, "T-999")
        self.assertEqual(owner, "")
        self.assertEqual(status, "")


# ---------------------------------------------------------------------------
# update_task_index_table
# ---------------------------------------------------------------------------


class TestUpdateTaskIndexTable(unittest.TestCase):
    def test_updates_owner_and_status(self):
        lines = SAMPLE_TASKS_MD.splitlines(keepends=True)
        result = update_task_index_table(lines, "T-001", "charlie", "DONE")
        self.assertTrue(result)
        joined = "".join(lines)
        self.assertIn("charlie", joined)
        self.assertIn("DONE", joined)

    def test_missing_task_returns_false(self):
        lines = SAMPLE_TASKS_MD.splitlines(keepends=True)
        result = update_task_index_table(lines, "T-999", "charlie", "DONE")
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# update_task_details_section
# ---------------------------------------------------------------------------


class TestUpdateTaskDetailsSection(unittest.TestCase):
    def test_updates_existing_fields(self):
        lines = SAMPLE_TASKS_MD.splitlines(keepends=True)
        result = update_task_details_section(lines, "T-001", "charlie", "DONE")
        self.assertTrue(result)
        joined = "".join(lines)
        self.assertIn("- Owner: charlie\n", joined)
        self.assertIn("- Status: DONE\n", joined)

    def test_inserts_missing_fields(self):
        md = "### T-NEW\n\nSome notes\n"
        lines = md.splitlines(keepends=True)
        result = update_task_details_section(lines, "T-NEW", "alice", "TODO")
        self.assertTrue(result)
        joined = "".join(lines)
        self.assertIn("- Owner: alice\n", joined)
        self.assertIn("- Status: TODO\n", joined)

    def test_missing_section(self):
        lines = SAMPLE_TASKS_MD.splitlines(keepends=True)
        result = update_task_details_section(lines, "T-999", "x", "y")
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# update_tasks_md_text
# ---------------------------------------------------------------------------


class TestUpdateTasksMdText(unittest.TestCase):
    def test_both_table_and_section_updated(self):
        updated, changed = update_tasks_md_text(SAMPLE_TASKS_MD, "T-001", "dave", "DONE")
        self.assertTrue(changed)
        self.assertIn("dave", updated)
        self.assertIn("- Owner: dave\n", updated)

    def test_no_change_for_missing_task(self):
        updated, changed = update_tasks_md_text(SAMPLE_TASKS_MD, "T-999", "x", "y")
        self.assertFalse(changed)


# ---------------------------------------------------------------------------
# split_deps
# ---------------------------------------------------------------------------


class TestSplitDeps(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(split_deps(""), [])

    def test_dash(self):
        self.assertEqual(split_deps("-"), [])

    def test_single(self):
        self.assertEqual(split_deps("T-001"), ["T-001"])

    def test_comma_separated(self):
        self.assertEqual(split_deps("T-001, T-002"), ["T-001", "T-002"])

    def test_space_separated(self):
        self.assertEqual(split_deps("T-001 T-002"), ["T-001", "T-002"])

    def test_none_value(self):
        self.assertEqual(split_deps(None), [])


# ---------------------------------------------------------------------------
# index_rows_by_id
# ---------------------------------------------------------------------------


class TestIndexRowsById(unittest.TestCase):
    def test_index(self):
        rows = parse_tasks_index(SAMPLE_TASKS_MD)
        by_id = index_rows_by_id(rows)
        self.assertIn("T-001", by_id)
        self.assertEqual(by_id["T-001"].owner, "alice")
        self.assertEqual(len(by_id), 3)


# ---------------------------------------------------------------------------
# file_is_draft
# ---------------------------------------------------------------------------


class TestFileIsDraft(unittest.TestCase):
    def test_draft_marker(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "file.md"
            p.write_text("<!-- DASOPS:DRAFT: remove this line when complete -->\n# Title\n")
            self.assertTrue(file_is_draft(p))

    def test_angle_bracket_placeholder(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "file.md"
            p.write_text("# Title\n\nOwner: <TBD>\n")
            self.assertTrue(file_is_draft(p))

    def test_clean_file(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "file.md"
            p.write_text("# Title\n\nOwner: alice\nStatus: DONE\n")
            self.assertFalse(file_is_draft(p))

    def test_missing_file(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "nope.md"
            self.assertTrue(file_is_draft(p))


# ---------------------------------------------------------------------------
# artifact_status
# ---------------------------------------------------------------------------


class TestArtifactStatus(unittest.TestCase):
    def test_all_done(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "a.md").write_text("clean content")
            (d / "b.md").write_text("clean content")
            arts = [
                Artifact(id="A", generates="a.md", requires=[]),
                Artifact(id="B", generates="b.md", requires=["A"]),
            ]
            status = artifact_status(d, arts)
            self.assertEqual(status["A"], "DONE")
            self.assertEqual(status["B"], "DONE")

    def test_blocked_by_dep(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            # A is missing, B depends on A
            (d / "b.md").write_text("clean content")
            arts = [
                Artifact(id="A", generates="a.md", requires=[]),
                Artifact(id="B", generates="b.md", requires=["A"]),
            ]
            status = artifact_status(d, arts)
            self.assertEqual(status["A"], "READY")  # no deps, just not done
            self.assertEqual(status["B"], "DONE")   # file exists and is clean

    def test_draft_counts_as_not_done(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "a.md").write_text("<!-- DASOPS:DRAFT: remove this line when complete -->")
            arts = [Artifact(id="A", generates="a.md", requires=[])]
            status = artifact_status(d, arts)
            self.assertEqual(status["A"], "READY")

    def test_missing_file_is_ready_when_no_deps(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            arts = [Artifact(id="A", generates="a.md", requires=[])]
            status = artifact_status(d, arts)
            self.assertEqual(status["A"], "READY")


if __name__ == "__main__":
    unittest.main()

class TestReviewedTaskMarkdown(unittest.TestCase):
    def test_fence_with_suffix_does_not_expose_example_tasks(self):
        import runpy
        from pathlib import Path
        from dasops.task_markdown import table_rows
        template = Path(__file__).resolve().parents[1] / 'templates/das-product/scripts/task_markdown.py'
        readers = [table_rows, runpy.run_path(str(template))['table_rows']]
        header = '| Task ID | Title | Owner | Status | Depends | Gate |\n| --- | --- | --- | --- | --- | --- |\n'
        example = header + '| EXAMPLE | Example | alice | TODO | - | - |\n'
        active = header + '| REAL | Actual task | alice | TODO | - | - |\n'
        for fence in ('```', '~~~'):
            text = fence + 'markdown\n' + fence + 'not-a-close\n' + example + fence + '\n\n' + active
            for read in readers:
                with self.subTest(fence=fence, reader=read.__module__):
                    self.assertEqual([parts[0] for _, parts in read(text.splitlines())], ['REAL'])

    def test_escaped_pipe_fences_and_exact_detail_binding(self):
        active = SAMPLE_TASKS_MD.replace("First task", r"First \| task")
        example = SAMPLE_TASKS_MD.replace("T-001", "EXAMPLE")
        text = "~~~markdown\n" + example + "~~~\n\n" + active
        rows = parse_tasks_index(text)
        self.assertEqual(rows[0].title, "First | task")
        self.assertEqual(rows[0].owner, "alice")
        updated, _ = update_tasks_md_text(text, "T-001", "carol", "IN_PROGRESS")
        self.assertTrue(updated.startswith("~~~markdown\n" + example + "~~~\n"))
        self.assertEqual(parse_tasks_index(updated)[0].owner, "carol")
        details = "### T-001.1\n- Branch: `wrong`\n### T-001: Main task\n- Branch: `right`\n"
        self.assertEqual(extract_task_branch(details, "T-001"), "right")
        self.assertEqual(extract_task_verify_cmds("### T-1\n- Verification: `python3 -m pytest tests/test_x.py`\n", "T-1"), ["python3 -m pytest tests/test_x.py"])
        with self.assertRaisesRegex(ValueError, "multiple active"):
            parse_tasks_index(active + "\n" + SAMPLE_TASKS_MD)

    def test_dependency_ids_and_artifact_schema(self):
        self.assertEqual(split_deps('"Task one", T-2', {"Task one": None, "T-2": None}), ["Task one", "T-2"])
        from dasops.tasks import validate_artifacts
        for artifacts in ([Artifact("x", "x.md", []), Artifact("x", "y.md", [])],
                          [Artifact("x", "x.md", "y")], [Artifact("x", "x.md", ["missing"])]):
            with self.subTest(artifacts=artifacts), self.assertRaises(SystemExit):
                validate_artifacts(artifacts)
        validate_artifacts([Artifact("x", "x.md", []), Artifact("y", "y.md", ["x"])])
