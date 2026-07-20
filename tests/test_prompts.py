"""Tests for dasops.prompts module."""
from __future__ import annotations
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from dasops.prompts import _render, load_prompt_template, render_prompt


class TestRender(unittest.TestCase):
    def test_replaces_placeholders(self):
        result = _render("Hello {{name}} from {{place}}", {"name": "Alice", "place": "Oz"})
        self.assertEqual(result, "Hello Alice from Oz")

    def test_no_placeholders_passthrough(self):
        result = _render("no placeholders here", {"key": "val"})
        self.assertEqual(result, "no placeholders here")

    def test_empty_mapping(self):
        result = _render("{{keep}}", {})
        self.assertEqual(result, "{{keep}}")


class TestLoadPromptTemplate(unittest.TestCase):
    def test_loads_existing_template(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tpl_dir = root / "templates" / "prompts"
            tpl_dir.mkdir(parents=True)
            (tpl_dir / "worker.md").write_text("Worker template {{task}}")
            text = load_prompt_template(root, "worker")
            self.assertEqual(text, "Worker template {{task}}")

    def test_fallback_when_missing(self):
        with TemporaryDirectory() as tmp:
            text = load_prompt_template(Path(tmp), "nonexistent")
            self.assertIn("Nonexistent", text)
            self.assertIn("No template found", text)


class TestRenderPrompt(unittest.TestCase):
    def test_end_to_end(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tpl_dir = root / "templates" / "prompts"
            tpl_dir.mkdir(parents=True)
            (tpl_dir / "orchestrator.md").write_text("Run task {{task_id}} for {{owner}}")
            result = render_prompt(root, "orchestrator", {"task_id": "T-001", "owner": "alice"})
            self.assertEqual(result, "Run task T-001 for alice")

    def test_fallback_rendering(self):
        with TemporaryDirectory() as tmp:
            result = render_prompt(Path(tmp), "missing", {"key": "val"})
            self.assertIn("Missing", result)


if __name__ == "__main__":
    unittest.main()
