"""Tests for dasops.repo_factory — seed_machine_readable_artifacts."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dasops.repo_factory import seed_machine_readable_artifacts


class TestSeedMachineReadableArtifacts(unittest.TestCase):
    def test_seed_creates_tooling_lock(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            seed_machine_readable_artifacts(repo)
            lock = repo / "tooling_lock.json"
            self.assertTrue(lock.exists())
            data = json.loads(lock.read_text(encoding="utf-8"))
            self.assertEqual(data["schemaVersion"], "1.0.0")
            self.assertEqual(data["standardManifestVersion"], "1.4.0")
            self.assertEqual(data["sourceOfTruth"]["kind"], "git")
            self.assertEqual(data["sourceOfTruth"]["uri"], ".")
            self.assertEqual(data["verifyRuntime"]["kind"], "package")
            self.assertEqual(data["suiteLockRef"]["kind"], "file")
            self.assertIsInstance(data["toolchain"], list)
            self.assertTrue(data["toolchain"])

    def test_seed_creates_extension_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            seed_machine_readable_artifacts(repo)
            ext = repo / "local_extension_manifest.json"
            self.assertTrue(ext.exists())
            data = json.loads(ext.read_text(encoding="utf-8"))
            self.assertEqual(data["schemaVersion"], "1.0.0")
            self.assertEqual(data["standardManifestVersion"], "1.4.0")
            self.assertIsInstance(data["extensions"], list)
            self.assertTrue(data["extensions"])
            self.assertIn("compatibilityNote", data["extensions"][0])

    def test_seed_does_not_overwrite_existing(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            lock = repo / "tooling_lock.json"
            lock.write_text('{"custom": true}', encoding="utf-8")
            seed_machine_readable_artifacts(repo)
            data = json.loads(lock.read_text(encoding="utf-8"))
            self.assertTrue(data.get("custom"))


class TestV15ScaffoldInputs(unittest.TestCase):
    def test_metadata_is_confined_to_document_control(self):
        from dasops.scaffold_v15 import metadata
        text = "# Fixture\n## Document Control\n- **Project slug** (stable identifier): `fixture-product`\n- **Status:** draft\n## Behavior\n- **Status:** active\n- **MUST**: unrelated prose\n"
        self.assertEqual(metadata(text), {"Project slug":"fixture-product","Status":"draft"})

    def test_duplicate_control_fields_reject(self):
        from dasops.scaffold_v15 import metadata
        with self.assertRaisesRegex(ValueError,"ambiguous"):
            metadata("## Document Control\n- **Status:** draft\n- **Status:** active\n")

    def test_visible_metadata_and_headings_share_fence_and_comment_rules(self):
        from dasops.scaffold_v15 import metadata, headings, document_prose
        text = ("<!--\n## Document Control\n- **Status:** active\n-->\n"
                "````md\n```\n## Document Control\n- **Status:** frozen\n````\n"
                "## Document Control\n- **Status:** draft <!-- allowed explanation -->\n"
                "## Scope\nVisible text.\n<!-- unclosed hidden tail\n## Hidden\n")
        self.assertEqual(metadata(text), {"Status":"draft"})
        self.assertEqual(headings(text), ["## Document Control", "## Scope"])
        self.assertNotIn("Hidden", document_prose(text))

    def test_legacy_and_unknown_vendor_formats_are_distinct(self):
        from dasops.vendor import validate_vendor_integrity
        self.assertTrue(validate_vendor_integrity({}, {}))
        self.assertTrue(validate_vendor_integrity({"pins":{}}, {}))
        self.assertTrue(validate_vendor_integrity({"verifyRuntime":{"pinValue":"fixed"}}, {}))

    def test_local_references_do_not_escape(self):
        from dasops.scaffold_v15 import local
        with tempfile.TemporaryDirectory() as temp:
            for value in ("../outside", "/outside"):
                with self.assertRaises(ValueError):local(Path(temp),value)


if __name__ == "__main__":
    unittest.main()
