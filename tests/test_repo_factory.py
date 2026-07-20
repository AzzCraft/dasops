"""Regression tests for the truthful standalone v1.0 scaffold."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dasops.repo_factory import seed_machine_readable_artifacts


class TestSeedMachineReadableArtifacts(unittest.TestCase):
    def test_seed_does_not_invent_governed_closure_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            seed_machine_readable_artifacts(repo)
            self.assertFalse((repo / "tooling_lock.json").exists())
            self.assertFalse((repo / "local_extension_manifest.json").exists())

    def test_seed_preserves_owner_supplied_governed_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            lock = repo / "tooling_lock.json"
            lock.write_text('{"ownerSupplied": true}\n', encoding="utf-8")
            seed_machine_readable_artifacts(repo)
            self.assertEqual(lock.read_text(encoding="utf-8"), '{"ownerSupplied": true}\n')


if __name__ == "__main__":
    unittest.main()
