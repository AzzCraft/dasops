"""Tests for dasops.vendor — lock enforcement."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dasops.vendor import load_vendor_lock, validate_vendor_integrity, enforce_vendor_lock


class TestVendorLock(unittest.TestCase):
    def test_load_vendor_lock(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "tooling_lock.json"
            p.write_text(json.dumps({"schemaVersion": "1.0.0", "pins": {"cadence": "1.0.0"}}))
            lock = load_vendor_lock(p)
            self.assertEqual(lock["pins"]["cadence"], "1.0.0")

    def test_validate_no_drift(self):
        lock = {"pins": {"cadence": "1.0.0"}}
        installed = {"cadence": "1.0.0"}
        drifts = validate_vendor_integrity(lock, installed)
        self.assertEqual(drifts, [])

    def test_validate_detects_version_drift(self):
        lock = {"pins": {"cadence": "1.0.0"}}
        installed = {"cadence": "2.0.0"}
        drifts = validate_vendor_integrity(lock, installed)
        self.assertEqual(len(drifts), 1)
        self.assertIn("expected 1.0.0", drifts[0])

    def test_validate_detects_missing_install(self):
        lock = {"pins": {"cadence": "1.0.0"}}
        installed = {}
        drifts = validate_vendor_integrity(lock, installed)
        self.assertEqual(len(drifts), 1)
        self.assertIn("not installed", drifts[0])

    def test_enforce_missing_lock(self):
        with tempfile.TemporaryDirectory() as d:
            drifts = enforce_vendor_lock(d)
            self.assertEqual(len(drifts), 1)
            self.assertIn("not found", drifts[0])


if __name__ == "__main__":
    unittest.main()
