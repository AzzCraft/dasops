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

    def test_v15_enforcement_binds_lock_and_reports_observer_failures(self):
        import subprocess
        from unittest.mock import patch

        runtime = {"kind": "git", "uri": "https://github.com/AzzCraft/cadence-oss.git",
                   "pinType": "commit", "pinValue": "a" * 40, "floating": False}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".dasops-scaffold.json").write_text(json.dumps({"selectedSources": {"runtime": runtime}}))
            lock = {"standardManifestVersion": "1.5.0-beta.1", "verifyRuntime": runtime}
            lock_path = root / "tooling_lock.json"
            lock_path.write_text(json.dumps(lock))
            # The installed observer is independently exercised by native integration;
            # this unit check proves it cannot substitute for comparing the input lock.
            with patch("dasops.scaffold_v15.installed") as observer:
                self.assertEqual(enforce_vendor_lock(root), [])
                observer.assert_called_once_with(root)
                observer.reset_mock()
                for changed in ({**runtime, "pinValue": "b" * 40},
                                {**runtime, "uri": "https://github.com/AzzCraft/other.git"}, None):
                    with self.subTest(runtime=changed):
                        lock_path.write_text(json.dumps({**lock, "verifyRuntime": changed}))
                        self.assertIn("differs from selected Suite runtime", enforce_vendor_lock(root)[0])
                        observer.assert_not_called()
            lock_path.write_text(json.dumps(lock))
            with patch("dasops.scaffold_v15.installed", side_effect=subprocess.TimeoutExpired("cadence", 10)):
                self.assertTrue(enforce_vendor_lock(root))


if __name__ == "__main__":
    unittest.main()


def test_vendor_failures_preserve_previous_and_relative_source(tmp_path, monkeypatch):
    import shutil
    import subprocess
    from dasops.vendor import build_install_cadence_command
    source = Path(__file__).resolve().parents[1] / 'templates/das-product/scripts/install_cadence_vendor.sh'
    product = tmp_path / 'product'; (product / 'scripts').mkdir(parents=True)
    installer = product / 'scripts/install_cadence_vendor.sh'
    shutil.copyfile(source, installer)
    def run(*args):
        return subprocess.run(['bash', str(installer), *args], cwd=product, capture_output=True, text=True)
    assert run().returncode != 0
    assert not (product / 'vendor/cadence').exists()
    old = product / 'vendor/cadence/cadence-oss'; old.mkdir(parents=True)
    (old / 'sentinel').write_bytes(b'old')
    assert run('--force', '--from-suite', str(tmp_path / 'missing')).returncode != 0
    assert (old / 'sentinel').read_bytes() == b'old'
    release = tmp_path / 'release'; (release / 'das-suite').mkdir(parents=True)
    (release / 'cadence-oss').mkdir()
    (release / 'cadence-oss/source').write_bytes(b'new')
    monkeypatch.chdir(tmp_path)
    cmd = build_install_cadence_command(tier='oss', from_suite='release/das-suite', force=True)
    assert Path(cmd[cmd.index('--from-suite') + 1]).is_absolute()
    proc = subprocess.run(cmd, cwd=product, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (old / 'source').read_bytes() == b'new'
    assert not (old / 'sentinel').exists()
    assert not list((product / 'vendor').glob('.cadence-install.*'))
