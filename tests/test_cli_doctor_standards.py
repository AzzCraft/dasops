from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


REPO_ROOT = repository_root_for_test_file(__file__)


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


class DoctorStrictCliTests(unittest.TestCase):
    def _write_product_repo_minimum(self, repo: Path) -> None:
        (repo / ".dasops_product_repo").write_text("", encoding="utf-8")

        required_files = [
            "docs/master_doc.md",
            "docs/ui_spec.md",
            "docs/USER_MANUAL.md",
            "docs/policies/AGENT_OPERATING_MODEL.md",
            "AGENTS.override.md",
            "CLAUDE.md",
            "progress.txt",
            "STANDARD_REF.md",
            "tooling_lock.json",
            "local_extension_manifest.json",
            "openspec/config.yaml",
        ]
        for rel in required_files:
            path = repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix == ".yaml":
                path.write_text("schema: das-standard\n", encoding="utf-8")
            elif rel == "tooling_lock.json":
                path.write_text(
                    json.dumps(
                        {
                            "schemaVersion": "1.0.0",
                            "standardManifestVersion": "1.4.0",
                            "sourceOfTruth": {
                                "kind": "git",
                                "uri": "x",
                                "pinType": "commit",
                                "pinValue": "abcdef1",
                                "floating": False,
                            },
                            "verifyRuntime": {
                                "kind": "package",
                                "uri": "x",
                                "pinType": "version",
                                "pinValue": "x",
                                "floating": False,
                            },
                            "suiteVersionClosureRef": {
                                "kind": "file",
                                "uri": "./suite_version_closure.json",
                                "pinType": "manifest",
                                "pinValue": "suite_version_closure.json",
                                "floating": False,
                            },
                            "suiteLockRef": {
                                "kind": "file",
                                "uri": "./suite_lock.json",
                                "pinType": "manifest",
                                "pinValue": "suite_lock.json",
                                "floating": False,
                            },
                            "verifyRegistryRef": {
                                "kind": "file",
                                "uri": "./vendor/cadence/cadence-oss/cadence-registry/registry.json",
                                "pinType": "manifest",
                                "pinValue": "registry.json",
                                "floating": False,
                            },
                            "toolchain": [{"name": "python3", "version": "3.10+"}],
                        }
                    ),
                    encoding="utf-8",
                )
            elif rel == "local_extension_manifest.json":
                path.write_text(
                    json.dumps(
                        {
                            "schemaVersion": "1.0.0",
                            "standardManifestVersion": "1.4.0",
                            "extensions": [
                                {
                                    "name": "org.example.placeholder",
                                    "compatibilityNote": "replace before release",
                                    "reviewDate": "2026-12-31",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
            else:
                path.write_text("placeholder\n", encoding="utf-8")

    def test_warning_only_repo_is_nonzero_under_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir)
            self._write_product_repo_minimum(repo)
            (repo / "openspec" / "config.yaml").write_text("schema: not-das-standard\n", encoding="utf-8")

            normal = subprocess.run(
                [sys.executable, "-m", "dasops", "doctor", "--repo-root", str(repo)],
                cwd=REPO_ROOT,
                env=_base_env(),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(normal.returncode, 0, normal.stdout)
            self.assertIn("Warnings:", normal.stdout)

            strict = subprocess.run(
                [sys.executable, "-m", "dasops", "doctor", "--strict", "--repo-root", str(repo)],
                cwd=REPO_ROOT,
                env=_base_env(),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(strict.returncode, 2, strict.stdout)
            self.assertIn("Result: FAIL (strict mode)", strict.stdout)

    def test_invalid_tooling_lock_ref_is_a_problem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir)
            self._write_product_repo_minimum(repo)
            tooling_lock = repo / "tooling_lock.json"
            payload = json.loads(tooling_lock.read_text(encoding="utf-8"))
            payload["suiteLockRef"]["uri"] = "./wrong.json"
            tooling_lock.write_text(json.dumps(payload), encoding="utf-8")

            result = subprocess.run(
                [sys.executable, "-m", "dasops", "doctor", "--repo-root", str(repo)],
                cwd=REPO_ROOT,
                env=_base_env(),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("suiteLockRef.uri must include 'suite_lock.json'", result.stdout)

    def test_invalid_extension_manifest_entry_is_a_problem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir)
            self._write_product_repo_minimum(repo)
            manifest = repo / "local_extension_manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["extensions"][0].pop("compatibilityNote", None)
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            result = subprocess.run(
                [sys.executable, "-m", "dasops", "doctor", "--repo-root", str(repo)],
                cwd=REPO_ROOT,
                env=_base_env(),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("local_extension_manifest.json extension[0] missing keys", result.stdout)


class StandardsCliTests(unittest.TestCase):
    def test_search_show_and_pack_use_machine_readable_indexes(self) -> None:
        env = _base_env()

        search = subprocess.run(
            [
                sys.executable,
                "-m",
                "dasops",
                "standards",
                "search",
                "--query",
                "closure",
                "--repo-root",
                str(REPO_ROOT),
                "--json",
            ],
            cwd=REPO_ROOT,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(search.returncode, 0, search.stdout)
        search_payload = json.loads(search.stdout)
        self.assertGreater(search_payload["count"], 0)

        show = subprocess.run(
            [
                sys.executable,
                "-m",
                "dasops",
                "standards",
                "show",
                "--clause",
                "cl-2.5",
                "--repo-root",
                str(REPO_ROOT),
                "--json",
            ],
            cwd=REPO_ROOT,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(show.returncode, 0, show.stdout)
        show_payload = json.loads(show.stdout)
        self.assertEqual(show_payload["id"], "cl-2.5")
        self.assertTrue(show_payload["chapterFile"].startswith("SPECIFICATION.md#"))

        pack = subprocess.run(
            [
                sys.executable,
                "-m",
                "dasops",
                "standards",
                "pack",
                "--for",
                "backend",
                "--repo-root",
                str(REPO_ROOT),
                "--json",
            ],
            cwd=REPO_ROOT,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(pack.returncode, 0, pack.stdout)
        pack_payload = json.loads(pack.stdout)
        self.assertEqual(pack_payload["role"], "backend")
        self.assertGreater(pack_payload["chapterCount"], 0)
