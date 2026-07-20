from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file

import yaml

from dasops.locks import claim_task
from dasops.repo_factory import create_product_repo


REPO_ROOT = repository_root_for_test_file(__file__)


class FactoryTemplateTests(unittest.TestCase):
    def _create_repo(self, tmp_root: Path) -> Path:
        master_doc = tmp_root / "master_doc.md"
        ui_spec = tmp_root / "ui_spec.md"
        master_doc.write_text("# Master Doc\n\n## Conformance profile\n\n## Repo topology\n\n## Contracts\n\n## Traceability\n\n## Verification\n\n## Execution plan\n", encoding="utf-8")
        ui_spec.write_text("# UI Spec\n", encoding="utf-8")
        dest = tmp_root / "product"
        return create_product_repo(
            factory_root=REPO_ROOT,
            dest_dir=dest,
            master_doc_path=master_doc,
            ui_spec_path=ui_spec,
            change_id="chg-001",
            intent="Initial scaffold",
            init_git=True,
        )

    def test_generated_repo_seeds_new_contract_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = self._create_repo(Path(tmp_dir))
            self.assertTrue((repo / "STANDARD_REF.md").exists())
            self.assertFalse((repo / "tooling_lock.json").exists())
            self.assertFalse((repo / "local_extension_manifest.json").exists())
            self.assertFalse((repo / "docs" / "standards" / "DAS_STANDARD.md").exists())
            self.assertFalse((repo / "cadence.yaml").exists())

            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(status.stdout, "", "generated repository must be clean")
            self.assertEqual(
                subprocess.run(
                    ["git", "rev-list", "--count", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
                ).stdout.strip(),
                "1",
                "the standalone scaffold must have one truthful bootstrap commit",
            )

    def test_fail_closed_sub_verifiers_and_structured_locks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = self._create_repo(Path(tmp_dir))
            direct_verify = subprocess.run(
                ["./scripts/verify"],
                cwd=repo,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(direct_verify.returncode, 0, direct_verify.stdout)

            verify = subprocess.run(
                ["bash", "./scripts/verify"],
                cwd=repo,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout)

            backend = subprocess.run(
                ["bash", "./scripts/verify-backend"],
                cwd=repo,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertNotEqual(backend.returncode, 0)
            self.assertIn("fail-closed", backend.stdout)

            lock_path = claim_task(
                repo_root=repo,
                change_id="chg-001",
                task_id="T-001",
                owner="worker01",
            )
            lock_data = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(lock_data),
                {
                    "version",
                    "taskId",
                    "owner",
                    "status",
                    "claimedAt",
                    "updatedAt",
                    "heartbeatAt",
                    "leaseSeconds",
                    "lockToken",
                },
            )

            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO_ROOT)
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "dasops",
                    "lock-status",
                    "--change-id",
                    "chg-001",
                    "--task-id",
                    "T-001",
                    "--expect-owner",
                    "worker01",
                    "--json",
                ],
                cwd=repo,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["exists"])
            self.assertTrue(payload["ownerMatches"])
