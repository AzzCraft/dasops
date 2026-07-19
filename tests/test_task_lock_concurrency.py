"""DAS-03-009 task lock concurrency tests."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dasops.locks import TaskLock, read_lock, write_lock


class TaskLockConcurrencyTests(unittest.TestCase):
    def test_must_create_rejects_second_writer(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "T-001.lock"
            first = TaskLock(
                version=1,
                task_id="T-001",
                owner="worker-a",
                status="IN_PROGRESS",
                claimed_at=now,
                updated_at=now,
                heartbeat_at=now,
                lease_seconds=3600,
                lock_token="token-a",
            )
            second = TaskLock(
                version=1,
                task_id="T-001",
                owner="worker-b",
                status="IN_PROGRESS",
                claimed_at=now,
                updated_at=now,
                heartbeat_at=now,
                lease_seconds=3600,
                lock_token="token-b",
            )
            write_lock(path, first, must_create=True)
            with self.assertRaises(SystemExit):
                write_lock(path, second, must_create=True)
            observed = read_lock(path)
            self.assertIsNotNone(observed)
            self.assertEqual(observed.owner, "worker-a")
            self.assertEqual(observed.lock_token, "token-a")


if __name__ == "__main__":
    unittest.main()
