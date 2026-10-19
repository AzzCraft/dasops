"""Tests for dasops.locks module."""

from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from dasops.locks import (
    DEFAULT_LEASE_SECONDS,
    TaskLock,
    _validate_id,
    is_stale,
    lock_path_for,
    read_lock,
    task_locks_dir,
    write_lock,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)
_NOW_ISO = _NOW.isoformat()
_FRESH_ISO = _NOW_ISO  # heartbeat == now → not stale


def _make_lock(**overrides) -> TaskLock:
    defaults = dict(
        version=2,
        task_id="T-001",
        owner="alice",
        status="IN_PROGRESS",
        claimed_at=_NOW_ISO,
        updated_at=_NOW_ISO,
        heartbeat_at=_NOW_ISO,
        lease_seconds=DEFAULT_LEASE_SECONDS,
        lock_token=uuid.uuid4().hex,
    )
    defaults.update(overrides)
    return TaskLock(**defaults)


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _lock_as_dict(lock: TaskLock) -> dict:
    return {
        "version": lock.version,
        "taskId": lock.task_id,
        "owner": lock.owner,
        "status": lock.status,
        "claimedAt": lock.claimed_at,
        "updatedAt": lock.updated_at,
        "heartbeatAt": lock.heartbeat_at,
        "leaseSeconds": lock.lease_seconds,
        "lockToken": lock.lock_token,
    }


# ---------------------------------------------------------------------------
# _validate_id
# ---------------------------------------------------------------------------


class TestValidateId(unittest.TestCase):
    def test_valid_id(self):
        _validate_id("test", "T-001")  # should not raise

    def test_slash_rejected(self):
        with self.assertRaises(SystemExit):
            _validate_id("change_id", "../../etc/passwd")

    def test_backslash_rejected(self):
        with self.assertRaises(SystemExit):
            _validate_id("task_id", "foo\\bar")

    def test_dotdot_rejected(self):
        with self.assertRaises(SystemExit):
            _validate_id("task_id", "..")

    def test_empty_rejected(self):
        with self.assertRaises(SystemExit):
            _validate_id("task_id", "")


# ---------------------------------------------------------------------------
# task_locks_dir / lock_path_for
# ---------------------------------------------------------------------------


class TestPathHelpers(unittest.TestCase):
    def test_task_locks_dir(self):
        d = Path("/repo/openspec/changes/C-001")
        self.assertEqual(task_locks_dir(d), d / "task_locks")

    def test_lock_path_for(self):
        d = Path("/repo/openspec/changes/C-001")
        self.assertEqual(lock_path_for(d, "T-001"), d / "task_locks" / "T-001.lock")


# ---------------------------------------------------------------------------
# read_lock
# ---------------------------------------------------------------------------


class TestReadLock(unittest.TestCase):
    def test_reads_valid_lock(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock()
            p = Path(tmp) / "T-001.lock"
            _write_yaml(p, _lock_as_dict(lock))
            result = read_lock(p)
            self.assertIsNotNone(result)
            self.assertEqual(result.task_id, "T-001")
            self.assertEqual(result.owner, "alice")

    def test_missing_file_returns_none(self):
        with TemporaryDirectory() as tmp:
            result = read_lock(Path(tmp) / "nope.lock")
            self.assertIsNone(result)

    def test_invalid_yaml_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.lock"
            p.write_text("{{not yaml", encoding="utf-8")
            with self.assertRaises(SystemExit):
                read_lock(p)

    def test_missing_key_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "partial.lock"
            _write_yaml(p, {"version": 2, "taskId": "T-001"})
            with self.assertRaises(SystemExit):
                read_lock(p)

    def test_version_zero_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock(version=0)
            p = Path(tmp) / "v0.lock"
            _write_yaml(p, _lock_as_dict(lock))
            with self.assertRaises(SystemExit):
                read_lock(p)

    def test_negative_lease_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock(lease_seconds=-1)
            p = Path(tmp) / "neg.lock"
            _write_yaml(p, _lock_as_dict(lock))
            with self.assertRaises(SystemExit):
                read_lock(p)

    def test_bad_status_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock(status="INVALID")
            p = Path(tmp) / "badstatus.lock"
            _write_yaml(p, _lock_as_dict(lock))
            with self.assertRaises(SystemExit):
                read_lock(p)

    def test_updated_before_claimed_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            earlier = (_NOW - timedelta(hours=2)).isoformat()
            lock = _make_lock(claimed_at=_NOW_ISO, updated_at=earlier)
            p = Path(tmp) / "bad_order.lock"
            _write_yaml(p, _lock_as_dict(lock))
            with self.assertRaises(SystemExit):
                read_lock(p)

    def test_empty_owner_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock(owner="  ")
            p = Path(tmp) / "blank_owner.lock"
            _write_yaml(p, _lock_as_dict(lock))
            with self.assertRaises(SystemExit):
                read_lock(p)

    def test_non_dict_raises_invalid_lock(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "list.lock"
            p.write_text("- item\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                read_lock(p)


# ---------------------------------------------------------------------------
# write_lock
# ---------------------------------------------------------------------------


class TestWriteLock(unittest.TestCase):
    def test_writes_and_reads_back(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock()
            p = Path(tmp) / "T-001.lock"
            write_lock(p, lock)
            result = read_lock(p)
            self.assertIsNotNone(result)
            self.assertEqual(result.task_id, lock.task_id)
            self.assertEqual(result.lock_token, lock.lock_token)

    def test_must_create_succeeds_for_new(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock()
            p = Path(tmp) / "new.lock"
            write_lock(p, lock, must_create=True)
            self.assertTrue(p.exists())

    def test_must_create_fails_if_exists(self):
        with TemporaryDirectory() as tmp:
            lock = _make_lock()
            p = Path(tmp) / "existing.lock"
            p.write_text("occupied", encoding="utf-8")
            with self.assertRaises(SystemExit):
                write_lock(p, lock, must_create=True)

    def test_overwrite_without_must_create(self):
        with TemporaryDirectory() as tmp:
            lock1 = _make_lock(owner="alice")
            lock2 = _make_lock(owner="bob")
            p = Path(tmp) / "T-001.lock"
            write_lock(p, lock1)
            write_lock(p, lock2)
            result = read_lock(p)
            self.assertEqual(result.owner, "bob")


# ---------------------------------------------------------------------------
# is_stale
# ---------------------------------------------------------------------------


class TestIsStale(unittest.TestCase):
    def test_fresh_lock_is_not_stale(self):
        lock = _make_lock(heartbeat_at=_NOW_ISO, lease_seconds=3600)
        self.assertFalse(is_stale(lock))

    def test_old_heartbeat_is_stale(self):
        old = (_NOW - timedelta(hours=2)).isoformat()
        lock = _make_lock(heartbeat_at=old, lease_seconds=3600)
        self.assertTrue(is_stale(lock))

    def test_invalid_heartbeat_is_stale(self):
        lock = _make_lock(heartbeat_at="not-a-date")
        self.assertTrue(is_stale(lock))

    def test_naive_heartbeat_treated_as_utc(self):
        # A naive datetime 30 seconds ago should NOT be stale with 3600s lease
        naive = (_NOW - timedelta(seconds=30)).replace(tzinfo=None).isoformat()
        lock = _make_lock(heartbeat_at=naive, lease_seconds=3600)
        self.assertFalse(is_stale(lock))


if __name__ == "__main__":
    unittest.main()
