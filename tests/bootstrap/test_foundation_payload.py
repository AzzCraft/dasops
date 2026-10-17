from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import stat
import subprocess

import pytest

from dasops.bootstrap.foundation_payload import (
    FoundationPayloadError,
    build_claim_adoption_request,
    build_foundation_payload_manifest,
    verify_prepared_package,
    write_prepared_package,
)

from .test_authority import digest


CREATED = "2026-07-16T12:00:00Z"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True, check=True,
    )
    return result.stdout.strip()


def worker_repository(tmp_path: Path):
    repo = tmp_path / "worker"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "user.email", "test@example.invalid")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "base")
    parent = git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("candidate\n", encoding="utf-8")
    script = repo / "scripts" / "verify"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    git(repo, "add", "README.md", "scripts/verify")
    git(repo, "commit", "-m", "candidate")
    candidate = git(repo, "rev-parse", "HEAD")
    return repo.resolve(), parent, candidate


def payload_and_request(tmp_path: Path):
    worker, parent, candidate = worker_repository(tmp_path)
    manifest = build_foundation_payload_manifest(
        worker_repository=worker,
        candidate_commit=candidate,
        expected_parent=parent,
        manifest_id="payload-001",
        created_at=CREATED,
    )
    old = tmp_path / "old-repo"
    old.mkdir()
    request = build_claim_adoption_request(
        request_id="adoption-request-001",
        package_id="package-001",
        root_digest=digest("1"),
        attempt_id="attempt-001",
        change_id="example-recovery-program",
        task_id="TASK-026",
        worker="worker-root",
        old_repository=old.resolve(),
        new_repository=str((tmp_path / "canonical.git").resolve()),
        payload_manifest=manifest,
        allowed_staging_namespace="refs/das-bootstrap/package-001/",
        requested_at=CREATED,
    )
    return worker, parent, candidate, manifest, request


def test_worker_payload_package_is_set_equal_and_retry_safe(tmp_path: Path) -> None:
    worker, parent, candidate, payload, request = payload_and_request(tmp_path)
    assert payload["candidateCommit"] == candidate
    assert payload["candidateParent"] == parent
    assert payload["entryCount"] == 2
    assert [item["path"] for item in payload["entries"]] == ["README.md", "scripts/verify"]
    assert [item["mode"] for item in payload["entries"]] == ["100644", "100755"]
    assert payload == build_foundation_payload_manifest(
        worker_repository=worker,
        candidate_commit=candidate,
        expected_parent=parent,
        manifest_id="payload-001",
        created_at=CREATED,
    )

    prepared = (tmp_path / "prepared").resolve()
    package = write_prepared_package(
        prepared_directory=prepared,
        package_id="package-001",
        adoption_request=request,
        payload_manifest=payload,
        records={},
        manifest_id="package-manifest-001",
        created_at=CREATED,
    )
    assert package == write_prepared_package(
        prepared_directory=prepared,
        package_id="package-001",
        adoption_request=request,
        payload_manifest=payload,
        records={},
        manifest_id="package-manifest-001",
        created_at=CREATED,
    )
    assert {path.name for path in prepared.iterdir()} == {
        "adoption-request.json", "foundation-payload.json", "package-manifest.json",
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in prepared.iterdir())
    assert verify_prepared_package(
        package_manifest=package,
        adoption_request=request,
        payload_manifest=payload,
    )["foundation-payload.json"] == payload

    concurrent = (tmp_path / "concurrent-prepared").resolve()

    def publish_once():
        return write_prepared_package(
            prepared_directory=concurrent,
            package_id="package-001",
            adoption_request=request,
            payload_manifest=payload,
            records={},
            manifest_id="package-manifest-concurrent",
            created_at=CREATED,
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _index: publish_once(), range(8)))
    assert results == [results[0]] * 8
    assert {path.name for path in concurrent.iterdir()} == {
        "adoption-request.json", "foundation-payload.json", "package-manifest.json",
    }


def test_payload_rejects_wrong_parent_symlink_and_non_top_level_repository(tmp_path: Path) -> None:
    worker, parent, candidate = worker_repository(tmp_path)
    with pytest.raises(FoundationPayloadError, match="expected old main"):
        build_foundation_payload_manifest(
            worker_repository=worker,
            candidate_commit=candidate,
            expected_parent="9" * 40,
            manifest_id="wrong-parent",
            created_at=CREATED,
        )

    link = worker / "unsafe-link"
    link.symlink_to("README.md")
    git(worker, "add", "unsafe-link")
    git(worker, "commit", "-m", "symlink")
    symlink_commit = git(worker, "rev-parse", "HEAD")
    with pytest.raises(FoundationPayloadError, match="symlink"):
        build_foundation_payload_manifest(
            worker_repository=worker,
            candidate_commit=symlink_commit,
            expected_parent=candidate,
            manifest_id="symlink",
            created_at=CREATED,
        )

    with pytest.raises(FoundationPayloadError, match="top level"):
        build_foundation_payload_manifest(
            worker_repository=worker / "scripts",
            candidate_commit=candidate,
            expected_parent=parent,
            manifest_id="subdirectory",
            created_at=CREATED,
        )


def test_prepared_package_rejects_extra_member_and_immutable_drift(tmp_path: Path) -> None:
    _worker, _parent, _candidate, payload, request = payload_and_request(tmp_path)
    extra = (tmp_path / "extra-prepared").resolve()
    extra.mkdir()
    (extra / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(FoundationPayloadError, match="unexpected member"):
        write_prepared_package(
            prepared_directory=extra,
            package_id="package-001",
            adoption_request=request,
            payload_manifest=payload,
            records={},
            manifest_id="package-manifest-extra",
            created_at=CREATED,
        )

    drift = (tmp_path / "drift-prepared").resolve()
    write_prepared_package(
        prepared_directory=drift,
        package_id="package-001",
        adoption_request=request,
        payload_manifest=payload,
        records={},
        manifest_id="package-manifest-drift",
        created_at=CREATED,
    )
    target = drift / "adoption-request.json"
    target.write_text("{}\n", encoding="utf-8")
    verify_drift = (tmp_path / "verify-drift-prepared").resolve()
    verify_package = write_prepared_package(
        prepared_directory=verify_drift,
        package_id="package-001",
        adoption_request=request,
        payload_manifest=payload,
        records={},
        manifest_id="package-manifest-verify-drift",
        created_at=CREATED,
    )
    (verify_drift / "foundation-payload.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(FoundationPayloadError, match="valid canonical record|inventory"):
        verify_prepared_package(
            package_manifest=verify_package,
            adoption_request=request,
            payload_manifest=payload,
        )
    with pytest.raises(FoundationPayloadError, match="immutable member drift"):
        write_prepared_package(
            prepared_directory=drift,
            package_id="package-001",
            adoption_request=request,
            payload_manifest=payload,
            records={},
            manifest_id="package-manifest-drift",
            created_at=CREATED,
        )
