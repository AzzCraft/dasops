from __future__ import annotations

import contextlib
from datetime import timedelta
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator, Protocol

from dasops.protected.canonical import canonical_bytes, load_canonical_json, semantic_digest, with_self_digest
from dasops.protected.encoding import strict_urlsafe_b64decode
from dasops.protected.state_store import atomic_write

from .authority import VerifiedOperation
from .foundation_payload import FoundationPayloadError, verify_prepared_package
from .legacy_claim import LegacyClaimCoordinator, LegacyClaimError, _utc
from .registry import BootstrapAttemptRegistry, BootstrapRegistryError


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class AdoptionPrepareError(RuntimeError):
    pass


class AdoptionPrepareCrash(AdoptionPrepareError):
    pass


class AdoptionRepositoryInspector(Protocol):
    def snapshot(self) -> dict[str, Any]: ...


class AdoptionSecretProvider(Protocol):
    def prepare(self, request: dict[str, Any], *, recovery: bool) -> None: ...


def _safe_id(kind: str, value: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise AdoptionPrepareError(f"unsafe {kind}: {value!r}")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class AdoptionPrepareCoordinator:
    """Build an expiring adoption package without mutating either repository."""

    def __init__(self, registry: BootstrapAttemptRegistry) -> None:
        self.registry = registry
        self.root = registry.root / "adoption"
        self.root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        if self.root.is_symlink() or os.stat(self.root).st_uid != os.getuid():
            raise AdoptionPrepareError("adoption authority store is not owner controlled")
        for name in ("locks", "operations", "packages", "results"):
            directory = self.root / name
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        _fsync_directory(self.root)

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        path = self.root / "locks" / "prepare.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _operation_dir(self, operation_id: str) -> Path:
        return self.root / "operations" / _safe_id("operation id", operation_id)

    @property
    def _current_path(self) -> Path:
        return self.root / "packages" / "current.json"

    @property
    def _lifecycle_path(self) -> Path:
        return self.root / "packages" / "state.json"

    def _write_record(self, path: Path, record: dict[str, Any]) -> None:
        self.registry._validate(record)
        encoded = canonical_bytes(record)
        if path.exists():
            if path.is_symlink() or path.read_bytes() != encoded:
                raise AdoptionPrepareError(f"immutable adoption record drift: {path.name}")
            return
        atomic_write(path, encoded, mode=0o600, create_only=True)

    def _read_record(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        if path.is_symlink() or stat.S_IMODE(os.stat(path).st_mode) != 0o600:
            raise AdoptionPrepareError(f"adoption record is not a mode-0600 regular file: {path}")
        value = load_canonical_json(path.read_bytes())
        self.registry._validate(value)
        return value

    def current_package(self) -> dict[str, Any] | None:
        value = self._read_record(self._current_path)
        if value is not None and value["schema"] != "bootstrap-adoption-package/v2":
            raise AdoptionPrepareError("adoption current pointer is not a package")
        return value

    @staticmethod
    def _crash(crash_after: str | None, phase: str) -> None:
        if crash_after == phase:
            raise AdoptionPrepareCrash(f"injected crash after {phase}")

    def _append_wal(
        self,
        *,
        request: dict[str, Any],
        phase: str,
        old_snapshot_digest: str,
        new_snapshot_digest: str,
        prepared_at: str,
        package_digest: str | None = None,
        subject_digest: str | None = None,
        result_digest: str | None = None,
    ) -> None:
        wal = with_self_digest(
            {
                "schema": "bootstrap-adoption-prepare-wal/v1",
                "operationId": request["operationId"],
                "packageId": request["packageId"],
                "requestDigest": request["recordDigest"],
                "phase": phase,
                "claimedHeadDigest": request["claimedHeadDigest"],
                "oldSnapshotDigest": old_snapshot_digest,
                "newSnapshotDigest": new_snapshot_digest,
                "packageDigest": package_digest,
                "approvalSubjectDigest": subject_digest,
                "resultDigest": result_digest,
                "recordedAt": prepared_at,
            }
        )
        self._write_record(self._operation_dir(request["operationId"]) / f"{phase}.json", wal)

    def _private_path(self, value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise AdoptionPrepareError("adoption private-state path must be absolute")
        parent = path.parent.resolve()
        resolved = parent / path.name
        try:
            resolved.relative_to(self.registry.root)
        except ValueError:
            pass
        else:
            raise AdoptionPrepareError("adoption token state cannot enter the authority store")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or os.stat(parent).st_uid != os.getuid():
            raise AdoptionPrepareError("adoption private-state parent is not owner controlled")
        os.chmod(parent, stat.S_IMODE(os.stat(parent).st_mode) & ~0o077)
        return resolved

    def _read_private(self, path: Path) -> dict[str, Any]:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid():
            raise AdoptionPrepareError("adoption private state is not an owner-controlled mode-0600 regular file")
        value = load_canonical_json(path.read_bytes())
        self.registry._validate(value)
        if value["schema"] != "bootstrap-adoption-private-state/v1":
            raise AdoptionPrepareError("adoption private state has the wrong schema")
        try:
            token = strict_urlsafe_b64decode(value["tokenBase64"], expected_size=32)
        except Exception as exc:
            raise AdoptionPrepareError("adoption private token encoding is invalid") from exc
        if value["tokenHash"] != "sha256:" + hashlib.sha256(token).hexdigest():
            raise AdoptionPrepareError("adoption private token/hash mismatch")
        return value

    @staticmethod
    def _snapshot(inspector: AdoptionRepositoryInspector) -> dict[str, Any]:
        value = inspector.snapshot()
        required = {"path", "objectFormat", "main", "refs", "drained", "fenced", "fenceMode"}
        if not isinstance(value, dict) or set(value) != required:
            raise AdoptionPrepareError("repository snapshot field set is not exact")
        if not isinstance(value["refs"], list) or value["refs"] != sorted(set(value["refs"])):
            raise AdoptionPrepareError("repository snapshot refs must be sorted and unique")
        if value["objectFormat"] not in {"sha1", "sha256"}:
            raise AdoptionPrepareError("repository snapshot object format is unsupported")
        if not isinstance(value["drained"], bool) or not isinstance(value["fenced"], bool):
            raise AdoptionPrepareError("repository snapshot drain/fence fields are invalid")
        if value["fenceMode"] not in {"open", "prefenced", "permanent"} or (
            value["fenced"] != (value["fenceMode"] != "open")
        ):
            raise AdoptionPrepareError("repository snapshot fence mode is invalid")
        return value

    @staticmethod
    def _validate_repo_preconditions(
        request: dict[str, Any],
        old: dict[str, Any],
        new: dict[str, Any],
    ) -> None:
        old_path = str(Path(request["oldRepositoryPath"]).resolve())
        new_path = str(Path(request["newRepositoryPath"]).resolve())
        if old_path == new_path or old["path"] != old_path or new["path"] != new_path:
            raise AdoptionPrepareError("adoption repository identity/path mismatch")
        if request["objectFormat"] != "sha1":
            raise AdoptionPrepareError("this bootstrap release supports only the legacy SHA-1 object format")
        if old["objectFormat"] != request["objectFormat"] or new["objectFormat"] != request["objectFormat"]:
            raise AdoptionPrepareError("adoption repository object formats differ")
        if old["main"] != request["oldMain"] or new["main"] is not None:
            raise AdoptionPrepareError("adoption old-main/new-main precondition failed")
        if old["drained"] or old["fenced"] or new["drained"] or new["fenced"]:
            raise AdoptionPrepareError("adoption prepare cannot run on drained or fenced repositories")
        namespace = request["allowedStagingNamespace"]
        if any(not ref.startswith(namespace) for ref in new["refs"]):
            raise AdoptionPrepareError("new repository contains a ref outside the allowed staging namespace")

    def prepare(
        self,
        *,
        request: dict[str, Any],
        candidate_result: dict[str, Any],
        publication_receipt: dict[str, Any],
        publication_verification: dict[str, Any],
        handoff_receipt: dict[str, Any],
        handoff_verification: dict[str, Any],
        claim_adoption_request: dict[str, Any],
        foundation_payload: dict[str, Any],
        prepared_package_manifest: dict[str, Any],
        operation: VerifiedOperation,
        old_repository: AdoptionRepositoryInspector,
        new_repository: AdoptionRepositoryInspector,
        secret_provider: AdoptionSecretProvider,
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        records = [
            request,
            candidate_result,
            publication_receipt,
            publication_verification,
            handoff_receipt,
            handoff_verification,
            claim_adoption_request,
            foundation_payload,
            prepared_package_manifest,
        ]
        for record in records:
            self.registry._validate(record)
        try:
            verify_prepared_package(
                package_manifest=prepared_package_manifest,
                adoption_request=claim_adoption_request,
                payload_manifest=foundation_payload,
            )
        except FoundationPayloadError as exc:
            raise AdoptionPrepareError(str(exc)) from exc
        current = self.registry.current()
        if current is None:
            raise AdoptionPrepareError("claimed bootstrap attempt is absent")
        entry = self.registry.object(current["entryDigest"])
        try:
            request_manifest = self.registry._validate_operation(
                operation,
                expected_operation="adopt_prepare",
                records=records,
                change_id=entry["changeId"],
                task_id=entry["taskId"],
            )
            self.registry._validate_operation_time(
                operation,
                effective_at=effective_at,
                not_before=(request["requestedAt"], handoff_receipt["completedAt"]),
            )
            LegacyClaimCoordinator._verify_signed_record(
                self,
                record=publication_receipt,
                verification=publication_verification,
                purpose="bootstrap_publication_receipt",
                operation=operation,
            )
            LegacyClaimCoordinator._verify_signed_record(
                self,
                record=handoff_receipt,
                verification=handoff_verification,
                purpose="bootstrap_handoff_receipt",
                operation=operation,
            )
        except (BootstrapRegistryError, LegacyClaimError) as exc:
            raise AdoptionPrepareError(str(exc)) from exc
        root = operation.tool_release.authority.root
        relations = {
            "attemptId": current["attemptId"],
            "claimedHeadDigest": current["headDigest"],
            "rootDigest": root["recordDigest"],
            "changeId": entry["changeId"],
            "taskId": entry["taskId"],
            "worker": entry["worker"],
            "oldMain": publication_receipt["candidateCommit"],
            "publicationReceiptDigest": publication_receipt["recordDigest"],
            "publicationVerificationDigest": publication_verification["recordDigest"],
            "handoffReceiptDigest": handoff_receipt["recordDigest"],
            "handoffVerificationDigest": handoff_verification["recordDigest"],
            "legacyTokenHash": candidate_result["tokenHash"],
        }
        for field, expected in relations.items():
            if request[field] != expected:
                raise AdoptionPrepareError(f"adoption-prepare {field} mismatch")
        foundation_relations = {
            "packageId": request["packageId"],
            "rootDigest": request["rootDigest"],
            "attemptId": request["attemptId"],
            "changeId": request["changeId"],
            "taskId": request["taskId"],
            "worker": request["worker"],
            "oldRepositoryPath": str(Path(request["oldRepositoryPath"]).resolve()),
            "newRepositoryPath": str(Path(request["newRepositoryPath"]).resolve()),
            "objectFormat": request["objectFormat"],
            "expectedOldMain": request["oldMain"],
            "candidateParent": request["oldMain"],
            "foundationPayloadManifestDigest": foundation_payload["recordDigest"],
            "allowedStagingNamespace": request["allowedStagingNamespace"],
        }
        for field, expected in foundation_relations.items():
            if claim_adoption_request[field] != expected:
                raise AdoptionPrepareError(f"foundation adoption {field} mismatch")
        if (
            claim_adoption_request["candidateCommit"] != foundation_payload["candidateCommit"]
            or claim_adoption_request["candidateTree"] != foundation_payload["candidateTree"]
            or claim_adoption_request["candidateParent"] != foundation_payload["candidateParent"]
            or claim_adoption_request["workerRepositoryPath"] != foundation_payload["workerRepositoryPath"]
            or prepared_package_manifest["packageId"] != request["packageId"]
            or prepared_package_manifest["adoptionRequestDigest"] != claim_adoption_request["recordDigest"]
            or prepared_package_manifest["foundationPayloadManifestDigest"] != foundation_payload["recordDigest"]
            or foundation_payload["candidateParent"] != request["oldMain"]
            or foundation_payload["candidateCommit"] == request["oldMain"]
        ):
            raise AdoptionPrepareError("foundation candidate/package closure mismatch")
        if current["state"] != "claimed" or handoff_receipt["outcome"] != "acknowledged" or handoff_receipt["workAuthority"] != "legacy_bootstrap_only":
            raise AdoptionPrepareError("adoption prepare requires an acknowledged claimed handoff")
        if (
            candidate_result["attemptId"] != request["attemptId"]
            or candidate_result["candidateCommit"] != request["oldMain"]
            or publication_receipt["attemptId"] != request["attemptId"]
            or publication_receipt["candidateCommit"] != request["oldMain"]
            or handoff_receipt["attemptId"] != request["attemptId"]
            or handoff_receipt["publicationReceiptDigest"] != publication_receipt["recordDigest"]
            or handoff_receipt["worker"] != request["worker"]
        ):
            raise AdoptionPrepareError("adoption candidate/attempt binding mismatch")
        operation_id = _safe_id("operation id", request["operationId"])
        private_path = self._private_path(request["privateStatePath"])
        prepared_at = request["requestedAt"]
        expires_at = (_utc(prepared_at) + timedelta(seconds=request["packageLifetimeSeconds"])).isoformat().replace("+00:00", "Z")
        if _utc(expires_at) > _utc(operation.descriptor["validUntil"]):
            raise AdoptionPrepareError("adoption package lifetime exceeds the operation descriptor")

        with self._lock():
            active = self.current_package()
            if active is not None and (active["operationId"] != operation_id or active["packageId"] != request["packageId"]):
                lifecycle = self._read_record(self._lifecycle_path)
                if (
                    lifecycle is None
                    or lifecycle["schema"] != "bootstrap-adoption-lifecycle-state/v1"
                    or lifecycle["packageDigest"] != active["recordDigest"]
                    or lifecycle["status"] not in {"cancelled", "consumed"}
                ):
                    raise AdoptionPrepareError("another adoption package remains live and must be cancelled or consumed")
            old_before = self._snapshot(old_repository)
            new_before = self._snapshot(new_repository)
            self._validate_repo_preconditions(request, old_before, new_before)
            old_digest = semantic_digest(old_before)
            new_digest = semantic_digest(new_before)
            self._write_record(self._operation_dir(operation_id) / "request.json", request)
            self._append_wal(
                request=request,
                phase="prepare_intent",
                old_snapshot_digest=old_digest,
                new_snapshot_digest=new_digest,
                prepared_at=prepared_at,
            )
            self._crash(crash_after, "prepare_intent")

            recovery = private_path.exists() or private_path.is_symlink()
            prior_private_digest: str | None = None
            if recovery:
                prior_private_digest = self._read_private(private_path)["recordDigest"]
            secret_provider.prepare(request, recovery=recovery)
            private = self._read_private(private_path)
            if prior_private_digest is not None and private["recordDigest"] != prior_private_digest:
                raise AdoptionPrepareError("adoption preparation regenerated private token state")
            if private["operationId"] != operation_id or private["packageId"] != request["packageId"]:
                raise AdoptionPrepareError("adoption private state subject mismatch")
            if private["createdAt"] != prepared_at:
                raise AdoptionPrepareError("adoption private state preparation-time mismatch")
            if private["tokenHash"] == request["legacyTokenHash"]:
                raise AdoptionPrepareError("adoption token must be distinct from the legacy token")
            self._append_wal(
                request=request,
                phase="secret_prepared",
                old_snapshot_digest=old_digest,
                new_snapshot_digest=new_digest,
                prepared_at=prepared_at,
            )
            self._crash(crash_after, "secret_prepared")

            package_path = self._operation_dir(operation_id) / "package.json"
            package = self._read_record(package_path)
            if package is None:
                package = with_self_digest(
                    {
                        "schema": "bootstrap-adoption-package/v2",
                        "packageId": request["packageId"],
                        "operationId": operation_id,
                        "status": "awaiting_approval",
                        "rootDigest": root["recordDigest"],
                        "rootEpoch": root["epoch"],
                        "toolReleaseDigest": operation.tool_release.release["recordDigest"],
                        "attemptId": request["attemptId"],
                        "claimedHeadDigest": request["claimedHeadDigest"],
                        "oldRepositoryPath": str(Path(request["oldRepositoryPath"]).resolve()),
                        "newRepositoryPath": str(Path(request["newRepositoryPath"]).resolve()),
                        "workerRepositoryPath": foundation_payload["workerRepositoryPath"],
                        "oldMain": request["oldMain"],
                        "candidateCommit": foundation_payload["candidateCommit"],
                        "candidateTree": foundation_payload["candidateTree"],
                        "candidateParent": foundation_payload["candidateParent"],
                        "newMainExpectedAbsent": True,
                        "objectFormat": request["objectFormat"],
                        "allowedStagingNamespace": request["allowedStagingNamespace"],
                        "claimAdoptionRequestDigest": claim_adoption_request["recordDigest"],
                        "foundationPayloadManifestDigest": foundation_payload["recordDigest"],
                        "preparedPackageManifestDigest": prepared_package_manifest["recordDigest"],
                        "publicationReceiptDigest": request["publicationReceiptDigest"],
                        "handoffReceiptDigest": request["handoffReceiptDigest"],
                        "legacyTokenHash": request["legacyTokenHash"],
                        "adoptionTokenHash": private["tokenHash"],
                        "keyEnvelopeDigest": private["keyEnvelopeDigest"],
                        "generation": private["generation"],
                        "oldSnapshotDigest": old_digest,
                        "newSnapshotDigest": new_digest,
                        "preparedAt": prepared_at,
                        "expiresAt": expires_at,
                    }
                )
                self._write_record(package_path, package)
            self._append_wal(
                request=request,
                phase="package_built",
                old_snapshot_digest=old_digest,
                new_snapshot_digest=new_digest,
                prepared_at=prepared_at,
                package_digest=package["recordDigest"],
            )
            self._crash(crash_after, "package_built")

            subject_path = self._operation_dir(operation_id) / "approval-subject.json"
            subject = self._read_record(subject_path)
            if subject is None:
                subject = with_self_digest(
                    {
                        "schema": "bootstrap-adoption-approval-subject/v2",
                        "subjectId": f"approval-{request['packageId']}",
                        "packageDigest": package["recordDigest"],
                        "rootDigest": root["recordDigest"],
                        "attemptId": request["attemptId"],
                        "oldRepositoryPath": str(Path(request["oldRepositoryPath"]).resolve()),
                        "oldMain": request["oldMain"],
                        "newRepositoryPath": str(Path(request["newRepositoryPath"]).resolve()),
                        "workerRepositoryPath": foundation_payload["workerRepositoryPath"],
                        "candidateCommit": foundation_payload["candidateCommit"],
                        "candidateTree": foundation_payload["candidateTree"],
                        "candidateParent": foundation_payload["candidateParent"],
                        "claimAdoptionRequestDigest": claim_adoption_request["recordDigest"],
                        "foundationPayloadManifestDigest": foundation_payload["recordDigest"],
                        "preparedPackageManifestDigest": prepared_package_manifest["recordDigest"],
                        "legacyTokenHash": request["legacyTokenHash"],
                        "adoptionTokenHash": private["tokenHash"],
                        "keyEnvelopeDigest": private["keyEnvelopeDigest"],
                        "generation": private["generation"],
                        "requiredRoles": sorted(root["toolPolicy"]["requiredOperationRoles"]),
                        "createdAt": prepared_at,
                        "expiresAt": expires_at,
                    }
                )
                self._write_record(subject_path, subject)
            self._append_wal(
                request=request,
                phase="approval_subject_built",
                old_snapshot_digest=old_digest,
                new_snapshot_digest=new_digest,
                prepared_at=prepared_at,
                package_digest=package["recordDigest"],
                subject_digest=subject["recordDigest"],
            )
            self._crash(crash_after, "approval_subject_built")

            old_after = self._snapshot(old_repository)
            new_after = self._snapshot(new_repository)
            if old_after != old_before or new_after != new_before:
                raise AdoptionPrepareError("adoption prepare mutated or raced either repository")
            no_mutation = semantic_digest(
                {
                    "schema": "bootstrap-adoption-no-mutation-proof/v1",
                    "oldBefore": old_before,
                    "oldAfter": old_after,
                    "newBefore": new_before,
                    "newAfter": new_after,
                }
            )
            result_path = self.root / "results" / f"{operation_id}.json"
            result = self._read_record(result_path)
            if result is None:
                result = with_self_digest(
                    {
                        "schema": "bootstrap-adoption-prepare-result/v2",
                        "operationId": operation_id,
                        "packageId": request["packageId"],
                        "outcome": "awaiting_approval",
                        "requestDigest": request_manifest,
                        "packageDigest": package["recordDigest"],
                        "approvalSubjectDigest": subject["recordDigest"],
                        "claimAdoptionRequestDigest": claim_adoption_request["recordDigest"],
                        "foundationPayloadManifestDigest": foundation_payload["recordDigest"],
                        "preparedPackageManifestDigest": prepared_package_manifest["recordDigest"],
                        "noMutationProofDigest": no_mutation,
                        "privateStateDigest": private["recordDigest"],
                        "completedAt": prepared_at,
                    }
                )
                self._write_record(result_path, result)
            if self._current_path.exists():
                if self._current_path.read_bytes() != canonical_bytes(package):
                    lifecycle = self._read_record(self._lifecycle_path)
                    if lifecycle is None or lifecycle["status"] not in {"cancelled", "consumed"}:
                        raise AdoptionPrepareError("adoption current-package CAS failed")
                    atomic_write(self._current_path, canonical_bytes(package), mode=0o600)
            else:
                atomic_write(self._current_path, canonical_bytes(package), mode=0o600, create_only=True)
            lifecycle = with_self_digest(
                {
                    "schema": "bootstrap-adoption-lifecycle-state/v1",
                    "packageId": package["packageId"],
                    "packageDigest": package["recordDigest"],
                    "status": "awaiting_approval",
                    "generation": 0,
                    "publishRequestDigest": None,
                    "oldDrained": False,
                    "oldFenced": False,
                    "newMain": None,
                    "stagingRef": None,
                    "publishResultDigest": None,
                    "activationReceiptDigest": None,
                    "cancelResultDigest": None,
                    "updatedAt": prepared_at,
                }
            )
            if self._lifecycle_path.exists() and self._lifecycle_path.read_bytes() != canonical_bytes(lifecycle):
                prior_lifecycle = self._read_record(self._lifecycle_path)
                if prior_lifecycle is None or prior_lifecycle["status"] not in {"cancelled", "consumed"}:
                    raise AdoptionPrepareError("adoption lifecycle CAS failed")
                atomic_write(self._lifecycle_path, canonical_bytes(lifecycle), mode=0o600)
            elif not self._lifecycle_path.exists():
                atomic_write(self._lifecycle_path, canonical_bytes(lifecycle), mode=0o600, create_only=True)
            self._append_wal(
                request=request,
                phase="completed",
                old_snapshot_digest=old_digest,
                new_snapshot_digest=new_digest,
                prepared_at=prepared_at,
                package_digest=package["recordDigest"],
                subject_digest=subject["recordDigest"],
                result_digest=result["recordDigest"],
            )
            self._crash(crash_after, "completed")
            return package, subject, result
