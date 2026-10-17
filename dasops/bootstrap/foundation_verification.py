from __future__ import annotations

import contextlib
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator, Mapping

from dasops.protected.canonical import canonical_bytes, load_canonical_json, semantic_digest, with_self_digest
from dasops.protected.state_store import atomic_write

from .schema_registry import BootstrapSchemaRegistry


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class FoundationVerificationError(RuntimeError):
    pass


class FoundationVerificationCrash(FoundationVerificationError):
    pass


class AdoptionFoundationVerificationStore:
    """Append-only adoption FV-M0/M1/M2/M3/MA authority-store core."""

    TRANSITIONS = {
        None: ("FV-M0", "prepared"),
        "prepared": ("FV-M1", "verified"),
        "verified": ("FV-M2", "adoption_authorized"),
        "adoption_authorized": ("FV-M3", "adoption_published"),
    }
    ABORTABLE = frozenset({"prepared", "verified", "adoption_authorized"})

    def __init__(self, authority_root: str | Path, *, slot_id: str) -> None:
        if not SAFE_ID.fullmatch(slot_id):
            raise FoundationVerificationError("foundation verification slot id is unsafe")
        supplied = Path(authority_root).expanduser()
        if not supplied.is_absolute() or supplied.is_symlink() or str(supplied.resolve(strict=False)) != str(supplied):
            raise FoundationVerificationError("foundation verification root must be normalized, absolute and non-symlink")
        self.root = supplied / slot_id
        self.slot_id = slot_id
        self.registry = BootstrapSchemaRegistry()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        if self.root.is_symlink() or os.stat(self.root).st_uid != os.getuid():
            raise FoundationVerificationError("foundation verification root is not owner controlled")
        for name in ("locks", "objects", "manifests", "heads", "head", "rejected"):
            directory = self.root / name
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        self._fsync(self.root)

    @staticmethod
    def _fsync(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        path = self.root / "locks" / "slot.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _crash(crash_after: str | None, phase: str) -> None:
        if crash_after == phase:
            raise FoundationVerificationCrash(f"injected crash after {phase}")

    def _write_immutable(self, path: Path, value: dict[str, Any]) -> None:
        self.registry.validate(value)
        encoded = canonical_bytes(value)
        if path.exists():
            before = os.lstat(path)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.getuid()
                or path.read_bytes() != encoded
            ):
                raise FoundationVerificationError("foundation verification immutable object drift")
            return
        atomic_write(path, encoded, mode=0o600, create_only=True)

    def _read(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
        ):
            raise FoundationVerificationError("foundation verification record is not owner-controlled mode 0600")
        value = load_canonical_json(path.read_bytes())
        self.registry.validate(value)
        return value

    def _object_path(self, digest: str) -> Path:
        return self.root / "objects" / f"{digest.removeprefix('sha256:')}.json"

    def _store_objects(self, records: Mapping[str, dict[str, Any]]) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        for role in sorted(records):
            if not SAFE_ID.fullmatch(role):
                raise FoundationVerificationError("foundation verification object role is unsafe")
            record = records[role]
            self.registry.validate(record)
            self._write_immutable(self._object_path(record["recordDigest"]), record)
            entries.append({"role": role, "schema": record["schema"], "digest": record["recordDigest"]})
        if not entries:
            raise FoundationVerificationError("foundation verification milestone cannot be empty")
        return entries

    @property
    def _current_path(self) -> Path:
        return self.root / "head" / "current.json"

    def current(self) -> dict[str, Any] | None:
        value = self._read(self._current_path)
        if value is not None and value["schema"] != "foundation-verification-descriptor-head/v1":
            raise FoundationVerificationError("foundation verification current head has the wrong schema")
        return value

    def manifest(self, head: dict[str, Any] | None = None) -> dict[str, Any] | None:
        selected = head or self.current()
        if selected is None:
            return None
        value = self._read(self.root / "manifests" / f"{selected['manifestDigest'][7:]}.json")
        if value is None or value["recordDigest"] != selected["manifestDigest"]:
            raise FoundationVerificationError("foundation verification manifest closure is absent")
        return value

    def _validate_manifest_objects(self, manifest: dict[str, Any]) -> None:
        entries = manifest["entries"]
        if (
            [entry["role"] for entry in entries] != sorted({entry["role"] for entry in entries})
            or manifest["entryCount"] != len(entries)
            or manifest["inventoryDigest"]
            != semantic_digest({"schema": "foundation-verification-inventory/v1", "entries": entries})
        ):
            raise FoundationVerificationError("foundation verification manifest inventory is inconsistent")
        for entry in entries:
            value = self._read(self._object_path(entry["digest"]))
            if value is None or value["recordDigest"] != entry["digest"] or value["schema"] != entry["schema"]:
                raise FoundationVerificationError("foundation verification manifest object closure is incomplete")

    def validate_chain(self) -> list[dict[str, Any]]:
        current = self.current()
        if current is None:
            return []
        chain: list[dict[str, Any]] = []
        cursor = current
        seen: set[str] = set()
        while True:
            if cursor["recordDigest"] in seen:
                raise FoundationVerificationError("foundation verification head chain contains a cycle")
            seen.add(cursor["recordDigest"])
            manifest = self.manifest(cursor)
            if manifest is None:
                raise FoundationVerificationError("foundation verification head has no manifest")
            self._validate_manifest_objects(manifest)
            if (
                manifest["slotId"] != self.slot_id
                or manifest["milestone"] != cursor["milestone"]
                or manifest["sequence"] != cursor["sequence"]
                or manifest["state"] != cursor["state"]
                or manifest["descriptorDigest"] != cursor["descriptorDigest"]
                or manifest["packageDigest"] != cursor["packageDigest"]
            ):
                raise FoundationVerificationError("foundation verification head/manifest chain is inconsistent")
            chain.append(cursor)
            if cursor["previousHeadDigest"] is None:
                if (
                    cursor["sequence"] != 0
                    or cursor["milestone"] != "FV-M0"
                    or cursor["state"] != "prepared"
                    or manifest["previousManifestDigest"] is not None
                ):
                    raise FoundationVerificationError("foundation verification genesis is invalid")
                break
            predecessor = self._head_by_digest(cursor["previousHeadDigest"])
            if (
                predecessor["sequence"] + 1 != cursor["sequence"]
                or manifest["previousManifestDigest"] != predecessor["manifestDigest"]
                or predecessor["descriptorDigest"] != cursor["descriptorDigest"]
                or predecessor["packageDigest"] != cursor["packageDigest"]
            ):
                raise FoundationVerificationError("foundation verification predecessor chain is inconsistent")
            cursor = predecessor
        chain.reverse()
        expected_prefix = [("FV-M0", "prepared"), ("FV-M1", "verified"), ("FV-M2", "adoption_authorized")]
        observed = [(head["milestone"], head["state"]) for head in chain]
        if observed[-1] == ("FV-M3", "adoption_published"):
            expected = [*expected_prefix, ("FV-M3", "adoption_published")]
        elif observed[-1] == ("FV-MA", "aborted_pre_cas"):
            expected = [*expected_prefix[: len(observed) - 1], ("FV-MA", "aborted_pre_cas")]
        else:
            expected = expected_prefix[: len(observed)]
        if observed != expected:
            raise FoundationVerificationError("foundation verification state history is invalid")
        return chain

    def _head_by_digest(self, digest: str) -> dict[str, Any]:
        matches = list((self.root / "heads").glob(f"*-{digest[7:]}.json"))
        if len(matches) != 1:
            raise FoundationVerificationError("foundation verification predecessor head is absent or ambiguous")
        value = self._read(matches[0])
        if value is None or value["recordDigest"] != digest:
            raise FoundationVerificationError("foundation verification predecessor head digest mismatch")
        return value

    def head(self, digest: str) -> dict[str, Any]:
        return deepcopy(self._head_by_digest(digest))

    def object(self, digest: str) -> dict[str, Any]:
        value = self._read(self._object_path(digest))
        if value is None or value["recordDigest"] != digest:
            raise FoundationVerificationError("foundation verification object is absent")
        return deepcopy(value)

    def _commit(
        self,
        *,
        milestone: str,
        state: str,
        descriptor: dict[str, Any],
        package: dict[str, Any],
        records: Mapping[str, dict[str, Any]],
        evidence_digest: str,
        effective_at: str,
        crash_after: str | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        with self.lock():
            current = self.current()
            if current is not None and current["milestone"] == milestone:
                if (
                    current["state"] != state
                    or current["descriptorDigest"] != descriptor["recordDigest"]
                    or current["packageDigest"] != package["recordDigest"]
                    or current["evidenceDigest"] != evidence_digest
                ):
                    raise FoundationVerificationError("foundation verification milestone replay drift")
                manifest = self.manifest(current)
                if manifest is None:
                    raise FoundationVerificationError("foundation verification retry manifest is absent")
                return current, manifest
            previous_state = current["state"] if current is not None else None
            if state == "aborted_pre_cas":
                if milestone != "FV-MA" or previous_state not in self.ABORTABLE:
                    raise FoundationVerificationError("foundation verification abort edge is ineligible")
            elif self.TRANSITIONS.get(previous_state) != (milestone, state):
                raise FoundationVerificationError("foundation verification milestone sequence is invalid")
            if current is not None and (
                current["descriptorDigest"] != descriptor["recordDigest"]
                or current["packageDigest"] != package["recordDigest"]
                or current["candidateCommit"] != package["candidateCommit"]
                or current["candidateParent"] != package["candidateParent"]
            ):
                raise FoundationVerificationError("foundation verification candidate identity drift")
            entries = self._store_objects(records)
            self._crash(crash_after, "objects_written")
            sequence = 0 if current is None else current["sequence"] + 1
            manifest = with_self_digest(
                {
                    "schema": "foundation-verification-store-manifest/v1",
                    "manifestId": f"manifest-{sequence:04d}-{milestone.lower()}",
                    "slotId": self.slot_id,
                    "milestone": milestone,
                    "sequence": sequence,
                    "state": state,
                    "previousManifestDigest": None if current is None else current["manifestDigest"],
                    "descriptorDigest": descriptor["recordDigest"],
                    "packageDigest": package["recordDigest"],
                    "entries": entries,
                    "entryCount": len(entries),
                    "inventoryDigest": semantic_digest(
                        {"schema": "foundation-verification-inventory/v1", "entries": entries}
                    ),
                    "createdAt": effective_at,
                }
            )
            manifest_path = self.root / "manifests" / f"{manifest['recordDigest'][7:]}.json"
            self._write_immutable(manifest_path, manifest)
            self._crash(crash_after, "manifest_written")
            head = with_self_digest(
                {
                    "schema": "foundation-verification-descriptor-head/v1",
                    "headId": f"head-{sequence:04d}",
                    "slotId": self.slot_id,
                    "milestone": milestone,
                    "sequence": sequence,
                    "state": state,
                    "previousHeadDigest": None if current is None else current["recordDigest"],
                    "manifestDigest": manifest["recordDigest"],
                    "descriptorDigest": descriptor["recordDigest"],
                    "packageDigest": package["recordDigest"],
                    "candidateCommit": package["candidateCommit"],
                    "candidateTree": package["candidateTree"],
                    "candidateParent": package["candidateParent"],
                    "evidenceDigest": evidence_digest,
                    "updatedAt": effective_at,
                }
            )
            head_path = self.root / "heads" / f"{sequence:04d}-{head['recordDigest'][7:]}.json"
            siblings = list((self.root / "heads").glob(f"{sequence:04d}-*.json"))
            if siblings and (len(siblings) != 1 or siblings[0] != head_path):
                raise FoundationVerificationError("foundation verification head sequence is ambiguous")
            self._write_immutable(head_path, head)
            self._crash(crash_after, "head_written")
            if current is not None and self._current_path.read_bytes() != canonical_bytes(current):
                raise FoundationVerificationError("foundation verification current-head CAS failed")
            atomic_write(self._current_path, canonical_bytes(head), mode=0o600)
            self._crash(crash_after, "current_committed")
            return head, manifest

    @staticmethod
    def descriptor_for(
        *,
        slot_id: str,
        package: dict[str, Any],
        approval_subject: dict[str, Any],
        prepare_result: dict[str, Any],
        created_at: str,
    ) -> dict[str, Any]:
        repository_pair = semantic_digest(
            {
                "schema": "bootstrap-adoption-repository-pair/v1",
                "oldRepositoryPath": package["oldRepositoryPath"],
                "newRepositoryPath": package["newRepositoryPath"],
                "workerRepositoryPath": package["workerRepositoryPath"],
                "objectFormat": package["objectFormat"],
            }
        )
        return with_self_digest(
            {
                "schema": "bootstrap-foundation-candidate-descriptor/v1",
                "descriptorId": slot_id,
                "slotId": slot_id,
                "operationClass": "bootstrap_adoption_validate",
                "rootDigest": package["rootDigest"],
                "packageDigest": package["recordDigest"],
                "approvalSubjectDigest": approval_subject["recordDigest"],
                "prepareResultDigest": prepare_result["recordDigest"],
                "repositoryPairBindingDigest": repository_pair,
                "oldRepositoryPath": package["oldRepositoryPath"],
                "newRepositoryPath": package["newRepositoryPath"],
                "workerRepositoryPath": package["workerRepositoryPath"],
                "objectFormat": package["objectFormat"],
                "oldMain": package["oldMain"],
                "expectedNewMainAbsent": True,
                "allowedStagingNamespace": package["allowedStagingNamespace"],
                "candidateCommit": package["candidateCommit"],
                "candidateTree": package["candidateTree"],
                "candidateParent": package["candidateParent"],
                "createdAt": created_at,
            }
        )

    def prepare(
        self,
        *,
        package: dict[str, Any],
        approval_subject: dict[str, Any],
        prepare_result: dict[str, Any],
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        for record in (package, approval_subject, prepare_result):
            self.registry.validate(record)
        if (
            package["candidateParent"] != package["oldMain"]
            or approval_subject["packageDigest"] != package["recordDigest"]
            or prepare_result["packageDigest"] != package["recordDigest"]
        ):
            raise FoundationVerificationError("FV-M0 adoption package closure mismatch")
        descriptor = self.descriptor_for(
            slot_id=self.slot_id,
            package=package,
            approval_subject=approval_subject,
            prepare_result=prepare_result,
            created_at=effective_at,
        )
        evidence = semantic_digest(
            {
                "schema": "foundation-verification-prepared-evidence/v1",
                "descriptorDigest": descriptor["recordDigest"],
                "packageDigest": package["recordDigest"],
            }
        )
        head, manifest = self._commit(
            milestone="FV-M0",
            state="prepared",
            descriptor=descriptor,
            package=package,
            records={
                "approval_subject": approval_subject,
                "descriptor": descriptor,
                "package": package,
                "prepare_result": prepare_result,
            },
            evidence_digest=evidence,
            effective_at=effective_at,
            crash_after=crash_after,
        )
        return descriptor, head, manifest

    def verify(
        self,
        *,
        descriptor: dict[str, Any],
        package: dict[str, Any],
        verification_result: dict[str, Any],
        result_verification: dict[str, Any],
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        for record in (descriptor, package, verification_result, result_verification):
            self.registry.validate(record)
        current = self.current()
        prepared = (
            self._head_by_digest(current["previousHeadDigest"])
            if current is not None and current["state"] == "verified"
            else current
        )
        manifest = self.manifest(prepared)
        if prepared is None or manifest is None or prepared["state"] != "prepared":
            raise FoundationVerificationError("FV-M1 requires the prepared head")
        if (
            verification_result["descriptorDigest"] != descriptor["recordDigest"]
            or verification_result["preparedHeadDigest"] != prepared["recordDigest"]
            or verification_result["m0ManifestDigest"] != manifest["recordDigest"]
            or verification_result["packageDigest"] != package["recordDigest"]
            or verification_result["candidateCommit"] != package["candidateCommit"]
            or verification_result["candidateTree"] != package["candidateTree"]
            or verification_result["candidateParent"] != package["candidateParent"]
            or result_verification["purpose"] != "bootstrap_candidate_verification_result"
            or result_verification["subjectDigest"] != verification_result["signatureSubjectDigest"]
        ):
            raise FoundationVerificationError("FV-M1 verification-result closure mismatch")
        if verification_result["outcome"] == "rejected":
            path = self.root / "rejected" / f"{verification_result['recordDigest'][7:]}.json"
            self._write_immutable(path, verification_result)
            self._write_immutable(
                self.root / "rejected" / f"{result_verification['recordDigest'][7:]}.json",
                result_verification,
            )
            return None
        evidence = semantic_digest(
            {
                "schema": "foundation-verification-verified-evidence/v1",
                "verificationResultDigest": verification_result["recordDigest"],
                "resultVerificationDigest": result_verification["recordDigest"],
            }
        )
        return self._commit(
            milestone="FV-M1",
            state="verified",
            descriptor=descriptor,
            package=package,
            records={"result_verification": result_verification, "verification_result": verification_result},
            evidence_digest=evidence,
            effective_at=effective_at,
            crash_after=crash_after,
        )

    def authorize(
        self,
        *,
        descriptor: dict[str, Any],
        package: dict[str, Any],
        approval: dict[str, Any],
        approval_verification: dict[str, Any],
        publish_request: dict[str, Any],
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for record in (descriptor, package, approval, approval_verification, publish_request):
            self.registry.validate(record)
        current = self.current()
        if current is None or current["state"] not in {"verified", "adoption_authorized"}:
            raise FoundationVerificationError("FV-M2 requires the verified head")
        if (
            approval["packageDigest"] != package["recordDigest"]
            or publish_request["packageDigest"] != package["recordDigest"]
            or publish_request["candidateCommit"] != package["candidateCommit"]
            or approval_verification["purpose"] != "bootstrap_adoption_approval"
        ):
            raise FoundationVerificationError("FV-M2 adoption authorization closure mismatch")
        evidence = semantic_digest(
            {
                "schema": "foundation-verification-adoption-authorization-evidence/v1",
                "approvalDigest": approval["recordDigest"],
                "approvalVerificationDigest": approval_verification["recordDigest"],
                "publishRequestDigest": publish_request["recordDigest"],
            }
        )
        return self._commit(
            milestone="FV-M2",
            state="adoption_authorized",
            descriptor=descriptor,
            package=package,
            records={
                "approval": approval,
                "approval_verification": approval_verification,
                "publish_request": publish_request,
            },
            evidence_digest=evidence,
            effective_at=effective_at,
            crash_after=crash_after,
        )

    def publish(
        self,
        *,
        descriptor: dict[str, Any],
        package: dict[str, Any],
        publish_result: dict[str, Any],
        publish_verification: dict[str, Any],
        registry_result: dict[str, Any],
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for record in (descriptor, package, publish_result, publish_verification, registry_result):
            self.registry.validate(record)
        current = self.current()
        if current is None or current["state"] not in {"adoption_authorized", "adoption_published"}:
            raise FoundationVerificationError("FV-M3 requires the adoption-authorized head")
        if (
            publish_result["packageDigest"] != package["recordDigest"]
            or publish_result["newMain"] != package["candidateCommit"]
            or publish_result["registryHeadDigest"] != registry_result["headDigest"]
            or publish_verification["purpose"] != "bootstrap_adoption_publish_result"
        ):
            raise FoundationVerificationError("FV-M3 adoption publication closure mismatch")
        evidence = semantic_digest(
            {
                "schema": "foundation-verification-adoption-publication-evidence/v1",
                "publishResultDigest": publish_result["recordDigest"],
                "publishVerificationDigest": publish_verification["recordDigest"],
                "registryResultDigest": registry_result["recordDigest"],
            }
        )
        return self._commit(
            milestone="FV-M3",
            state="adoption_published",
            descriptor=descriptor,
            package=package,
            records={
                "publish_result": publish_result,
                "publish_verification": publish_verification,
                "registry_result": registry_result,
            },
            evidence_digest=evidence,
            effective_at=effective_at,
            crash_after=crash_after,
        )

    def abort(
        self,
        *,
        descriptor: dict[str, Any],
        package: dict[str, Any],
        abort_subject: dict[str, Any],
        effective_at: str,
        crash_after: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for record in (descriptor, package, abort_subject):
            self.registry.validate(record)
        evidence = semantic_digest(
            {
                "schema": "foundation-verification-adoption-abort-evidence/v1",
                "abortSubjectDigest": abort_subject["recordDigest"],
            }
        )
        return self._commit(
            milestone="FV-MA",
            state="aborted_pre_cas",
            descriptor=descriptor,
            package=package,
            records={"abort_subject": abort_subject},
            evidence_digest=evidence,
            effective_at=effective_at,
            crash_after=crash_after,
        )

    def require(self, *, milestone: str, state: str, package: dict[str, Any]) -> dict[str, Any]:
        current = self.current()
        if (
            current is None
            or current["milestone"] != milestone
            or current["state"] != state
            or current["packageDigest"] != package["recordDigest"]
            or current["candidateCommit"] != package["candidateCommit"]
            or self.manifest(current) is None
        ):
            raise FoundationVerificationError("required foundation verification head is absent")
        self.validate_chain()
        return deepcopy(current)
