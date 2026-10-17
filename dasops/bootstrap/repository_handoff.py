from __future__ import annotations

import contextlib
from copy import deepcopy
from datetime import timedelta
import fcntl
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator

from dasops.protected.canonical import canonical_bytes, load_canonical_json, semantic_digest, with_self_digest
from dasops.protected.state_store import atomic_write

from .legacy_claim import SignedReceiptIssuer, _utc
from .schema_registry import BootstrapSchemaRegistry


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class RepositoryHandoffError(RuntimeError):
    pass


class RepositoryHandoffCrash(RepositoryHandoffError):
    pass


class RepositoryHandoffStore:
    """Append-only paired selector/profile repository-handoff authority store."""

    CLOSER_OPERATIONS = (
        "complete_consumed",
        "complete_profile_head",
        "complete_recovery_fences",
        "complete_recovery_receipt",
    )

    def __init__(
        self,
        authority_root: str | Path,
        *,
        foundation_program_id: str,
        profile_digest: str,
    ) -> None:
        supplied = Path(authority_root).expanduser()
        if (
            not supplied.is_absolute()
            or supplied.is_symlink()
            or str(supplied.resolve(strict=False)) != str(supplied)
        ):
            raise RepositoryHandoffError("repository handoff root must be normalized, absolute and non-symlink")
        if not SAFE_ID.fullmatch(foundation_program_id) or not DIGEST.fullmatch(profile_digest):
            raise RepositoryHandoffError("repository handoff program/profile identity is invalid")
        self.root = supplied / foundation_program_id
        self.foundation_program_id = foundation_program_id
        self.profile_digest = profile_digest
        self.registry = BootstrapSchemaRegistry()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        if self.root.is_symlink() or os.stat(self.root).st_uid != os.getuid():
            raise RepositoryHandoffError("repository handoff root is not owner controlled")
        for name in (
            "locks",
            "transactions",
            "selector/generations",
            "selector/verifications",
            "selector/current",
            "profile/generations",
            "profile/verifications",
            "profile/current",
        ):
            directory = self.root / name
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
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
        path = self.root / "locks" / "handoff.lock"
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
            raise RepositoryHandoffCrash(f"injected crash after {phase}")

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
                raise RepositoryHandoffError("repository handoff immutable object drift")
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
            raise RepositoryHandoffError("repository handoff record is not owner-controlled mode 0600")
        value = load_canonical_json(path.read_bytes())
        self.registry.validate(value)
        return value

    @staticmethod
    def _repository_id(path: str, object_format: str) -> str:
        return semantic_digest(
            {
                "schema": "canonical-repository-identity/v1",
                "path": str(Path(path).resolve()),
                "objectFormat": object_format,
            }
        )

    @property
    def _selector_current_path(self) -> Path:
        return self.root / "selector" / "current" / "head.json"

    @property
    def _profile_current_path(self) -> Path:
        return self.root / "profile" / "current" / "head.json"

    def _verification(self, namespace: str, head: dict[str, Any], purpose: str) -> dict[str, Any]:
        value = self._read(self.root / namespace / "verifications" / f"{head['recordDigest'][7:]}.json")
        if (
            value is None
            or value["purpose"] != purpose
            or value["subjectDigest"] != head["signatureSubjectDigest"]
        ):
            raise RepositoryHandoffError(f"repository handoff {namespace} verification closure is absent")
        return value

    def _write_head(
        self,
        *,
        namespace: str,
        head: dict[str, Any],
        verification: dict[str, Any],
        expected_current: dict[str, Any] | None,
    ) -> None:
        purpose = (
            "foundation_program_selector_head"
            if namespace == "selector"
            else "verification_profile_transition_head"
        )
        if verification["purpose"] != purpose or verification["subjectDigest"] != head["signatureSubjectDigest"]:
            raise RepositoryHandoffError("repository handoff head verification mismatch")
        sequence_path = (
            self.root
            / namespace
            / "generations"
            / f"{head['sequence']:020d}-{head['recordDigest'][7:]}.json"
        )
        verification_path = self.root / namespace / "verifications" / f"{head['recordDigest'][7:]}.json"
        self._write_immutable(sequence_path, head)
        self._write_immutable(verification_path, verification)
        current_path = self._selector_current_path if namespace == "selector" else self._profile_current_path
        observed = self._read(current_path)
        if observed is not None and observed["recordDigest"] == head["recordDigest"]:
            return
        if observed != expected_current:
            raise RepositoryHandoffError("repository handoff current-head CAS failed")
        atomic_write(current_path, canonical_bytes(head), mode=0o600)

    def current(self) -> dict[str, dict[str, Any]]:
        selector = self._read(self._selector_current_path)
        profile = self._read(self._profile_current_path)
        if selector is None or profile is None:
            raise RepositoryHandoffError("repository handoff current pair is absent")
        return {
            "selectorHead": selector,
            "selectorVerification": self._verification(
                "selector", selector, "foundation_program_selector_head"
            ),
            "profileHead": profile,
            "profileVerification": self._verification(
                "profile", profile, "verification_profile_transition_head"
            ),
        }

    def genesis(self, *, package: dict[str, Any]) -> dict[str, dict[str, Any]]:
        selector_matches = sorted((self.root / "selector" / "generations").glob("00000000000000000000-*.json"))
        profile_matches = sorted((self.root / "profile" / "generations").glob("00000000000000000000-*.json"))
        if len(selector_matches) != 1 or len(profile_matches) != 1:
            raise RepositoryHandoffError("repository handoff genesis history is absent or ambiguous")
        selector = self._read(selector_matches[0])
        profile = self._read(profile_matches[0])
        if selector is None or profile is None:
            raise RepositoryHandoffError("repository handoff genesis history is absent")
        pair = {
            "selectorHead": selector,
            "selectorVerification": self._verification(
                "selector", selector, "foundation_program_selector_head"
            ),
            "profileHead": profile,
            "profileVerification": self._verification(
                "profile", profile, "verification_profile_transition_head"
            ),
        }
        self._validate_genesis_pair(pair, package)
        return pair

    def _validate_genesis_pair(self, pair: dict[str, dict[str, Any]], package: dict[str, Any]) -> None:
        selector = pair["selectorHead"]
        profile = pair["profileHead"]
        old_repository_id = self._repository_id(package["oldRepositoryPath"], package["objectFormat"])
        if (
            selector["sequence"] != 0
            or profile["sequence"] != 0
            or selector["repositoryBindingKind"] != "genesis"
            or profile["headKind"] != "initial"
            or selector["previousHeadDigest"] is not None
            or profile["previousHeadDigest"] is not None
            or selector["currentCanonicalRepositoryId"] != old_repository_id
            or profile["currentCanonicalRepositoryId"] != old_repository_id
            or selector["repositoryBindingId"] != profile["repositoryBindingId"]
            or selector["profileDigest"] != self.profile_digest
            or profile["profileDigest"] != self.profile_digest
            or selector["rootDigest"] != package["rootDigest"]
            or profile["rootDigest"] != package["rootDigest"]
            or any(
                value is not None
                for value in (
                    selector["handoffTransactionDigest"],
                    selector["handoffCloserCapabilitySubjectDigest"],
                    selector["observedMainAtTransition"],
                    profile["handoffTransactionDigest"],
                    profile["handoffCloserCapabilitySubjectDigest"],
                    profile["observedMainAtTransition"],
                )
            )
        ):
            raise RepositoryHandoffError("repository handoff genesis pair is inconsistent")

    def initialize(
        self,
        *,
        package: dict[str, Any],
        issuer: SignedReceiptIssuer,
        effective_at: str,
    ) -> dict[str, dict[str, Any]]:
        self.registry.validate(package)
        with self.lock():
            selector = self._read(self._selector_current_path)
            profile = self._read(self._profile_current_path)
            if selector is not None or profile is not None:
                if selector is None or profile is None:
                    raise RepositoryHandoffError("repository handoff genesis pair is partially initialized")
                pair = self.current()
                self._validate_genesis_pair(pair, package)
                return pair
            old_repository_id = self._repository_id(package["oldRepositoryPath"], package["objectFormat"])
            genesis_binding = semantic_digest(
                {
                    "schema": "repository-genesis-binding/v1",
                    "foundationProgramId": self.foundation_program_id,
                    "rootDigest": package["rootDigest"],
                    "profileDigest": self.profile_digest,
                    "repositoryId": old_repository_id,
                    "authorityEpoch": package["rootEpoch"],
                }
            )
            selector, selector_verification = issuer(
                "foundation_program_selector_head",
                {
                    "schema": "foundation-program-selector-head/v1",
                    "headId": "selector-00000000000000000000",
                    "foundationProgramId": self.foundation_program_id,
                    "sequence": 0,
                    "previousHeadDigest": None,
                    "state": "foundation_open",
                    "rootDigest": package["rootDigest"],
                    "profileDigest": self.profile_digest,
                    "rootEpoch": package["rootEpoch"],
                    "currentCanonicalRepositoryId": old_repository_id,
                    "repositoryTransitionGeneration": 0,
                    "repositoryBindingKind": "genesis",
                    "repositoryBindingId": genesis_binding,
                    "handoffTransactionDigest": None,
                    "handoffCloserCapabilitySubjectDigest": None,
                    "observedMainAtTransition": None,
                    "updatedAt": effective_at,
                },
            )
            profile, profile_verification = issuer(
                "verification_profile_transition_head",
                {
                    "schema": "verification-profile-transition-head/v1",
                    "headId": "profile-00000000000000000000",
                    "foundationProgramId": self.foundation_program_id,
                    "sequence": 0,
                    "previousHeadDigest": None,
                    "headKind": "initial",
                    "rootDigest": package["rootDigest"],
                    "profileDigest": self.profile_digest,
                    "rootEpoch": package["rootEpoch"],
                    "currentCanonicalRepositoryId": old_repository_id,
                    "repositoryBindingId": genesis_binding,
                    "handoffTransactionDigest": None,
                    "handoffCloserCapabilitySubjectDigest": None,
                    "observedMainAtTransition": None,
                    "updatedAt": effective_at,
                },
            )
            self._write_head(
                namespace="selector",
                head=selector,
                verification=selector_verification,
                expected_current=None,
            )
            self._write_head(
                namespace="profile",
                head=profile,
                verification=profile_verification,
                expected_current=None,
            )
            pair = self.current()
            self._validate_genesis_pair(pair, package)
            return pair

    def _transaction(
        self,
        *,
        package: dict[str, Any],
        publish_result: dict[str, Any],
        registry_result: dict[str, Any],
        fv_head: dict[str, Any],
        fv_manifest: dict[str, Any],
        effective_at: str,
    ) -> dict[str, Any]:
        old_repository_id = self._repository_id(package["oldRepositoryPath"], package["objectFormat"])
        new_repository_id = self._repository_id(package["newRepositoryPath"], package["objectFormat"])
        binding_subject = {
            "schema": "repository-adoption-handoff-binding/v1",
            "foundationProgramId": self.foundation_program_id,
            "rootDigest": package["rootDigest"],
            "profileDigest": self.profile_digest,
            "packageDigest": package["recordDigest"],
            "oldRepositoryId": old_repository_id,
            "newRepositoryId": new_repository_id,
            "oldAuthorityEpoch": package["rootEpoch"],
            "newAuthorityEpoch": package["rootEpoch"],
            "objectFormat": package["objectFormat"],
            "oldMain": package["oldMain"],
            "newMain": package["candidateCommit"],
            "publishResultDigest": publish_result["recordDigest"],
            "registryResultDigest": registry_result["recordDigest"],
            "fvPublishedHeadDigest": fv_head["recordDigest"],
            "fvPublishedManifestDigest": fv_manifest["recordDigest"],
        }
        repository_binding_id = semantic_digest(binding_subject)
        expires_at = (_utc(effective_at) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
        closer_digest = semantic_digest(
            {
                "schema": "repository-handoff-closer-capability-subject/v1",
                "repositoryBindingId": repository_binding_id,
                "packageDigest": package["recordDigest"],
                "allowedOperations": list(self.CLOSER_OPERATIONS),
                "expiresAt": expires_at,
            }
        )
        return with_self_digest(
            {
                "schema": "bootstrap-repository-handoff-transaction/v1",
                "transactionId": f"handoff-{package['packageId']}",
                "foundationProgramId": self.foundation_program_id,
                "rootDigest": package["rootDigest"],
                "profileDigest": self.profile_digest,
                "packageId": package["packageId"],
                "packageDigest": package["recordDigest"],
                "oldRepositoryId": old_repository_id,
                "newRepositoryId": new_repository_id,
                "oldRepositoryPath": package["oldRepositoryPath"],
                "newRepositoryPath": package["newRepositoryPath"],
                "oldAuthorityEpoch": package["rootEpoch"],
                "newAuthorityEpoch": package["rootEpoch"],
                "objectFormat": package["objectFormat"],
                "oldMain": package["oldMain"],
                "newMain": package["candidateCommit"],
                "publishResultDigest": publish_result["recordDigest"],
                "registryResultDigest": registry_result["recordDigest"],
                "fvPublishedHeadDigest": fv_head["recordDigest"],
                "fvPublishedManifestDigest": fv_manifest["recordDigest"],
                "oldPermanentFence": True,
                "repositoryBindingId": repository_binding_id,
                "handoffCloserCapabilitySubjectDigest": closer_digest,
                "allowedCloserOperations": list(self.CLOSER_OPERATIONS),
                "expiresAt": expires_at,
                "createdAt": effective_at,
            }
        )

    def publish(
        self,
        *,
        package: dict[str, Any],
        publish_result: dict[str, Any],
        registry_result: dict[str, Any],
        fv_head: dict[str, Any],
        fv_manifest: dict[str, Any],
        issuer: SignedReceiptIssuer,
        effective_at: str,
        crash_after: str | None = None,
    ) -> dict[str, dict[str, Any]]:
        for record in (package, publish_result, registry_result, fv_head, fv_manifest):
            self.registry.validate(record)
        if (
            publish_result["packageDigest"] != package["recordDigest"]
            or publish_result["newMain"] != package["candidateCommit"]
            or not publish_result["oldPermanentFence"]
            or publish_result["registryHeadDigest"] != registry_result["headDigest"]
            or fv_head["milestone"] != "FV-M3"
            or fv_head["state"] != "adoption_published"
            or fv_head["manifestDigest"] != fv_manifest["recordDigest"]
            or fv_head["packageDigest"] != package["recordDigest"]
        ):
            raise RepositoryHandoffError("repository handoff publication evidence mismatch")
        transaction = self._transaction(
            package=package,
            publish_result=publish_result,
            registry_result=registry_result,
            fv_head=fv_head,
            fv_manifest=fv_manifest,
            effective_at=effective_at,
        )
        with self.lock():
            pair = self.current()
            selector_current = pair["selectorHead"]
            profile_current = pair["profileHead"]
            transaction_path = self.root / "transactions" / f"{transaction['recordDigest'][7:]}.json"
            self._write_immutable(transaction_path, transaction)
            if selector_current["repositoryBindingKind"] == "genesis":
                self._validate_genesis_pair(pair, package)
                selector, selector_verification = issuer(
                    "foundation_program_selector_head",
                    {
                        "schema": "foundation-program-selector-head/v1",
                        "headId": "selector-00000000000000000001",
                        "foundationProgramId": self.foundation_program_id,
                        "sequence": 1,
                        "previousHeadDigest": selector_current["recordDigest"],
                        "state": "foundation_open",
                        "rootDigest": package["rootDigest"],
                        "profileDigest": self.profile_digest,
                        "rootEpoch": package["rootEpoch"],
                        "currentCanonicalRepositoryId": transaction["newRepositoryId"],
                        "repositoryTransitionGeneration": 1,
                        "repositoryBindingKind": "adoption_handoff",
                        "repositoryBindingId": transaction["repositoryBindingId"],
                        "handoffTransactionDigest": transaction["recordDigest"],
                        "handoffCloserCapabilitySubjectDigest": transaction[
                            "handoffCloserCapabilitySubjectDigest"
                        ],
                        "observedMainAtTransition": package["candidateCommit"],
                        "updatedAt": effective_at,
                    },
                )
                self._write_head(
                    namespace="selector",
                    head=selector,
                    verification=selector_verification,
                    expected_current=selector_current,
                )
                selector_current = selector
            elif (
                selector_current["repositoryBindingKind"] != "adoption_handoff"
                or selector_current["handoffTransactionDigest"] != transaction["recordDigest"]
                or selector_current["repositoryBindingId"] != transaction["repositoryBindingId"]
            ):
                raise RepositoryHandoffError("repository handoff selector retry drift")
            self._crash(crash_after, "repository_selector_handoff_committed")

            if profile_current["headKind"] == "initial":
                profile, profile_verification = issuer(
                    "verification_profile_transition_head",
                    {
                        "schema": "verification-profile-transition-head/v1",
                        "headId": "profile-00000000000000000001",
                        "foundationProgramId": self.foundation_program_id,
                        "sequence": 1,
                        "previousHeadDigest": profile_current["recordDigest"],
                        "headKind": "repository_handoff",
                        "rootDigest": package["rootDigest"],
                        "profileDigest": self.profile_digest,
                        "rootEpoch": package["rootEpoch"],
                        "currentCanonicalRepositoryId": transaction["newRepositoryId"],
                        "repositoryBindingId": transaction["repositoryBindingId"],
                        "handoffTransactionDigest": transaction["recordDigest"],
                        "handoffCloserCapabilitySubjectDigest": transaction[
                            "handoffCloserCapabilitySubjectDigest"
                        ],
                        "observedMainAtTransition": package["candidateCommit"],
                        "updatedAt": effective_at,
                    },
                )
                self._write_head(
                    namespace="profile",
                    head=profile,
                    verification=profile_verification,
                    expected_current=profile_current,
                )
            elif (
                profile_current["headKind"] != "repository_handoff"
                or profile_current["handoffTransactionDigest"] != transaction["recordDigest"]
                or profile_current["repositoryBindingId"] != transaction["repositoryBindingId"]
            ):
                raise RepositoryHandoffError("repository handoff profile retry drift")
            self._crash(crash_after, "repository_profile_handoff_committed")
            return self.require(package=package, publish_result=publish_result)

    def require(
        self,
        *,
        package: dict[str, Any],
        publish_result: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        pair = self.current()
        selector = pair["selectorHead"]
        profile = pair["profileHead"]
        genesis = self.genesis(package=package)
        expected_new_repository_id = self._repository_id(
            package["newRepositoryPath"], package["objectFormat"]
        )
        if (
            selector["sequence"] != 1
            or profile["sequence"] != 1
            or selector["repositoryBindingKind"] != "adoption_handoff"
            or profile["headKind"] != "repository_handoff"
            or selector["previousHeadDigest"] != genesis["selectorHead"]["recordDigest"]
            or profile["previousHeadDigest"] != genesis["profileHead"]["recordDigest"]
            or selector["repositoryBindingId"] != profile["repositoryBindingId"]
            or selector["handoffTransactionDigest"] != profile["handoffTransactionDigest"]
            or selector["handoffCloserCapabilitySubjectDigest"]
            != profile["handoffCloserCapabilitySubjectDigest"]
            or selector["currentCanonicalRepositoryId"] != profile["currentCanonicalRepositoryId"]
            or selector["currentCanonicalRepositoryId"] != expected_new_repository_id
            or selector["observedMainAtTransition"] != package["candidateCommit"]
            or profile["observedMainAtTransition"] != package["candidateCommit"]
            or selector["rootDigest"] != package["rootDigest"]
            or profile["rootDigest"] != package["rootDigest"]
            or selector["profileDigest"] != self.profile_digest
            or profile["profileDigest"] != self.profile_digest
        ):
            raise RepositoryHandoffError("repository handoff current pair is incomplete or mismatched")
        transaction = self._read(
            self.root / "transactions" / f"{selector['handoffTransactionDigest'][7:]}.json"
        )
        if (
            transaction is None
            or transaction["recordDigest"] != selector["handoffTransactionDigest"]
            or transaction["repositoryBindingId"] != selector["repositoryBindingId"]
            or transaction["packageDigest"] != package["recordDigest"]
            or transaction["rootDigest"] != package["rootDigest"]
            or transaction["profileDigest"] != self.profile_digest
            or transaction["newRepositoryId"] != expected_new_repository_id
            or transaction["publishResultDigest"] != publish_result["recordDigest"]
            or transaction["newMain"] != publish_result["newMain"]
            or transaction["handoffCloserCapabilitySubjectDigest"]
            != selector["handoffCloserCapabilitySubjectDigest"]
            or tuple(transaction["allowedCloserOperations"]) != self.CLOSER_OPERATIONS
            or _utc(transaction["expiresAt"]) <= _utc(transaction["createdAt"])
        ):
            raise RepositoryHandoffError("repository handoff transaction closure is invalid")
        return {**pair, "transaction": deepcopy(transaction)}
