from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from dasops.protected.canonical import load_canonical_json

from .authority_driver import OperationHandler, VerifiedDriverInvocation
from .git_claim import GitCanonicalClaimPublisher
from .registry import BootstrapAttemptRegistry
from .schema_registry import BootstrapSchemaRegistry


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_RECORD_BYTES = 4_194_304


class BootstrapOperationHandlerError(RuntimeError):
    pass


class UpstreamBootstrapOperationHandlers:
    """Real upstream-core handlers installed behind ``BootstrapAuthorityDriver``.

    Product schema/projection adapters remain a separate, explicit boundary. This
    class never treats a same-named product record as semantically compatible.
    """

    def __init__(self, *, absent_registry_head_digest: str) -> None:
        if not isinstance(absent_registry_head_digest, str) or not _DIGEST.fullmatch(
            absent_registry_head_digest
        ):
            raise BootstrapOperationHandlerError(
                "absent registry-head digest must be an externally pinned SHA-256 digest"
            )
        self.absent_registry_head_digest = absent_registry_head_digest
        self.schemas = BootstrapSchemaRegistry()

    @property
    def handlers(self) -> Mapping[str, OperationHandler]:
        return {
            "cancel_attempt": self.cancel_registered_attempt,
            "recover_receipt": self.recover_receipt,
            "register_attempt": self.register_attempt,
        }

    def _attempt_records(self, path_value: str) -> tuple[dict[str, Any], dict[str, Any]]:
        supplied = Path(path_value).expanduser()
        if (
            not supplied.is_absolute()
            or supplied.is_symlink()
            or str(supplied.resolve(strict=False)) != str(supplied)
        ):
            raise BootstrapOperationHandlerError(
                "attempt package must be a normalized absolute non-symlink directory"
            )
        directory = os.open(
            supplied,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(directory)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
            ):
                raise BootstrapOperationHandlerError(
                    "attempt package must be an owner-controlled mode-0700 directory"
                )
            if sorted(os.listdir(directory)) != ["intent.json", "waiver.json"]:
                raise BootstrapOperationHandlerError(
                    "upstream attempt package must contain exactly intent.json and waiver.json"
                )
            intent = self._record_at(directory, "intent.json", "bootstrap-attempt-intent/v1")
            waiver = self._record_at(directory, "waiver.json", "bootstrap-attempt-waiver/v1")
            after = os.fstat(directory)
            path_after = os.stat(supplied, follow_symlinks=False)
            if (
                sorted(os.listdir(directory)) != ["intent.json", "waiver.json"]
                or (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_mtime_ns)
                or (path_after.st_dev, path_after.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise BootstrapOperationHandlerError("attempt package changed during read")
            return intent, waiver
        finally:
            os.close(directory)

    def _record_at(self, directory: int, name: str, expected_schema: str) -> dict[str, Any]:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 3
            or before.st_size > _MAX_RECORD_BYTES
        ):
            raise BootstrapOperationHandlerError(
                f"{expected_schema} is not an owner-only bounded single-link record"
            )
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_nlink,
                opened.st_size,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
            ):
                raise BootstrapOperationHandlerError(f"{expected_schema} changed during open")
            value = bytearray()
            while len(value) <= _MAX_RECORD_BYTES:
                chunk = os.read(descriptor, min(_MAX_RECORD_BYTES + 1 - len(value), 65_536))
                if not chunk:
                    break
                value.extend(chunk)
            after = os.fstat(descriptor)
            if (
                len(value) != opened.st_size
                or len(value) > _MAX_RECORD_BYTES
                or (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_uid,
                    after.st_nlink,
                    after.st_size,
                    after.st_mtime_ns,
                )
                != (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_mode,
                    opened.st_uid,
                    opened.st_nlink,
                    opened.st_size,
                    opened.st_mtime_ns,
                )
            ):
                raise BootstrapOperationHandlerError(f"{expected_schema} changed during read")
        finally:
            os.close(descriptor)
        try:
            record = load_canonical_json(bytes(value))
            self.schemas.validate(record)
        except Exception as exc:
            raise BootstrapOperationHandlerError(
                f"{expected_schema} is not canonical validated JSON"
            ) from exc
        if record["schema"] != expected_schema:
            raise BootstrapOperationHandlerError(f"attempt package record is not {expected_schema}")
        return record

    def _record_path(self, path_value: str, expected_schema: str) -> dict[str, Any]:
        supplied = Path(path_value).expanduser()
        if (
            not supplied.is_absolute()
            or supplied.is_symlink()
            or str(supplied.resolve(strict=False)) != str(supplied)
        ):
            raise BootstrapOperationHandlerError(
                f"{expected_schema} path must be normalized, absolute and non-symlink"
            )
        parent = supplied.parent
        directory = os.open(
            parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(directory)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) & 0o022
            ):
                raise BootstrapOperationHandlerError(
                    f"{expected_schema} parent is not owner-controlled and write-protected"
                )
            record = self._record_at(directory, supplied.name, expected_schema)
            after = os.fstat(directory)
            path_after = os.stat(parent, follow_symlinks=False)
            if (
                (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_mtime_ns)
                or (path_after.st_dev, path_after.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise BootstrapOperationHandlerError(f"{expected_schema} parent changed during read")
            return record
        finally:
            os.close(directory)

    def register_attempt(self, context: VerifiedDriverInvocation) -> dict[str, Any]:
        invocation = context.invocation
        if invocation["operation"] != "register_attempt":
            raise BootstrapOperationHandlerError("registration handler received another operation")
        parameters = invocation["parameters"]
        if set(parameters) != {"attempt", "canonicalRepo", "expectedHead", "expectedMain"}:
            raise BootstrapOperationHandlerError("registration handler parameter set is not exact")

        intent, waiver = self._attempt_records(parameters["attempt"])
        if (
            intent["changeId"] != invocation["changeId"]
            or intent["taskId"] != invocation["taskId"]
            or intent["worker"] != invocation["owner"]
            or intent["baseCommit"] != parameters["expectedMain"]
        ):
            raise BootstrapOperationHandlerError(
                "registration intent does not bind the invocation subject and expected main"
            )

        registry = BootstrapAttemptRegistry(
            invocation["registryRoot"],
            registry_id=invocation["registryId"],
        )
        replay, replay_head = registry.operation_prestate_head(
            intent["operationId"], expected_operation="register_attempt"
        )
        current = registry.current()
        if replay:
            observed_head = self.absent_registry_head_digest if replay_head is None else replay_head
        else:
            observed_head = self.absent_registry_head_digest if current is None else current["headDigest"]
        if parameters["expectedHead"] != observed_head:
            raise BootstrapOperationHandlerError("registration expected registry head drift")

        repository = GitCanonicalClaimPublisher(
            parameters["canonicalRepo"],
            authority_root=registry.root / "git-claim-publisher",
        )
        if repository.head() != parameters["expectedMain"]:
            raise BootstrapOperationHandlerError("registration canonical main drift")

        return registry.register_attempt(
            intent=intent,
            waiver=waiver,
            operation=context.operation,
            effective_at=context.effective_at,
        )

    def recover_receipt(self, context: VerifiedDriverInvocation) -> dict[str, Any]:
        invocation = context.invocation
        if invocation["operation"] != "recover_receipt":
            raise BootstrapOperationHandlerError(
                "receipt-recovery handler received another operation"
            )
        parameters = invocation["parameters"]
        if set(parameters) != {
            "attempt",
            "expectedRegistryHead",
            "recoveryAuthorization",
            "recoverySearch",
        }:
            raise BootstrapOperationHandlerError(
                "receipt-recovery handler parameter set is not exact"
            )

        intent, waiver = self._attempt_records(parameters["attempt"])
        authorization = self._record_path(
            parameters["recoveryAuthorization"],
            "bootstrap-receipt-recovery-authorization/v1",
        )
        search = self._record_path(
            parameters["recoverySearch"],
            "bootstrap-receipt-recovery-search/v1",
        )
        registry = BootstrapAttemptRegistry(
            invocation["registryRoot"],
            registry_id=invocation["registryId"],
        )
        bundle = registry._load_bundle(authorization["operationId"])
        if bundle is not None:
            if bundle["operation"] != "recover_receipt":
                raise BootstrapOperationHandlerError(
                    "receipt-recovery operation id is bound to another operation"
                )
            selected_head = registry.object(bundle["currentHeadDigest"])
            selected_head_digest = selected_head["recordDigest"]
            selected_attempt_id = selected_head["attemptId"]
            selected_entry_digest = selected_head["entryDigest"]
        else:
            selected = registry.current()
            if selected is None:
                raise BootstrapOperationHandlerError(
                    "receipt recovery has no selected registry head"
                )
            selected_head_digest = selected["headDigest"]
            selected_attempt_id = selected["attemptId"]
            selected_entry_digest = selected["entryDigest"]
        if not isinstance(selected_head_digest, str):
            raise BootstrapOperationHandlerError(
                "receipt recovery has no selected registry head"
            )
        entry = registry.object(selected_entry_digest)
        if (
            parameters["expectedRegistryHead"] != selected_head_digest
            or authorization["headDigest"] != selected_head_digest
            or authorization["attemptId"] != selected_attempt_id
        ):
            raise BootstrapOperationHandlerError(
                "receipt-recovery expected registry head or attempt drift"
            )
        if (
            entry["intentDigest"] != intent["recordDigest"]
            or entry["waiverDigest"] != waiver["recordDigest"]
            or entry["changeId"] != invocation["changeId"]
            or entry["taskId"] != invocation["taskId"]
            or entry["worker"] != invocation["owner"]
            or entry["rootDigest"] != authorization["rootDigest"]
        ):
            raise BootstrapOperationHandlerError(
                "receipt-recovery records do not bind the selected attempt and invocation"
            )

        return registry.recover_receipt(
            authorization=authorization,
            search=search,
            operation=context.operation,
            effective_at=context.effective_at,
        )

    def cancel_registered_attempt(self, context: VerifiedDriverInvocation) -> dict[str, Any]:
        invocation = context.invocation
        if invocation["operation"] != "cancel_attempt":
            raise BootstrapOperationHandlerError("cancellation handler received another operation")
        parameters = invocation["parameters"]
        if set(parameters) != {
            "attempt",
            "authorization",
            "canonicalRepo",
            "expectedRegistryHead",
        }:
            raise BootstrapOperationHandlerError("cancellation handler parameter set is not exact")

        intent, waiver = self._attempt_records(parameters["attempt"])
        authorization = self._record_path(
            parameters["authorization"], "bootstrap-attempt-cancel-authorization/v1"
        )
        registry = BootstrapAttemptRegistry(
            invocation["registryRoot"],
            registry_id=invocation["registryId"],
        )
        replay, prestate = registry.operation_prestate_current(
            authorization["operationId"], expected_operation="cancel_attempt"
        )
        selected = prestate if replay else registry.current()
        if selected is None:
            raise BootstrapOperationHandlerError("cancellation has no selected registry prestate")
        if parameters["expectedRegistryHead"] != selected["headDigest"]:
            raise BootstrapOperationHandlerError("cancellation expected registry head drift")
        entry = registry.object(selected["entryDigest"])
        if (
            selected["state"] != "registered"
            or entry["tokenState"] != "not_generated"
            or authorization["expectedState"] != "registered"
            or authorization["tokenDisposition"] != "not_generated"
            or authorization["publicationWalDisposition"] != "absent"
            or authorization["candidateAtMain"] is not False
            or authorization["residualsDisposition"] != "complete"
        ):
            raise BootstrapOperationHandlerError(
                "upstream cancellation handler permits only registered/not-started attempts"
            )
        if (
            entry["intentDigest"] != intent["recordDigest"]
            or entry["waiverDigest"] != waiver["recordDigest"]
            or entry["changeId"] != invocation["changeId"]
            or entry["taskId"] != invocation["taskId"]
            or entry["worker"] != invocation["owner"]
            or authorization["attemptId"] != selected["attemptId"]
            or authorization["headDigest"] != selected["headDigest"]
        ):
            raise BootstrapOperationHandlerError(
                "cancellation records do not bind the selected attempt and invocation"
            )

        if not replay:
            if (registry.root / "legacy-claim").exists() or (registry.root / "legacy-claim").is_symlink():
                raise BootstrapOperationHandlerError(
                    "registered-only cancellation found legacy candidate-preparation state"
                )
            repository = GitCanonicalClaimPublisher(
                parameters["canonicalRepo"],
                authority_root=registry.root / "git-claim-publisher",
            )
            if repository.head() != entry["baseCommit"]:
                raise BootstrapOperationHandlerError("cancellation canonical main drift")

        return registry.cancel_attempt(
            authorization=authorization,
            operation=context.operation,
            effective_at=context.effective_at,
        )
