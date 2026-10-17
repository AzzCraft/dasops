from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import stat
import threading
from typing import Any, Callable, Iterable, Mapping

from dasops.protected.canonical import canonical_bytes, load_canonical_json, with_self_digest

from .ipc import deadline, read_exact, write_all, shutdown, authenticated_socket, IpcError

from .authority import AuthorityVerificationError, BootstrapAuthorityVerifier, VerifiedOperation
from .schema_registry import BootstrapSchemaError, BootstrapSchemaRegistry


MAX_FRAME_BYTES = 4_194_304
COMMAND_OPERATIONS = {
    "abandon-claim": "abandon_claim",
    "adopt-bootstrap-claim.cancel": "adopt_cancel",
    "adopt-bootstrap-claim.prepare": "adopt_prepare",
    "adopt-bootstrap-claim.publish": "adopt_publish",
    "adopt-bootstrap-claim.recover-publication": "recover_publication",
    "cancel-attempt": "cancel_attempt",
    "compensate-claim": "compensate_claim",
    "handoff-claim": "handoff_claim",
    "prepare-candidate": "prepare_candidate",
    "publish-claim": "publish_claim",
    "recover-receipt": "recover_receipt",
    "register-attempt": "register_attempt",
}


class BootstrapAuthorityDriverError(RuntimeError):
    pass


class BootstrapAuthorityDriverRejection(BootstrapAuthorityDriverError):
    """A fail-closed, non-mutating rejection safe to expose to the CLI."""


@dataclass(frozen=True)
class VerifiedDriverInvocation:
    invocation: dict[str, Any]
    operation: VerifiedOperation
    verified_at: datetime | None = None

    @property
    def effective_at(self) -> str:
        # Direct trusted-library callers retain their historical explicit-time
        # contract. The authenticated driver always supplies its own clock.
        value = self.verified_at or _effective_time(self.invocation["effectiveAt"])
        return value.isoformat().replace("+00:00", "Z")


OperationHandler = Callable[[VerifiedDriverInvocation], dict[str, Any]]


def _normalized_absolute(value: str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() or path.is_symlink() or str(path.resolve(strict=False)) != str(path):
        raise BootstrapAuthorityDriverRejection(f"{label} is not a normalized absolute path")
    return path


def _effective_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise BootstrapAuthorityDriverRejection("invocation effective time is invalid") from exc
    if parsed.tzinfo is None:
        raise BootstrapAuthorityDriverRejection("invocation effective time lacks an offset")
    return parsed.astimezone(timezone.utc)


class BootstrapAuthorityDriver:
    """Authenticated one-frame authority driver with injected production adapters."""

    def __init__(
        self,
        *,
        authority_verifier: BootstrapAuthorityVerifier,
        handlers: Mapping[str, OperationHandler],
        allowed_peer_uids: Iterable[int],
        allowed_registry_roots: Iterable[str | Path],
        allowed_subjects: Iterable[tuple[str, str, str, str]],
        peer_actors: Mapping[int, str],
        trusted_clock: Callable[[], datetime] | None = None,
        registry: BootstrapSchemaRegistry | None = None,
    ) -> None:
        if not isinstance(authority_verifier, BootstrapAuthorityVerifier):
            raise BootstrapAuthorityDriverError("a pinned authority verifier is mandatory")
        if set(handlers) - set(COMMAND_OPERATIONS.values()):
            raise BootstrapAuthorityDriverError("authority driver handler operation is unsupported")
        if not handlers:
            raise BootstrapAuthorityDriverError("authority driver has no operation handlers")
        if any(not callable(handler) for handler in handlers.values()):
            raise BootstrapAuthorityDriverError("authority driver operation handler is not callable")
        peer_uids = frozenset(allowed_peer_uids)
        if not peer_uids or any(type(value) is not int or value < 0 for value in peer_uids):
            raise BootstrapAuthorityDriverError("authority driver peer UID allowlist is invalid")
        actors = dict(peer_actors)
        if (set(actors) != set(peer_uids)
                or any(type(uid) is not int or not isinstance(actor, str) or not 1 <= len(actor) <= 128
                       for uid, actor in actors.items())):
            raise BootstrapAuthorityDriverError("every allowed peer UID requires one installed actor binding")
        if trusted_clock is not None and not callable(trusted_clock):
            raise BootstrapAuthorityDriverError("trusted clock must be an installed local callable")
        registry_roots = frozenset(
            str(_normalized_absolute(str(value), "allowed registry root"))
            for value in allowed_registry_roots
        )
        if not registry_roots:
            raise BootstrapAuthorityDriverError("authority driver registry-root allowlist is empty")
        subject_values = tuple(allowed_subjects)
        if not subject_values or any(not isinstance(value, (tuple, list)) for value in subject_values):
            raise BootstrapAuthorityDriverError("authority driver subject allowlist is invalid")
        subjects = frozenset(tuple(value) for value in subject_values)
        if any(len(value) != 4 or not all(isinstance(item, str) and item for item in value) for value in subjects):
            raise BootstrapAuthorityDriverError("authority driver subject allowlist is invalid")
        self.authority_verifier = authority_verifier
        self.handlers = dict(handlers)
        self.allowed_peer_uids = peer_uids
        self.allowed_registry_roots = registry_roots
        self.allowed_subjects = subjects
        self.peer_actors = actors
        self.trusted_clock = trusted_clock or (lambda: datetime.now(timezone.utc))
        self._clock_lock = threading.Lock()
        self._clock_floor: datetime | None = None
        self.registry = registry or BootstrapSchemaRegistry()

    def _current_time(self) -> datetime:
        value = self.trusted_clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise BootstrapAuthorityDriverRejection("trusted current time is unavailable")
        value = value.astimezone(timezone.utc)
        with self._clock_lock:
            if self._clock_floor is not None and value < self._clock_floor:
                raise BootstrapAuthorityDriverRejection("trusted clock moved backwards")
            self._clock_floor = value
        return value

    def _record(self, path_value: str, expected_schema: str) -> dict[str, Any]:
        path = _normalized_absolute(path_value, expected_schema)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise BootstrapAuthorityDriverRejection(f"{expected_schema} cannot be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_size < 3
                or metadata.st_size > MAX_FRAME_BYTES
            ):
                raise BootstrapAuthorityDriverRejection(
                    f"{expected_schema} is not a bounded trusted non-writable regular file"
                )
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1_048_576))
                if not chunk:
                    raise BootstrapAuthorityDriverRejection(f"{expected_schema} changed during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise BootstrapAuthorityDriverRejection(f"{expected_schema} grew during read")
        finally:
            os.close(descriptor)
        try:
            value = load_canonical_json(b"".join(chunks))
            self.registry.validate(value)
        except (ValueError, BootstrapSchemaError) as exc:
            raise BootstrapAuthorityDriverRejection(
                f"{expected_schema} is not strict canonical validated JSON"
            ) from exc
        if value["schema"] != expected_schema:
            raise BootstrapAuthorityDriverRejection(f"authority record is not {expected_schema}")
        return value

    def _verify(self, invocation: dict[str, Any], peer_uid: int) -> VerifiedDriverInvocation:
        try:
            self.registry.validate(invocation)
        except BootstrapSchemaError as exc:
            raise BootstrapAuthorityDriverRejection("authority invocation failed strict schema validation") from exc
        if invocation["schema"] != "bootstrap-cli-invocation/v1":
            raise BootstrapAuthorityDriverRejection("authority invocation has the wrong schema")
        expected_operation = COMMAND_OPERATIONS.get(invocation["command"])
        if expected_operation != invocation["operation"]:
            raise BootstrapAuthorityDriverRejection("authority invocation command/operation mismatch")
        if invocation["effectiveAt"] != invocation["requestedAt"]:
            raise BootstrapAuthorityDriverRejection("authority invocation effective/request time mismatch")
        if self.peer_actors.get(peer_uid) != invocation["owner"]:
            raise BootstrapAuthorityDriverRejection("request owner differs from the authenticated peer actor")
        effective_at = self._current_time()
        if abs((effective_at - _effective_time(invocation["requestedAt"])).total_seconds()) > 30:
            raise BootstrapAuthorityDriverRejection("request time is outside the freshness window")
        if invocation["operation"] not in self.handlers:
            raise BootstrapAuthorityDriverRejection("authority operation has no installed production handler")
        if invocation["registryRoot"] not in self.allowed_registry_roots:
            raise BootstrapAuthorityDriverRejection("authority invocation registry root is outside the allowlist")
        subject = (
            invocation["changeId"],
            invocation["taskId"],
            invocation["owner"],
            invocation["registryId"],
        )
        if subject not in self.allowed_subjects:
            raise BootstrapAuthorityDriverRejection("authority invocation subject is outside the allowlist")
        paths = invocation["authority"]
        anchor = self._record(paths["trustAnchor"], "bootstrap-trust-anchor/v1")
        root = self._record(paths["root"], "bootstrap-root/v1")
        source = self._record(paths["sourceDecision"], "tool-source-decision/v1")
        release = self._record(paths["toolRelease"], "tool-release/v1")
        descriptor = self._record(paths["operationDescriptor"], "bootstrap-operation-descriptor/v1")
        try:
            authority = self.authority_verifier.verify_anchor_root(
                anchor=anchor,
                root=root,
                now=effective_at,
            )
            tool_release = self.authority_verifier.verify_tool_release(
                authority=authority,
                source_decision=source,
                release=release,
                now=effective_at,
            )
            operation = self.authority_verifier.verify_operation_descriptor(
                tool_release=tool_release,
                descriptor=descriptor,
                expected_operation=invocation["operation"],
                change_id=invocation["changeId"],
                task_id=invocation["taskId"],
                now=effective_at,
            )
        except AuthorityVerificationError as exc:
            raise BootstrapAuthorityDriverRejection("independent authority-chain verification rejected") from exc
        return VerifiedDriverInvocation(invocation=invocation, operation=operation, verified_at=effective_at)

    def _result(
        self,
        invocation: dict[str, Any],
        *,
        outcome: str,
        result_digest: str | None,
        message: str | None,
    ) -> dict[str, Any]:
        result = with_self_digest(
            {
                "schema": "bootstrap-cli-result/v1",
                "invocationDigest": invocation["recordDigest"],
                "operation": invocation["operation"],
                "outcome": outcome,
                "resultDigest": result_digest,
                "message": message,
                "completedAt": (self._clock_floor or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
            }
        )
        self.registry.validate(result)
        return result

    def dispatch(self, invocation: dict[str, Any]) -> dict[str, Any]:
        """Trusted local call; identity is the actual process UID, never owner JSON."""
        return self._dispatch(invocation, os.getuid())

    def _dispatch(self, invocation: dict[str, Any], peer_uid: int) -> dict[str, Any]:
        try:
            verified = self._verify(invocation, peer_uid)
            result = self.handlers[invocation["operation"]](verified)
            self.registry.validate(result)
            if not isinstance(result.get("recordDigest"), str):
                raise BootstrapAuthorityDriverError("operation handler returned no result digest")
            return self._result(
                invocation,
                outcome="succeeded",
                result_digest=result["recordDigest"],
                message=None,
            )
        except BootstrapAuthorityDriverRejection:
            return self._result(
                invocation,
                outcome="rejected",
                result_digest=None,
                message="bootstrap authority rejected the invocation",
            )
        except Exception:
            return self._result(
                invocation,
                outcome="failed",
                result_digest=None,
                message="bootstrap authority operation failed",
            )

    def _authenticated_socket(self, fd: int) -> tuple[socket.socket, int]:
        try:
            return authenticated_socket(fd, self.allowed_peer_uids)
        except IpcError as exc:
            raise BootstrapAuthorityDriverError(str(exc)) from exc

    def serve_once(self, fd: int) -> dict[str, Any]:
        channel, peer_uid = self._authenticated_socket(fd)
        with channel:
            try:
                limit = deadline()
                size = int.from_bytes(read_exact(channel, 8, limit), "big")
                if size < 3 or size > MAX_FRAME_BYTES:
                    raise BootstrapAuthorityDriverError("authority driver request frame length is invalid")
                try:
                    invocation = load_canonical_json(read_exact(channel, size, limit))
                    self.registry.validate(invocation)
                except (ValueError, BootstrapSchemaError) as exc:
                    raise BootstrapAuthorityDriverError("authority driver request is not canonical validated JSON") from exc
                result = self._dispatch(invocation, peer_uid)
                payload = canonical_bytes(result)
                if len(payload) > MAX_FRAME_BYTES:
                    raise BootstrapAuthorityDriverError("authority driver result exceeds its frame budget")
                write_all(channel, len(payload).to_bytes(8, "big") + payload, limit)
                return result
            finally:
                shutdown(channel)
