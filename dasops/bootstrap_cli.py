from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import socket
import stat
import sys
from typing import Any, Iterable

from .bootstrap.ipc import IpcError, deadline, read_exact, write_all, shutdown
from .bootstrap.schema_registry import BootstrapSchemaRegistry
from .protected.canonical import canonical_bytes, load_canonical_json, with_self_digest


class BootstrapCliError(RuntimeError):
    pass


@dataclass(frozen=True)
class Parameter:
    flag: str
    name: str
    kind: str = "path"


@dataclass(frozen=True)
class CommandSpec:
    command: str
    operation: str
    parameters: tuple[Parameter, ...]


PUBLISHER_SPECS = {
    "register-attempt": CommandSpec(
        "register-attempt",
        "register_attempt",
        (
            Parameter("--attempt", "attempt"),
            Parameter("--canonical-repo", "canonicalRepo"),
            Parameter("--expected-head", "expectedHead", "digest"),
            Parameter("--expected-main", "expectedMain", "oid"),
        ),
    ),
    "cancel-attempt": CommandSpec(
        "cancel-attempt",
        "cancel_attempt",
        (
            Parameter("--attempt", "attempt"),
            Parameter("--canonical-repo", "canonicalRepo"),
            Parameter("--authorization", "authorization"),
            Parameter("--expected-registry-head", "expectedRegistryHead", "digest"),
        ),
    ),
    "recover-receipt": CommandSpec(
        "recover-receipt",
        "recover_receipt",
        (
            Parameter("--attempt", "attempt"),
            Parameter("--recovery-authorization", "recoveryAuthorization"),
            Parameter("--recovery-search", "recoverySearch"),
            Parameter("--expected-registry-head", "expectedRegistryHead", "digest"),
        ),
    ),
    "prepare-candidate": CommandSpec(
        "prepare-candidate",
        "prepare_candidate",
        (Parameter("--request", "request"), Parameter("--worker-lock", "workerLock")),
    ),
    "publish-claim": CommandSpec(
        "publish-claim",
        "publish_claim",
        (
            Parameter("--request", "request"),
            Parameter("--candidate-result", "candidateResult"),
            Parameter("--candidate-receipt", "candidateReceipt"),
            Parameter("--candidate-verification", "candidateVerification"),
            Parameter("--canonical-repo", "canonicalRepo"),
        ),
    ),
    "handoff-claim": CommandSpec(
        "handoff-claim",
        "handoff_claim",
        (
            Parameter("--request", "request"),
            Parameter("--candidate-result", "candidateResult"),
            Parameter("--publication-receipt", "publicationReceipt"),
            Parameter("--publication-verification", "publicationVerification"),
            Parameter("--challenge", "challenge"),
            Parameter("--response-fd-label", "responseFdLabel", "label"),
        ),
    ),
    "compensate-claim": CommandSpec(
        "compensate-claim",
        "compensate_claim",
        (Parameter("--authorization", "authorization"), Parameter("--canonical-repo", "canonicalRepo")),
    ),
    "abandon-claim": CommandSpec(
        "abandon-claim",
        "abandon_claim",
        (Parameter("--authorization", "authorization"), Parameter("--canonical-repo", "canonicalRepo")),
    ),
}


ADOPTION_SPECS = {
    "prepare": CommandSpec(
        "adopt-bootstrap-claim.prepare",
        "adopt_prepare",
        (
            Parameter("--bootstrap-repo", "bootstrapRepo"),
            Parameter("--repo-root", "repoRoot"),
            Parameter("--worker-repo", "workerRepo"),
            Parameter("--waiver", "waiver"),
            Parameter("--prepared-output", "preparedOutput"),
        ),
    ),
    "publish": CommandSpec(
        "adopt-bootstrap-claim.publish",
        "adopt_publish",
        (
            Parameter("--bootstrap-repo", "bootstrapRepo"),
            Parameter("--repo-root", "repoRoot"),
            Parameter("--worker-repo", "workerRepo"),
            Parameter("--waiver", "waiver"),
            Parameter("--prepared", "prepared"),
            Parameter("--adoption-approval", "adoptionApproval"),
        ),
    ),
    "cancel": CommandSpec(
        "adopt-bootstrap-claim.cancel",
        "adopt_cancel",
        (
            Parameter("--bootstrap-repo", "bootstrapRepo"),
            Parameter("--repo-root", "repoRoot"),
            Parameter("--waiver", "waiver"),
            Parameter("--prepared", "prepared"),
            Parameter("--cancel-authorization", "cancelAuthorization"),
        ),
    ),
    "recover-publication": CommandSpec(
        "adopt-bootstrap-claim.recover-publication",
        "recover_publication",
        (
            Parameter("--bootstrap-repo", "bootstrapRepo"),
            Parameter("--repo-root", "repoRoot"),
            Parameter("--waiver", "waiver"),
            Parameter("--prepared", "prepared"),
            Parameter("--recovery-authorization", "recoveryAuthorization"),
        ),
    ),
}


COMMANDS = frozenset({"bootstrap-publisher", "adopt-bootstrap-claim"})
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OID = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--trust-anchor", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--source-decision", required=True)
    parser.add_argument("--tool-release", required=True)
    parser.add_argument("--operation-descriptor", required=True)
    parser.add_argument("--registry-root", required=True)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--change-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--effective-at", required=True)
    parser.add_argument("--driver-fd", required=True, type=int)


def _add_spec(parser: argparse.ArgumentParser, spec: CommandSpec) -> None:
    _common(parser)
    for parameter in spec.parameters:
        parser.add_argument(parameter.flag, required=True)
    parser.set_defaults(bootstrap_spec=spec)


def add_bootstrap_parsers(sub: argparse._SubParsersAction) -> None:
    publisher = sub.add_parser("bootstrap-publisher", help=argparse.SUPPRESS)
    publisher_sub = publisher.add_subparsers(dest="bootstrap_action", required=True)
    for name, spec in PUBLISHER_SPECS.items():
        _add_spec(publisher_sub.add_parser(name), spec)

    adoption = sub.add_parser(
        "adopt-bootstrap-claim",
        help="Run the root/release-pinned bootstrap adoption protocol through an authenticated driver FD",
    )
    adoption_sub = adoption.add_subparsers(dest="bootstrap_action", required=True)
    for name, spec in ADOPTION_SPECS.items():
        _add_spec(adoption_sub.add_parser(name), spec)


def _publisher_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="das-bootstrap-publisher")
    sub = parser.add_subparsers(dest="bootstrap_action", required=True)
    for name, spec in PUBLISHER_SPECS.items():
        _add_spec(sub.add_parser(name), spec)
    return parser


def _absolute(value: str, label: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute() or str(path.resolve(strict=False)) != value or "\x00" in value:
        raise BootstrapCliError(f"{label} must be a normalized absolute path")
    return value


def _identifier(value: str, label: str) -> str:
    if not SAFE_ID.fullmatch(value):
        raise BootstrapCliError(f"{label} is not a safe explicit identifier")
    return value


def _record(path_value: str, schema: str, registry: BootstrapSchemaRegistry) -> dict[str, Any]:
    path = Path(_absolute(path_value, schema))
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise BootstrapCliError(f"{schema} cannot be opened safely") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.getuid()} or stat.S_IMODE(before.st_mode) & 0o022:
        raise BootstrapCliError(f"{schema} is not a trusted non-writable regular file")
    try:
        value = load_canonical_json(path.read_bytes())
        registry.validate(value)
    except Exception as exc:
        raise BootstrapCliError(f"{schema} is not strict canonical validated JSON") from exc
    if value["schema"] != schema:
        raise BootstrapCliError(f"expected {schema}, received {value['schema']}")
    return value


def _authority(args: argparse.Namespace, spec: CommandSpec) -> dict[str, str]:
    registry = BootstrapSchemaRegistry()
    paths = {
        "trustAnchor": _absolute(args.trust_anchor, "trust anchor"),
        "root": _absolute(args.root, "root"),
        "sourceDecision": _absolute(args.source_decision, "source decision"),
        "toolRelease": _absolute(args.tool_release, "tool release"),
        "operationDescriptor": _absolute(args.operation_descriptor, "operation descriptor"),
    }
    anchor = _record(paths["trustAnchor"], "bootstrap-trust-anchor/v1", registry)
    root = _record(paths["root"], "bootstrap-root/v1", registry)
    source = _record(paths["sourceDecision"], "tool-source-decision/v1", registry)
    release = _record(paths["toolRelease"], "tool-release/v1", registry)
    descriptor = _record(paths["operationDescriptor"], "bootstrap-operation-descriptor/v1", registry)
    if root["recordDigest"] != anchor["expectedRootDigest"] or root["rootId"] != anchor["expectedRootId"]:
        raise BootstrapCliError("root does not match the supplied trust anchor")
    if source["rootId"] != root["rootId"] or release["rootId"] != root["rootId"]:
        raise BootstrapCliError("tool lineage does not match the supplied root")
    if release["sourceDecisionDigest"] != source["recordDigest"]:
        raise BootstrapCliError("tool release does not match the source decision")
    if (
        descriptor["rootDigest"] != root["recordDigest"]
        or descriptor["toolReleaseDigest"] != release["recordDigest"]
        or descriptor["operation"] != spec.operation
        or descriptor["changeId"] != args.change_id
        or descriptor["taskId"] != args.task_id
    ):
        raise BootstrapCliError("operation descriptor does not match the requested command/task/tool")
    return paths


def _parameters(args: argparse.Namespace, spec: CommandSpec) -> dict[str, str]:
    result: dict[str, str] = {}
    for parameter in spec.parameters:
        value = getattr(args, parameter.flag.removeprefix("--").replace("-", "_"))
        if parameter.kind == "path":
            value = _absolute(value, parameter.name)
        elif parameter.kind == "digest" and not DIGEST.fullmatch(value):
            raise BootstrapCliError(f"{parameter.name} is not a SHA-256 record digest")
        elif parameter.kind == "oid" and not OID.fullmatch(value):
            raise BootstrapCliError(f"{parameter.name} is not a full Git object ID")
        elif parameter.kind == "label":
            value = _identifier(value, parameter.name)
        result[parameter.name] = value
    return result


def build_invocation(args: argparse.Namespace) -> dict[str, Any]:
    spec: CommandSpec = args.bootstrap_spec
    if args.driver_fd < 3:
        raise BootstrapCliError("authenticated bootstrap driver descriptor must be fd 3 or greater")
    change_id = _identifier(args.change_id, "change id")
    task_id = _identifier(args.task_id, "task id")
    owner = _identifier(args.owner, "owner")
    registry_id = _identifier(args.registry_id, "registry id")
    authority = _authority(args, spec)
    descriptor = _record(authority["operationDescriptor"], "bootstrap-operation-descriptor/v1", BootstrapSchemaRegistry())
    invocation = with_self_digest(
        {
            "schema": "bootstrap-cli-invocation/v1",
            "invocationId": f"cli-{spec.operation}-{descriptor['recordDigest'][-16:]}",
            "command": spec.command,
            "operation": spec.operation,
            "changeId": change_id,
            "taskId": task_id,
            "owner": owner,
            "registryRoot": _absolute(args.registry_root, "registry root"),
            "registryId": registry_id,
            "authority": authority,
            "parameters": _parameters(args, spec),
            "effectiveAt": args.effective_at,
            "requestedAt": args.effective_at,
        }
    )
    try:
        BootstrapSchemaRegistry().validate(invocation)
    except Exception as exc:
        raise BootstrapCliError("bootstrap invocation failed strict schema validation") from exc
    return invocation


def invoke_driver(fd: int, invocation: dict[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
    limit = deadline(timeout)
    payload = canonical_bytes(invocation)
    if type(fd) is not int or fd < 3 or len(payload) > 4_194_304:
        raise BootstrapCliError("invalid authenticated driver channel or payload bound")
    duplicate = os.dup(fd)
    try:
        channel = socket.socket(fileno=duplicate)
    except OSError as exc:
        os.close(duplicate)
        raise BootstrapCliError("bootstrap driver FD must be a Unix stream socket") from exc
    try:
        if channel.family != socket.AF_UNIX or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise BootstrapCliError("bootstrap driver FD must be a Unix stream socket")
        write_all(channel, len(payload).to_bytes(8, "big") + payload, limit)
        size = int.from_bytes(read_exact(channel, 8, limit), "big")
        if size < 3 or size > 4_194_304:
            raise BootstrapCliError("bootstrap driver result frame length is invalid")
        raw = read_exact(channel, size, limit)
    except (IpcError, OSError) as exc:
        raise BootstrapCliError("bootstrap channel failed; operation outcome is unknown; reconcile original operation") from exc
    finally:
        shutdown(channel)
        channel.close()
    try:
        value = load_canonical_json(raw)
        BootstrapSchemaRegistry().validate(value)
    except Exception as exc:
        raise BootstrapCliError("bootstrap driver returned noncanonical or invalid data") from exc
    if value["schema"] != "bootstrap-cli-result/v1" or (
        value["invocationDigest"] != invocation["recordDigest"]
        or value["operation"] != invocation["operation"]
    ):
        raise BootstrapCliError("bootstrap driver result does not bind the invocation")
    return value


def _execute(args: argparse.Namespace) -> int:
    invocation = build_invocation(args)
    result = invoke_driver(args.driver_fd, invocation)
    sys.stdout.buffer.write(canonical_bytes(result))
    return {"succeeded": 0, "rejected": 2, "failed": 3}[result["outcome"]]


def handle_bootstrap(args: argparse.Namespace) -> int | None:
    if args.cmd not in COMMANDS:
        return None
    return _execute(args)


def publisher_main(argv: Iterable[str] | None = None) -> int:
    args = _publisher_parser().parse_args(argv)
    args.cmd = "bootstrap-publisher"
    try:
        return _execute(args)
    except BootstrapCliError as exc:
        print(f"bootstrap publisher rejected invocation: {exc}", file=sys.stderr)
        return 2
