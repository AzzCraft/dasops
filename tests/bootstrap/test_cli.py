from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import socket
import threading
from types import SimpleNamespace

import pytest

from dasops.bootstrap.registry import output_profile_digest
from dasops.bootstrap.authority_driver import COMMAND_OPERATIONS
from dasops.__main__ import main as dasops_main
from dasops.bootstrap_cli import (
    ADOPTION_SPECS,
    PUBLISHER_SPECS,
    BootstrapCliError,
    _publisher_parser,
    build_invocation,
    publisher_main,
)
from dasops.protected.canonical import canonical_bytes, load_canonical_json, with_self_digest
from dasops.protected.launcher import ProtectedLaunchError, validate_bootstrap_launch

from .test_authority import digest, signed, verified_chain


EFFECTIVE = "2026-07-16T12:00:00Z"


def write_record(path: Path, value) -> str:
    path.write_bytes(canonical_bytes(value))
    path.chmod(0o600)
    return str(path.resolve())


def authority_args(tmp_path: Path, operation: str):
    _verifier, authority, tool, descriptor_template = verified_chain()
    subject = {
        key: deepcopy(value)
        for key, value in descriptor_template.items()
        if key not in {"recordDigest", "signatureSubjectDigest", "signatures"}
    }
    subject.update(
        {
            "descriptorId": f"descriptor-cli-{operation}",
            "operation": operation,
            "inputManifestDigest": digest("1"),
            "outputManifestDigest": output_profile_digest(operation),
        }
    )
    descriptor = signed(subject, descriptor_template["signatures"])
    records = tmp_path / "authority"
    records.mkdir()
    return [
        "--trust-anchor", write_record(records / "anchor.json", authority.anchor),
        "--root", write_record(records / "root.json", authority.root),
        "--source-decision", write_record(records / "source.json", tool.source_decision),
        "--tool-release", write_record(records / "release.json", tool.release),
        "--operation-descriptor", write_record(records / "operation.json", descriptor),
        "--registry-root", str((tmp_path / "registry").resolve()),
        "--registry-id", "example-bootstrap-registry",
        "--change-id", "example-recovery-program",
        "--task-id", "TASK-026",
        "--owner", "worker-root",
        "--effective-at", EFFECTIVE,
    ]


def register_argv(tmp_path: Path, driver_fd: int):
    return [
        "register-attempt",
        *authority_args(tmp_path, "register_attempt"),
        "--driver-fd", str(driver_fd),
        "--attempt", str((tmp_path / "attempt").resolve()),
        "--canonical-repo", str((tmp_path / "bootstrap-repo").resolve()),
        "--expected-head", digest("2"),
        "--expected-main", "a" * 40,
    ]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    while size:
        value = sock.recv(size)
        assert value
        chunks.append(value)
        size -= len(value)
    return b"".join(chunks)


def driver(server: socket.socket, observed: list[dict]):
    size = int.from_bytes(recv_exact(server, 8), "big")
    invocation = load_canonical_json(recv_exact(server, size))
    observed.append(invocation)
    result = with_self_digest(
        {
            "schema": "bootstrap-cli-result/v1",
            "invocationDigest": invocation["recordDigest"],
            "operation": invocation["operation"],
            "outcome": "succeeded",
            "resultDigest": digest("3"),
            "message": None,
            "completedAt": EFFECTIVE,
        }
    )
    payload = canonical_bytes(result)
    server.sendall(len(payload).to_bytes(8, "big") + payload)


def test_publisher_cli_sends_exact_canonical_invocation_over_authenticated_fd(
    tmp_path: Path, capfd,
) -> None:
    client, server = socket.socketpair()
    observed: list[dict] = []
    thread = threading.Thread(target=driver, args=(server, observed))
    thread.start()
    try:
        assert publisher_main(register_argv(tmp_path, client.fileno())) == 0
    finally:
        client.close()
        server.close()
        thread.join()
    output = load_canonical_json(capfd.readouterr().out.encode())
    assert output["outcome"] == "succeeded"
    assert observed[0]["command"] == "register-attempt"
    assert observed[0]["owner"] == "worker-root"
    assert observed[0]["parameters"] == {
        "attempt": str((tmp_path / "attempt").resolve()),
        "canonicalRepo": str((tmp_path / "bootstrap-repo").resolve()),
        "expectedHead": digest("2"),
        "expectedMain": "a" * 40,
    }
    assert "driver" not in observed[0] and "token" not in canonical_bytes(observed[0]).decode().lower()


def test_dasops_adoption_surface_uses_the_same_authenticated_driver_contract(tmp_path: Path, capfd) -> None:
    (tmp_path / "canonical.git").mkdir()
    client, server = socket.socketpair()
    observed: list[dict] = []
    thread = threading.Thread(target=driver, args=(server, observed))
    thread.start()
    argv = [
        "adopt-bootstrap-claim", "prepare",
        *authority_args(tmp_path, "adopt_prepare"),
        "--driver-fd", str(client.fileno()),
        "--bootstrap-repo", str((tmp_path / "bootstrap-repo").resolve()),
        "--repo-root", str((tmp_path / "canonical.git").resolve()),
        "--worker-repo", str((tmp_path / "worker").resolve()),
        "--waiver", str((tmp_path / "waiver.json").resolve()),
        "--prepared-output", str((tmp_path / "prepared").resolve()),
    ]
    try:
        assert dasops_main(argv) == 0
    finally:
        client.close()
        server.close()
        thread.join()
    output = load_canonical_json(capfd.readouterr().out.encode())
    assert output["outcome"] == "succeeded"
    assert observed[0]["command"] == "adopt-bootstrap-claim.prepare"
    assert observed[0]["operation"] == "adopt_prepare"


def test_cli_command_inventory_matches_closed_bootstrap_operation_set() -> None:
    assert {spec.operation for spec in PUBLISHER_SPECS.values()} == {
        "register_attempt", "cancel_attempt", "recover_receipt", "prepare_candidate",
        "publish_claim", "handoff_claim", "compensate_claim", "abandon_claim",
    }
    assert {spec.operation for spec in ADOPTION_SPECS.values()} == {
        "adopt_prepare", "adopt_publish", "adopt_cancel", "recover_publication",
    }
    flags = {
        parameter.flag
        for spec in [*PUBLISHER_SPECS.values(), *ADOPTION_SPECS.values()]
        for parameter in spec.parameters
    }
    assert not flags.intersection({"--force", "--push", "--token", "--password", "--secret"})
    assert COMMAND_OPERATIONS == {
        spec.command: spec.operation
        for spec in [*PUBLISHER_SPECS.values(), *ADOPTION_SPECS.values()]
    }


def test_cli_requires_explicit_owner_driver_and_exact_descriptor(tmp_path: Path) -> None:
    parser = _publisher_parser()
    argv = register_argv(tmp_path, 9)
    owner_index = argv.index("--owner")
    without_owner = [*argv[:owner_index], *argv[owner_index + 2 :]]
    with pytest.raises(SystemExit):
        parser.parse_args(without_owner)

    args = parser.parse_args(argv)
    args.driver_fd = 2
    with pytest.raises(BootstrapCliError, match="fd 3 or greater"):
        build_invocation(args)

    args = parser.parse_args(argv)
    descriptor_path = Path(args.operation_descriptor)
    descriptor = load_canonical_json(descriptor_path.read_bytes())
    subject = {
        key: deepcopy(value)
        for key, value in descriptor.items()
        if key not in {"recordDigest", "signatureSubjectDigest", "signatures"}
    }
    subject["operation"] = "cancel_attempt"
    subject["outputManifestDigest"] = output_profile_digest("cancel_attempt")
    descriptor_path.write_bytes(canonical_bytes(signed(subject, descriptor["signatures"])))
    with pytest.raises(BootstrapCliError, match="does not match"):
        build_invocation(args)


def test_cli_rejects_noncanonical_or_writable_authority_input(tmp_path: Path) -> None:
    parser = _publisher_parser()
    args = parser.parse_args(register_argv(tmp_path, 9))
    anchor = Path(args.trust_anchor)
    value = load_canonical_json(anchor.read_bytes())
    anchor.write_text(str(value), encoding="utf-8")
    with pytest.raises(BootstrapCliError, match="strict canonical"):
        build_invocation(args)

    anchor.write_bytes(canonical_bytes(value))
    anchor.chmod(0o666)
    with pytest.raises(BootstrapCliError, match="non-writable"):
        build_invocation(args)


def bootstrap_launch_values(tmp_path: Path):
    launcher = tmp_path / "trusted-launcher"
    launcher.write_bytes(b"#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    runtime = artifacts / "dasops-runtime.pyz"
    runtime.write_bytes(b"#!/usr/bin/python3\nprint('runtime')\n")
    runtime.chmod(0o755)
    launcher_hash = hashlib.sha256(launcher.read_bytes()).hexdigest()
    runtime_hash = hashlib.sha256(runtime.read_bytes()).hexdigest()
    verified = SimpleNamespace(
        authority=SimpleNamespace(
            anchor={
                "trustedComponents": {
                    "launcher": {
                        "runtimePath": str(launcher.resolve()),
                        "packageDigest": "sha256:" + launcher_hash,
                    }
                }
            }
        ),
        release={
            "runtime": {
                "path": runtime.name,
                "sha256": runtime_hash,
                "size": runtime.stat().st_size,
            }
        },
    )
    descriptor = {
        "executablePath": str(runtime.resolve()),
        "executableSha256": runtime_hash,
        "argv": [
            "bootstrap-publisher", "register-attempt", "--owner", "worker-root", "--driver-fd", "7",
        ],
        "passFds": [7],
    }
    return verified, artifacts, descriptor, runtime


def test_bootstrap_launcher_binds_anchor_launcher_release_runtime_and_fd(tmp_path: Path) -> None:
    verified, artifacts, descriptor, runtime = bootstrap_launch_values(tmp_path)
    validate_bootstrap_launch(
        descriptor=descriptor,
        verified_tool_release=verified,
        artifact_root=artifacts,
    )

    runtime.write_bytes(b"changed")
    with pytest.raises(ProtectedLaunchError, match="digest mismatch"):
        validate_bootstrap_launch(
            descriptor=descriptor,
            verified_tool_release=verified,
            artifact_root=artifacts,
        )


def test_bootstrap_launcher_rejects_symlinked_release_runtime(tmp_path: Path) -> None:
    verified, artifacts, descriptor, runtime = bootstrap_launch_values(tmp_path)
    real = artifacts / "real-runtime.pyz"
    runtime.rename(real)
    runtime.symlink_to(real.name)
    with pytest.raises(ProtectedLaunchError, match="symlink"):
        validate_bootstrap_launch(
            descriptor=descriptor,
            verified_tool_release=verified,
            artifact_root=artifacts,
        )


@pytest.mark.parametrize(
    "argv",
    [
        ["das-route-runner", "publish", "--owner", "worker-root", "--driver-fd", "7"],
        ["bootstrap-publisher", "register-attempt", "--driver-fd", "7"],
        ["bootstrap-publisher", "register-attempt", "--owner", "worker-root", "--driver-fd", "8"],
        ["bootstrap-publisher", "register-attempt", "--owner", "worker-root", "--driver-fd", "7", "--force"],
    ],
)
def test_bootstrap_launcher_rejects_routing_implicit_owner_fd_drift_and_force(tmp_path: Path, argv) -> None:
    verified, artifacts, descriptor, _runtime = bootstrap_launch_values(tmp_path)
    descriptor["argv"] = argv
    with pytest.raises(ProtectedLaunchError, match="bootstrap command|explicit owner|pass-FD|forbidden"):
        validate_bootstrap_launch(
            descriptor=descriptor,
            verified_tool_release=verified,
            artifact_root=artifacts,
        )
