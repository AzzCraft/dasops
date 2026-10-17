from __future__ import annotations

from pathlib import Path
from datetime import datetime
import os
import socket
import threading

import pytest

from dasops.bootstrap.authority_driver import (
    COMMAND_OPERATIONS,
    BootstrapAuthorityDriver,
    BootstrapAuthorityDriverError,
)
from dasops.bootstrap_cli import _publisher_parser, build_invocation, invoke_driver
from dasops.protected.canonical import load_canonical_json, with_self_digest

from .test_authority import make_verifier
from .test_cli import register_argv


def driver_values(tmp_path: Path, *, handler=None, operation="register_attempt", subject=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    args = _publisher_parser().parse_args(register_argv(tmp_path, 9))
    invocation = build_invocation(args)
    anchor = load_canonical_json(Path(args.trust_anchor).read_bytes())
    root = load_canonical_json(Path(args.root).read_bytes())
    observed = []

    def successful(context):
        observed.append(context)
        return context.operation.descriptor

    selected = successful if handler is None else handler
    authority_driver = BootstrapAuthorityDriver(
        authority_verifier=make_verifier(anchor, root),
        handlers={operation: selected},
        allowed_peer_uids={os.getuid()},
        peer_actors={os.getuid(): invocation["owner"]},
        trusted_clock=lambda: datetime.fromisoformat(invocation["effectiveAt"].replace("Z", "+00:00")),
        allowed_registry_roots={invocation["registryRoot"]},
        allowed_subjects=subject or {
            (
                invocation["changeId"],
                invocation["taskId"],
                invocation["owner"],
                invocation["registryId"],
            )
        },
    )
    return invocation, authority_driver, observed


def exchange(authority_driver: BootstrapAuthorityDriver, invocation: dict):
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    returned = []
    failures = []

    def run():
        try:
            returned.append(authority_driver.serve_once(server.fileno()))
        except Exception as exc:  # pragma: no cover - asserted by caller
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        result = invoke_driver(client.fileno(), invocation)
    finally:
        client.close()
        server.close()
        thread.join()
    assert failures == []
    assert returned == [result]
    return result


def test_authenticated_driver_verifies_authority_and_dispatches_exact_handler(tmp_path: Path) -> None:
    invocation, authority_driver, observed = driver_values(tmp_path)
    result = exchange(authority_driver, invocation)
    assert result["outcome"] == "succeeded"
    assert result["resultDigest"] == observed[0].operation.descriptor["recordDigest"]
    assert observed[0].invocation == invocation
    assert observed[0].operation.descriptor_verification["purpose"] == "bootstrap_operation_descriptor"


def test_driver_rejects_missing_handler_subject_and_authority_drift(tmp_path: Path) -> None:
    invocation, missing_handler, _observed = driver_values(
        tmp_path / "missing-handler",
        operation="cancel_attempt",
    )
    assert exchange(missing_handler, invocation)["outcome"] == "rejected"

    invocation, subject_driver, _observed = driver_values(
        tmp_path / "wrong-subject",
        subject={("wrong", "TASK-026", "worker-root", "example-bootstrap-registry")},
    )
    assert exchange(subject_driver, invocation)["outcome"] == "rejected"

    invocation, authority_driver, _observed = driver_values(tmp_path / "authority-drift")
    root_path = Path(invocation["authority"]["root"])
    root_path.chmod(0o666)
    assert exchange(authority_driver, invocation)["outcome"] == "rejected"

    invocation, time_driver, _observed = driver_values(tmp_path / "time-drift")
    drift = dict(invocation)
    drift.pop("recordDigest")
    drift["requestedAt"] = "2026-07-16T11:59:59Z"
    assert exchange(time_driver, with_self_digest(drift))["outcome"] == "rejected"


def test_driver_contains_handler_failure_without_leaking_exception(tmp_path: Path) -> None:
    def failing(_context):
        raise RuntimeError("credential=do-not-leak")

    invocation, authority_driver, _observed = driver_values(tmp_path, handler=failing)
    result = exchange(authority_driver, invocation)
    assert result["outcome"] == "failed"
    assert result["resultDigest"] is None
    assert "credential" not in result["message"]


def test_driver_requires_authenticated_unix_stream_peer(tmp_path: Path) -> None:
    _invocation, authority_driver, _observed = driver_values(tmp_path)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BootstrapAuthorityDriverError, match="not a socket"):
            authority_driver.serve_once(read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_driver_command_operation_inventory_matches_cli() -> None:
    assert COMMAND_OPERATIONS == {
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


def test_self_reported_owner_cannot_override_the_installed_unix_peer_actor(tmp_path):
    invocation, authority_driver, observed = driver_values(tmp_path)
    authority_driver.allowed_subjects = frozenset({
        (invocation['changeId'], invocation['taskId'], 'other-admin', invocation['registryId'])
    })
    changed = dict(invocation)
    changed.pop('recordDigest')
    changed['owner'] = 'other-admin'
    assert exchange(authority_driver, with_self_digest(changed))['outcome'] == 'rejected'
    assert observed == []


@pytest.mark.parametrize('offset', [-31, 31, 86400 * 180])
def test_client_clock_cannot_extend_current_signed_authority(tmp_path, offset):
    from datetime import timedelta
    invocation, authority_driver, observed = driver_values(tmp_path)
    original = datetime.fromisoformat(invocation['effectiveAt'].replace('Z', '+00:00'))
    authority_driver.trusted_clock = lambda: original + timedelta(seconds=offset)
    assert exchange(authority_driver, invocation)['outcome'] == 'rejected'
    assert observed == []


def test_actual_checked_time_is_forwarded_to_the_real_handler(tmp_path):
    from datetime import timedelta
    invocation, authority_driver, observed = driver_values(tmp_path)
    actual = datetime.fromisoformat(invocation['effectiveAt'].replace('Z', '+00:00')) + timedelta(seconds=1)
    authority_driver.trusted_clock = lambda: actual
    anchor = load_canonical_json(Path(invocation['authority']['trustAnchor']).read_bytes())
    root = load_canonical_json(Path(invocation['authority']['root']).read_bytes())
    authority_driver.authority_verifier = make_verifier(anchor, root, expected_now=actual)
    result = exchange(authority_driver, invocation)
    assert result['outcome'] == 'succeeded'
    assert observed[0].verified_at == actual
    assert observed[0].effective_at == actual.isoformat().replace('+00:00', 'Z')
    assert result['completedAt'] == observed[0].effective_at
    assert observed[0].invocation == invocation


def test_trusted_clock_rollback_cannot_reenable_an_old_request(tmp_path):
    from datetime import timedelta
    invocation, authority_driver, observed = driver_values(tmp_path)
    actual = datetime.fromisoformat(invocation['effectiveAt'].replace('Z', '+00:00'))
    assert exchange(authority_driver, invocation)['outcome'] == 'succeeded'
    authority_driver.trusted_clock = lambda: actual - timedelta(seconds=1)
    assert exchange(authority_driver, invocation)['outcome'] == 'rejected'
    assert len(observed) == 1
