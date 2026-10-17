from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import os
from pathlib import Path
import subprocess

import pytest

from dasops.bootstrap.authority_driver import BootstrapAuthorityDriver, VerifiedDriverInvocation
from dasops.bootstrap.operation_handlers import (
    BootstrapOperationHandlerError,
    UpstreamBootstrapOperationHandlers,
)
from dasops.bootstrap.registry import BootstrapAttemptRegistry
from dasops.protected.canonical import canonical_bytes, load_canonical_json, with_self_digest

from .test_authority import digest, make_verifier, verified_chain
from .test_registry import (
    EFFECTIVE,
    attempt_records,
    cancel_authorization,
    recovery_records,
    verified_operation,
)


def git(*args: str, cwd: Path | None = None) -> str:
    process = subprocess.run(
        ["/usr/bin/git", *args],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
        env={
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
    )
    return process.stdout.strip()


def registration_context(tmp_path: Path):
    verifier, _authority, tool, descriptor = verified_chain()
    repository = (tmp_path / "bootstrap-repo").resolve()
    repository.mkdir()
    git("init", "-b", "main", cwd=repository)
    (repository / "README.md").write_text("bootstrap\n", encoding="utf-8")
    git("add", "README.md", cwd=repository)
    git("commit", "-m", "base", cwd=repository)
    base = git("rev-parse", "HEAD", cwd=repository)

    intent, waiver = attempt_records(tool, base_commit=base)
    operation = verified_operation(verifier, tool, descriptor, "register_attempt", [intent, waiver])
    attempt = (tmp_path / "attempt").resolve()
    attempt.mkdir(mode=0o700)
    attempt.chmod(0o700)
    for name, value in (("intent.json", intent), ("waiver.json", waiver)):
        path = attempt / name
        path.write_bytes(canonical_bytes(value))
        path.chmod(0o600)
    registry_root = (tmp_path / "registry").resolve()
    absent = digest("0")
    invocation = with_self_digest(
        {
            "schema": "bootstrap-cli-invocation/v1",
            "invocationId": "cli-register-handler-001",
            "command": "register-attempt",
            "operation": "register_attempt",
            "changeId": intent["changeId"],
            "taskId": intent["taskId"],
            "owner": intent["worker"],
            "registryRoot": str(registry_root),
            "registryId": "example-bootstrap-registry",
            "authority": {
                "trustAnchor": str((tmp_path / "anchor.json").resolve()),
                "root": str((tmp_path / "root.json").resolve()),
                "sourceDecision": str((tmp_path / "source.json").resolve()),
                "toolRelease": str((tmp_path / "release.json").resolve()),
                "operationDescriptor": str((tmp_path / "descriptor.json").resolve()),
            },
            "parameters": {
                "attempt": str(attempt),
                "canonicalRepo": str(repository),
                "expectedHead": absent,
                "expectedMain": base,
            },
            "effectiveAt": EFFECTIVE,
            "requestedAt": EFFECTIVE,
        }
    )
    context = VerifiedDriverInvocation(invocation=invocation, operation=operation)
    return context, UpstreamBootstrapOperationHandlers(absent_registry_head_digest=absent)


def cancellation_context(tmp_path: Path):
    registration, handlers = registration_context(tmp_path)
    handlers.register_attempt(registration)
    registry = BootstrapAttemptRegistry(
        registration.invocation["registryRoot"],
        registry_id=registration.invocation["registryId"],
    )
    authority = registration.operation.tool_release.authority
    tool = registration.operation.tool_release
    authorization = cancel_authorization(tool, registry.current())
    authorization_path = (tmp_path / "cancel-authorization.json").resolve()
    authorization_path.write_bytes(canonical_bytes(authorization))
    authorization_path.chmod(0o600)
    verifier = make_verifier(authority.anchor, authority.root)
    operation = verified_operation(
        verifier,
        tool,
        registration.operation.descriptor,
        "cancel_attempt",
        [authorization],
    )
    invocation = deepcopy(registration.invocation)
    invocation.pop("recordDigest")
    invocation.update(
        {
            "invocationId": "cli-cancel-handler-001",
            "command": "cancel-attempt",
            "operation": "cancel_attempt",
            "parameters": {
                "attempt": registration.invocation["parameters"]["attempt"],
                "authorization": str(authorization_path),
                "canonicalRepo": registration.invocation["parameters"]["canonicalRepo"],
                "expectedRegistryHead": registry.current()["headDigest"],
            },
        }
    )
    return (
        VerifiedDriverInvocation(invocation=with_self_digest(invocation), operation=operation),
        handlers,
    )


def receipt_recovery_context(tmp_path: Path):
    registration, handlers = registration_context(tmp_path)
    handlers.register_attempt(registration)
    registry = BootstrapAttemptRegistry(
        registration.invocation["registryRoot"],
        registry_id=registration.invocation["registryId"],
    )
    verifier = make_verifier(
        registration.operation.tool_release.authority.anchor,
        registration.operation.tool_release.authority.root,
    )
    authorization, search = recovery_records(
        registration.operation.tool_release,
        registry.current(),
        operation_id="recover-handler-001",
        classification="zero_accepted",
    )
    operation = verified_operation(
        verifier,
        registration.operation.tool_release,
        registration.operation.descriptor,
        "recover_receipt",
        [authorization, search],
    )
    authorization_path = (tmp_path / "recovery-authorization.json").resolve()
    search_path = (tmp_path / "recovery-search.json").resolve()
    for path, value in ((authorization_path, authorization), (search_path, search)):
        path.write_bytes(canonical_bytes(value))
        path.chmod(0o600)
    invocation = deepcopy(registration.invocation)
    invocation.pop("recordDigest")
    invocation.update(
        {
            "invocationId": "cli-recover-receipt-handler-001",
            "command": "recover-receipt",
            "operation": "recover_receipt",
            "parameters": {
                "attempt": registration.invocation["parameters"]["attempt"],
                "expectedRegistryHead": registry.current()["headDigest"],
                "recoveryAuthorization": str(authorization_path),
                "recoverySearch": str(search_path),
            },
        }
    )
    return (
        VerifiedDriverInvocation(invocation=with_self_digest(invocation), operation=operation),
        handlers,
    )


def test_registration_handler_publishes_real_registry_checkpoint_without_git_mutation(
    tmp_path: Path,
) -> None:
    context, handlers = registration_context(tmp_path)
    before = git("rev-parse", "HEAD", cwd=Path(context.invocation["parameters"]["canonicalRepo"]))
    authority = context.operation.tool_release.authority
    records = {
        "trustAnchor": authority.anchor,
        "root": authority.root,
        "sourceDecision": context.operation.tool_release.source_decision,
        "toolRelease": context.operation.tool_release.release,
        "operationDescriptor": context.operation.descriptor,
    }
    for name, value in records.items():
        path = Path(context.invocation["authority"][name])
        path.write_bytes(canonical_bytes(value))
        path.chmod(0o600)
    driver = BootstrapAuthorityDriver(
        authority_verifier=make_verifier(authority.anchor, authority.root),
        handlers=handlers.handlers,
        allowed_peer_uids={os.getuid()},
        peer_actors={os.getuid(): context.invocation["owner"]},
        trusted_clock=lambda: datetime.fromisoformat(context.invocation["effectiveAt"].replace("Z", "+00:00")),
        allowed_registry_roots={context.invocation["registryRoot"]},
        allowed_subjects={
            (
                context.invocation["changeId"],
                context.invocation["taskId"],
                context.invocation["owner"],
                context.invocation["registryId"],
            )
        },
    )
    first = driver.dispatch(context.invocation)
    second = driver.dispatch(context.invocation)
    assert first == second
    assert first["outcome"] == "succeeded"
    registry = BootstrapAttemptRegistry(
        context.invocation["registryRoot"], registry_id=context.invocation["registryId"]
    )
    assert registry.current()["state"] == "registered"
    assert registry.object(first["resultDigest"])["outcome"] == "registered"
    assert git("rev-parse", "HEAD", cwd=Path(context.invocation["parameters"]["canonicalRepo"])) == before


@pytest.mark.parametrize(
    "defect", ["extra-member", "hardlink", "mode", "expected-head", "expected-main", "worker"]
)
def test_registration_handler_rejects_package_head_repository_and_subject_drift(
    tmp_path: Path, defect: str
) -> None:
    context, handlers = registration_context(tmp_path)
    invocation = deepcopy(context.invocation)
    invocation.pop("recordDigest")
    if defect == "extra-member":
        extra = Path(invocation["parameters"]["attempt"]) / "unexpected.json"
        extra.write_text("{}", encoding="utf-8")
        extra.chmod(0o600)
    elif defect == "hardlink":
        attempt = Path(invocation["parameters"]["attempt"])
        (attempt / "waiver.json").unlink()
        os.link(attempt / "intent.json", attempt / "waiver.json")
    elif defect == "mode":
        (Path(invocation["parameters"]["attempt"]) / "intent.json").chmod(0o640)
    elif defect == "expected-head":
        invocation["parameters"]["expectedHead"] = digest("9")
    elif defect == "expected-main":
        invocation["parameters"]["expectedMain"] = "f" * 40
    else:
        invocation["owner"] = "substituted-worker"
    drifted = VerifiedDriverInvocation(
        invocation=with_self_digest(invocation), operation=context.operation
    )
    with pytest.raises(BootstrapOperationHandlerError):
        handlers.register_attempt(drifted)


def test_registration_handler_requires_externally_pinned_absent_head() -> None:
    with pytest.raises(BootstrapOperationHandlerError, match="externally pinned"):
        UpstreamBootstrapOperationHandlers(absent_registry_head_digest="absent")


def test_registered_only_cancellation_is_retry_safe_and_does_not_mutate_git(tmp_path: Path) -> None:
    context, handlers = cancellation_context(tmp_path)
    repository = Path(context.invocation["parameters"]["canonicalRepo"])
    before = git("rev-parse", "HEAD", cwd=repository)
    first = handlers.handlers["cancel_attempt"](context)
    second = handlers.cancel_registered_attempt(context)
    assert first == second
    assert first["outcome"] == "cancelled_pre_cas"
    registry = BootstrapAttemptRegistry(
        context.invocation["registryRoot"], registry_id=context.invocation["registryId"]
    )
    assert registry.current()["state"] == "cancelled_pre_cas"
    assert git("rev-parse", "HEAD", cwd=repository) == before


def test_receipt_recovery_handler_closes_only_the_selected_slot_and_is_retry_safe(
    tmp_path: Path,
) -> None:
    context, handlers = receipt_recovery_context(tmp_path)
    registry = BootstrapAttemptRegistry(
        context.invocation["registryRoot"], registry_id=context.invocation["registryId"]
    )
    current = registry.current()
    assert current is not None
    before = deepcopy(current)
    first = handlers.handlers["recover_receipt"](context)
    second = handlers.recover_receipt(context)
    assert first == second
    assert first["outcome"] == "recovered_alternate"
    assert registry.current() == before
    slot = registry.receipt_slot(before["headDigest"])
    assert slot["status"] == "closed"
    assert slot["generation"] == 1
    assert slot["closureVariant"] == "recovered_alternate"

    tool = context.operation.tool_release
    verifier = make_verifier(tool.authority.anchor, tool.authority.root)
    cancellation = cancel_authorization(
        tool, registry.current(), operation_id="cancel-after-recovery-handler-001"
    )
    cancellation_operation = verified_operation(
        verifier,
        tool,
        context.operation.descriptor,
        "cancel_attempt",
        [cancellation],
    )
    registry.cancel_attempt(
        authorization=cancellation,
        operation=cancellation_operation,
        effective_at=EFFECTIVE,
    )
    assert registry.current()["state"] == "cancelled_pre_cas"
    assert handlers.recover_receipt(context) == first


@pytest.mark.parametrize("defect", ["expected-head", "owner", "authorization-hardlink"])
def test_receipt_recovery_handler_rejects_head_subject_and_record_drift(
    tmp_path: Path, defect: str
) -> None:
    context, handlers = receipt_recovery_context(tmp_path)
    invocation = deepcopy(context.invocation)
    invocation.pop("recordDigest")
    if defect == "expected-head":
        invocation["parameters"]["expectedRegistryHead"] = digest("8")
    elif defect == "owner":
        invocation["owner"] = "substituted-worker"
    else:
        authorization = Path(invocation["parameters"]["recoveryAuthorization"])
        os.link(authorization, authorization.with_name("linked-recovery-authorization.json"))
    drifted = VerifiedDriverInvocation(
        invocation=with_self_digest(invocation), operation=context.operation
    )
    with pytest.raises(BootstrapOperationHandlerError):
        handlers.recover_receipt(drifted)


@pytest.mark.parametrize(
    "defect",
    ["expected-head", "git-main", "legacy-state", "owner", "candidate-state", "hardlink"],
)
def test_registered_only_cancellation_rejects_state_repository_and_record_drift(
    tmp_path: Path, defect: str
) -> None:
    context, handlers = cancellation_context(tmp_path)
    invocation = deepcopy(context.invocation)
    invocation.pop("recordDigest")
    if defect == "expected-head":
        invocation["parameters"]["expectedRegistryHead"] = digest("8")
    elif defect == "git-main":
        repository = Path(invocation["parameters"]["canonicalRepo"])
        (repository / "README.md").write_text("advanced\n", encoding="utf-8")
        git("add", "README.md", cwd=repository)
        git("commit", "-m", "advance", cwd=repository)
    elif defect == "legacy-state":
        legacy = Path(invocation["registryRoot"]) / "legacy-claim"
        legacy.mkdir(mode=0o700)
    elif defect == "owner":
        invocation["owner"] = "substituted-worker"
    elif defect == "candidate-state":
        path = Path(invocation["parameters"]["authorization"])
        authorization = deepcopy(load_canonical_json(path.read_bytes()))
        authorization.pop("recordDigest")
        authorization["expectedState"] = "candidate_prepared"
        authorization["tokenDisposition"] = "destroyed"
        path.write_bytes(canonical_bytes(with_self_digest(authorization)))
        path.chmod(0o600)
    else:
        path = Path(invocation["parameters"]["authorization"])
        linked = path.with_name("linked-authorization.json")
        os.link(path, linked)
    drifted = VerifiedDriverInvocation(
        invocation=with_self_digest(invocation), operation=context.operation
    )
    with pytest.raises(BootstrapOperationHandlerError):
        handlers.cancel_registered_attempt(drifted)
