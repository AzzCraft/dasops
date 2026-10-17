from __future__ import annotations

from pathlib import Path

import pytest

from dasops.protected import SchemaRegistry, SchemaValidationError, with_self_digest


EXPECTED_SCHEMA_IDS = (
    "protected-activation-challenge/v1",
    "protected-activation-receipt/v1",
    "protected-challenge-consumption/v1",
    "protected-claim-result/v1",
    "protected-completion-approval/v1",
    "protected-completion-decision-intent/v1",
    "protected-completion-request/v1",
    "protected-completion-result/v1",
    "protected-completion-verification/v1",
    "protected-launch-descriptor/v1",
    "protected-launch-receipt/v1",
    "protected-lifecycle-wal/v1",
    "protected-materialization-receipt/v1",
    "protected-materialization-request/v1",
    "protected-operation-wal/v1",
    "protected-reclaim-authorization/v1",
    "protected-reclaim-result/v1",
    "protected-release-result/v1",
    "protected-renewal-result/v1",
    "protected-route-approval/v1",
    "protected-route-decision-intent/v1",
    "protected-route-prepare-intent/v1",
    "protected-route-request/v1",
    "protected-route-result/v1",
    "protected-task-policy/v1",
    "protected-task-state/v1",
    "protected-worker-lock/v1",
)


def valid_policy() -> dict:
    return {
        "schema": "protected-task-policy/v1",
        "policyId": "POLICY-PROTECTED-001",
        "canonicalRepoPath": "/srv/git/customer-service.git",
        "canonicalRef": "refs/heads/main",
        "allowedOperations": ["activate", "claim", "renew"],
        "leaseSecondsMin": 60,
        "leaseSecondsMax": 3600,
        "toolDigests": {"dasops": "sha256:" + "a" * 64},
    }


def test_registry_is_complete_unique_and_schema_valid() -> None:
    registry = SchemaRegistry()
    assert registry.schema_ids == EXPECTED_SCHEMA_IDS
    inventory = registry.inventory()
    assert [row["schemaId"] for row in inventory] == list(EXPECTED_SCHEMA_IDS)
    assert len({row["rawSha256"] for row in inventory}) == len(inventory)
    assert all(len(row["canonicalSha256"]) == 64 for row in inventory)


def test_policy_accepts_valid_value_and_rejects_unknown_field() -> None:
    registry = SchemaRegistry()
    policy = valid_policy()
    registry.validate(policy)
    policy["ambientCommand"] = "claim-ready"
    with pytest.raises(SchemaValidationError, match="Additional properties"):
        registry.validate(policy)


def test_unknown_schema_and_mismatched_discriminator_fail() -> None:
    registry = SchemaRegistry()
    with pytest.raises(SchemaValidationError, match="unknown"):
        registry.validate({"schema": "attacker/v1"})
    with pytest.raises(SchemaValidationError, match="validation failed"):
        registry.validate(valid_policy(), schema_id="protected-task-state/v1")


def test_task_state_requires_valid_non_circular_digest() -> None:
    registry = SchemaRegistry()
    state = with_self_digest(
        {
            "schema": "protected-task-state/v1",
            "operationId": "claim-0001",
            "changeId": "recover-customer-service",
            "taskId": "TASK-026",
            "owner": "worker-01",
            "status": "claimed_pending_activation",
            "tokenHash": "sha256:" + "b" * 64,
            "claimGeneration": 1,
            "leaseGeneration": 1,
            "leaseExpiresAt": "2026-07-16T11:00:00Z",
            "canonicalCommit": "c" * 40,
            "updatedAt": "2026-07-16T10:00:00Z",
            "workerLockPath": "/tmp/TASK-026.lock",
        }
    )
    registry.validate(state)
    state["owner"] = "attacker"
    with pytest.raises(SchemaValidationError, match="self-digest"):
        registry.validate(state)


def test_invalid_timestamp_is_rejected_by_format_checker() -> None:
    registry = SchemaRegistry()
    state = with_self_digest(
        {
            "schema": "protected-task-state/v1",
            "operationId": "claim-0002",
            "changeId": "recover-customer-service",
            "taskId": "TASK-026",
            "owner": "worker-01",
            "status": "claimed_pending_activation",
            "tokenHash": "sha256:" + "b" * 64,
            "claimGeneration": 1,
            "leaseGeneration": 1,
            "leaseExpiresAt": "2026-07-16T11:00:00Z",
            "canonicalCommit": "c" * 40,
            "updatedAt": "not-a-time",
            "workerLockPath": "/tmp/TASK-026.lock",
        }
    )
    with pytest.raises(SchemaValidationError, match="date-time"):
        registry.validate(state)


def test_route_request_rejects_owner_assignment() -> None:
    registry = SchemaRegistry()
    request = with_self_digest(
        {
            "schema": "protected-route-request/v1",
            "requestId": "route-001",
            "changeId": "recovery",
            "baseCommit": "d" * 40,
            "sourceResults": [
                {"taskId": "TASK-026", "resultDigest": "sha256:" + "e" * 64}
            ],
            "targetTransitions": [
                {
                    "taskId": "T-025",
                    "fromStatus": "BLOCKED",
                    "toStatus": "TODO",
                    "owner": "worker-02",
                }
            ],
        }
    )
    with pytest.raises(SchemaValidationError, match="'-'"):
        registry.validate(request)
