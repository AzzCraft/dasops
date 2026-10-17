from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path

import pytest

from dasops.bootstrap.root_rotation import (
    RootEpochRotationStore,
    RootRotationCrash,
    RootRotationError,
    successor_v3_activation_slot_digest,
    successor_v3_activation_subject_digest,
    successor_v3_activation_response,
)
from dasops.protected.canonical import canonical_bytes, semantic_digest, with_self_digest


NOW = "2026-07-17T12:00:00Z"
NOW_DT = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def signature(fingerprint: str, identity: str, role: str) -> dict:
    return {
        "keyFingerprint": fingerprint,
        "identity": identity,
        "role": role,
        "algorithm": "ed25519",
        "signatureBase64": "e" * 86 + "==",
        "signedAt": "2026-07-17T11:59:00Z",
    }


def signed_root_subject(subject: dict, signatures: list[dict]) -> dict:
    result = dict(subject)
    result["signatureSubjectDigest"] = semantic_digest(subject)
    result["signatures"] = signatures
    return with_self_digest(result)


def root(epoch: int, previous: str | None, signer_chars: tuple[str, str], profile_char: str) -> dict:
    keys = [
        {"keyId": f"owner-{epoch}", "fingerprint": digest("9"), "roles": ["repository_owner"]},
        {"keyId": f"recovery-{epoch}", "fingerprint": digest("8"), "roles": ["recovery"]},
        {"keyId": f"root-a-{epoch}", "fingerprint": digest(signer_chars[0]), "roles": ["root_signer"]},
        {"keyId": f"root-b-{epoch}", "fingerprint": digest(signer_chars[1]), "roles": ["root_signer"]},
    ]
    subject = {
        "schema": "bootstrap-root/v1",
        "rootId": "BOOTSTRAP-ROOT-001",
        "epoch": epoch,
        "anchorId": "BOOTSTRAP-ANCHOR-001",
        "previousRootDigest": previous,
        "keys": keys,
        "ordinaryThreshold": 2,
        "recoveryThreshold": 1,
        "toolPolicy": {
            "allowedSourceRepos": ["AzzCraft/das-tools.git"],
            "minimumDasopsVersion": "1.1.0rc11",
            "requiredReviewRoles": ["independent_verifier", "repository_owner", "upstream_governance"],
            "requiredOperationRoles": ["independent_verifier", "orchestrator", "repository_owner"],
            "allowedOperations": ["register_attempt"],
        },
        "registryProfileDigest": digest(profile_char),
        "storeProfileDigest": digest("a"),
        "checkpointProfileDigest": digest("b"),
        "legacyTokenProfileDigest": digest("c"),
        "validFrom": "2026-07-17T11:00:00Z",
        "validUntil": "2026-07-17T13:00:00Z",
        "revocationEndpoint": f"https://authority.example/root/{epoch}",
    }
    return signed_root_subject(
        subject,
        [
            signature(digest(signer_chars[0]), f"root-a-{epoch}", "root_signer"),
            signature(digest(signer_chars[1]), f"root-b-{epoch}", "root_signer"),
        ],
    )


def terminal_frontier(current: dict, old_root: dict, *, attempts: list[dict] | None = None) -> dict:
    if attempts is None:
        attempts = [
            {
                "attemptId": "ATTEMPT-001",
                "state": "adopted",
                "entryDigest": digest("1"),
                "headDigest": digest("2"),
                "terminalClosureDigest": digest("3"),
                "tokenState": "disposed",
                "writerState": "fenced",
            },
            {
                "attemptId": "ATTEMPT-002",
                "state": "cancelled_pre_cas",
                "entryDigest": digest("4"),
                "headDigest": digest("5"),
                "terminalClosureDigest": digest("6"),
                "tokenState": "disposed",
                "writerState": "fenced",
            },
        ]
    return with_self_digest(
        {
            "schema": "bootstrap-root-rotation-frontier/v1",
            "registryId": "REGISTRY-001",
            "rootDigest": old_root["recordDigest"],
            "rootEpoch": old_root["epoch"],
            "currentHeadDigest": current["recordDigest"],
            "registrySequence": current["registrySequence"],
            "attempts": attempts,
            "capturedAt": "2026-07-17T11:58:00Z",
        }
    )


class Harness:
    def __init__(
        self,
        tmp_path: Path,
        *,
        verifier=None,
        root_authenticator=None,
        adoption_authenticator=None,
        pop_verifier=None,
    ) -> None:
        self.old_root = root(1, None, ("1", "2"), "d")
        self.new_root = root(2, self.old_root["recordDigest"], ("3", "4"), "e")
        self.frontier: dict | None = None
        self.approval_calls: list = []

        def approve(request):
            self.approval_calls.append(request)
            if verifier is not None:
                return verifier(request)
            return {
                "verifierAuthorityRef": "https://authority.example/rotation-verifier",
                "verifierReceiptDigest": digest({"old_threshold": "a", "new_threshold": "b", "anchor_owner": "c"}[request.acceptance_kind]),
                "verifiedSigners": [
                    {
                        "role": item["role"],
                        "identity": item["identity"],
                        "keyFingerprint": item["keyFingerprint"],
                    }
                    for item in request.signatures
                ],
            }

        def authenticate_root(request):
            if root_authenticator is not None:
                return root_authenticator(request)
            return {
                "anchorDigest": digest("0"),
                "revocationStatus": "good",
                "rootDigest": request.root["recordDigest"],
                "verificationReceiptDigest": semantic_digest(
                    {
                        "purpose": request.purpose,
                        "rootDigest": request.root["recordDigest"],
                    }
                ),
                "verifierAuthorityRef": "https://authority.example/root-authenticator",
                "verifiedAt": request.verified_at,
            }

        def authenticate_adoption(request):
            if adoption_authenticator is not None:
                return adoption_authenticator(request)
            state = request.activation_state
            return {
                "activationGeneration": state["activationGeneration"],
                "adoptionReceiptDigest": state["adoptionReceiptDigest"],
                "rotationHeadDigest": state["rotationHeadDigest"],
                "successorProfileDigest": state["successorProfileDigest"],
                "successorRegistryDigest": state["successorRegistryDigest"],
                "taskLockV3Digest": state["taskLockV3Digest"],
                "tokenHash": state["tokenHash"],
                "verificationReceiptDigest": state[
                    "adoptionClosureVerificationReceiptDigest"
                ],
                "verifierAuthorityRef": state["adoptionClosureVerifierAuthorityRef"],
                "verifiedAt": state["adoptionClosureVerifiedAt"],
            }

        self.store = RootEpochRotationStore(
            tmp_path / "rotation-store",
            registry_id="REGISTRY-001",
            approval_verifier=approve,
            root_authenticator=authenticate_root,
            adoption_closure_authenticator=authenticate_adoption,
            frontier_reader=lambda: deepcopy(self.frontier),
            anchor_owner_fingerprints=[digest("7")],
            nonce_factory=lambda: b"n" * 32,
            pop_verifier=pop_verifier,
        )
        self.genesis = self.store.initialize_current(
            root=self.old_root,
            activated_at="2026-07-17T11:30:00Z",
            registry_sequence=7,
        )
        self.frontier = terminal_frontier(self.genesis, self.old_root)

    @property
    def rotation_args(self) -> dict:
        return {
            "operation_id": "ROTATE-001",
            "idempotency_key": "ROTATE-IDEMPOTENCY-001",
            "expected_current_head_digest": self.genesis["recordDigest"],
            "old_root": self.old_root,
            "new_root": self.new_root,
            "terminal_frontier": deepcopy(self.frontier),
            "old_threshold_signatures": [
                signature(digest("1"), "old-root-a", "root_signer"),
                signature(digest("2"), "old-root-b", "root_signer"),
            ],
            "new_threshold_signatures": [
                signature(digest("3"), "new-root-a", "root_signer"),
                signature(digest("4"), "new-root-b", "root_signer"),
            ],
            "anchor_owner_signatures": [signature(digest("7"), "anchor-owner", "anchor_owner")],
            "effective_at": NOW,
        }

    def rotate(self, **changes):
        args = self.rotation_args
        args.update(changes)
        return self.store.rotate_normal(**args)


def pending_activation(harness: Harness, token: bytes) -> dict:
    current = harness.store.current_head()
    token_hash = semantic_digest({"tokenSha256": hashlib.sha256(token).hexdigest()})
    subject = {
            "schema": "bootstrap-successor-v3-activation-state/v1",
            "activationId": "ACTIVATE-001",
            "registryId": "REGISTRY-001",
            "rootEpoch": current["rootEpoch"],
            "rootDigest": current["rootDigest"],
            "rotationHeadDigest": current["recordDigest"],
            "adoptionReceiptDigest": digest("a"),
            "adoptionClosureVerificationReceiptDigest": digest("e"),
            "adoptionClosureVerifierAuthorityRef": "https://authority.example/adoption-closure",
            "adoptionClosureVerifiedAt": NOW,
            "successorProfileDigest": digest("b"),
            "successorRegistryDigest": digest("c"),
            "taskLockV3Digest": digest("d"),
            "tokenHash": token_hash,
            "activationGeneration": 1,
            "adoptionState": "adopted",
            "successorState": "successor_inactive",
            "activationReceiptDigest": None,
            "updatedAt": NOW,
    }
    subject["activationSlotDigest"] = successor_v3_activation_slot_digest(subject)
    subject["activationSubjectDigest"] = successor_v3_activation_subject_digest(subject)
    return with_self_digest(subject)


def test_root_rotation_and_v3_activation_close_adoption_without_secret_leakage(tmp_path: Path) -> None:
    token = b"s" * 32

    def verify_pop(challenge, response):
        return {
            "matched": response == successor_v3_activation_response(token, challenge),
            "tokenHash": challenge["tokenHash"],
            "verificationReceiptDigest": digest("f"),
        }

    harness = Harness(tmp_path, pop_verifier=verify_pop)
    result = harness.rotate()
    assert result.operation_result["outcome"] == "rotated"
    assert result.transition["oldRootEpoch"] == 1
    assert result.transition["newRootEpoch"] == 2
    assert result.transition["oldHeadDigest"] == harness.genesis["recordDigest"]
    assert result.current_head["previousHeadDigest"] == harness.genesis["recordDigest"]
    assert result.current_head["registrySequence"] == 8
    assert [value["acceptanceKind"] for value in result.authorizations] == [
        "old_threshold",
        "new_threshold",
        "anchor_owner",
    ]
    assert len(harness.approval_calls) == 3

    state = pending_activation(harness, token)
    harness.store.install_pending_activation(state)
    challenge = harness.store.issue_activation_challenge(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        idempotency_key="CHALLENGE-IDEMPOTENCY-001",
        issued_at="2026-07-17T12:01:00Z",
    )
    assert challenge == harness.store.issue_activation_challenge(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        idempotency_key="CHALLENGE-IDEMPOTENCY-001",
        issued_at="2026-07-17T12:01:00Z",
    )
    with pytest.raises(RootRotationError, match="different selected challenge"):
        harness.store.issue_activation_challenge(
            activation_id="ACTIVATE-001",
            challenge_id="CHALLENGE-002",
            idempotency_key="CHALLENGE-IDEMPOTENCY-002",
            issued_at="2026-07-17T12:01:00Z",
        )
    response = successor_v3_activation_response(token, challenge)
    receipt, active = harness.store.complete_activation(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        response=response,
        effective_at="2026-07-17T12:02:00Z",
    )
    assert receipt["outcome"] == "active"
    assert active["successorState"] == "active"
    assert active["activationReceiptDigest"] == receipt["recordDigest"]
    same_receipt, same_state = harness.store.complete_activation(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        response=response,
        effective_at="2026-07-17T12:05:00Z",
    )
    assert same_receipt == receipt
    assert same_state == active
    assert challenge == harness.store.issue_activation_challenge(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        idempotency_key="CHALLENGE-IDEMPOTENCY-001",
        issued_at="2026-07-17T12:01:00Z",
    )

    durable = b"".join(path.read_bytes() for path in (tmp_path / "rotation-store").rglob("*.json"))
    assert token not in durable
    assert base64.urlsafe_b64encode(token).rstrip(b"=") not in durable
    assert response not in durable


@pytest.mark.parametrize(
    "phase",
    [
        "old_authorization",
        "new_authorization",
        "anchor_authorization",
        "transition",
        "head",
        "current",
        "result",
    ],
)
def test_rotation_retry_is_idempotent_after_every_durable_boundary(tmp_path: Path, phase: str) -> None:
    harness = Harness(tmp_path)
    with pytest.raises(RootRotationCrash, match=phase):
        harness.rotate(crash_after=phase)
    result = harness.rotate()
    retried = harness.rotate()
    assert retried == result
    assert harness.store.current_head() == result.current_head
    assert len(harness.approval_calls) == 3
    assert len(list((tmp_path / "rotation-store" / "objects" / "bootstrap-registry-epoch-transition-v1").glob("*.json"))) == 1


def test_rotation_rejects_live_unsorted_or_drifting_authoritative_frontier(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    live = deepcopy(harness.frontier)
    live["attempts"][0]["state"] = "claimed"
    live.pop("recordDigest")
    live = with_self_digest(live)
    with pytest.raises(RootRotationError, match="validation failed"):
        harness.rotate(terminal_frontier=live)

    unsorted = deepcopy(harness.frontier)
    unsorted["attempts"].reverse()
    unsorted.pop("recordDigest")
    unsorted = with_self_digest(unsorted)
    harness.frontier = unsorted
    with pytest.raises(RootRotationError, match="sorted and unique"):
        harness.rotate(terminal_frontier=unsorted)

    expected = terminal_frontier(harness.genesis, harness.old_root)
    harness.frontier = with_self_digest(
        {
            **{key: value for key, value in expected.items() if key != "recordDigest"},
            "capturedAt": "2026-07-17T11:59:00Z",
        }
    )
    with pytest.raises(RootRotationError, match="frontier changed"):
        harness.rotate(terminal_frontier=expected)


def test_rotation_rejects_stale_epoch_threshold_and_verifier_substitution(tmp_path: Path) -> None:
    harness = Harness(tmp_path / "epoch")
    skipped = root(3, harness.old_root["recordDigest"], ("3", "4"), "e")
    with pytest.raises(RootRotationError, match="next normal epoch"):
        harness.rotate(new_root=skipped)

    harness = Harness(tmp_path / "threshold")
    with pytest.raises(RootRotationError, match="threshold or identity separation"):
        harness.rotate(old_threshold_signatures=[signature(digest("1"), "old-root-a", "root_signer")])

    def substituted(request):
        return {
            "verifierAuthorityRef": "https://authority.example/rotation-verifier",
            "verifierReceiptDigest": digest("f"),
            "verifiedSigners": [{"role": "root_signer", "identity": "intruder", "keyFingerprint": digest("1")}],
        }

    harness = Harness(tmp_path / "substitution", verifier=substituted)
    with pytest.raises(RootRotationError, match="unbound"):
        harness.rotate()
    assert harness.store.current_head() == harness.genesis


def test_rotation_replay_and_second_current_epoch_fail_closed(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    completed = harness.rotate()
    changed = harness.rotation_args
    changed["idempotency_key"] = "ROTATE-IDEMPOTENCY-CHANGED"
    with pytest.raises(RootRotationError, match="different bytes"):
        harness.store.rotate_normal(**changed)
    with pytest.raises(RootRotationError, match="stale"):
        harness.store.rotate_normal(**{**harness.rotation_args, "operation_id": "ROTATE-002"})
    assert harness.store.current_head() == completed.current_head


def test_activation_rejects_expiry_bad_pop_replay_and_pre_rotation_state(tmp_path: Path) -> None:
    token = b"t" * 32

    def bad_pop(challenge, response):
        return {
            "matched": False,
            "tokenHash": challenge["tokenHash"],
            "verificationReceiptDigest": digest("f"),
        }

    harness = Harness(tmp_path / "pre", pop_verifier=bad_pop)
    pre_rotation_subject = {
            "schema": "bootstrap-successor-v3-activation-state/v1",
            "activationId": "ACTIVATE-001",
            "registryId": "REGISTRY-001",
            "rootEpoch": 2,
            "rootDigest": harness.new_root["recordDigest"],
            "rotationHeadDigest": digest("1"),
            "adoptionReceiptDigest": digest("a"),
            "adoptionClosureVerificationReceiptDigest": digest("e"),
            "adoptionClosureVerifierAuthorityRef": "https://authority.example/adoption-closure",
            "adoptionClosureVerifiedAt": NOW,
            "successorProfileDigest": digest("b"),
            "successorRegistryDigest": digest("c"),
            "taskLockV3Digest": digest("d"),
            "tokenHash": digest("e"),
            "activationGeneration": 1,
            "adoptionState": "adopted",
            "successorState": "successor_inactive",
            "activationReceiptDigest": None,
            "updatedAt": NOW,
    }
    pre_rotation_subject["activationSlotDigest"] = successor_v3_activation_slot_digest(
        pre_rotation_subject
    )
    pre_rotation_subject["activationSubjectDigest"] = successor_v3_activation_subject_digest(
        pre_rotation_subject
    )
    pre_rotation = with_self_digest(pre_rotation_subject)
    with pytest.raises(RootRotationError, match="post-rotation head"):
        harness.store.install_pending_activation(pre_rotation)

    harness.rotate()
    harness.store.install_pending_activation(pending_activation(harness, token))
    challenge = harness.store.issue_activation_challenge(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        idempotency_key="CHALLENGE-IDEMPOTENCY-001",
        issued_at="2026-07-17T12:01:00Z",
        lifetime_seconds=30,
    )
    response = successor_v3_activation_response(token, challenge)
    with pytest.raises(RootRotationError, match="not currently valid"):
        harness.store.complete_activation(
            activation_id="ACTIVATE-001",
            challenge_id="CHALLENGE-001",
            response=response,
            effective_at="2026-07-17T12:01:30Z",
        )
    with pytest.raises(RootRotationError, match="proof of possession failed"):
        harness.store.complete_activation(
            activation_id="ACTIVATE-001",
            challenge_id="CHALLENGE-001",
            response=response,
            effective_at="2026-07-17T12:01:15Z",
        )


def test_activation_receipt_response_loss_recovers_same_bytes(tmp_path: Path) -> None:
    token = b"u" * 32

    def verify_pop(challenge, response):
        return {
            "matched": response == successor_v3_activation_response(token, challenge),
            "tokenHash": challenge["tokenHash"],
            "verificationReceiptDigest": digest("f"),
        }

    harness = Harness(tmp_path, pop_verifier=verify_pop)
    harness.rotate()
    harness.store.install_pending_activation(pending_activation(harness, token))
    challenge = harness.store.issue_activation_challenge(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        idempotency_key="CHALLENGE-IDEMPOTENCY-001",
        issued_at="2026-07-17T12:01:00Z",
    )
    response = successor_v3_activation_response(token, challenge)
    with pytest.raises(RootRotationCrash, match="activation_receipt"):
        harness.store.complete_activation(
            activation_id="ACTIVATE-001",
            challenge_id="CHALLENGE-001",
            response=response,
            effective_at="2026-07-17T12:02:00Z",
            crash_after="activation_receipt",
        )
    receipt, active = harness.store.complete_activation(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        response=response,
        effective_at="2026-07-17T12:04:00Z",
    )
    assert receipt["activatedAt"] == "2026-07-17T12:02:00Z"
    assert active["activationReceiptDigest"] == receipt["recordDigest"]
    with pytest.raises(RootRotationError, match="different response"):
        harness.store.complete_activation(
            activation_id="ACTIVATE-001",
            challenge_id="CHALLENGE-001",
            response=b"x" * 32,
            effective_at="2026-07-17T12:04:00Z",
        )


def test_current_pointer_requires_canonical_byte_equal_immutable_head(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    current_path = tmp_path / "rotation-store" / "heads" / "current.json"
    current_path.write_bytes(canonical_bytes(harness.genesis).rstrip(b"\n"))
    with pytest.raises(RootRotationError, match="strict canonical JSON"):
        harness.store.current_head()


def test_external_root_authentication_rejects_revocation_and_unrecoverable_threshold(
    tmp_path: Path,
) -> None:
    def revoked(request):
        return {
            "anchorDigest": digest("0"),
            "revocationStatus": "revoked",
            "rootDigest": request.root["recordDigest"],
            "verificationReceiptDigest": digest("f"),
            "verifierAuthorityRef": "https://authority.example/root-authenticator",
            "verifiedAt": request.verified_at,
        }

    with pytest.raises(RootRotationError, match="anchor/signature/revocation"):
        Harness(tmp_path / "revoked", root_authenticator=revoked)

    harness = Harness(tmp_path / "threshold")
    subject = {
        key: deepcopy(value)
        for key, value in harness.new_root.items()
        if key not in {"recordDigest", "signatureSubjectDigest", "signatures"}
    }
    subject["recoveryThreshold"] = 2
    unrecoverable = signed_root_subject(subject, deepcopy(harness.new_root["signatures"]))
    with pytest.raises(RootRotationError, match="recovery threshold"):
        harness.rotate(new_root=unrecoverable)


def test_adoption_closure_requires_external_exact_authentication(tmp_path: Path) -> None:
    def substituted(request):
        state = request.activation_state
        return {
            "activationGeneration": state["activationGeneration"],
            "adoptionReceiptDigest": digest("f"),
            "rotationHeadDigest": state["rotationHeadDigest"],
            "successorProfileDigest": state["successorProfileDigest"],
            "successorRegistryDigest": state["successorRegistryDigest"],
            "taskLockV3Digest": state["taskLockV3Digest"],
            "tokenHash": state["tokenHash"],
            "verificationReceiptDigest": state[
                "adoptionClosureVerificationReceiptDigest"
            ],
            "verifierAuthorityRef": state["adoptionClosureVerifierAuthorityRef"],
            "verifiedAt": state["adoptionClosureVerifiedAt"],
        }

    harness = Harness(tmp_path, adoption_authenticator=substituted)
    harness.rotate()
    with pytest.raises(RootRotationError, match="subject mismatch"):
        harness.store.install_pending_activation(pending_activation(harness, b"a" * 32))


def test_activation_subject_slot_is_globally_unique(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.rotate()
    first = pending_activation(harness, b"b" * 32)
    harness.store.install_pending_activation(first)
    second_subject = {
        key: deepcopy(value) for key, value in first.items() if key != "recordDigest"
    }
    second_subject["activationId"] = "ACTIVATE-002"
    second = with_self_digest(second_subject)
    with pytest.raises(RootRotationError, match="immutable rotation record drift"):
        harness.store.install_pending_activation(second)


def test_pending_activation_fences_a_later_root_rotation(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.rotate()
    harness.store.install_pending_activation(pending_activation(harness, b"c" * 32))
    with pytest.raises(RootRotationError, match="pending successor activation"):
        harness.rotate(operation_id="ROTATE-002")


def test_activation_subject_reservation_crash_fences_rotation_and_repairs(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path)
    harness.rotate()
    state = pending_activation(harness, b"h" * 32)
    with pytest.raises(RootRotationCrash, match="activation_subject_reserved"):
        harness.store.install_pending_activation(
            state, crash_after="activation_subject_reserved"
        )
    with pytest.raises(RootRotationError, match="in-flight successor activation"):
        harness.rotate(operation_id="ROTATE-002")
    assert harness.store.install_pending_activation(state) == state


@pytest.mark.parametrize("phase", ["challenge_record", "challenge_selected"])
def test_challenge_two_file_publication_recovers_every_response_loss(
    tmp_path: Path, phase: str
) -> None:
    harness = Harness(tmp_path)
    harness.rotate()
    harness.store.install_pending_activation(pending_activation(harness, b"d" * 32))
    arguments = {
        "activation_id": "ACTIVATE-001",
        "challenge_id": "CHALLENGE-001",
        "idempotency_key": "CHALLENGE-IDEMPOTENCY-001",
        "issued_at": "2026-07-17T12:01:00Z",
    }
    with pytest.raises(RootRotationCrash, match=phase):
        harness.store.issue_activation_challenge(**arguments, crash_after=phase)
    challenge = harness.store.issue_activation_challenge(**arguments)
    selected = harness.store._read(
        harness.store.root / "activations" / "ACTIVATE-001" / "challenge.json"
    )
    assert selected == challenge


def test_pop_response_binds_exact_challenge_digest_and_lifecycle(tmp_path: Path) -> None:
    token = b"e" * 32
    harness = Harness(tmp_path)
    harness.rotate()
    harness.store.install_pending_activation(pending_activation(harness, token))
    challenge = harness.store.issue_activation_challenge(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        idempotency_key="CHALLENGE-IDEMPOTENCY-001",
        issued_at="2026-07-17T12:01:00Z",
    )
    original = successor_v3_activation_response(token, challenge)
    changed_subject = {
        key: deepcopy(value) for key, value in challenge.items() if key != "recordDigest"
    }
    changed_subject["expiresAt"] = "2026-07-17T12:20:00Z"
    changed = with_self_digest(changed_subject)
    assert successor_v3_activation_response(token, changed) != original


def test_existing_activation_receipt_retry_rechecks_current_head(
    tmp_path: Path, monkeypatch
) -> None:
    token = b"f" * 32

    def verify_pop(challenge, response):
        return {
            "matched": response == successor_v3_activation_response(token, challenge),
            "tokenHash": challenge["tokenHash"],
            "verificationReceiptDigest": digest("f"),
        }

    harness = Harness(tmp_path, pop_verifier=verify_pop)
    harness.rotate()
    harness.store.install_pending_activation(pending_activation(harness, token))
    challenge = harness.store.issue_activation_challenge(
        activation_id="ACTIVATE-001",
        challenge_id="CHALLENGE-001",
        idempotency_key="CHALLENGE-IDEMPOTENCY-001",
        issued_at="2026-07-17T12:01:00Z",
    )
    response = successor_v3_activation_response(token, challenge)
    with pytest.raises(RootRotationCrash, match="activation_receipt"):
        harness.store.complete_activation(
            activation_id="ACTIVATE-001",
            challenge_id="CHALLENGE-001",
            response=response,
            effective_at="2026-07-17T12:02:00Z",
            crash_after="activation_receipt",
        )
    stale = deepcopy(harness.store.current_head())
    stale["recordDigest"] = digest("0")
    monkeypatch.setattr(harness.store, "current_head", lambda: stale)
    with pytest.raises(RootRotationError, match="current root/head changed"):
        harness.store.complete_activation(
            activation_id="ACTIVATE-001",
            challenge_id="CHALLENGE-001",
            response=response,
            effective_at="2026-07-17T12:03:00Z",
        )


@pytest.mark.parametrize(
    ("successor_state", "receipt_digest"),
    [("successor_inactive", digest("f")), ("active", None)],
)
def test_activation_state_schema_rejects_impossible_state_receipt_union(
    tmp_path: Path, successor_state: str, receipt_digest: str | None
) -> None:
    harness = Harness(tmp_path)
    harness.rotate()
    valid = pending_activation(harness, b"g" * 32)
    subject = {key: deepcopy(value) for key, value in valid.items() if key != "recordDigest"}
    subject["successorState"] = successor_state
    subject["activationReceiptDigest"] = receipt_digest
    impossible = with_self_digest(subject)
    with pytest.raises(RootRotationError, match="validation failed"):
        harness.store._validate(
            impossible, "bootstrap-successor-v3-activation-state/v1"
        )
