from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import stat

import pytest

from dasops.bootstrap.adoption_recovery import (
    AdoptionPublicationRecoveryStore,
    AdoptionRecoveryCrash,
    AdoptionRecoveryError,
    RecoveryRootPolicy,
    _signature_subject,
    _verification_request_digest,
)
from dasops.protected.canonical import canonical_bytes, semantic_digest, with_self_digest

from .test_authority import digest, signature


EFFECTIVE = "2026-07-17T12:00:00Z"
EXPECTED_OLD = "a" * 40
CANDIDATE = "b" * 40
RECOVERY_ROLES = (
    "new_repository_owner",
    "old_repository_owner",
    "root_recovery",
    "security_recovery_owner",
)
ROOT_POLICY = RecoveryRootPolicy(
    root_digest=digest("8"),
    root_epoch=7,
    verifier_authority_ref="https://authority.example/recovery/epoch-7",
    controller_authority_ref="https://authority.example/recovery-controller/epoch-1",
    root_recovery_threshold=2,
    role_signers={
        "new_repository_owner": (("new-owner", digest("1")),),
        "old_repository_owner": (("old-owner", digest("2")),),
        "root_recovery": (("root-recovery-a", digest("3")), ("root-recovery-b", digest("4"))),
        "security_recovery_owner": (("security-owner", digest("5")),),
    },
)


def signed(subject: dict, signatures: list[dict]) -> dict:
    value = deepcopy(subject)
    value["signatureSubjectDigest"] = semantic_digest(subject)
    value["signatures"] = deepcopy(signatures)
    return with_self_digest(value)


def recovery_signatures(*, duplicate_security_key: bool = False) -> list[dict]:
    values = [
        signature(digest("1"), "new-owner", "new_repository_owner"),
        signature(digest("2"), "old-owner", "old_repository_owner"),
        signature(digest("3"), "root-recovery-a", "root_recovery"),
        signature(digest("4"), "root-recovery-b", "root_recovery"),
        signature(
            digest("2") if duplicate_security_key else digest("5"),
            "security-owner",
            "security_recovery_owner",
        ),
    ]
    for value in values:
        value["signedAt"] = "2026-07-17T11:58:00Z"
    return sorted(values, key=lambda item: (item["role"], item["identity"], item["keyFingerprint"]))


def verification(record: dict, purpose: str, *, verified_at: str = "2026-07-17T11:59:00Z") -> dict:
    allowed = tuple(
        sorted(fingerprint for entries in ROOT_POLICY.role_signers.values() for _, fingerprint in entries)
    )
    return with_self_digest(
        {
            "schema": "external-cryptographic-verification-receipt/v1",
            "receiptId": f"crypto-{record['signatureSubjectDigest'][-24:]}",
            "requestDigest": _verification_request_digest(
                record,
                purpose,
                allowed_fingerprints=allowed,
                threshold=3 + ROOT_POLICY.root_recovery_threshold,
                required_roles=RECOVERY_ROLES,
            ),
            "purpose": purpose,
            "subjectDigest": record["signatureSubjectDigest"],
            "verifiedSigners": [
                {
                    "role": item["role"],
                    "identity": item["identity"],
                    "keyFingerprint": item["keyFingerprint"],
                }
                for item in record["signatures"]
            ],
            "verifierAuthorityRef": "https://authority.example/recovery/epoch-7",
            "verifiedAt": verified_at,
        }
    )


def old_fence(*, state: str = "transition_fenced", package_id: str = "package-001") -> dict:
    return with_self_digest(
        {
            "schema": "bootstrap-claim-adoption-repository-fence/v1",
            "fenceId": "old-transition-fence-001",
            "packageId": package_id,
            "operationId": "original-adoption-publish",
            "authorizationDigest": None,
            "endpointRole": "old_repository",
            "repositoryId": digest("6"),
            "generation": 4,
            "state": state,
            "previousFenceDigest": None,
            "previousState": None,
            "authorityEpoch": 11,
            "credentialEpoch": 21,
            "denyWriteScope": (
                "permanent_noncanonical"
                if state == "permanent_noncanonical"
                else "all_non_recovery_writes"
            ),
            "recoveryExceptionOperationId": (
                None if state == "permanent_noncanonical" else "original-adoption-publish"
            ),
            "transitionSubjectDigest": digest("7"),
            "branchClosureDigest": None,
            "installedAt": "2026-07-17T11:00:00Z",
            "readbackAt": "2026-07-17T11:00:01Z",
        }
    )


def authorization(
    fence: dict,
    *,
    operation_id: str = "recover-publication-001",
    signatures: list[dict] | None = None,
) -> tuple[dict, dict]:
    auth = signed(
        {
            "schema": "bootstrap-claim-adoption-publication-recovery-authorization/v1",
            "authorizationId": f"auth-{operation_id}",
            "operationId": operation_id,
            "rootDigest": digest("8"),
            "rootEpoch": 7,
            "packageId": fence["packageId"],
            "packageDigest": digest("9"),
            "prepareResultDigest": digest("a"),
            "candidateCommit": CANDIDATE,
            "oldRepositoryId": fence["repositoryId"],
            "newRepositoryId": digest("b"),
            "expectedOldMain": EXPECTED_OLD,
            "oldFencePrestateDigest": fence["recordDigest"],
            "expectedOldFenceState": fence["state"],
            "transitionSubjectDigest": fence["transitionSubjectDigest"],
            "newFencePrestateExpectedAbsent": True,
            "oldAuthorityEpoch": 11,
            "newAuthorityEpoch": 12,
            "oldCredentialEpoch": 21,
            "newCredentialEpoch": 22,
            "lockProfileDigest": digest("c"),
            "observationProfileDigest": digest("d"),
            "idempotencyKey": f"idem-{operation_id}",
            "executorId": "recovery-executor",
            "oldRepositoryOwnerId": "old-owner",
            "newRepositoryOwnerId": "new-owner",
            "securityRecoveryOwnerId": "security-owner",
            "rootRecoverySignerIdentities": ["root-recovery-a", "root-recovery-b"],
            "rootRecoveryThreshold": 2,
            "requiredRoles": list(RECOVERY_ROLES),
            "authorizedAt": "2026-07-17T11:58:00Z",
            "expiresAt": "2026-07-17T12:30:00Z",
        },
        recovery_signatures() if signatures is None else signatures,
    )
    return auth, verification(
        auth, "bootstrap_claim_adoption_publication_recovery_authorization"
    )


class RecoveryIssuer:
    def __init__(self, signatures: list[dict] | None = None) -> None:
        self.signatures = deepcopy(recovery_signatures() if signatures is None else signatures)
        for value in self.signatures:
            value["signedAt"] = EFFECTIVE
        self.calls = 0

    def __call__(self, purpose: str, subject: dict):
        self.calls += 1
        receipt = signed(subject, self.signatures)
        return receipt, verification(receipt, purpose, verified_at=EFFECTIVE)


def cryptographic_verifier(request) -> dict:
    verified_at = (
        "2026-07-17T11:59:00Z"
        if request.purpose == "bootstrap_claim_adoption_publication_recovery_authorization"
        else EFFECTIVE
    )
    return with_self_digest(
        {
            "schema": "external-cryptographic-verification-receipt/v1",
            "receiptId": f"crypto-{request.subject_digest[-24:]}",
            "requestDigest": semantic_digest(
                {
                    "schema": "external-cryptographic-verification-request/v1",
                    "purpose": request.purpose,
                    "subjectDigest": request.subject_digest,
                    "signatures": list(request.signatures),
                    "allowedFingerprints": list(request.allowed_fingerprints),
                    "threshold": request.threshold,
                    "requiredRoles": list(request.required_roles),
                }
            ),
            "purpose": request.purpose,
            "subjectDigest": request.subject_digest,
            "verifiedSigners": [
                {
                    "role": item["role"],
                    "identity": item["identity"],
                    "keyFingerprint": item["keyFingerprint"],
                }
                for item in request.signatures
            ],
            "verifierAuthorityRef": ROOT_POLICY.verifier_authority_ref,
            "verifiedAt": verified_at,
        }
    )


class FakeRecoveryController:
    authority_ref = "https://authority.example/recovery-controller/epoch-1"

    def __init__(self) -> None:
        self.fences: dict[tuple[str, str, str], dict] = {}
        self.next_observations: dict | None = None
        self.branch_valid = True

    @staticmethod
    def _key(value: dict) -> tuple[str, str, str]:
        return value["packageId"], value["endpointRole"], value["repositoryId"]

    def apply_fence(self, fence: dict) -> dict:
        self.fences[self._key(fence)] = deepcopy(fence)
        return deepcopy(fence)

    def read_fence(self, *, package_id: str, endpoint_role: str, repository_id: str):
        value = self.fences.get((package_id, endpoint_role, repository_id))
        return deepcopy(value)

    def observe(self, request: dict):
        assert self.next_observations is not None
        return {
            "controllerAuthorityRef": self.authority_ref,
            "observationRequestDigest": semantic_digest(request),
            "observationReceiptDigest": semantic_digest(
                {"requestDigest": semantic_digest(request), "observations": self.next_observations}
            ),
            **deepcopy(self.next_observations),
        }

    def validate_branch_closure(self, request: dict):
        return {
            "controllerAuthorityRef": self.authority_ref,
            "validationRequestDigest": semantic_digest(request),
            "validationReceiptDigest": semantic_digest(
                {"requestDigest": semantic_digest(request), "valid": self.branch_valid}
            ),
            "outcome": request["outcome"],
            "branchClosureDigest": request["branchClosureDigest"],
            "valid": self.branch_valid,
        }


def make_store(path: Path) -> AdoptionPublicationRecoveryStore:
    return AdoptionPublicationRecoveryStore(
        path.resolve(),
        root_policy=ROOT_POLICY,
        cryptographic_verifier=cryptographic_verifier,
        controller=FakeRecoveryController(),
    )


def run_recovery(
    store: AdoptionPublicationRecoveryStore,
    fence: dict,
    auth: dict,
    auth_verification: dict,
    *,
    new_main: str | None,
    branch_closure: str | None,
    issuer: RecoveryIssuer,
    old_readable: bool = True,
    new_readable: bool = True,
    crash_after: str | None = None,
):
    observations = {
        "oldReadable": old_readable,
        "newReadable": new_readable,
        "oldMain": EXPECTED_OLD,
        "newMain": new_main,
    }
    store.controller.fences.setdefault(
        (fence["packageId"], fence["endpointRole"], fence["repositoryId"]),
        deepcopy(fence),
    )
    store.controller.next_observations = deepcopy(observations)
    return store.recover(
        authorization=auth,
        authorization_verification=auth_verification,
        old_fence_prestate=fence,
        new_transition_subject_digest=fence["transitionSubjectDigest"],
        observations=observations,
        branch_closure_digest=branch_closure,
        issuer=issuer,
        effective_at=EFFECTIVE,
        crash_after=crash_after,
    )


def current(store: AdoptionPublicationRecoveryStore, package_id: str, relative: str) -> dict:
    value = store._read(store._package(package_id) / relative / "current.json")
    assert value is not None
    return value


def test_success_closes_old_permanently_and_releases_only_new_and_authority(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    issuer = RecoveryIssuer()

    receipt, receipt_verification = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=CANDIDATE,
        branch_closure=digest("f"),
        issuer=issuer,
    )

    assert receipt["outcome"] == "success"
    assert len(receipt["operationHeadDigests"]) == 5
    assert receipt_verification["subjectDigest"] == receipt["signatureSubjectDigest"]
    assert current(store, fence["packageId"], "authority-deny")["state"] == "released_after_success"
    old = current(store, fence["packageId"], "endpoint-fences/old_repository")
    new = current(store, fence["packageId"], "endpoint-fences/new_repository")
    head = current(store, fence["packageId"], f"operations/{auth['operationId']}")
    assert (old["state"], new["state"], head["state"]) == (
        "permanent_noncanonical",
        "released_after_success",
        "recovery_closed",
    )
    assert receipt["oldPermanentFenceDigest"] == old["recordDigest"]
    assert "oldFenceReleaseDigest" not in receipt
    assert issuer.calls == 1


def test_abort_releases_both_endpoints_only_after_selected_closure(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    receipt, _ = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=None,
        branch_closure=digest("f"),
        issuer=RecoveryIssuer(),
    )

    assert receipt["outcome"] == "abort"
    assert current(store, fence["packageId"], "authority-deny")["state"] == "released_after_abort"
    assert current(store, fence["packageId"], "endpoint-fences/old_repository")["state"] == "released_after_abort"
    assert current(store, fence["packageId"], "endpoint-fences/new_repository")["state"] == "released_after_abort"
    assert receipt["recoveryClosedHeadDigest"] == receipt["operationHeadDigests"][-1]
    assert "oldPermanentFenceDigest" not in receipt


@pytest.mark.parametrize("unreadable", [False, True])
def test_ambiguity_retains_package_deny_and_both_endpoint_fences(
    tmp_path: Path, unreadable: bool
) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence(state="permanent_noncanonical")
    auth, auth_verification = authorization(fence)
    receipt, _ = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=None,
        branch_closure=None,
        issuer=RecoveryIssuer(),
        new_readable=not unreadable,
    )

    assert receipt["outcome"] == "ambiguous"
    assert len(receipt["operationHeadDigests"]) == 4
    assert current(store, fence["packageId"], "authority-deny")["state"] == "recovery_deny"
    assert current(store, fence["packageId"], "endpoint-fences/old_repository")["state"] == "permanent_noncanonical"
    assert current(store, fence["packageId"], "endpoint-fences/new_repository")["state"] == "recovery_deny"
    assert current(store, fence["packageId"], f"operations/{auth['operationId']}")["state"] == "ambiguous_blocked"
    forbidden = {
        "branchClosureDigest",
        "authorityDenyReleaseDigest",
        "oldFenceReleaseDigest",
        "newFenceReleaseDigest",
        "oldPermanentFenceDigest",
        "recoveryClosedHeadDigest",
    }
    assert forbidden.isdisjoint(receipt)


@pytest.mark.parametrize(
    "phase",
    [
        "authority_deny_committed",
        "recovery_prepared",
        "old_fence_committed",
        "dual_fences_committed",
        "observations_committed",
        "branch_selected",
        "endpoint_fences_closed",
        "authority_deny_released",
        "recovery_closed",
        "receipt_candidate_written",
        "receipt_written",
    ],
)
def test_every_success_response_loss_boundary_returns_same_terminal_bytes(
    tmp_path: Path, phase: str
) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    issuer = RecoveryIssuer()
    with pytest.raises(AdoptionRecoveryCrash, match=phase):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=issuer,
            crash_after=phase,
        )
    first, _ = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=CANDIDATE,
        branch_closure=digest("f"),
        issuer=issuer,
    )
    second, _ = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=CANDIDATE,
        branch_closure=digest("f"),
        issuer=issuer,
    )
    assert canonical_bytes(first) == canonical_bytes(second)
    assert issuer.calls == 1
    receipt_path = store._operation_root(auth) / "recovery-receipt.json"
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600


def test_four_role_validation_rejects_missing_root_threshold_and_shared_keys(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    insufficient = [
        item for item in recovery_signatures() if item["identity"] != "root-recovery-b"
    ]
    auth, auth_verification = authorization(fence, signatures=insufficient)
    with pytest.raises(AdoptionRecoveryError, match="threshold"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(insufficient),
        )

    shared = recovery_signatures(duplicate_security_key=True)
    auth, auth_verification = authorization(fence, signatures=shared)
    with pytest.raises(AdoptionRecoveryError, match="pinned root policy|separate keys"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(shared),
        )


def test_package_global_deny_rejects_a_second_operation(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence(state="permanent_noncanonical")
    first, first_verification = authorization(fence)
    run_recovery(
        store,
        fence,
        first,
        first_verification,
        new_main=None,
        branch_closure=None,
        issuer=RecoveryIssuer(),
    )
    second, second_verification = authorization(fence, operation_id="recover-publication-002")
    with pytest.raises(AdoptionRecoveryError, match="another recovery authorization"):
        run_recovery(
            store,
            fence,
            second,
            second_verification,
            new_main=None,
            branch_closure=None,
            issuer=RecoveryIssuer(),
        )


def test_committed_observation_is_immutable_and_no_secret_fields_are_emitted(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence(state="permanent_noncanonical")
    auth, auth_verification = authorization(fence)
    receipt, _ = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=None,
        branch_closure=None,
        issuer=RecoveryIssuer(),
    )
    assert receipt["outcome"] == "ambiguous"
    for path in (tmp_path / "authority").rglob("*.json"):
        lowered = path.read_text(encoding="utf-8").lower()
        assert '"token"' not in lowered
        assert '"password"' not in lowered
        assert '"secret"' not in lowered

    operation = store._operation_root(auth)
    (operation / "recovery-receipt.json").unlink()
    (operation / "recovery-receipt-verification.json").unlink()
    with pytest.raises(AdoptionRecoveryError, match="observation drift"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=None,
            issuer=RecoveryIssuer(),
        )


def test_signature_subject_helper_matches_authorization() -> None:
    fence = old_fence()
    auth, _ = authorization(fence)
    assert _signature_subject(auth) == auth["signatureSubjectDigest"]


def test_caller_cannot_forge_verifier_or_use_non_ed25519_bytes(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    forged = {
        **{key: value for key, value in auth_verification.items() if key != "recordDigest"},
        "verifierAuthorityRef": "https://attacker.example/verifier",
    }
    forged = with_self_digest(forged)
    with pytest.raises(AdoptionRecoveryError, match="pinned verifier"):
        run_recovery(
            store,
            fence,
            auth,
            forged,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(),
        )

    invalid = recovery_signatures()
    for value in invalid:
        value["signatureBase64"] = "!" * 88
    auth, auth_verification = authorization(fence, signatures=invalid)
    with pytest.raises(AdoptionRecoveryError, match="validation failed"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(invalid),
        )


def test_controller_observation_and_branch_validation_are_mandatory(tmp_path: Path) -> None:
    store = make_store(tmp_path / "observation")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    original_observe = store.controller.observe

    def substituted_observation(request):
        result = original_observe(request)
        result["newMain"] = None
        return result

    store.controller.observe = substituted_observation
    with pytest.raises(AdoptionRecoveryError, match="caller observations differ"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(),
        )

    store = make_store(tmp_path / "branch")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    store.controller.branch_valid = False
    with pytest.raises(AdoptionRecoveryError, match="not independently validated"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(),
        )
    assert current(store, fence["packageId"], "authority-deny")["state"] == "recovery_deny"
    assert current(store, fence["packageId"], "endpoint-fences/old_repository")["state"] == "recovery_deny"
    assert current(store, fence["packageId"], "endpoint-fences/new_repository")["state"] == "recovery_deny"


def test_controller_must_byte_confirm_fence_enforcement_and_readback(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    original_apply = store.controller.apply_fence

    def mismatched_apply(value):
        original_apply(value)
        return {**value, "readbackAt": "2026-07-17T12:00:01Z"}

    store.controller.apply_fence = mismatched_apply
    with pytest.raises(AdoptionRecoveryError, match="byte-confirm"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(),
        )
    operation = store._operation_root(auth)
    assert not (operation / "heads" / "00000000000000000001.json").exists()


def test_object_pointer_partial_writes_repair_deny_and_both_fences(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    store.controller.fences[(fence["packageId"], fence["endpointRole"], fence["repositoryId"])] = deepcopy(fence)
    auth_verification = store._verify_authorization_roles(
        auth, auth_verification, effective_at=EFFECTIVE
    )
    store._persist_authorization(
        authorization=auth,
        verification=auth_verification,
        effective_at=EFFECTIVE,
    )

    deny = store._initial_deny(auth, auth_verification, EFFECTIVE)
    deny_current = store._deny_paths(auth["packageId"])[1]
    deny_current.unlink()
    assert store._initial_deny(auth, auth_verification, EFFECTIVE)["recordDigest"] == deny["recordDigest"]
    assert store._read(deny_current)["recordDigest"] == deny["recordDigest"]

    old_recovery = store._old_recovery_fence(
        authorization=auth, old_fence_prestate=fence, effective_at=EFFECTIVE
    )
    old_current = store._endpoint_paths(auth["packageId"], "old_repository")[1]
    store._write_current(old_current, fence)
    repaired_old = store._old_recovery_fence(
        authorization=auth, old_fence_prestate=fence, effective_at=EFFECTIVE
    )
    assert repaired_old == old_recovery
    assert store._read(old_current)["recordDigest"] == old_recovery["recordDigest"]

    new_recovery = store._new_recovery_fence(
        authorization=auth,
        transition_subject_digest=auth["transitionSubjectDigest"],
        effective_at=EFFECTIVE,
    )
    new_current = store._endpoint_paths(auth["packageId"], "new_repository")[1]
    new_current.unlink()
    repaired_new = store._new_recovery_fence(
        authorization=auth,
        transition_subject_digest=auth["transitionSubjectDigest"],
        effective_at=EFFECTIVE,
    )
    assert repaired_new == new_recovery
    assert store._read(new_current)["recordDigest"] == new_recovery["recordDigest"]


def test_split_receipt_candidate_recovers_without_resigning(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    issuer = RecoveryIssuer()
    expected, _ = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=CANDIDATE,
        branch_closure=digest("f"),
        issuer=issuer,
    )
    operation = store._operation_root(auth)
    (operation / "recovery-receipt.json").unlink()
    (operation / "recovery-receipt-verification.json").unlink()
    (operation / "recovery-receipt-verification-candidate.json").unlink()
    recovered, _ = run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=CANDIDATE,
        branch_closure=digest("f"),
        issuer=issuer,
    )
    assert recovered == expected
    assert issuer.calls == 1


def test_terminal_retry_revalidates_complete_current_closure(tmp_path: Path) -> None:
    store = make_store(tmp_path / "authority")
    fence = old_fence()
    auth, auth_verification = authorization(fence)
    run_recovery(
        store,
        fence,
        auth,
        auth_verification,
        new_main=CANDIDATE,
        branch_closure=digest("f"),
        issuer=RecoveryIssuer(),
    )
    operation = store._operation_root(auth)
    selected = store._read(operation / "heads" / "00000000000000000003.json")
    store._write_current(operation / "current.json", selected)
    with pytest.raises(AdoptionRecoveryError, match="current head drift"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(),
        )


def test_role_identity_time_and_fence_state_semantics_fail_closed(tmp_path: Path) -> None:
    duplicate_policy = RecoveryRootPolicy(
        **{
            **ROOT_POLICY.__dict__,
            "role_signers": {
                **ROOT_POLICY.role_signers,
                "new_repository_owner": (("old-owner", digest("1")),),
            },
        }
    )
    with pytest.raises(AdoptionRecoveryError, match="distinct identities"):
        AdoptionPublicationRecoveryStore(
            (tmp_path / "duplicate").resolve(),
            root_policy=duplicate_policy,
            cryptographic_verifier=cryptographic_verifier,
            controller=FakeRecoveryController(),
        )

    store = make_store(tmp_path / "late")
    fence = old_fence()
    late = recovery_signatures()
    late[0]["signedAt"] = "2026-07-17T12:01:00Z"
    auth, auth_verification = authorization(fence, signatures=late)
    with pytest.raises(AdoptionRecoveryError, match="signature time"):
        run_recovery(
            store,
            fence,
            auth,
            auth_verification,
            new_main=CANDIDATE,
            branch_closure=digest("f"),
            issuer=RecoveryIssuer(),
        )

    invalid_fence = {
        **{key: value for key, value in fence.items() if key != "recordDigest"},
        "denyWriteScope": "released",
    }
    invalid_fence = with_self_digest(invalid_fence)
    with pytest.raises(AdoptionRecoveryError, match="validation failed"):
        store._validate_fence_semantics(invalid_fence)
