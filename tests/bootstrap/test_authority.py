from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from dasops.bootstrap.authority import AuthorityVerificationError, BootstrapAuthorityVerifier
from dasops.bootstrap.schema_registry import BootstrapSchemaRegistry
from dasops.protected.canonical import semantic_digest, with_self_digest


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def oid(char: str) -> str:
    return char * 40


def signature(fingerprint: str, identity: str, role: str) -> dict:
    return {
        "keyFingerprint": fingerprint,
        "identity": identity,
        "role": role,
        "algorithm": "ed25519",
        "signatureBase64": "e" * 86 + "==",
        "signedAt": "2026-07-16T11:59:00Z",
    }


def signed(subject: dict, signatures: list[dict]) -> dict:
    value = dict(subject)
    value["signatureSubjectDigest"] = semantic_digest(subject)
    value["signatures"] = signatures
    return with_self_digest(value)


ROOT_KEYS = [
    {"keyId": "independent-verifier", "fingerprint": digest("7"), "roles": ["independent_verifier"]},
    {"keyId": "orchestrator", "fingerprint": digest("9"), "roles": ["orchestrator"]},
    {"keyId": "recovery-a", "fingerprint": digest("3"), "roles": ["recovery"]},
    {"keyId": "recovery-b", "fingerprint": digest("4"), "roles": ["recovery"]},
    {"keyId": "repository-owner", "fingerprint": digest("5"), "roles": ["repository_owner"]},
    {"keyId": "root-a", "fingerprint": digest("1"), "roles": ["root_signer"]},
    {"keyId": "root-b", "fingerprint": digest("2"), "roles": ["root_signer"]},
    {"keyId": "security-reviewer", "fingerprint": digest("8"), "roles": ["security_reviewer"]},
    {"keyId": "upstream-governance", "fingerprint": digest("6"), "roles": ["upstream_governance"]},
]


def valid_records() -> tuple[dict, dict, dict, dict, dict]:
    root = signed(
        {
            "schema": "bootstrap-root/v1",
            "rootId": "BOOTSTRAP-ROOT-001",
            "epoch": 1,
            "anchorId": "BOOTSTRAP-ANCHOR-001",
            "previousRootDigest": None,
            "keys": ROOT_KEYS,
            "ordinaryThreshold": 2,
            "recoveryThreshold": 2,
            "toolPolicy": {
                "allowedSourceRepos": ["AzzCraft/das-tools.git"],
                "minimumDasopsVersion": "1.1.0rc11",
                "requiredReviewRoles": ["independent_verifier", "repository_owner", "upstream_governance"],
                "requiredOperationRoles": ["independent_verifier", "orchestrator", "repository_owner"],
                "allowedOperations": [
                    "abandon_claim",
                    "adopt_cancel",
                    "adopt_prepare",
                    "adopt_publish",
                    "cancel_attempt",
                    "compensate_claim",
                    "handoff_claim",
                    "prepare_candidate",
                    "publish_claim",
                    "recover_publication",
                    "recover_receipt",
                    "register_attempt",
                ],
            },
            "registryProfileDigest": digest("a"),
            "storeProfileDigest": digest("b"),
            "checkpointProfileDigest": digest("c"),
            "legacyTokenProfileDigest": digest("d"),
            "validFrom": "2026-07-16T11:00:00Z",
            "validUntil": "2026-07-16T13:00:00Z",
            "revocationEndpoint": "https://authority.example/revocations/root-001",
        },
        [
            signature(digest("1"), "root-signer-a", "root_signer"),
            signature(digest("2"), "root-signer-b", "root_signer"),
        ],
    )
    anchor = with_self_digest(
        {
            "schema": "bootstrap-trust-anchor/v1",
            "anchorId": "BOOTSTRAP-ANCHOR-001",
            "expectedRootId": root["rootId"],
            "expectedRootDigest": root["recordDigest"],
            "rootSigningKeyFingerprints": [digest("1"), digest("2")],
            "rootThreshold": 2,
            "recoveryKeyFingerprints": [digest("3"), digest("4")],
            "recoveryThreshold": 2,
            "trustedComponents": {
                "launcher": {"componentId": "launcher-v1", "sourceDigest": digest("a"), "packageDigest": digest("b"), "runtimePath": "/opt/das/bin/launcher"},
                "materializer": {"componentId": "materializer-v1", "sourceDigest": digest("c"), "packageDigest": digest("d"), "runtimePath": "/opt/das/bin/materializer"},
                "legacyBridge": {"componentId": "legacy-bridge-v1", "sourceDigest": digest("e"), "packageDigest": digest("f"), "runtimePath": "/opt/das/bin/legacy-bridge"},
            },
            "validFrom": "2026-07-16T11:00:00Z",
            "validUntil": "2026-07-16T13:00:00Z",
            "revocationEndpoint": "https://authority.example/revocations/root-001",
        }
    )
    review_signatures = [
        signature(digest("7"), "independent-reviewer", "independent_verifier"),
        signature(digest("5"), "repository-owner", "repository_owner"),
        signature(digest("6"), "upstream-governance", "upstream_governance"),
    ]
    source = signed(
        {
            "schema": "tool-source-decision/v1",
            "decisionId": "TOOL-SOURCE-DECISION-001",
            "rootId": root["rootId"],
            "rootEpoch": root["epoch"],
            "upstreamRepo": "AzzCraft/das-tools.git",
            "upstreamBaseCommit": oid("1"),
            "changeId": "example-bootstrap-v1",
            "taskId": "TASK-008",
            "governanceProfileDigest": digest("1"),
            "claimResultDigest": digest("2"),
            "reviewResultDigest": digest("3"),
            "gateResultDigest": digest("4"),
            "publicationReceiptDigest": digest("5"),
            "sourceCommit": oid("2"),
            "sourceTree": oid("3"),
            "sourceSubtree": oid("4"),
            "status": "accepted",
            "validFrom": "2026-07-16T11:30:00Z",
            "validUntil": "2026-07-16T12:30:00Z",
        },
        review_signatures,
    )
    artifact = {"path": "artifact.bin", "sha256": "a" * 64, "size": 123}
    release = signed(
        {
            "schema": "tool-release/v1",
            "releaseId": "TOOL-RELEASE-001",
            "rootId": root["rootId"],
            "rootEpoch": root["epoch"],
            "version": "1.1.0rc11",
            "sourceDecisionDigest": source["recordDigest"],
            "sourceCommit": source["sourceCommit"],
            "sourceTree": source["sourceTree"],
            "sourceSubtree": source["sourceSubtree"],
            "runtime": {**artifact, "path": "dasops-runtime.pyz"},
            "wheel": artifact,
            "sourcePackage": {**artifact, "path": "source.tar.gz"},
            "sbom": {**artifact, "path": "sbom.json"},
            "provenance": {**artifact, "path": "provenance.json"},
            "testEvidence": {**artifact, "path": "tests.json"},
            "status": "accepted",
            "independentReviewStatus": "accepted",
            "signatureStatus": "signed",
            "validFrom": "2026-07-16T11:30:00Z",
            "validUntil": "2026-07-16T12:30:00Z",
        },
        review_signatures,
    )
    operation_signatures = [
        signature(digest("7"), "independent-reviewer", "independent_verifier"),
        signature(digest("9"), "orchestrator", "orchestrator"),
        signature(digest("5"), "repository-owner", "repository_owner"),
    ]
    descriptor = signed(
        {
            "schema": "bootstrap-operation-descriptor/v1",
            "descriptorId": "BOOTSTRAP-DESCRIPTOR-001",
            "operation": "register_attempt",
            "rootDigest": root["recordDigest"],
            "toolReleaseDigest": release["recordDigest"],
            "changeId": "example-recovery-program",
            "taskId": "TASK-026",
            "inputManifestDigest": digest("1"),
            "outputManifestDigest": digest("2"),
            "lockProfileDigest": digest("3"),
            "budgetProfileDigest": digest("4"),
            "validFrom": "2026-07-16T11:45:00Z",
            "validUntil": "2026-07-16T12:15:00Z",
        },
        operation_signatures,
    )
    return anchor, root, source, release, descriptor


def external_verifier(request) -> dict:
    return {
        "verifierAuthorityRef": "https://authority.example/verifier/epoch-1",
        "verifierReceiptDigest": digest("f"),
        "verifiedSigners": [
            {
                "role": item["role"],
                "identity": item["identity"],
                "keyFingerprint": item["keyFingerprint"],
            }
            for item in request.signatures
            if item["keyFingerprint"] in request.allowed_fingerprints
        ],
    }


def make_verifier(anchor: dict, root: dict, *, external=external_verifier, revoked: bool = False, expected_now=NOW) -> BootstrapAuthorityVerifier:
    def revocation(endpoint: str, root_id: str, epoch: int, now: datetime) -> dict:
        assert endpoint.startswith("https://") and root_id == root["rootId"] and epoch == 1 and now == expected_now
        return {"status": "revoked" if revoked else "good", "rootDigest": root["recordDigest"], "receiptDigest": digest("e")}

    return BootstrapAuthorityVerifier(
        trusted_anchor_digest=anchor["recordDigest"],
        external_verifier=external,
        revocation_verifier=revocation,
    )


def verified_chain() -> tuple[BootstrapAuthorityVerifier, object, object, dict]:
    anchor, root, source, release, descriptor = valid_records()
    verifier = make_verifier(anchor, root)
    authority = verifier.verify_anchor_root(anchor=anchor, root=root, now=NOW)
    tool = verifier.verify_tool_release(authority=authority, source_decision=source, release=release, now=NOW)
    return verifier, authority, tool, descriptor


def test_schema_inventory_and_valid_authority_release_operation_chain() -> None:
    registry = BootstrapSchemaRegistry()
    assert registry.schema_ids == (
        "bootstrap-adoption-activation-challenge/v1",
        "bootstrap-adoption-activation-receipt/v1",
        "bootstrap-adoption-approval-subject/v1",
        "bootstrap-adoption-approval-subject/v2",
        "bootstrap-adoption-approval/v1",
        "bootstrap-adoption-cancel-authorization/v1",
        "bootstrap-adoption-cancel-result/v1",
        "bootstrap-adoption-cancel-result/v2",
        "bootstrap-adoption-disposition-tombstone/v1",
        "bootstrap-adoption-fence-release-receipt/v1",
        "bootstrap-adoption-lifecycle-state/v1",
        "bootstrap-adoption-package/v1",
        "bootstrap-adoption-package/v2",
        "bootstrap-adoption-prepare-request/v1",
        "bootstrap-adoption-prepare-result/v1",
        "bootstrap-adoption-prepare-result/v2",
        "bootstrap-adoption-prepare-wal/v1",
        "bootstrap-adoption-private-state/v1",
        "bootstrap-adoption-publish-request/v1",
        "bootstrap-adoption-publish-result/v1",
        "bootstrap-adoption-publish-wal/v1",
        "bootstrap-adoption-recovery-request/v1",
        "bootstrap-attempt-cancel-authorization/v1",
        "bootstrap-attempt-intent/v1",
        "bootstrap-attempt-operation-wal/v1",
        "bootstrap-attempt-registry-entry/v1",
        "bootstrap-attempt-transition-result/v1",
        "bootstrap-attempt-waiver/v1",
        "bootstrap-candidate-preparation-request/v1",
        "bootstrap-candidate-preparation-result/v1",
        "bootstrap-candidate-preparation-wal/v1",
        "bootstrap-candidate-verification-result/v1",
        "bootstrap-claim-adoption-package-manifest/v1",
        "bootstrap-claim-adoption-publication-recovery-authorization/v1",
        "bootstrap-claim-adoption-publication-recovery-observation/v1",
        "bootstrap-claim-adoption-publication-recovery-operation-head/v1",
        "bootstrap-claim-adoption-publication-recovery-receipt/v1",
        "bootstrap-claim-adoption-recovery-authority-deny/v1",
        "bootstrap-claim-adoption-repository-fence/v1",
        "bootstrap-claim-adoption-request/v1",
        "bootstrap-claim-candidate-receipt/v1",
        "bootstrap-claim-early-closure-authorization/v1",
        "bootstrap-claim-early-closure-result/v1",
        "bootstrap-claim-early-closure-wal/v1",
        "bootstrap-claim-lock-handoff-receipt/v1",
        "bootstrap-claim-lock-handoff-request/v1",
        "bootstrap-claim-publication-request/v1",
        "bootstrap-claim-publication-wal/v1",
        "bootstrap-cli-invocation/v1",
        "bootstrap-cli-result/v1",
        "bootstrap-current-head/v1",
        "bootstrap-foundation-candidate-descriptor/v1",
        "bootstrap-foundation-payload-manifest/v1",
        "bootstrap-handoff-challenge/v1",
        "bootstrap-head-slot-commit/v1",
        "bootstrap-operation-descriptor/v1",
        "bootstrap-publication-receipt/v1",
        "bootstrap-receipt-closure-result/v1",
        "bootstrap-receipt-recovery-authorization/v1",
        "bootstrap-receipt-recovery-result/v1",
        "bootstrap-receipt-recovery-search/v1",
        "bootstrap-receipt-slot/v1",
        "bootstrap-registry-epoch-transition/v1",
        "bootstrap-registry-head/v1",
        "bootstrap-registry-operation-result/v1",
        "bootstrap-repository-handoff-transaction/v1",
        "bootstrap-root-registry-current-head/v1",
        "bootstrap-root-rotation-authorization/v1",
        "bootstrap-root-rotation-frontier/v1",
        "bootstrap-root-rotation-operation-result/v1",
        "bootstrap-root/v1",
        "bootstrap-successor-v3-activation-challenge/v1",
        "bootstrap-successor-v3-activation-receipt/v1",
        "bootstrap-successor-v3-activation-state/v1",
        "bootstrap-successor-v3-activation-subject-index/v1",
        "bootstrap-trust-anchor/v1",
        "external-cryptographic-verification-receipt/v1",
        "external-role-verification/v1",
        "foundation-program-selector-head/v1",
        "foundation-verification-descriptor-head/v1",
        "foundation-verification-store-manifest/v1",
        "git-adoption-repository-state/v1",
        "tool-release/v1",
        "tool-source-decision/v1",
        "verification-profile-transition-head/v1",
    )
    verifier, _authority, tool, descriptor = verified_chain()
    operation = verifier.verify_operation_descriptor(
        tool_release=tool,
        descriptor=descriptor,
        expected_operation="register_attempt",
        change_id="example-recovery-program",
        task_id="TASK-026",
        now=NOW,
    )
    assert operation.descriptor_verification["purpose"] == "bootstrap_operation_descriptor"


def test_anchor_digest_root_substitution_expiry_and_revocation_fail() -> None:
    anchor, root, _source, _release, _descriptor = valid_records()
    wrong = BootstrapAuthorityVerifier(
        trusted_anchor_digest=digest("0"),
        external_verifier=external_verifier,
        revocation_verifier=lambda *_args: {},
    )
    with pytest.raises(AuthorityVerificationError, match="out-of-band digest"):
        wrong.verify_anchor_root(anchor=anchor, root=root, now=NOW)

    substituted = deepcopy(anchor)
    substituted.pop("recordDigest")
    substituted["expectedRootDigest"] = digest("0")
    substituted = with_self_digest(substituted)
    verifier = make_verifier(substituted, root)
    with pytest.raises(AuthorityVerificationError, match="substitution"):
        verifier.verify_anchor_root(anchor=substituted, root=root, now=NOW)

    with pytest.raises(AuthorityVerificationError, match="validity window"):
        make_verifier(anchor, root).verify_anchor_root(
            anchor=anchor,
            root=root,
            now=datetime(2026, 7, 16, 14, 0, tzinfo=timezone.utc),
        )
    with pytest.raises(AuthorityVerificationError, match="revocation"):
        make_verifier(anchor, root, revoked=True).verify_anchor_root(anchor=anchor, root=root, now=NOW)


def test_local_external_authority_duplicate_identity_and_signature_subject_fail() -> None:
    anchor, root, _source, _release, _descriptor = valid_records()

    def local(request) -> dict:
        result = external_verifier(request)
        result["verifierAuthorityRef"] = "local:self-attested"
        return result

    with pytest.raises(AuthorityVerificationError, match="local-only"):
        make_verifier(anchor, root, external=local).verify_anchor_root(anchor=anchor, root=root, now=NOW)

    duplicate_root = deepcopy(root)
    duplicate_root.pop("recordDigest")
    for item in duplicate_root["signatures"]:
        item["identity"] = "same-person"
    duplicate_root = with_self_digest(duplicate_root)
    duplicate_anchor = deepcopy(anchor)
    duplicate_anchor.pop("recordDigest")
    duplicate_anchor["expectedRootDigest"] = duplicate_root["recordDigest"]
    duplicate_anchor = with_self_digest(duplicate_anchor)
    with pytest.raises(AuthorityVerificationError, match="multiple verified signer"):
        make_verifier(duplicate_anchor, duplicate_root).verify_anchor_root(
            anchor=duplicate_anchor,
            root=duplicate_root,
            now=NOW,
        )

    mutated = deepcopy(root)
    mutated["toolPolicy"]["minimumDasopsVersion"] = "1.2.0rc1"
    mutated.pop("recordDigest")
    mutated = with_self_digest(mutated)
    substituted_anchor = deepcopy(anchor)
    substituted_anchor.pop("recordDigest")
    substituted_anchor["expectedRootDigest"] = mutated["recordDigest"]
    substituted_anchor = with_self_digest(substituted_anchor)
    with pytest.raises(AuthorityVerificationError, match="signature subject"):
        make_verifier(substituted_anchor, mutated).verify_anchor_root(anchor=substituted_anchor, root=mutated, now=NOW)


def test_tool_release_lineage_version_and_review_status_fail_closed() -> None:
    anchor, root, source, release, _descriptor = valid_records()
    verifier = make_verifier(anchor, root)
    authority = verifier.verify_anchor_root(anchor=anchor, root=root, now=NOW)

    drifted = deepcopy(release)
    drifted.pop("recordDigest")
    drifted["sourceCommit"] = oid("9")
    drifted = with_self_digest(drifted)
    with pytest.raises(AuthorityVerificationError, match="signature subject"):
        verifier.verify_tool_release(authority=authority, source_decision=source, release=drifted, now=NOW)

    low = deepcopy(release)
    base = {key: value for key, value in low.items() if key not in {"recordDigest", "signatureSubjectDigest", "signatures"}}
    base["version"] = "1.0.0"
    low = signed(base, low["signatures"])
    with pytest.raises(AuthorityVerificationError, match="below"):
        verifier.verify_tool_release(authority=authority, source_decision=source, release=low, now=NOW)

    rejected = deepcopy(release)
    rejected["independentReviewStatus"] = "not_started"
    with pytest.raises(AuthorityVerificationError, match="accepted"):
        verifier.verify_tool_release(authority=authority, source_decision=source, release=rejected, now=NOW)


def test_descriptor_subject_operation_task_release_and_unknown_fields_fail() -> None:
    verifier, _authority, tool, descriptor = verified_chain()
    with pytest.raises(AuthorityVerificationError, match="operation"):
        verifier.verify_operation_descriptor(
            tool_release=tool,
            descriptor=descriptor,
            expected_operation="adopt_prepare",
            change_id="example-recovery-program",
            task_id="TASK-026",
            now=NOW,
        )
    with pytest.raises(AuthorityVerificationError, match="task subject"):
        verifier.verify_operation_descriptor(
            tool_release=tool,
            descriptor=descriptor,
            expected_operation="register_attempt",
            change_id="wrong-change",
            task_id="TASK-026",
            now=NOW,
        )
    extra = deepcopy(descriptor)
    extra["unexpected"] = True
    with pytest.raises(AuthorityVerificationError, match="Additional properties"):
        verifier.verify_operation_descriptor(
            tool_release=tool,
            descriptor=extra,
            expected_operation="register_attempt",
            change_id="example-recovery-program",
            task_id="TASK-026",
            now=NOW,
        )
