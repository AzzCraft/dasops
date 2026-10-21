from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path

import pytest

from dasops.bundle_preview import CadenceDependencyError, resolve_preview, resolve_facts_preview
from dasops.standards_contracts import exact_json as codec


def request():
    return {"contractIdentity": "das-bundle-preview-input/v1", "scope": "fixture", "policyDigest": "sha256:" + "0" * 64,
            "catalog": {"standardVersion": "1.4.0"}, "facts": []}


def response(input):
    subject = {"contractIdentity": "das-bundle-preview/v1", "scope": input["scope"], "standardVersion": input["catalog"]["standardVersion"],
               "policyDigest": input["policyDigest"], "factsDigest": codec.digest(input["facts"]), "catalogDigest": codec.digest(input["catalog"]),
               "digestMethod": codec.DIGEST_METHOD, "resolvedModules": [], "unresolvedModules": [], "factStates": [], "ruleTrace": [],
               "authorityVerified": False, "qualificationEligible": False,
               "limitations": ["facts_are_unapproved_proposals", "legacy_leaf_applicability_not_migrated", "protected_resolution_not_enabled"]}
    return {**subject, "previewDigest": codec.digest(subject)}


def leaf_request():
    # Transport-only fixture; the real Cadence exchange validates the authored
    # catalog and executes its predicates in the root integration suite.
    input = request()
    input['contractIdentity'] = 'das-bundle-preview-input/v2'
    leaves = [dict(id=f'das.security-agent.fixture-{i:02}', ownerModule='das.security-agent',
                   parentClause='cl-11.1' if i < 12 else 'cl-13.13') for i in range(31)]
    input['requirementsCatalog'] = dict(requirements=leaves[:12], editionRequirements=leaves[12:])
    return input


def leaf_response(input):
    subject = response(input)
    subject.pop('previewDigest')
    current=input['contractIdentity']=='das-bundle-preview-input/v3'
    subject.update(contractIdentity='das-bundle-preview/v3' if current else 'das-bundle-preview/v2', leafMigrationComplete=current,
                   requirementsCatalogDigest=codec.digest(input['requirementsCatalog']),
                   limitations=(['facts_are_unapproved_proposals', 'protected_resolution_not_enabled'] if current else
                               ['facts_are_unapproved_proposals', 'requirement_leaf_migration_incomplete', 'protected_resolution_not_enabled']))
    leaves = input['requirementsCatalog']['requirements'] + input['requirementsCatalog']['editionRequirements']
    subject['requirementTrace'] = [dict(requirementId=leaf['id'], ownerModule=leaf['ownerModule'],
                                      parentClause=leaf['parentClause'], state='unknown') for leaf in leaves]
    return dict(subject, previewDigest=codec.digest(subject))


def binary(tmp_path, output, behavior="normal"):
    # A disposable transport stub tests error handling only. It is not an
    # implementation of module rules and cannot produce approved authority.
    path = tmp_path / "cadence-fixture"
    path.write_text("#!/usr/bin/python3\n" + '''import hashlib,json,sys,time
if sys.argv[1]=='version':
    digest='sha256:'+hashlib.sha256(open(sys.argv[0],'rb').read()).hexdigest()
    print(json.dumps(dict(schemaVersion='1.0.0',component='cadence-oss',releaseVersion='1.0.0',binarySha256=digest,goVersion='fixture',goos='linux',goarch='amd64',sourceRevision='unavailable',sourceModified=True)))
else:
    sys.stdin.buffer.read()
''' + ("    time.sleep(5)\n" if behavior == "timeout" else "    sys.stdout.write('x'*5000000)\n" if behavior == "oversized" else "    sys.exit(3)\n" if behavior == "rejected" else "    sys.stdout.write(" + repr(output) + ")\n"))
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def call(input, path, digest, **kwargs):
    return resolve_preview(input, binary=path, binary_sha256=digest, release_version="1.0.0", **kwargs)


def test_pinned_transport_preserves_preview_and_requires_runtime_identity(tmp_path):
    input = request()
    expected = response(input)
    path, digest = binary(tmp_path, codec.canonical(expected).decode())
    assert call(input, path, digest) == expected
    assert expected["qualificationEligible"] is False
    with pytest.raises(CadenceDependencyError):
        resolve_preview(input, binary=path, binary_sha256=digest, release_version="1.2.0-beta.1")


def test_leaf_transport_preserves_unapproved_trace_and_exact_profile(tmp_path):
    input = leaf_request()
    expected = leaf_response(input)
    path, digest = binary(tmp_path, codec.canonical(expected).decode())
    assert call(input, path, digest) == expected
    assert expected['leafMigrationComplete'] is False
    with pytest.raises(CadenceDependencyError):
        call(request(), path, digest)  # v2 cannot silently reinterpret v1.


def test_complete_mapping_transport_rejects_an_old_consumer_and_missing_denominator(tmp_path):
    current = leaf_request()
    current['contractIdentity'] = 'das-bundle-preview-input/v3'
    old = leaf_response(leaf_request())
    path, digest = binary(tmp_path, codec.canonical(old).decode())
    with pytest.raises(CadenceDependencyError):
        call(current, path, digest)
    output = deepcopy(old)
    output.update(contractIdentity='das-bundle-preview/v3', leafMigrationComplete=True,
        limitations=['facts_are_unapproved_proposals', 'protected_resolution_not_enabled'])
    subject = dict(output); subject.pop('previewDigest'); output['previewDigest'] = codec.digest(subject)
    path, digest = binary(tmp_path, codec.canonical(output).decode())
    assert call(current, path, digest) == output
    output['requirementTrace'].pop()
    subject = dict(output); subject.pop('previewDigest'); output['previewDigest'] = codec.digest(subject)
    path, digest = binary(tmp_path, codec.canonical(output).decode())
    with pytest.raises(CadenceDependencyError):
        call(current, path, digest)


@pytest.mark.parametrize('fault', ['catalog-digest', 'omit', 'duplicate', 'unknown-id', 'order', 'owner', 'parent',
                                 'state', 'extension', 'complete', 'approval', 'old-profile', 'digest'])
def test_leaf_response_cannot_change_catalog_coverage_or_claim_authority(tmp_path, fault):
    input = leaf_request()
    result = leaf_response(input)
    trace = result['requirementTrace']
    if fault == 'catalog-digest': result['requirementsCatalogDigest'] = 'sha256:' + 'a' * 64
    elif fault == 'omit': trace.pop()
    elif fault == 'duplicate': trace[-1] = deepcopy(trace[0])
    elif fault == 'unknown-id': trace[-1]['requirementId'] = 'das.security-agent.foreign'
    elif fault == 'order': trace.reverse()
    elif fault == 'owner': trace[0]['ownerModule'] = 'das.core'
    elif fault == 'parent': trace[0]['parentClause'] = 'cl-13.13'
    elif fault == 'state': trace[0]['state'] = 'PASS'
    elif fault == 'extension': trace[0]['passed'] = True
    elif fault == 'complete': result['leafMigrationComplete'] = True
    elif fault == 'approval': result['authorityVerified'] = True
    elif fault == 'old-profile': result = response(input)
    subject = dict(result)
    subject.pop('previewDigest')
    result['previewDigest'] = codec.digest(subject) if fault != 'digest' else 'sha256:' + 'f' * 64
    path, digest = binary(tmp_path, codec.canonical(result).decode())
    with pytest.raises(CadenceDependencyError):
        call(input, path, digest)


@pytest.mark.parametrize("mutation", ["wrong-scope", "wrong-facts", "wrong-policy", "wrong-catalog", "wrong-digest", "self-approval", "unknown-field", "duplicate-key", "case-fold"])
def test_invalid_response_never_becomes_authority(tmp_path, mutation):
    input = request()
    result = deepcopy(response(input))
    if mutation == "wrong-scope": result["scope"] = "other"
    elif mutation == "wrong-facts": result["factsDigest"] = "sha256:" + "1" * 64
    elif mutation == "wrong-policy": result["policyDigest"] = "sha256:" + "1" * 64
    elif mutation == "wrong-catalog": result["catalogDigest"] = "sha256:" + "1" * 64
    elif mutation == "wrong-digest": result["previewDigest"] = "sha256:" + "1" * 64
    elif mutation == "self-approval": result["authorityVerified"] = True
    elif mutation == "unknown-field": result["critical"] = True
    elif mutation == "case-fold": result["Scope"] = result.pop("scope")
    output = json.dumps(result)
    if mutation == "duplicate-key": output = output[:-1] + ',"scope":"fixture"}'
    path, digest = binary(tmp_path, output)
    with pytest.raises(CadenceDependencyError):
        call(input, path, digest)


@pytest.mark.parametrize("behavior", ["timeout", "oversized", "rejected"])
def test_dependency_failures_are_not_empty_success(tmp_path, behavior):
    input = request()
    path, digest = binary(tmp_path, "", behavior)
    with pytest.raises(CadenceDependencyError):
        call(input, path, digest, timeout=0.3)


def test_missing_component_wrong_pin_and_symlink_rejected(tmp_path):
    input = request()
    with pytest.raises(CadenceDependencyError):
        call(input, tmp_path / "missing", "sha256:" + "0" * 64)
    path, digest = binary(tmp_path, codec.canonical(response(input)).decode())
    with pytest.raises(CadenceDependencyError):
        call(input, path, "sha256:" + "0" * 64)
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(CadenceDependencyError):
        call(input, alias, digest)


def facts_wire_request():
    # Transport-only stub input, not a signed/approved fact fixture. Real native
    # signatures/current bindings are exercised in the root Go/Python exchange.
    proposal = leaf_request()
    proposal['contractIdentity']='das-bundle-preview-input/v3'
    payload = dict(scope=proposal['scope'], policyRef=dict(policyDigest=proposal['policyDigest']), facts=proposal['facts'])
    wire = dict(contractIdentity='das-approved-facts-preview-input/v1', factsEnvelope=dict(payload=base64.b64encode(codec.canonical(payload)).decode()),
                controlContext={}, catalog=proposal['catalog'], requirementsCatalog=proposal['requirementsCatalog'])
    return wire, proposal


def test_signed_facts_transport_preserves_same_preview_and_original_payload_binding(tmp_path):
    wire, proposal = facts_wire_request()
    expected = leaf_response(proposal)
    path, digest = binary(tmp_path, codec.canonical(expected).decode())
    assert resolve_facts_preview(wire, binary=path, binary_sha256=digest, release_version='1.0.0') == expected
    assert not expected['authorityVerified'] and not expected['qualificationEligible']


@pytest.mark.parametrize('fault', ['missing-envelope', 'wrong-profile', 'alternate-facts', 'bad-base64',
                                 'whitespace-base64', 'bad-json', 'missing-payload-binding', 'wrong-response-facts',
                                 'wrong-response-scope', 'missing-leaf', 'authority', 'rejected'])
def test_signed_facts_transport_failures_cannot_become_approved_results(tmp_path, fault):
    wire, proposal = facts_wire_request()
    output = leaf_response(proposal)
    if fault == 'missing-envelope': del wire['factsEnvelope']
    elif fault == 'wrong-profile': wire['contractIdentity'] = 'das-bundle-preview-input/v2'
    elif fault == 'alternate-facts': wire['facts'] = []
    elif fault == 'bad-base64': wire['factsEnvelope']['payload'] = 'not!base64'
    elif fault == 'whitespace-base64': wire['factsEnvelope']['payload'] += '\n'
    elif fault == 'bad-json': wire['factsEnvelope']['payload'] = base64.b64encode(b'{"scope":"first","scope":"second"}').decode()
    elif fault == 'missing-payload-binding': wire['factsEnvelope']['payload'] = base64.b64encode(b'{}').decode()
    elif fault == 'wrong-response-facts': output['factsDigest'] = 'sha256:' + 'f' * 64
    elif fault == 'wrong-response-scope': output['scope'] = 'another-project'
    elif fault == 'missing-leaf': output['requirementTrace'].pop()
    elif fault == 'authority': output['authorityVerified'] = True
    # A malicious but correctly pinned transport stub may recompute its own
    # digest; context/coverage checks must independently reject the change.
    subject = dict(output); subject.pop('previewDigest')
    output['previewDigest'] = codec.digest(subject)
    path, digest = binary(tmp_path, codec.canonical(output).decode(), 'rejected' if fault == 'rejected' else 'normal')
    with pytest.raises((CadenceDependencyError, ValueError)):
        resolve_facts_preview(wire, binary=path, binary_sha256=digest, release_version='1.0.0')


@pytest.mark.parametrize("raw", [b"1e16", b"295147905179352830000", b"1.2345", b"1e-7"])
def test_generic_jcs_reads_its_own_numeric_output(raw):
    first=codec.canonical(codec.parse(raw))
    assert codec.canonical(codec.parse(first))==first


def test_generic_jcs_still_rejects_rounding_unsafe_integer():
    with pytest.raises(ValueError):
        codec.canonical(codec.parse(b"9007199254740993"))
