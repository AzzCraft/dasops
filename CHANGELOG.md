# Changelog

## v1.2.0-beta.1 — Unreleased

- Add current physical Standard/Bundle consumption and authenticated candidate
  preparation, integration, Completion, and original-receipt recovery references.
- Use VERSION as the sole package version author; Python wheel metadata spells
  this release as 1.2.0b1. Final beta installation and release remain unfinished.

## v1.1.0rc12 — 2026-07-22

- Make the public `scripts/verify` bootstrap its reviewed exact verification
  environment when a direct host invocation lacks `pytest-timeout` or another
  required verification dependency. The temporary environment is outside the
  source tree and is removed after the run, while already-provisioned release
  environments remain in use unchanged.

## v1.1.0rc11 — 2026-07-22

- Complete the public Cadence OSS-only boundary in scaffold documentation and
  template-audit parity checks. The source-level regression now checks private
  identifiers without embedding a private product name in the public candidate.

## v1.1.0rc10 — 2026-07-22

- Removed optional private-tier Cadence vendoring from the public DASOps
  scaffold. The public installer now accepts and installs Cadence OSS only,
  so public templates and their tests do not name or attempt to retrieve
  private product repositories.

## v1.1.0rc9 — 2026-07-22

- Upgrade the pinned build backend to `setuptools==83.0.0` and
  `wheel==0.46.2` after the exact candidate dependency audit identified known
  vulnerabilities in the prior lock.

## v1.1.0rc8 — 2026-07-22

- Execute final task verification gates as a parsed argv vector, rejecting
  shell operators instead of evaluating task metadata with `shell=True`.

## v1.1.0rc7 — 2026-07-22

- Preserve the protected launcher's strict trusted-owner check while making
  local acceptance explicit: hosts that rewrite `/usr/bin/bwrap` ownership
  report skipped execution acceptance instead of weakening the invariant.

## v1.1.0rc6 — 2026-07-22

- Resolve every public integration test's component root at runtime and source
  the closure-schema fixture from the exported template, so the candidate does
  not depend on a sibling DAS Tools checkout.

## v1.1.0rc5 — 2026-07-22

- Remove the DAS Tools-only protected release-builder regression test from the
  public candidate itself, so both the documented manifest and an ordinary
  public `pytest` collection remain self-contained.

## v1.1.0rc4 — 2026-07-22

- Make the public verification manifest standalone: retain all portable
  protected-state tests and keep the DAS Tools-only release-builder test out
  of the exported candidate.

## v1.1.0rc3 — 2026-07-22

- Include the optional Streamlit factory GUI and its separately installed,
  version-locked dependency file in the public candidate. This repairs the
  public README/audit contract: every documented public entry point now ships
  in the same immutable candidate that verifies it.

## v1.1.0rc2 — 2026-07-22

- Added strict canonical protected task-state contracts and an access-controlled
  bare-repository pull lifecycle with exact-base CAS and recovery journals.
- Added protected completion and atomic routing transactions with independently
  verifiable approval boundaries.
- Added exact-commit no-ref materialization and a digest-pinned Bubblewrap
  launcher with clean environment, bounded output, no network, and FD-only
  secret transport.
- Added a reproducible offline wheel/source candidate, dependency lock, SPDX
  SBOM, SLSA provenance, installed-file inventory, and frozen review packet.
- Repaired the three inherited test-suite defects identified at bootstrap.
- Added fail-closed generic bootstrap authority, attempt-registry, claim/adoption,
  Foundation Verification and repository-handoff foundations, including real
  old-non-bare/new-bare Git adoption
  controllers, a real exact-base non-bare Git claim publisher and an authenticated
  authority-side dispatch core. A concrete OpenSSL Ed25519 adapter now enforces
  exact DER-key fingerprints, identity/role bindings, raw signature verification
  and immutable retry-stable verification receipts. These remain release-candidate
  capabilities pending the external trust chain and the still-open product-
  handler/recovery/rotation gates.
- Replaced fixed-padding token and challenge decoding with strict canonical
  unpadded-base64url decoding, repairing an inherited 32-byte private-lock failure
  exposed by the broad bootstrap gate.
- Added the first authenticated upstream-core operation handler: real
  `register_attempt` execution over a set-equal owner-only input package, externally
  pinned empty/current/retry-prestate head, real Git-main readback and the
  crash-safe append-only registry coordinator. Product projection adapters remain
  explicitly blocked.
- Added a fail-closed registered/not-started `cancel_attempt` handler with exact
  retry-prestate recovery, unchanged-Git/no-legacy-state proof and strict external
  authorization loading. Candidate/residual cancellation remains unavailable.

## v1.0.0 — 2026-04-08

- Split the monolithic factory core into dedicated repo-factory, task, lock, doctor, adopt, and vendor modules.
- Added structured YAML task locks and the `dasops lock-status` CLI surface.
- Reseeded the product template to use `STANDARD_REF.md`, `tooling_lock.json`, and `local_extension_manifest.json`.
- Standardized the Cadence vendor installer on named flags and the public `vendor/cadence/cadence-oss` path.
- Replaced placeholder template sub-verifies with explicit fail-closed skeletons.
