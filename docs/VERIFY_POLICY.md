# Verify Policy

## Purpose

This document defines the verification policy for DAS product repositories and the dasops factory itself.

## Verification Layers

### Layer 1: Repository Structure

Checks that required files exist:

- VERSION, CHANGELOG.md, README.md
- LICENSE, NOTICE
- scripts/verify
- BUILD_REQUIREMENTS.md, VERIFY_REQUIREMENTS.md
- cadence.yaml (or cadence.yml)

### Layer 2: Schema Validity

Checks that structured files are well-formed:

- `cadence.yaml` parses correctly
- `openspec/config.yaml` has required schema fields (`schema`, `product_name`)
- `tooling_lock.json` is valid JSON with required top-level keys
  (`schemaVersion`, `standardManifestVersion`, `sourceOfTruth`, `verifyRuntime`)
  and ref-object keys where applicable
- `local_extension_manifest.json` is valid JSON with required top-level keys
  (`schemaVersion`, `standardManifestVersion`, `extensions`) and `extensions` is
  a list
- `cadence.lock` (if present) is valid JSON

### Layer 3: Contract Consistency

Checks cross-file consistency:

- `STANDARD_REF.md` references a known standard version
- `cadence.yaml` baseline reference is not stale
- `tooling_lock.json` matches expected schema version
- VERSION file matches CHANGELOG.md latest entry
- Stale task locks detected (lock heartbeat older than 24 hours)
- `tasks.md` table format validated (canonical header, allowed status values,
  verify-gate column present)
- Stray `tasks.md` files outside `openspec/changes/` detected

### Layer 4: Forbidden Patterns

Checks that banned patterns are absent:

- No `docs/standards/DAS_STANDARD.md` (copied standard)
- No legacy `current-baseline` baseline references
- No absolute filesystem paths (`<sandbox-root>/`, etc.)
- No `git clone --depth 1` in verification scripts

## Factory Self-Verify

`dasops/scripts/verify` validates:

1. Template completeness
2. All Python files import cleanly
3. No forbidden patterns in templates
4. Generated repos pass their own verify

## CI Integration

Every push and PR triggers `.github/workflows/verify.yml`, which runs the full verify chain.

Release candidates can run the manually triggered `.github/workflows/release.yml` for verification, tool-asset build/install and evidence. It does not create a tag, move a ref or publish a GitHub Release; the authorized publisher performs those separate actions under `docs/RELEASE_PROCESS.md`.
