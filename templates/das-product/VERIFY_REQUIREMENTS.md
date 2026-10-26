# Verify Requirements

## What `scripts/verify` checks

1. Required DAS shell files exist.
2. Seed contract integrity (STANDARD_REF.md, core-v146-baseline policy).
3. Master doc minimum sections.
4. Deterministic layout.
5. Task lock schema.
6. Frontend evidence gate (main verify when `cadence.yaml` has boolean `ui.enabled: true`, or explicitly `scripts/verify-frontend`): `scripts/verify-frontend` requires
   `artifacts/frontend/visualMatrix.json` to match
   `openspec/schemas/das-standard/visual_matrix.schema.json`, plus at least one ordinary evidence file in each of
   `artifacts/frontend/baseline/` and `artifacts/frontend/screenshots/`.

7. Default/full scope requires the recorded fixed Cadence installation and executes its native verify command. Missing, changed or failing runtime is a failure.

`./scripts/verify --scope scaffold` runs the local checks above without Cadence and
prints an explicit pending notice. It is not full verification. The native config
must be prepared for the chosen version; installation does not invent these inputs.

## Prerequisites

- Python >= 3.10; install the product’s `requirements.txt` (PyYAML and jsonschema).
- Bash (not POSIX sh).
- Python and Linux file locking for installed identity checks; Git, Go and
  `flock` additionally for installation. The installed resources need no Git checkout.
- Full scope: an explicit fixed install via `scripts/install_cadence_vendor.sh --commit "$CADENCE_COMMIT"` and a selected source, plus valid native configuration.
  The product's `tooling_lock.json.verifyRuntime` must declare that same Git
  commit; new 1.4 projects can set it with `dasops create --runtime-commit`.

JSON Schema validation uses the delivered local schemas and rejects remote reference retrieval. Frontend constraints such as `enum` are enforced; no network schema download is required.

This legacy gate checks matrix structure and file presence only, once per invocation. It does not perform visual comparison, UI workflow validation or approve a DAS 1.5 applicability fact.
Task-state readers share the local change guard and reject unresolved recovery records. Stop all old workers before upgrading one coordinated worktree; separate clones are not coordinated.
