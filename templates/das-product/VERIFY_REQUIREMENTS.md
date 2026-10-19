# Verify Requirements

## What `scripts/verify` checks

1. Required DAS shell files exist.
2. Seed contract integrity (STANDARD_REF.md, core-v146-baseline policy).
3. Master doc minimum sections.
4. Deterministic layout.
5. Task lock schema.
6. Frontend evidence gate (main verify when `cadence.yaml` has boolean `ui.enabled: true`, or explicitly `scripts/verify-frontend`): `scripts/verify-frontend` requires
   `artifacts/frontend/visualMatrix.json` to match
   `openspec/schemas/das-standard/visual_matrix.schema.json`, plus non-empty
   `artifacts/frontend/baseline/` and `artifacts/frontend/screenshots/`.

## Prerequisites

- python3 >= 3.11
- bash

This legacy gate checks matrix structure and file presence only, once per invocation. It does not perform visual comparison, UI workflow validation or approve a DAS 1.5 applicability fact.
Task-state readers share the local change guard and reject unresolved recovery records. Stop all old workers before upgrading one coordinated worktree; separate clones are not coordinated.
