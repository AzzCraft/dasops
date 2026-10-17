# Verify Requirements

## What `scripts/verify` checks

1. Required DAS shell files exist.
2. Seed contract integrity (STANDARD_REF.md, core-v146-baseline policy).
3. Master doc minimum sections.
4. Deterministic layout.
5. Task lock schema.
6. Frontend evidence gate: `scripts/verify-frontend` requires
   `artifacts/frontend/visualMatrix.json` to match
   `openspec/schemas/das-standard/visual_matrix.schema.json`, plus non-empty
   `artifacts/frontend/baseline/` and `artifacts/frontend/screenshots/`.

## Prerequisites

- python3 >= 3.11
- bash
