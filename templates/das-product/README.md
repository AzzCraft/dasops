# Product Repo (DAS + OpenSpec)

This repository was scaffolded using **DAS + OpenSpec Factory**.

## What you get

- **DAS-aligned docs**
  - `docs/master_doc.md` (canonical requirements + topology + contracts + verify gates)
  - `docs/ui_spec.md` (workflow + screen/state spec)
  - `STANDARD_REF.md` (canonical standard reference)

- **OpenSpec change workflow (OPSX-style)**
  - `openspec/changes/<change-id>/` holds change-scoped artifacts:
    - `master_doc_delta.md`
    - `contracts_plan.md`
    - `verification_plan.md`
    - `tasks.md`
    - `task_locks/` (anti-collision locks, e.g. `T-001.lock`)

- **Verification gates**
  - `./scripts/verify` (minimum checks; expand per repo)
  - `./scripts/verify-backend`, `./scripts/verify-contracts` (fail-closed gates until repo-specific evidence exists)
  - `./scripts/verify-frontend` (real fail-closed visual regression gate requiring `artifacts/frontend/visualMatrix.json` to match `openspec/schemas/das-standard/visual_matrix.schema.json`, plus `artifacts/frontend/baseline/` and `artifacts/frontend/screenshots/`)
  - Frontend repos should treat `./scripts/verify-frontend` as the visual regression and baseline ratchet gate.

- **Agent governance**
  - `docs/policies/AGENT_OPERATING_MODEL.md`
  - `AGENTS.override.md` (Codex instruction overrides)
  - `CLAUDE.md` (AI rules for tools that auto-load it)
  - `progress.txt` (external memory / project progress)

- **Prompt templates**
  - `prompts/orchestrator.md`
  - `prompts/worker.md`

## Start here

1. Read `docs/USER_MANUAL.md`.
2. Run `./scripts/verify`.
3. Create your first change folder:

```bash
# Example
python3 -m pip install -U pip
# If you installed dasops via the factory repo:
dasops new-change --id add-feature-x --intent "Add feature X"
```

4. Before a Worker starts coding, claim the task (anti-collision lock):

Pull mode:

```bash
dasops claim-ready --change-id <change-id> --owner worker01
```

Push mode:

```bash
dasops start-task --change-id <change-id> --task-id T-001 --owner worker01
```

Then run the Worker loop:

```bash
./scripts/run_worker_codex.sh <change-id> T-001 worker01
```

## Notes

- Keep `main` protected. Merge via PRs only.
- Treat contracts and verify gates as non-negotiable release safety rails.
- Run `dasops doctor` to check repo health before starting work.
- This v1.0 scaffold is standalone. Add Cadence/suite integration only after
  your owner has supplied a complete, immutable, schema-valid closure.
