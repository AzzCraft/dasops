# Product Repo (DAS + OpenSpec)

This repository was scaffolded using **DAS + OpenSpec Factory**.

## What you get

- **DAS-aligned docs**
  - `docs/master_doc.md` (canonical requirements + topology + contracts + verify gates)
  - `docs/ui_spec.md` (workflow + screen/state spec)
  - `docs/standards/DAS_STANDARD.md` (reference standard)

- **OpenSpec change workflow (OPSX-style)**
  - `openspec/changes/<change-id>/` holds change-scoped artifacts:
    - `master_doc_delta.md`
    - `contracts_plan.md`
    - `verification_plan.md`
    - `tasks.md`
    - `task_locks/` (anti-collision locks, e.g. `T-001.lock`)

- **Verification gates**
  - `./scripts/verify` (minimum checks; expand per repo)
  - `./scripts/verify-backend`, `./scripts/verify-frontend`, `./scripts/verify-contracts` (placeholders)

- **Agent governance**
  - `docs/policies/AGENT_OPERATING_MODEL.md`
  - `AGENTS.override.md` (Codex instruction overrides)
  - `CLAUDE.md` (AI rules for tools that auto-load it)
  - `progress.txt` (external memory / project progress)

- **Prompt templates**
  - `prompts/orchestrator.md`
  - `prompts/worker.md`

- **Cadence integration hooks**
  - `cadence.yaml`
  - `cadencew`
  - `./scripts/install_cadence_vendor.sh` (optional)

## Start here

1. Read `docs/USER_MANUAL.md`.
2. Run `./scripts/verify`.
3. Create your first change folder:

```bash
# Example
python -m pip install -U pip
# If you installed dasops via the factory repo:
dasops new-change --id add-feature-x --intent "Add feature X"
```

4. Before a Worker starts coding, claim the task (anti-collision lock):


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
