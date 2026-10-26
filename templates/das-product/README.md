# Product Repo (DAS + OpenSpec)

This repository was scaffolded using **DAS + OpenSpec Factory**.

## What you get

- **DAS-aligned docs**
  - `docs/master_doc.md` (canonical requirements + topology + contracts + verify gates)
  - `docs/ui_spec.md` (workflow + screen/state spec)
  - `STANDARD_REF.md` (canonical standard reference)
  - `tooling_lock.json` (repo-local toolchain and runtime pin)
  - `local_extension_manifest.json` (registered local deviations/extensions)

- **OpenSpec change workflow (OPSX-style)**
  - `openspec/changes/<change-id>/` holds change-scoped artifacts:
    - `master_doc_delta.md`
    - `contracts_plan.md`
    - `verification_plan.md`
    - `tasks.md`
    - `task_locks/` (anti-collision locks, e.g. `T-001.lock`)

- **Verification gates**
  - `./scripts/verify` (full checks, including verified local Cadence; requires installation and valid native configuration)
  - `./scripts/verify --scope scaffold` (local checks only; reports Cadence execution pending)
  - `./scripts/verify-backend`, `./scripts/verify-contracts` (fail-closed gates until repo-specific evidence exists)
  - `./scripts/verify-frontend` (fail-closed matrix/file-presence check requiring `artifacts/frontend/visualMatrix.json` to match `openspec/schemas/das-standard/visual_matrix.schema.json`, plus `artifacts/frontend/baseline/` and `artifacts/frontend/screenshots/`)
  - Frontend products need actual visual regression and baseline ratchet tests; this helper checks only matrix structure and non-empty directories. Main verify selects it via boolean `ui.enabled` or explicit `--frontend`.

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
  - `./scripts/install_cadence_vendor.sh --from-suite /path/to/suite --commit "$CADENCE_COMMIT"` (full 40-character commit; Suite src layout or an independent sibling Git checkout)
  - `./scripts/install_cadence_vendor.sh --git-base https://github.com/<org> --commit "$CADENCE_COMMIT"` (explicit source and commit; builds and verifies before replacing)
  - Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof.

## Start here

1. Read `docs/USER_MANUAL.md`.
2. Run `./scripts/verify --scope scaffold`. Install the chosen Cadence commit and configure its native inputs before the full `./scripts/verify` gate, including in CI. The wrapper never falls back to PATH.
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
