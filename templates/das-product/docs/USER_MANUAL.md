# Product Repo Manual

Audience

This manual is written for an intern who is new to multi-branch development and AI-assisted coding.

Prerequisites

- `dasops` is installed on your machine
- `codex` CLI is installed and authenticated

Core rule

Tooling and product repositories must be physically isolated.

If the tooling repo and the product repo share a folder, AI agents will eventually run the wrong code.

Section 1. Deterministic truth paths

Do not allow AI tools to invent new truth file locations.

The only allowed paths are:

- System truth
  - `docs/master_doc.md`
  - `docs/ui_spec.md`
  - `STANDARD_REF.md`
  - `tooling_lock.json`
  - `local_extension_manifest.json`
- Change truth
  - `openspec/changes/<change-id>/master_doc_delta.md`
  - `openspec/changes/<change-id>/contracts_plan.md`
  - `openspec/changes/<change-id>/verification_plan.md`
  - `openspec/changes/<change-id>/tasks.md`
- Coordination locks
  - `openspec/changes/<change-id>/task_locks/<task-id>.lock`

If any new `tasks.md` appears outside these folders, treat it as a failure.

Section 2. Orchestrator workflow

Orchestrator owns the plan.

Orchestrator creates and maintains the change artifacts and the task plan.

Step 1. Create a change folder

```
dasops new-change --id add-login --intent "Add login"
```

If you want an automatic change id:

```
dasops new-change --id auto --intent "Add login"
```

Step 2. Use the Orchestrator prompt

Open this file and paste it into the Codex IDE agent chat.

`prompts/orchestrator.md`

Replace `{{CHANGE_ID}}` with your change id.

Step 3. Produce a stable tasks file

The tasks plan of record is:

`openspec/changes/<change-id>/tasks.md`

It must contain a single canonical task index table.

Task IDs are sequential and stable.

T-001, T-002, T-003.

Every task has a verify gate command.

Step 4. Assign owners

Orchestrator assigns owners in `tasks.md`.

Workers must not override an Orchestrator assignment.

Section 3. Worker workflow

Workers implement only the tasks assigned to them.

Step 1. Start a task

Pick the coordination mode from `tasks.md`.

Pull mode:

```
export DASOPS_OWNER=worker01
dasops claim-ready --change-id add-login
```

Push mode:

```
export DASOPS_OWNER=worker01
dasops start-task --change-id add-login --task-id T-001
```

This creates a feature branch, creates a worktree, and claims the task lock.

Step 2. Run the Codex worker loop

Inside the worktree:

```
./scripts/run_worker_codex.sh add-login T-001 worker01
```

This renders `prompts/worker.md` and runs `codex exec --full-auto`.

Step 3. Complete the task

```
./scripts/verify
dasops complete-task --change-id add-login --task-id T-001

git add -A
git commit -m "T-001: <summary>"
git push -u origin HEAD
```

Open a pull request and let CI run the verify gates again.

Section 4. Git worktree basics

Worktrees let you check out multiple branches at the same time.

List worktrees

```
git worktree list
```

Remove a worktree

```
git worktree remove <path>
git worktree prune
```

Section 5. Cadence integration

Cadence provides deterministic verification and evidence artifacts.

Vendor Cadence

```
./scripts/install_cadence_vendor.sh --from-suite /path/to/suite --commit "$CADENCE_COMMIT"
```

Set `CADENCE_COMMIT` to the full 40-character commit selected for your product.
Local mode reads an independent Git checkout at `suite/src/cadence-oss` or the
legacy sibling `cadence-oss`; only committed files at that SHA are installed.
A source archive without Git identity is refused. Git, Go, Python and Linux
`flock` are required. On creation, `dasops create --runtime-commit "$CADENCE_COMMIT"`
records this selection. For an existing product, explicitly update only
`tooling_lock.json.verifyRuntime` to `kind: git`,
`uri: ./vendor/cadence/cadence-oss`, `pinType: commit`, `pinValue: <full SHA>`,
`floating: false`. Installation refuses a missing or mismatched declaration;
it does not rewrite the product lock for you.

Or clone from a Git base:

```
./scripts/install_cadence_vendor.sh --git-base https://github.com/<org> --commit "$CADENCE_COMMIT"
```

Clone mode is fail-closed: pass `--git-base`, `--org`, or set
`DAS_SUITE_GIT_BASE`, plus the full commit. The installer builds and verifies
the selected binary before replacing the old installation. Use `--force` to
replace explicitly; a failed build or identity check leaves the old installation
untouched. Only registry resources, licenses, VERSION and the binary are installed;
build sources, tests and Git databases are not retained in the product.
Resources, binary and declared runtime are checked by `cadencew`
on execution; PATH fallback and automatic rebuilding are disabled. Reinstall
explicitly after changing the selected source or runtime declaration.
The wrapper holds a shared guard during native execution; replacement waits.
If replacement fails and another directory occupies the destination, the error
prints the preserved previous-installation path. Inspect that backup and the
occupied destination before restoring; automatic cleanup does not delete either.

Run Cadence on this repo

The default Factory seed retains its legacy 1.4 configuration. Before invoking
the native CLI, supply valid `closureRef`, `toolingLock`, `runtimeRef`, `registryRef`
and `sandboxRef` inputs following the installed Cadence version's contract.
Installing a binary or copying the vendor folder does not create these inputs
or approve 1.5 adoption; the native gate refuses an unconfigured project.
For a ready synthetic example, use Cadence's public
`cadence-examples/examples/headless-minimal` separately.

```
./cadencew verify --profile dev
```

Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof.

Default `./scripts/verify` (also `--scope full`) requires the verified installation
and runs `./cadencew verify --profile dev`; missing runtime or native failure is
a failure. Use `./scripts/verify --scope scaffold` for local checks before setup;
it explicitly reports Cadence execution pending. The generated CI uses full scope:
add your pinned installation and native configuration setup before that gate.
The ignored `vendor/cadence` resources and binary must be recreated on each runner.
Old unrecorded installations need explicit pinned reinstall before the new wrapper
can run them. These checks do not certify all DAS requirements.

Evidence output is written to:

`.cadence/out/<run-id>/`

The latest alias is:

`.cadence/out/latest/`

Health check and sub-system verification:

```
dasops doctor
scripts/verify-backend
scripts/verify-frontend
```

Product UI tests should implement a visual regression baseline ratchet.
The shipped `scripts/verify-frontend` checks only `visualMatrix` structure and
file presence, not visual comparisons, review or approval. Main verify selects
it through boolean legacy `ui.enabled`; an explicit call forces it once.
The matrix schema is `openspec/schemas/das-standard/visual_matrix.schema.json`.
The template presence check expects:

- `artifacts/frontend/visualMatrix.json` to match the governed `viewports`,
  `themes`, and `locales` array contract
- `artifacts/frontend/baseline/` to exist and contain baseline artifacts
- `artifacts/frontend/screenshots/` to exist and contain caller-supplied files
