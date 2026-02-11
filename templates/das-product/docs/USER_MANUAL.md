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

The safest intern flow is a single command.

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
./scripts/install_cadence_vendor.sh submodule https://github.com/<org>/cadence.git
```

Run Cadence on this repo

```
./cadencew verify --profile dev
```

When Cadence is vendored under `vendor/cadence`, `./scripts/verify` also runs `./cadencew verify --profile dev`.

Evidence output is written to:

`.cadence/out/<run-id>/`

The latest alias is:

`.cadence/out/latest/`
