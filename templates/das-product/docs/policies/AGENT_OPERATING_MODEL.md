# Agent Operating Model (DAS + OpenSpec)

This document defines the **human + AI** operating model for this repo.

The goal is safe, fast multi-worker delivery **without** architecture drift:

- DAS provides the governance (contracts + verify gates + traceability).
- OpenSpec-style change folders provide the change-level execution container.
- Task locks provide a small, mechanical guardrail against duplicate work.

In addition, we standardize **artifact paths** (fixed folders/filenames) to
reduce AI drift and to make automation/CI reliable.

---

## 1. Roles and authority

### 1.1 Orchestrator (single point of authority)

Orchestrator responsibilities:

- Own and maintain:
  - `docs/master_doc.md` (the project “constitution”)
  - `docs/ui_spec.md` (UI contract)
- For each change:
  - Create and maintain `openspec/changes/<change-id>/` artifacts
  - Generate/curate `tasks.md` (WBS), assign Owners, define dependencies
  - Define/confirm **verify gates** (exact commands)
- Review and merge PRs only after verify gates are green
- Run sync: when a change affects system-level decisions, **sync back** into `docs/master_doc.md` (traceability + verify commands + WBS summary)

Master Doc rule:

- `docs/master_doc.md` must contain traceability from requirements to contracts and verify gates.
- If a change impacts any part of that mapping, the Orchestrator must update the Master Doc before merging.

### 1.2 Worker (executor)

Worker responsibilities:

- Execute **only** the tasks assigned to them in `openspec/changes/<change-id>/tasks.md`
- Before coding: claim the task (lock + owner + status)
- During coding: keep changes within task scope and run the exact verify gate
- After finishing: mark the task DONE and open a PR

Workers **must not**:

- Rewrite `tasks.md` execution plan (except “Proposed tasks”, see below)
- Change contracts across boundaries without Orchestrator approval
- Skip verify gates or merge directly to `main`

---

## 2. Where tasks are recorded

We keep **two tracks** to satisfy “history + current truth”:

### 2.1 Change-level (best for multi-agent execution)

- `openspec/changes/<change-id>/tasks.md`
  - The execution plan for **this** change
  - Owners, dependencies, per-task verify commands
  - Best place for Worker coordination

### 2.2 Project-level (system truth)

- `docs/master_doc.md` (see DAS §11)
  - System-level verify commands
  - High-level WBS, acceptance checklist
  - **Traceability index**: requirements → contracts → verify/tests

**Rule (mandatory):** If a change modifies requirements, contracts, verify commands, or cross-module topology, Orchestrator must sync the updates into `docs/master_doc.md`.

---

## 3. Deterministic artifact paths (mandatory)

AI tools often “helpfully” create new folders or alternative files (e.g. new `tasks.md` in another location). In multi-agent development this quickly becomes unreviewable.

**Hard rules:**

1) **Change artifacts live only here**:

- `openspec/changes/<change-id>/master_doc_delta.md`
- `openspec/changes/<change-id>/contracts_plan.md`
- `openspec/changes/<change-id>/verification_plan.md`
- `openspec/changes/<change-id>/tasks.md`

2) **No legacy delta folders**: do not create `docs/deltas/...` or `docs/delta/...`.

3) **No stray `tasks.md`**: the only authoritative tasks file is `openspec/changes/<change-id>/tasks.md`.

4) **Enforcement**: `./scripts/verify` includes a deterministic layout check and will fail the build if it finds stray files.

These rules implement the “don’t blame AI” principle: if outputs are not deterministic, the process is broken, not the agent.

---

## 4. Traceability rule (DAS-aligned)

The project must maintain traceability:

- Requirements → Contracts → Verification gates/tests

Minimum expectation:

- Each requirement ID referenced in `docs/master_doc.md` maps to:
  - at least one contract (schema/API/event)
  - at least one verification gate (script/command)

If Workers implement code without an associated requirement mapping, Orchestrator should treat it as out-of-scope until the mapping is added.

---

## 5. Task claim lock mechanism

### 4.1 Why locks

In multi-worker mode, two workers can accidentally pick the same task (especially when using AI agents).

We add a mechanical lock to reduce collisions:

- Lock directory: `openspec/changes/<change-id>/task_locks/`
- Lock file: `openspec/changes/<change-id>/task_locks/<task-id>.lock`

### 4.2 Recommended command

Prefer:

- `dasops start-task` (creates a branch/worktree **and** claims the task)

Fallback:

- `dasops claim-ready` (pull mode: claim the next READY task)
- `dasops claim-task` (claim only; you manage branch/worktree yourself)

### 4.3 One Task = One Owner = One Branch

Default policy:

- Branch naming: `feat/<change-id>/<task-id>-<short>`
- One branch implements exactly one Task ID

### 4.4 Conflict handling

If a lock exists and owner is not you:

- Worker must stop and notify Orchestrator
- Orchestrator decides whether to reassign or (rarely) force-claim

`--force` should be treated as an Orchestrator-only tool.

---

## 6. Worker workflow requirements

### 5.1 Before coding

Worker must:

1) Ensure they are **not** on `main`
2) Claim the task:

```bash
export DASOPS_OWNER=<your-worker-id>

dasops start-task --change-id <change-id> --task-id T-001
# or: dasops claim-ready --change-id <change-id>
# or: dasops claim-task --change-id <change-id> --task-id T-001
```

### 5.2 During coding

Worker must:

- Run baseline: `./scripts/verify`
- Run the task’s verify gate (from `tasks.md`)
- Keep changes within scope

### 5.3 Finishing

Worker should:

```bash
# mark DONE (updates tasks.md + lock)
dasops complete-task --change-id <change-id> --task-id T-001

./scripts/verify

git add -A

git commit -m "T-001: <short summary>"

git push -u origin HEAD
```

---

## 7. Proposed tasks and change requests

Workers may discover missing work.

Workers must **not** directly rewrite the WBS.

Instead, Workers may:

- Append to the **Proposed tasks** section in `openspec/changes/<change-id>/tasks.md` (status `PROPOSED`), and/or
- Add an ADR (`docs/adr/ADR-XXXX.md`) or open questions note (`openspec/changes/<change-id>/open_questions.md`)

Orchestrator decides whether to add/approve and assigns Owner + verify gate.

---

## 8. Tooling notes

- Prefer `git worktree` for running multiple Workers on one machine.
- Keep AI instructions + progress in stable files:
  - `CLAUDE.md` / `AGENTS.override.md` — operating rules
  - `progress.txt` — external memory (update each session)
- Prefer Codex CLI for autonomous loops:

```bash
codex exec --full-auto --sandbox workspace-write "<your prompt>"
```

See `docs/USER_MANUAL.md` for step-by-step intern instructions.
