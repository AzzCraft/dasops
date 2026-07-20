<!-- DASOPS:DRAFT -->
> **Draft marker:** remove the `<!-- DASOPS:DRAFT -->` line when this artifact is complete (so `dasops status` can mark it as DONE).

# Execution Tasks (DAS §11 aligned)

> Orchestrator owns this file.
>
> Rules:
> - Every task MUST include: Task ID, Owner, Scope, Contract impact, and an executable verification command.
> - Default model: one task maps to one owner and one branch.
> - If a Worker discovers missing work, they may only add items under Proposed tasks at the end. The Orchestrator decides whether to promote them into the main plan.
>
> Dispatch model:
> - **Pull (recommended)**: set `Owner = -` for most tasks; Workers run `dasops claim-ready` to claim the next READY task (when dependencies are DONE).
> - **Push**: Orchestrator sets an explicit Owner; Workers run `dasops claim-task` for that task.
>
> Before starting work, Workers MUST claim a task:
>
> Pull: `dasops claim-ready --change-id <change-id> --owner <owner>`
>
> Push: `dasops claim-task --change-id <change-id> --task-id T-001 --owner <owner>`
>
> This sets task status to IN_PROGRESS and writes a lock file:
>
> `openspec/changes/<change-id>/task_locks/T-001.lock`

## Task index

| Task ID | Title | Owner | Status | Depends on | Verify gate |
|---|---|---|---|---|---|
| T-001 | <short title> | - | TODO | - | `./scripts/verify ...` |

Status values: TODO | IN_PROGRESS | DONE | BLOCKED | PROPOSED

## Task details

### T-001: <short task title>
- Owner: -
- Status: TODO
- Branch: `feat/<change-id>/T-001-...`
- Scope (repo/module):
- Contract impact: None | Additive | Behavioral | Breaking
- Determinism tier impact:
- Budgets impact:
- Dependencies:
  - ...
- Acceptance criteria:
  - [ ] ...
- Verification:
  - `./scripts/verify ...`

### T-002: <short task title>
- Owner: -
- Status: TODO
- Branch: `feat/<change-id>/T-002-...`
- Scope (repo/module):
- Contract impact: None | Additive | Behavioral | Breaking
- Determinism tier impact:
- Budgets impact:
- Dependencies:
  - ...
- Acceptance criteria:
  - [ ] ...
- Verification:
  - `./scripts/verify ...`

## Proposed tasks

> Add new items here with **Status = PROPOSED**. Do not start work until Orchestrator assigns an Owner and verify gate.

- PROPOSED: <description>
