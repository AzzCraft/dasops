# Do not blame the AI

This note turns common AI-coding failure patterns into executable repository rules.

Principle 1. Fix the truth paths

AI tools drift when the repository allows multiple competing sources of truth.

In this system, truth paths are treated as a contract:

- System truth
  - `docs/master_doc.md`
  - `docs/ui_spec.md`
- Change truth
  - `openspec/changes/<change-id>/master_doc_delta.md`
  - `openspec/changes/<change-id>/contracts_plan.md`
  - `openspec/changes/<change-id>/verification_plan.md`
  - `openspec/changes/<change-id>/tasks.md`

Anything else is drift.

Enforcement

- `./scripts/verify` fails on stray `tasks.md` or legacy delta folders.
- `dasops doctor` performs additional sanity checks.

Principle 2. External memory is mandatory

AI has limited memory across sessions. Humans also lose context across branches and windows.

Use these stable files:

- `progress.txt` for status handoffs
- `prompts/` for stable agent instructions
- `docs/master_doc.md` and `docs/ui_spec.md` as the system contract

Principle 3. Gates beat good intentions

Every task must list an exact verify command.

Workers must run the task gate and `./scripts/verify` before committing.

Principle 4. Coordination must be mechanical

Multi-worker projects fail when task ownership is informal.

This scaffold uses lock files:

`openspec/changes/<change-id>/task_locks/<task-id>.lock`

Workers claim tasks with `dasops claim-task` or `dasops start-task`.

Result

When the paths are fixed, the gates are explicit, and coordination is mechanical, AI output becomes controllable.
