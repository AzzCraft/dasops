# Do not blame the AI

AI-assisted coding fails most often because the repository allows ambiguity.

This guide turns that observation into mechanical rules.

Rule 1. Fix the truth paths

Truth paths are part of the contract.

- System truth
  - `docs/master_doc.md`
  - `docs/ui_spec.md`
- Change truth
  - `openspec/changes/<change-id>/master_doc_delta.md`
  - `openspec/changes/<change-id>/contracts_plan.md`
  - `openspec/changes/<change-id>/verification_plan.md`
  - `openspec/changes/<change-id>/tasks.md`

Do not create additional `tasks.md` files.

Rule 2. Use external memory

AI sessions end. Branches diverge. Humans forget.

Keep these files current:

- `progress.txt`
- `docs/master_doc.md`
- `docs/ui_spec.md`
- `prompts/`

Rule 3. Put quality in gates

Every task must define an exact verify command.

Workers run the task gate and `./scripts/verify` before committing.

Rule 4. Coordinate with locks

Workers claim tasks with lock files.

Lock path:

`openspec/changes/<change-id>/task_locks/<task-id>.lock`

Use `dasops claim-ready` (pull mode), `dasops claim-task` (push mode), or `dasops start-task`.

Result

When paths are fixed, gates are explicit, and coordination is mechanical, AI output becomes controllable.
