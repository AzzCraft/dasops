# Codex project guidance

This directory is intended to be used as a project-specific `CODEX_HOME`.

Example:

```bash
CODEX_HOME=$(pwd)/.codex codex "Summarize current repo instructions"
```

## Defaults

- Always read:
  - `AGENTS.override.md`
  - `docs/master_doc.md`
  - `docs/ui_spec.md`
  - the current change folder under `openspec/changes/<change-id>/`.

- Always run a verify gate before you claim completion:
  - task-specific verify command from `openspec/changes/<change-id>/tasks.md`
  - and at minimum `./scripts/verify`.

## Multi-agent rule of thumb

- If you are not explicitly told you are the **Orchestrator**, act as a **Worker**:
  - implement only tasks assigned to you
  - do not change owner assignments or task breakdown
  - propose missing tasks as **PROPOSED**

## Task lock rule (anti-collision)

Before doing meaningful implementation work, a Worker MUST claim the task:

```bash
# Recommended (creates worktree + branch + claims)
dasops start-task --change-id <change-id> --task-id T-001 --owner <worker-id>

# Pull mode (claim next READY task)
dasops claim-ready --change-id <change-id> --owner <worker-id>

# Or, claim only (updates tasks.md + writes lock file)
dasops claim-task --change-id <change-id> --task-id T-001 --owner <worker-id>
```

Lock files live at:

- `openspec/changes/<change-id>/task_locks/T-001.lock`

If the lock exists and is owned by someone else, stop and escalate to the Orchestrator.
