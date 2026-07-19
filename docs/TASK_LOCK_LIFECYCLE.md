# Task Lock Lifecycle

This document freezes the expected DASOPS task lock lifecycle.

## States

- `TODO`
- `IN_PROGRESS`
- `DONE`

## Operations

- `dasops claim-task`
  - creates `openspec/changes/<change-id>/task_locks/<task-id>.lock`
  - updates `tasks.md` owner and status
- `dasops renew-lock`
  - refreshes `heartbeatAt`
- `dasops reclaim-lock`
  - transfers stale locks to a new owner and rotates `lockToken`
- `dasops complete-task`
  - marks the task `DONE`
- `dasops release-task`
  - removes the lock file and updates task status

## Fail-Closed Rules

- A lock is invalid if any required field is missing.
- `tasks.md` owner and lock owner must not silently drift.
- Orchestrators may force-reassign; workers must not.
