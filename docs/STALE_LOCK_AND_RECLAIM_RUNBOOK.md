# Stale Lock And Reclaim Runbook

Use this runbook when a task appears stuck.

## Inspect

```bash
dasops lock-status --change-id <change-id> --task-id <task-id> --json
dasops check-stale --change-id <change-id> --task-id <task-id> --json
```

## Renew

If the current owner is still active:

```bash
dasops renew-lock --change-id <change-id> --task-id <task-id> --owner <owner> --lock-token <token>
```

## Reclaim

If the lock is stale and the Orchestrator approves the transfer:

```bash
dasops reclaim-lock --change-id <change-id> --task-id <task-id> --new-owner <owner> --reason "stale lock" --json
```

## Audit Rules

- Reclaims must record a reason.
- `lockToken` must rotate on reclaim.
- The JSON response must include `task: OPS-003`, `previousOwner`, `newOwner`, `oldToken`, and `newToken`.
- The lock YAML must append an `auditHistory` entry with the same owner transition and reason.
- Workers must not reclaim active locks without explicit approval.
