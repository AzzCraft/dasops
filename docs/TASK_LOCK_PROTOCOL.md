# Task Lock Protocol

## Overview

Task locks prevent conflicting concurrent edits to the same task within a DAS change folder. This document specifies the lock lifecycle, conflict resolution, and recovery rules.

## Lock Structure

Each lock is stored as YAML under `openspec/changes/<change-id>/task_locks/<task-id>.lock`:

```json
{
  "version": 2,
  "taskId": "TSK-001",
  "owner": "alice",
  "status": "IN_PROGRESS",
  "claimedAt": "2026-04-09T09:00:00+00:00",
  "updatedAt": "2026-04-09T10:00:00+00:00",
  "heartbeatAt": "2026-04-09T10:00:00+00:00",
  "leaseSeconds": 3600,
  "lockToken": "uuid-v4",
  "auditHistory": []
}
```

UTC timestamps use the explicit `+00:00` offset emitted by the writer, which is
also accepted by the lock reader on the minimum supported Python 3.10.

OPS-003 diagnostics use `task: OPS-003` in JSON error and reclaim payloads. Reclaim records are appended to `auditHistory` with `fromOwner`, `toOwner`, `reason`, `oldToken`, and `at`.

## Lifecycle and coordination boundary

This is cooperative coordination in one trusted local worktree. The change-level
shared/exclusive guard and fixed Markdown/lock journal keep readers consistent;
these files do not authenticate people or coordinate separate clones. Readers
refuse pending recovery, corrupt locks and task/lock disagreement. Writers recover
an exact valid pending pair before proceeding; conflicts require investigation.
Never delete a pending record merely to make a command pass.

| Operation | Actual behavior |
|---|---|
| `claim-task` | Creates an IN_PROGRESS claim for an eligible task; DONE rejects |
| Fresh same-owner claim | Idempotent: no heartbeat, token, version or history change |
| Fresh different-owner claim | Rejects unless `--force`; forced takeover rotates identity and records history |
| Stale IN_PROGRESS claim | Rejects even with same owner or `--force`; use explicit reasoned reclaim |
| `renew-lock` | Requires fresh IN_PROGRESS lock, matching owner and token; updates heartbeat/updatedAt |
| `reclaim-lock` | Requires stale IN_PROGRESS lock or explicit `--force`, new owner and nonempty reason; rotates token, increments version, retains history |
| `release-task` | Checks owner (or `--force`), deletes lock, sets TODO/BLOCKED/PROPOSED; **no token argument/check** |
| `complete-task` | Runs completion checks and rechecks the captured claim after the gate; separate from release |

Stale means `now - heartbeatAt > leaseSeconds`; DONE is not stale. The default
lease is 3600 seconds. Renewal/reclaim use the recorded lease. There is no
`--lease` CLI option. Restricting `--force` to an orchestrator is an operational
policy, not an authenticated role check in this local tool.

## Worker startup and diagnostics

`lock-status` reports structural validity; a DONE or stale lock can be valid.
`--require-active --expect-owner <owner>` additionally requires matching owner,
IN_PROGRESS state and an unexpired lease. It fails closed on missing owner,
pending recovery, corrupt/inconsistent state, unsupported flags or ineligible lock.

The generated `scripts/run_worker_codex.sh` first generates the complete prompt
in a private temporary directory, then performs this precheck immediately before
starting Codex. It retains the observed token/version privately for the life of
the invocation and removes its temporary files on exit; it does not log the token.
It neither claims nor auto-renews. A successful precheck is a point-in-time
observation, not continuous authorization or automatic termination on lease loss.
Supervised callers must use the existing renewal policy; no guard is held across
the model process.

## CLI examples and migration

```bash
dasops claim-task --change-id chg-001 --task-id TSK-001 --owner alice --json
dasops lock-status --change-id chg-001 --task-id TSK-001 --expect-owner alice --require-active --json
dasops renew-lock --change-id chg-001 --task-id TSK-001 --owner alice --lock-token "$LOCK_TOKEN" --json
dasops reclaim-lock --change-id chg-001 --task-id TSK-001 --new-owner alice --reason "previous attempt abandoned" --json
dasops release-task --change-id chg-001 --task-id TSK-001 --owner alice --status TODO --json
```

Keep JSON containing tokens in restricted files, not ordinary logs. Migrate
scripts that used repeated `claim-task` as renewal to `renew-lock`; migrate stale
`claim-task --force` takeover to `reclaim-lock` with a reason. Retrying a fresh
same-owner claim no longer extends its lease.
