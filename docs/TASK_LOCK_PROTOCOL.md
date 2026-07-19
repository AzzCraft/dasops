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
  "claimedAt": "2026-04-09T09:00:00Z",
  "updatedAt": "2026-04-09T10:00:00Z",
  "heartbeatAt": "2026-04-09T10:00:00Z",
  "leaseSeconds": 3600,
  "lockToken": "uuid-v4",
  "auditHistory": []
}
```

OPS-003 diagnostics use `task: OPS-003` in JSON error and reclaim payloads. Reclaim records are appended to `auditHistory` with `fromOwner`, `toOwner`, `reason`, `oldToken`, and `at`.

## Lifecycle

### Claim

```
claim(taskId, owner) →
  if no lock exists: create lock
  if lock exists and is stale: reclaim
  if lock exists and is fresh: reject
```

### Renew

```
renew(taskId, owner, token) →
  assert owner and token match
  update heartbeatAt to now
```

### Reclaim

```
reclaim(taskId, operator, reason) →
  assert lock is stale OR operator has override
  write reclaim record to lock history
  rotate lockToken
  update owner
```

### Release

```
release(taskId, owner, token) →
  assert owner and token match
  delete lock file
  update tasks.md status
```

## Stale Detection

A lock is **stale** when:

```
now - heartbeatAt > leaseSeconds
```

Default lease is 3600 seconds (1 hour). Override via `--lease` flag.

## Conflict Resolution

| Scenario | Resolution |
|----------|-----------|
| Two agents claim same task | Second claim rejected |
| Owner disappears (stale lock) | Orchestrator reclaims |
| Wrong token on renew | Renew rejected |
| Force override needed | `--force` flag (Orchestrator only) |

## CLI Commands

```bash
dasops claim-task --change-id chg-001 --task-id TSK-001 --owner alice --json
dasops renew-lock --change-id chg-001 --task-id TSK-001 --owner alice --lock-token <token> --json
dasops reclaim-lock --change-id chg-001 --task-id TSK-001 --new-owner orchestrator --reason "stale" --json
dasops check-stale --change-id chg-001 --task-id TSK-001 --json
```
