# DAS-03-022 - dasops Community Release Checklist

| Check | Evidence |
| --- | --- |
| product scaffold | `python3 -m dasops create ... --no-git` succeeds and the created repo passes `audit_repo()` |
| task coordination | `tests/test_task_lock_concurrency.py` and the lock-status CLI pass |
| change workflow | `dasops/change.py` legal transitions pass and illegal transitions are rejected |
| docs links | `bash ./scripts/verify` passes the seeded documentation link checks |
| release traceability | `VERSION`, `CHANGELOG.md`, `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` are present |

Community release approval requires recorded verification evidence, a clean rollback path via regenerated product repos, and no open P0/P1 release blockers.
Rollback evidence must identify the previous released scaffold version and the regeneration command used to recover it.
