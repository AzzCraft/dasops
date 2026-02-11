# Multi-worker with Codex (recommended setup)

This guide is a shorter, opinionated companion to `docs/USER_MANUAL.md`.

## TL;DR

- **Orchestrator** uses the Codex IDE extension for planning / review.
- **Workers** use **Codex CLI** in *their own worktrees*, looping:
  `edit → run verify → fix → re-run`.
- Use **task locks** to prevent duplicate work:
  `openspec/changes/<change-id>/task_locks/T-001.lock`.

---

## Recommended branch model

- `main` is protected.
- Workers implement **one task per branch/worktree**:
  `feat/<change-id>/<task-id>-<slug>`.

---

## Step-by-step

### 1) Orchestrator creates / updates tasks

- File: `openspec/changes/<change-id>/tasks.md`
- Rules:
  - Every task has a verify gate command.
  - Owners may be assigned (push) or left as `-` for workers to claim (pull).

### 2) Worker starts a task (creates branch/worktree + claims lock)

From the product repo root:

```bash
export DASOPS_OWNER=worker01

# Pull mode: claim the next READY task (prints the claimed task id)
dasops claim-ready --change-id initial
# Then substitute the claimed task id wherever you see T-001 below.

# Push mode: start a specific task (creates branch/worktree + claims lock)
dasops start-task --change-id initial --task-id T-001
```

This:
- creates a worktree under `.worktrees/<owner>/<task-id>` (default)
- creates a feature branch
- updates `tasks.md` owner/status
- creates `task_locks/T-001.lock`

### 3) Worker runs Codex CLI in full-auto mode

Inside the worktree, prefer the wrapper script:

```bash
./scripts/run_worker_codex.sh initial T-001 worker01
```

Or run Codex CLI directly:

```bash
dasops prompt --role worker --change-id initial --task-id T-001 --owner worker01 \
  | codex exec --full-auto -
```

### 4) Worker completes the task + opens PR

```bash
./scripts/verify

dasops complete-task --change-id initial --task-id T-001

git add -A
git commit -m "T-001: <short summary>"
git push -u origin HEAD
```

Open a PR and let CI enforce the verify gates.

---

## Troubleshooting

- If you see `lock exists`: run `dasops list-tasks --change-id <id>` and coordinate with Orchestrator.
- If Codex is not modifying files: ensure you used `--full-auto` or at least `--sandbox workspace-write`.
