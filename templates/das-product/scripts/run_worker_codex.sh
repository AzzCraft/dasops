#!/usr/bin/env bash
set -euo pipefail

CHANGE_ID="${1:-}"
TASK_ID="${2:-}"
OWNER="${3:-${DASOPS_OWNER:-}}"

if [[ -z "$CHANGE_ID" || -z "$TASK_ID" ]]; then
  echo "Usage: ./scripts/run_worker_codex.sh <change-id> <task-id> [owner]" >&2
  exit 2
fi

if [[ -z "$OWNER" ]]; then
  if command -v git >/dev/null 2>&1; then
    OWNER="$(git config user.name || true)"
  fi
fi

LOCK_FILE="openspec/changes/${CHANGE_ID}/task_locks/${TASK_ID}.lock"
if [[ ! -f "$LOCK_FILE" ]]; then
  echo "Task lock not found: $LOCK_FILE" >&2
  echo "Claim the task first:" >&2
  echo "  # Pull mode: claim the next READY task (prints the claimed task id)" >&2
  echo "  dasops claim-ready --change-id $CHANGE_ID --owner $OWNER" >&2
  echo "  # Push mode: claim a specific task" >&2
  echo "  dasops claim-task --change-id $CHANGE_ID --task-id $TASK_ID --owner $OWNER" >&2
  echo "Or use the one-command flow:" >&2
  echo "  DASOPS_OWNER=$OWNER dasops start-task --change-id $CHANGE_ID --task-id $TASK_ID" >&2
  exit 2
fi

if ! command -v codex >/dev/null 2>&1; then
  echo "codex CLI not found on PATH" >&2
  echo "Install it first, then re-run." >&2
  exit 127
fi

if ! command -v dasops >/dev/null 2>&1; then
  echo "dasops not found on PATH" >&2
  echo "Install dasops in your environment, then re-run." >&2
  exit 127
fi

if ! dasops lock-status --change-id "$CHANGE_ID" --task-id "$TASK_ID" --expect-owner "$OWNER" --json >/dev/null; then
  echo "Task lock exists but is not owned by $OWNER" >&2
  echo "Inspect the structured lock:" >&2
  echo "  dasops lock-status --change-id $CHANGE_ID --task-id $TASK_ID --json" >&2
  exit 2
fi

echo "Running Worker loop via Codex CLI"
echo "- Change: $CHANGE_ID"
echo "- Task:   $TASK_ID"
echo "- Owner:  $OWNER"

dasops prompt --role worker --change-id "$CHANGE_ID" --task-id "$TASK_ID" --owner "$OWNER" \
  | codex exec --full-auto -

echo
echo "Next steps"
echo "  ./scripts/verify"
echo "  git add -A"
echo "  git commit -m \"$TASK_ID: <summary>\""
echo "  git push -u origin HEAD"
