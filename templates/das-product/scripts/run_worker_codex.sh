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

if [[ -z "$OWNER" ]]; then
  echo "An explicit owner or configured git user.name is required" >&2
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

# Complete prompt generation before starting the worker. Keep the observed token
# private; this point-in-time precheck does not renew or supervise the child lease.
WORKER_TMP="$(mktemp -d "${TMPDIR:-/tmp}/dasops-worker.XXXXXXXX")"
chmod 700 "$WORKER_TMP"
trap 'rm -rf -- "$WORKER_TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
if ! dasops prompt --role worker --change-id "$CHANGE_ID" --task-id "$TASK_ID" --owner "$OWNER" >"$WORKER_TMP/prompt"; then
  echo "Worker prompt generation failed; worker not started" >&2
  exit 2
fi
if ! dasops lock-status --change-id "$CHANGE_ID" --task-id "$TASK_ID" --expect-owner "$OWNER" --require-active --json >"$WORKER_TMP/lock.json"; then
  python3 - "$WORKER_TMP/lock.json" <<'PYERROR'
import json, sys
try:
    reason = json.load(open(sys.argv[1])).get("error", "active_lock_check_failed")
except (ValueError, OSError):
    reason = "active_lock_check_failed"
print("Worker not started: " + str(reason), file=sys.stderr)
PYERROR
  exit 2
fi

echo "Running Worker loop via Codex CLI"
echo "- Change: $CHANGE_ID"
echo "- Task:   $TASK_ID"
echo "- Owner:  $OWNER"
codex exec --full-auto - <"$WORKER_TMP/prompt"

echo
echo "Next steps"
echo "  ./scripts/verify"
echo "  git add -A"
echo "  git commit -m \"$TASK_ID: <summary>\""
echo "  git push -u origin HEAD"
