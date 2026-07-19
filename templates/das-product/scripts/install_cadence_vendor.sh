#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$ROOT_DIR/vendor/cadence"

usage() {
  cat <<'USAGE'
Usage:
  scripts/install_cadence_vendor.sh [--from-suite PATH] [--tier oss] [--git-base URL] [--org ORG] [--ssh] [--force]

Installs only the public cadence-oss repository under vendor/cadence/cadence-oss.
Clone mode is fail-closed: provide --git-base, --org, or DAS_SUITE_GIT_BASE.
USAGE
}

FROM_SUITE=""
GIT_BASE="${DAS_SUITE_GIT_BASE:-}"
ORG=""
USE_SSH=0
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      [[ "${2:-}" == "oss" ]] || { echo "Only --tier oss is supported by this public release." >&2; exit 2; }
      shift 2 ;;
    --from-suite) FROM_SUITE="${2:-}"; shift 2 ;;
    --git-base) GIT_BASE="${2:-}"; shift 2 ;;
    --org) ORG="${2:-}"; shift 2 ;;
    --ssh) USE_SSH=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -e "$VENDOR_DIR" ]]; then
  [[ "$FORCE" -eq 1 ]] || { echo "vendor/cadence already exists; use --force to replace it." >&2; exit 1; }
  case "$VENDOR_DIR" in "$ROOT_DIR"/vendor/cadence) ;; *) echo "unsafe vendor path" >&2; exit 2 ;; esac
  rm -rf "$VENDOR_DIR"
fi
mkdir -p "$VENDOR_DIR"

if [[ -n "$FROM_SUITE" ]]; then
  suite_abs="$(cd "$FROM_SUITE" && pwd)" || { echo "DAS Suite path not found: $FROM_SUITE" >&2; exit 1; }
  release_root="$(cd "$suite_abs/.." && pwd)"
  source_dir="$release_root/cadence-oss"
  [[ -d "$source_dir" ]] || { echo "cadence-oss sibling not found: $source_dir" >&2; exit 1; }
  command -v rsync >/dev/null 2>&1 || { echo "rsync is required for --from-suite." >&2; exit 127; }
  rsync -a --delete "$source_dir/" "$VENDOR_DIR/cadence-oss/"
else
  [[ -n "$ORG" || -n "$GIT_BASE" ]] || { echo "Clone mode requires --git-base, --org, or DAS_SUITE_GIT_BASE." >&2; exit 2; }
  if [[ -n "$ORG" ]]; then
    if [[ "$USE_SSH" -eq 1 ]]; then
      url="git@github.com:${ORG}/cadence-oss.git"
    else
      url="https://github.com/${ORG}/cadence-oss.git"
    fi
  else
    [[ "$USE_SSH" -eq 0 ]] || { echo "--ssh with --git-base requires --org." >&2; exit 2; }
    url="${GIT_BASE%/}/cadence-oss.git"
  fi
  git clone -- "$url" "$VENDOR_DIR/cadence-oss"
fi

echo "Cadence OSS installed under: $VENDOR_DIR/cadence-oss"
