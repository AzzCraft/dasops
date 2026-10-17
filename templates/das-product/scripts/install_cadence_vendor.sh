#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$ROOT_DIR/vendor/cadence"

print_usage() {
  cat <<USAGE
Usage:
  scripts/install_cadence_vendor.sh [--from-suite PATH] [--tier oss] [--git-base URL] [--org ORG] [--ssh] [--force]

What this does
  Installs Cadence into a deterministic location:

    vendor/cadence/
      cadence-oss/

Notes
  - Without --from-suite, this script clones repositories from Git.
  - With --from-suite, pass <release-root>/das-suite; only the public
    sibling <release-root>/cadence-oss module is copied.
  - Clone mode is fail-closed: pass --git-base or --org, or set DAS_SUITE_GIT_BASE.
USAGE
}

TIER="oss"
FROM_SUITE=""
GIT_BASE="${DAS_SUITE_GIT_BASE:-}"
ORG=""
USE_SSH="0"
FORCE="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      TIER="$2"; shift 2 ;;
    --from-suite)
      FROM_SUITE="$2"; shift 2 ;;
    --git-base)
      GIT_BASE="$2"; shift 2 ;;
    --org)
      ORG="$2"; shift 2 ;;
    --ssh)
      USE_SSH="1"; shift 1 ;;
    --force)
      FORCE="1"; shift 1 ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      print_usage
      exit 2 ;;
  esac
done

case "$TIER" in
  oss) ;;
  *)
    echo "Invalid --tier: $TIER" >&2
    print_usage
    exit 2 ;;
esac

if [[ -d "$VENDOR_DIR" ]]; then
  if [[ "$FORCE" != "1" ]]; then
    echo "vendor/cadence already exists: $VENDOR_DIR" >&2
    echo "Re-run with --force to replace it." >&2
    exit 1
  fi
  rm -rf "$VENDOR_DIR"
fi

mkdir -p "$VENDOR_DIR"

url_for_repo() {
  local repo="$1"
  if [[ -n "$ORG" ]]; then
    if [[ "$USE_SSH" == "1" ]]; then
      echo "git@github.com:${ORG}/${repo}.git"
    else
      echo "https://github.com/${ORG}/${repo}.git"
    fi
    return 0
  fi

  if [[ "$USE_SSH" == "1" ]]; then
    if [[ "$GIT_BASE" =~ ^https?://github.com/([^/]+)$ ]]; then
      local base_org="${BASH_REMATCH[1]}"
      echo "git@github.com:${base_org}/${repo}.git"
    else
      echo "Could not derive an SSH GitHub org from --git-base=$GIT_BASE. Pass --org explicitly." >&2
      return 2
    fi
  else
    echo "${GIT_BASE%/}/${repo}.git"
  fi
}

copy_dir() {
  local src="$1"
  local dst="$2"
  mkdir -p "$(dirname "$dst")"
  rsync -a --delete "$src/" "$dst/" >/dev/null
}

install_from_suite() {
  local suite="$1"
  if [[ ! -d "$suite" ]]; then
    echo "Could not find DAS Suite path: $suite" >&2
    echo "Pass --from-suite as <release-root>/das-suite." >&2
    exit 1
  fi

  local suite_abs
  suite_abs="$(cd "$suite" && pwd)"
  local release_root
  release_root="$(cd "$suite_abs/.." && pwd)"
  local oss_src="$release_root/cadence-oss"

  if [[ ! -d "$oss_src" ]]; then
    echo "Could not find Cadence OSS release module at: $oss_src" >&2
    echo "Pass --from-suite as <release-root>/das-suite with sibling <release-root>/cadence-oss." >&2
    exit 1
  fi

  echo "Installing Cadence OSS from release module..."
  copy_dir "$oss_src" "$VENDOR_DIR/cadence-oss"

}

clone_repo() {
  local repo="$1"
  local dst="$2"

  local url
  url="$(url_for_repo "$repo")"

  echo "git clone $url -> $dst"
  if git clone "$url" "$dst" >/dev/null 2>&1; then
    return 0
  fi

  echo "Clone failed (repo missing or permission denied): $repo" >&2
  return 1
}

install_by_cloning() {
  if [[ -z "$ORG" && -z "$GIT_BASE" ]]; then
    echo "Clone mode requires --git-base, --org, or DAS_SUITE_GIT_BASE." >&2
    exit 2
  fi

  echo "Installing Cadence by cloning repos from Git..."

  clone_repo "cadence-oss" "$VENDOR_DIR/cadence-oss" || exit 1

}

if [[ -n "$FROM_SUITE" ]]; then
  install_from_suite "$FROM_SUITE"
else
  install_by_cloning
fi

echo
echo "Cadence installed under: $VENDOR_DIR"

if [[ -x "$ROOT_DIR/cadencew" ]]; then
  echo
  echo "Next steps:"
  echo "  1) ./cadencew version"
  echo "  2) git add vendor/cadence && git commit -m \"chore: vendor Cadence\""
fi
