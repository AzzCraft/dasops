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

# Validate inputs and prerequisites before creating or replacing any installation.
if [[ -n "$FROM_SUITE" ]]; then
  [[ -z "$ORG" && -z "$GIT_BASE" && "$USE_SSH" == "0" ]] || { echo "Choose one source mode" >&2; exit 2; }
  [[ -d "$FROM_SUITE" ]] || { echo "Suite source not found" >&2; exit 1; }
  FROM_SUITE="$(cd "$FROM_SUITE" && pwd)"
  [[ -d "$FROM_SUITE/../cadence-oss" ]] || { echo "Cadence source not found" >&2; exit 1; }
  command -v rsync >/dev/null
else
  [[ -n "$ORG" || -n "$GIT_BASE" ]] || { echo "Clone mode requires --git-base, --org, or DAS_SUITE_GIT_BASE." >&2; exit 2; }
  command -v git >/dev/null
  url_for_repo cadence-oss >/dev/null
fi
[[ ! -L "$ROOT_DIR/vendor" && ! -L "$VENDOR_DIR" ]] || { echo "Vendor links are unsupported" >&2; exit 1; }
if [[ -e "$VENDOR_DIR" ]]; then
  [[ -d "$VENDOR_DIR" && "$FORCE" == "1" ]] || { echo "vendor/cadence already exists; use --force for a directory" >&2; exit 1; }
fi
final_vendor="$VENDOR_DIR"
mkdir -p "$ROOT_DIR/vendor"
staging="$(mktemp -d "$ROOT_DIR/vendor/.cadence-install.XXXXXX")"
cleanup() {
  local code=$?
  if [[ -d "$staging/previous" && ! -e "$final_vendor" ]]; then
    mv "$staging/previous" "$final_vendor" || { echo "Restore previous install from $staging/previous" >&2; return 1; }
  fi
  rm -rf -- "$staging"
  return "$code"
}
trap cleanup EXIT
VENDOR_DIR="$staging/new"
mkdir "$VENDOR_DIR"
if [[ -n "$FROM_SUITE" ]]; then
  install_from_suite "$FROM_SUITE"
else
  install_by_cloning
fi

[[ -d "$VENDOR_DIR/cadence-oss" ]] || { echo "Incomplete Cadence installation" >&2; exit 1; }
if [[ -d "$final_vendor" ]]; then mv "$final_vendor" "$staging/previous"; fi
mv "$VENDOR_DIR" "$final_vendor"
VENDOR_DIR="$final_vendor"
echo
echo "Cadence installed under: $VENDOR_DIR"

if [[ -x "$ROOT_DIR/cadencew" ]]; then
  echo
  echo "Next steps:"
  echo "  1) ./cadencew version"
  echo "  2) git add vendor/cadence && git commit -m \"chore: vendor Cadence\""
fi
