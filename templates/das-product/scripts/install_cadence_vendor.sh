#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$ROOT_DIR/vendor/cadence"

print_usage() {
  cat <<USAGE
Usage:
  scripts/install_cadence_vendor.sh --commit FULL_SHA [--from-suite PATH] [--tier oss] [--git-base URL] [--org ORG] [--ssh] [--force]

What this does
  Installs Cadence into a deterministic location:

    vendor/cadence/
      cadence-oss/

Notes
  - Requires Git, Go, Python 3 and flock (Linux). Builds/checks before replacement.
  - tooling_lock.json verifyRuntime must declare the same fixed Git commit.
  - Without --from-suite, clone from the explicit Git source and checkout --commit.
  - With --from-suite, select its src/cadence-oss checkout or legacy sibling
    cadence-oss; only committed files at --commit are installed.
  - Clone mode is fail-closed: pass --git-base or --org, or set DAS_SUITE_GIT_BASE.
USAGE
}

TIER="oss"
FROM_SUITE=""
GIT_BASE="${DAS_SUITE_GIT_BASE:-}"
ORG=""
USE_SSH="0"
FORCE="0"
COMMIT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit)
      COMMIT="${2:?--commit requires a value}"; shift 2 ;;
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

# Validate inputs and prerequisites before creating or replacing any installation.
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "--commit requires a full lowercase 40-character commit; floating sources are refused" >&2; exit 2; }
command -v git >/dev/null
command -v go >/dev/null
command -v "${PYTHON:-python3}" >/dev/null
command -v flock >/dev/null
if [[ -n "$FROM_SUITE" ]]; then
  [[ -z "$ORG" && -z "$GIT_BASE" && "$USE_SSH" == "0" ]] || { echo "Choose one source mode" >&2; exit 2; }
  [[ -d "$FROM_SUITE" ]] || { echo "Suite source not found" >&2; exit 1; }
  FROM_SUITE="$(cd "$FROM_SUITE" && pwd)"
  SOURCE="$FROM_SUITE/src/cadence-oss"
  if [[ -d "$SOURCE" && -d "$FROM_SUITE/../cadence-oss" ]]; then
    echo "Ambiguous Suite Cadence sources" >&2; exit 2
  fi
  [[ -d "$SOURCE" ]] || SOURCE="$FROM_SUITE/../cadence-oss"
  [[ -d "$SOURCE" ]] || { echo "Cadence source not found" >&2; exit 1; }
  SOURCE="$(cd "$SOURCE" && pwd -P)"
  [[ "$(git -C "$SOURCE" rev-parse --show-toplevel)" == "$SOURCE" ]] || { echo "Cadence source must be an independent Git checkout" >&2; exit 1; }
else
  [[ -n "$ORG" || -n "$GIT_BASE" ]] || { echo "Clone mode requires --git-base, --org, or DAS_SUITE_GIT_BASE." >&2; exit 2; }
  SOURCE="$(url_for_repo cadence-oss)"
fi
[[ ! -L "$ROOT_DIR/.cadence" && ! -L "$ROOT_DIR/.cadence/tmp" && ! -L "$ROOT_DIR/.cadence/tmp/install.guard" ]] || { echo "Linked install guard refused" >&2; exit 1; }
mkdir -p "$ROOT_DIR/.cadence/tmp"
exec 9>>"$ROOT_DIR/.cadence/tmp/install.guard"
flock -x 9
"${PYTHON:-python3}" -B "$ROOT_DIR/scripts/cadence_runtime.py" select --repo-root "$ROOT_DIR" --commit "$COMMIT"
[[ ! -L "$ROOT_DIR/vendor" && ! -L "$VENDOR_DIR" ]] || { echo "Vendor links are unsupported" >&2; exit 1; }
if [[ -e "$VENDOR_DIR" ]]; then
  [[ -d "$VENDOR_DIR" && "$FORCE" == "1" ]] || { echo "vendor/cadence already exists; use --force for a directory" >&2; exit 1; }
fi
final_vendor="$VENDOR_DIR"
mkdir -p "$ROOT_DIR/vendor"
staging="$(mktemp -d "$ROOT_DIR/vendor/.cadence-install.XXXXXX")"
published="0"
cleanup() {
  local code=$?
  if [[ -d "$staging/previous" && "$published" != "1" ]]; then
    if [[ ! -e "$final_vendor" && ! -L "$final_vendor" ]]; then
      mv -Tn -- "$staging/previous" "$final_vendor" || true
    fi
    if [[ -e "$staging/previous" ]]; then
      echo "Recovery required: previous install preserved at $staging/previous; destination was not overwritten" >&2
      return 1
    fi
  fi
  rm -rf -- "$staging"
  return "$code"
}
trap cleanup EXIT
VENDOR_DIR="$staging/new"
mkdir "$VENDOR_DIR"
git clone --no-local --no-checkout -- "$SOURCE" "$staging/source"
[[ "$(git -C "$staging/source" cat-file -t "$COMMIT")" == "commit" ]] || { echo "Requested commit is unavailable" >&2; exit 1; }
git -C "$staging/source" checkout --detach "$COMMIT"
mkdir -p "$VENDOR_DIR/.cadence/bin"
(cd "$staging/source/cadence-core" && go build -buildvcs=true -trimpath -o "$VENDOR_DIR/.cadence/bin/cadence" ./cmd/cadence)
"${PYTHON:-python3}" -B "$ROOT_DIR/scripts/cadence_runtime.py" record --repo-root "$ROOT_DIR" --staged "$VENDOR_DIR" --source "$staging/source" --commit "$COMMIT"
if [[ -e "$final_vendor" || -L "$final_vendor" ]]; then
  [[ ! -L "$final_vendor" && -d "$final_vendor" && "$FORCE" == "1" ]] || { echo "Installation destination changed; previous content retained" >&2; exit 1; }
  mv -T -- "$final_vendor" "$staging/previous"
fi
mv -Tn -- "$VENDOR_DIR" "$final_vendor"
[[ ! -e "$VENDOR_DIR" ]] || { echo "Installation destination appeared; refusing to overwrite it" >&2; exit 1; }
published="1"
VENDOR_DIR="$final_vendor"
echo
echo "Cadence installed under: $VENDOR_DIR"

if [[ -x "$ROOT_DIR/cadencew" ]]; then
  echo
  echo "Next steps:"
  echo "  1) ./cadencew version"
  echo "  2) ./scripts/verify --scope full"
fi
