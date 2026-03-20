#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SCAN_ROOT="$ROOT_DIR"
TRACKED_ONLY=0

usage() {
  cat <<'EOF'
Usage:
  scripts/security/scan_runtime_artifacts.sh [--root DIR] [--tracked-only]

Scans for repository-local runtime artifacts and sensitive files that must not
be committed, archived, or shipped in release bundles.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      SCAN_ROOT="$2"
      shift 2
      ;;
    --tracked-only)
      TRACKED_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCAN_ROOT="$(cd "$SCAN_ROOT" && pwd)"

matches_path() {
  local rel="$1"
  local base
  base="${rel##*/}"

  case "$rel" in
    pc-data|pc-data/*) return 0 ;;
    pc-data-validator|pc-data-validator/*) return 0 ;;
    apps/phantom-dashboard/src-tauri/pc-data|apps/phantom-dashboard/src-tauri/pc-data/*) return 0 ;;
  esac

  case "$base" in
    *.key|*.crt|status_auth_token.txt|validator_bls.ks.toml|seat_bls.toml|payout_schnorr.toml)
      return 0
      ;;
  esac

  return 1
}

emit_matches_from_tree() {
  local dir
  for dir in \
    pc-data \
    pc-data-validator \
    apps/phantom-dashboard/src-tauri/pc-data
  do
    if [[ -e "$SCAN_ROOT/$dir" ]]; then
      printf '%s\n' "$dir"
    fi
  done

  (
    cd "$SCAN_ROOT"
    rg --files -0 \
      -g '!target' \
      -g '!**/target/**' \
      -g '!**/.git/**' \
      -g '!apps/phantom-dashboard/node_modules/**' \
      -g '!apps/phantom-dashboard/dist/**' \
      -g '!apps/phantom-dashboard/src-tauri/target/**'
  ) | while IFS= read -r -d '' rel; do
    if matches_path "$rel"; then
      printf '%s\n' "$rel"
    fi
  done
}

emit_matches_from_git() {
  git -C "$SCAN_ROOT" ls-files -z | while IFS= read -r -d '' rel; do
    if matches_path "$rel"; then
      printf '%s\n' "$rel"
    fi
  done
}

if [[ "$TRACKED_ONLY" -eq 1 ]] && ! git -C "$SCAN_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "tracked-only scan requires a git work tree: $SCAN_ROOT" >&2
  exit 2
fi

if [[ "$TRACKED_ONLY" -eq 1 ]]; then
  MATCHES="$(emit_matches_from_git | sort -u || true)"
else
  MATCHES="$(emit_matches_from_tree | sort -u || true)"
fi

if [[ -n "$MATCHES" ]]; then
  printf 'runtime-artifact-scan: FAIL (%s)\n' "$SCAN_ROOT" >&2
  printf '%s\n' "$MATCHES" >&2
  exit 1
fi

printf 'runtime-artifact-scan: ok (%s)\n' "$SCAN_ROOT"
