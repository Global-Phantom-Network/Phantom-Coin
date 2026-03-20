#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TARGETS=(
  "$ROOT_DIR/pc-data"
  "$ROOT_DIR/pc-data-validator"
  "$ROOT_DIR/apps/phantom-dashboard/src-tauri/pc-data"
  "$ROOT_DIR/status_auth_token.txt"
  "$ROOT_DIR/server.key"
  "$ROOT_DIR/server.crt"
)

echo "The following repository-local runtime artifacts will be removed if present:"
for target in "${TARGETS[@]}"; do
  echo "  $target"
done

if [[ "${1:-}" != "--force" ]]; then
  echo
  echo "Dry run only. Re-run with --force to delete these paths."
  exit 2
fi

for target in "${TARGETS[@]}"; do
  rm -rf "$target"
done

echo "Repository-local runtime artifacts removed."
