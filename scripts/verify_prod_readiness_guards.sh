#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

TARGETS=(
  README.md
  Makefile
  Dockerfile
  docker-compose.yml
  .github/workflows
  deploy
  configs
  docs/GENESIS.md
  docs/bootstrap_peers.json
  docs/mining-api.md
  docs/observability.md
  docs/deployment-guide.md
  docs/deployment-guide-part2.md
  docs/devops/docker-compose.md
  docs/devops/README.md
  docs/devops/emergency.md
  docs/devops/release-process.md
  docs/PHANTOMCOIN_TODO_PLAN.md
  docs/network_bootstrap.md
  docs/METRICS_CATEGORIZATION.md
  docs/STAKING.md
  runbooks/testnets
  scripts/security
  scripts/start_localnet.sh
  scripts/testnets
  scripts/verify_compose_stacks_ci.sh
  scripts/verify_runtime_paths_ci.sh
  scripts/verify_systemd_runtime_ci.sh
  scripts/verify_tauri_release_ci.sh
  systemd
)

RUNTIME_EXAMPLE_TARGETS=(
  README.md
  Makefile
  docker-compose.yml
  deploy
  configs
  docs/GENESIS.md
  docs/bootstrap_peers.json
  docs/mining-api.md
  docs/observability.md
  docs/deployment-guide.md
  docs/deployment-guide-part2.md
  docs/devops/docker-compose.md
  docs/devops/README.md
  docs/devops/release-process.md
  docs/PHANTOMCOIN_TODO_PLAN.md
  docs/network_bootstrap.md
  docs/METRICS_CATEGORIZATION.md
  docs/STAKING.md
  runbooks/testnets
  scripts/start_localnet.sh
  scripts/testnets
  scripts/verify_compose_stacks_ci.sh
  scripts/verify_runtime_paths_ci.sh
  scripts/verify_systemd_runtime_ci.sh
  scripts/verify_tauri_release_ci.sh
  systemd
)

fail=0

check_absent() {
  local label="$1"
  local pattern="$2"
  shift 2

  local matches
  matches="$(rg -n -e "$pattern" "$@" || true)"
  if [ -n "$matches" ]; then
    printf 'FAIL: %s\n%s\n\n' "$label" "$matches" >&2
    fail=1
  fi
}

check_absent \
  "repository-local runtime state examples still documented in operational artifacts" \
  '(^|[^[:alnum:]_./-])(\./)?pc-data([-./]|/|$)|(^|[^[:alnum:]_./-])(\./)?pc-data-validator([-./]|/|$)|src-tauri/pc-data' \
  "${RUNTIME_EXAMPLE_TARGETS[@]}"

check_absent \
  "legacy deploy subcommands still present" \
  '\\bStatusServe\\b|\\bP2pQuicListen\\b|\\bP2pMetricsServe\\b' \
  "${TARGETS[@]}"

check_absent \
  "legacy snake_case CLI flags still present" \
  '--mempool_dir\\b|--store_dir\\b|--network_name\\b|--shards_initial\\b|--committee_k\\b|--txs_per_payload\\b|--tx_proposer\\b|--tx_proposer_interval_ms\\b' \
  "${TARGETS[@]}"

check_absent \
  "demo credentials still documented in operational artifacts" \
  'admin/admin|changeme' \
  "${TARGETS[@]}"

check_absent \
  "RUST_BACKTRACE=1 leaked into operational defaults" \
  'RUST_BACKTRACE=1' \
  "${TARGETS[@]}"

docker_check="$(
python3 - <<'PY'
from pathlib import Path
import sys

dockerfile = Path("Dockerfile")
bad = []
for lineno, line in enumerate(dockerfile.read_text().splitlines(), 1):
    stripped = line.strip()
    if stripped.startswith("ARG BASE_") and "=" in stripped:
        value = stripped.split("=", 1)[1].strip()
        if value.startswith(("rust:", "debian:")) and "@sha256:" not in value:
            bad.append(f"Dockerfile:{lineno}:{line}")
    elif stripped.startswith("FROM "):
        parts = stripped.split()
        if len(parts) >= 2:
            ref = parts[1]
            if ref.startswith(("rust:", "debian:")) and "@sha256:" not in ref:
                bad.append(f"Dockerfile:{lineno}:{line}")

if bad:
    print("\n".join(bad))
    sys.exit(1)
PY
)" || {
  printf 'FAIL: unpinned Docker base image references detected\n%s\n\n' "$docker_check" >&2
  fail=1
}

runtime_scan="$(
  scripts/security/scan_runtime_artifacts.sh --tracked-only
)" || {
  printf 'FAIL: tracked runtime artifacts detected\n%s\n\n' "$runtime_scan" >&2
  fail=1
}

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "prod-readiness-guards: ok"
