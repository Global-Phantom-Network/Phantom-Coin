#!/usr/bin/env bash
set -euo pipefail

# Stoppt alle lokal laufenden Multi-Node-Instanzen

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STATE_ROOT="${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}"

cd "$REPO_ROOT"

echo "Stopping all nodes..."

for i in 1 2 3; do
  if [ -f "$STATE_ROOT/node$i.pid" ]; then
    PID=$(cat "$STATE_ROOT/node$i.pid")
    if kill -0 "$PID" 2>/dev/null; then
      echo "Stopping Node $i (PID: $PID)..."
      kill "$PID" || true
      rm "$STATE_ROOT/node$i.pid"
    else
      echo "Node $i (PID: $PID) is not running."
      rm "$STATE_ROOT/node$i.pid"
    fi
  else
    echo "No PID file for Node $i."
  fi
done

# Fallback: kill alle phantom-node Prozesse
echo ""
echo "Killing any remaining phantom-node processes..."
pkill -f "phantom-node.*status-serve" || echo "No phantom-node processes found."

echo ""
echo "All nodes stopped."
