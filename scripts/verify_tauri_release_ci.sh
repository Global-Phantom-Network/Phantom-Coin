#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT_DIR/apps/phantom-dashboard"
BUNDLE_DIR="$ROOT_DIR/target/release/bundle"
SMOKE_DIR="${SMOKE_DIR:-$ROOT_DIR/target/tauri-smoke}"
SMOKE_PORT="${SMOKE_PORT:-18765}"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

run_with_timeout() {
  local duration="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$duration" "$@"
    return $?
  fi
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$duration" "$@"
    return $?
  fi
  python3 - "$duration" "$@" <<'PY'
import subprocess
import sys

raw = sys.argv[1]
cmd = sys.argv[2:]
if raw.endswith("s"):
    timeout = float(raw[:-1])
elif raw.endswith("m"):
    timeout = float(raw[:-1]) * 60.0
else:
    timeout = float(raw)

proc = subprocess.Popen(cmd)
try:
    sys.exit(proc.wait(timeout=timeout))
except subprocess.TimeoutExpired:
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    sys.exit(124)
PY
}

require_cmd node
require_cmd npm
require_cmd cargo
require_cmd python3
require_cmd rg
require_cmd curl

python3 - "$APP_DIR/src-tauri/tauri.release.conf.json" <<'PY'
import json
import sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text())
tauri = cfg["tauri"]
assert tauri["bundle"]["active"] is True, cfg
csp = tauri["security"]["csp"]
for origin in ("ws://127.0.0.1:5173", "ws://localhost:5173", "ws://[::1]:5173"):
    assert origin not in csp, csp
PY
printf 'PASS tauri_release_config_hardened\n'

(
  cd "$APP_DIR"
  npm ci
  rm -rf "$BUNDLE_DIR"
  ./node_modules/.bin/tauri build --config src-tauri/tauri.release.conf.json --bundles app
)

test -d "$BUNDLE_DIR"
find "$BUNDLE_DIR" -mindepth 1 -maxdepth 2 | head -n 20 >/dev/null
if rg -n "ws://127\\.0\\.0\\.1:5173|ws://localhost:5173|ws://\\[::1\\]:5173" "$BUNDLE_DIR" >/dev/null 2>&1; then
  echo "dev websocket origin leaked into release bundle" >&2
  exit 1
fi
printf 'PASS tauri_release_bundle_built\n'

APP_BUNDLE="$(find "$BUNDLE_DIR" -path '*/macos/*.app' -type d | head -n 1)"
test -n "$APP_BUNDLE"
APP_EXECUTABLE="$(python3 - "$APP_BUNDLE/Contents/Info.plist" <<'PY'
import plistlib
import sys
from pathlib import Path

with Path(sys.argv[1]).open("rb") as fh:
    info = plistlib.load(fh)
print(info["CFBundleExecutable"])
PY
)"
test -n "$APP_EXECUTABLE"
APP_BIN="$APP_BUNDLE/Contents/MacOS/$APP_EXECUTABLE"
test -x "$APP_BIN"

mkdir -p "$SMOKE_DIR"
printf '{"ok":true,"service":"smoke"}\n' > "$SMOKE_DIR/status"
python3 -m http.server "$SMOKE_PORT" --bind 127.0.0.1 --directory "$SMOKE_DIR" > "$SMOKE_DIR/http.log" 2>&1 &
PIDS+=("$!")
for _ in $(seq 1 40); do
  if curl --silent --show-error --fail "http://127.0.0.1:${SMOKE_PORT}/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl --silent --show-error --fail "http://127.0.0.1:${SMOKE_PORT}/status" >/dev/null

SMOKE_RESULT_FILE="$SMOKE_DIR/packaged-app-result.json"
SMOKE_STDOUT_LOG="$SMOKE_DIR/packaged-app.stdout.log"
SMOKE_STDERR_LOG="$SMOKE_DIR/packaged-app.stderr.log"
rm -f "$SMOKE_RESULT_FILE"
set +e
run_with_timeout 45s env \
  PHANTOM_DASHBOARD_SMOKE_HTTP_URL="http://127.0.0.1:${SMOKE_PORT}/status" \
  PHANTOM_DASHBOARD_SMOKE_EXPECT_BODY_INCLUDES='"service":"smoke"' \
  PHANTOM_DASHBOARD_SMOKE_RESULT_FILE="$SMOKE_RESULT_FILE" \
  PHANTOM_DASHBOARD_SMOKE_TIMEOUT_SECS=20 \
  "$APP_BIN" >"$SMOKE_STDOUT_LOG" 2>"$SMOKE_STDERR_LOG"
smoke_rc=$?
set -e
if [ "$smoke_rc" -ne 0 ]; then
  cat "$SMOKE_STDOUT_LOG" >&2 || true
  cat "$SMOKE_STDERR_LOG" >&2 || true
  test -f "$SMOKE_RESULT_FILE" && cat "$SMOKE_RESULT_FILE" >&2 || true
  exit 1
fi
python3 - "$SMOKE_RESULT_FILE" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
assert payload["ok"] is True, payload
preview = payload.get("body_preview") or ""
assert '"service":"smoke"' in preview.replace(" ", ""), payload
PY
printf 'PASS tauri_packaged_app_smoke\n'
