#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NODE_BIN="${NODE_BIN:-$ROOT_DIR/target/debug/phantom-node}"
MINER_BIN="${MINER_BIN:-$ROOT_DIR/target/debug/phantom-miner}"
STATUS_HTTP_BIN="${STATUS_HTTP_BIN:-$ROOT_DIR/target/debug/status_http}"
GENESIS_BOOTSTRAP_BIN="${GENESIS_BOOTSTRAP_BIN:-$ROOT_DIR/target/debug/genesis_bootstrap}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
PIDS=()
STATUS_PORT=18443
STATUS_HTTP_PORT=19443

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  if [ "${KEEP_WORK_DIR:-0}" != "1" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

require_executable() {
  local path="$1"
  test -x "$path" || {
    echo "missing executable: $path" >&2
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

wait_https_with_ca() {
  local ca="$1"
  local url="$2"
  local attempts="${3:-80}"
  for _ in $(seq 1 "$attempts"); do
    if curl --silent --show-error --fail --cacert "$ca" "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "timeout waiting for $url" >&2
  return 1
}

wait_https_insecure() {
  local url="$1"
  local attempts="${2:-80}"
  for _ in $(seq 1 "$attempts"); do
    if curl --silent --show-error --fail --insecure "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "timeout waiting for $url" >&2
  return 1
}

wait_http_plain() {
  local url="$1"
  local attempts="${2:-80}"
  for _ in $(seq 1 "$attempts"); do
    if curl --silent --show-error --fail "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "timeout waiting for $url" >&2
  return 1
}

require_executable "$NODE_BIN"
require_executable "$MINER_BIN"
require_executable "$STATUS_HTTP_BIN"
require_executable "$GENESIS_BOOTSTRAP_BIN"
command -v curl >/dev/null 2>&1
command -v openssl >/dev/null 2>&1
command -v python3 >/dev/null 2>&1

"$NODE_BIN" status-serve --help >/dev/null
printf 'PASS status_serve_help\n'
"$NODE_BIN" p2p-quic-listen --help >/dev/null
printf 'PASS p2p_quic_listen_help\n'
"$NODE_BIN" p2p-metrics-serve --help >/dev/null
printf 'PASS p2p_metrics_serve_help\n'

CERT_DIR="$WORK_DIR/certs"
mkdir -p "$CERT_DIR"
CA_KEY="$CERT_DIR/ca.key"
CA_CERT="$CERT_DIR/ca.crt"
SERVER_KEY="$CERT_DIR/server.key"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CERT="$CERT_DIR/server.crt"
SERVER_EXT="$CERT_DIR/server.ext"
WRONG_CA_KEY="$CERT_DIR/wrong-ca.key"
WRONG_CA_CERT="$CERT_DIR/wrong-ca.crt"

openssl genrsa -out "$CA_KEY" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 2 -subj "/CN=Phantom CI Test CA" -out "$CA_CERT" >/dev/null 2>&1
openssl genrsa -out "$SERVER_KEY" 2048 >/dev/null 2>&1
openssl req -new -key "$SERVER_KEY" -subj "/CN=127.0.0.1" -out "$SERVER_CSR" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$SERVER_EXT"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 2 -sha256 -extfile "$SERVER_EXT" >/dev/null 2>&1
openssl genrsa -out "$WRONG_CA_KEY" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$WRONG_CA_KEY" -sha256 -days 2 -subj "/CN=Phantom CI Wrong CA" -out "$WRONG_CA_CERT" >/dev/null 2>&1

STORE_DIR="$WORK_DIR/store"
MEMPOOL_DIR="$STORE_DIR/mempool"
GENESIS_SRC_DIR="$WORK_DIR/genesis-src/mempool"
mkdir -p "$MEMPOOL_DIR" "$GENESIS_SRC_DIR"
AUTH_TOKEN_FILE="$WORK_DIR/status-auth.token"
printf 'ci-status-token\n' > "$AUTH_TOKEN_FILE"
chmod 600 "$AUTH_TOKEN_FILE"

"$GENESIS_BOOTSTRAP_BIN" --mempool-dir "$GENESIS_SRC_DIR" --network-name ci-runtime-check >/dev/null
GENESIS_NOTE_PATH="$GENESIS_SRC_DIR/genesis_note.bin"
test -f "$GENESIS_NOTE_PATH"

LISTENER_STORE_DIR="$WORK_DIR/listener-store"
LISTENER_LOG="$WORK_DIR/listener-example.log"
mkdir -p "$LISTENER_STORE_DIR"
set +e
run_with_timeout 5s env RUST_LOG=info "$NODE_BIN" p2p-quic-listen --config "$ROOT_DIR/configs/node.toml" --addr "127.0.0.1:19001" --store-dir "$LISTENER_STORE_DIR" --unsafe-confirm --fsync >"$LISTENER_LOG" 2>&1
listener_rc=$?
set -e
test "$listener_rc" -eq 124
test -f "$LISTENER_STORE_DIR/utxo/CURRENT"
printf 'PASS node_example_config_starts\n'

STATUS_EXAMPLE_PORT=18444
STATUS_EXAMPLE_STORE_DIR="$WORK_DIR/store-example"
STATUS_EXAMPLE_MEMPOOL_DIR="$STATUS_EXAMPLE_STORE_DIR/mempool"
mkdir -p "$STATUS_EXAMPLE_MEMPOOL_DIR"
cp "$GENESIS_NOTE_PATH" "$STATUS_EXAMPLE_MEMPOOL_DIR/genesis_note.bin"
STATUS_EXAMPLE_CFG="$WORK_DIR/status-serve-example.toml"
sed \
  -e "s|127.0.0.1:8080|127.0.0.1:${STATUS_EXAMPLE_PORT}|" \
  -e "s|/var/lib/phantom-coin/data/mempool|${STATUS_EXAMPLE_MEMPOOL_DIR}|" \
  -e "s|/var/lib/phantom-coin/data|${STATUS_EXAMPLE_STORE_DIR}|" \
  -e "s|/etc/phantom-coin/status-auth.token|${AUTH_TOKEN_FILE}|" \
  "$ROOT_DIR/configs/status-serve.toml" > "$STATUS_EXAMPLE_CFG"
STATUS_EXAMPLE_LOG="$WORK_DIR/status-serve-example.log"
RUST_LOG=info "$NODE_BIN" status-serve --config "$STATUS_EXAMPLE_CFG" --genesis-note "$GENESIS_NOTE_PATH" >"$STATUS_EXAMPLE_LOG" 2>&1 &
STATUS_EXAMPLE_PID=$!
PIDS+=("$STATUS_EXAMPLE_PID")
wait_http_plain "http://127.0.0.1:${STATUS_EXAMPLE_PORT}/readyz"
wait_http_plain "http://127.0.0.1:${STATUS_EXAMPLE_PORT}/status"
STATUS_EXAMPLE_NOAUTH_STATUS="$WORK_DIR/status-example-noauth.status"
curl --silent --show-error --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${STATUS_EXAMPLE_PORT}/validator/control" > "$STATUS_EXAMPLE_NOAUTH_STATUS"
test "$(cat "$STATUS_EXAMPLE_NOAUTH_STATUS")" = "401"
if grep -q 'Finalitäts-Verifikation deaktiviert' "$STATUS_EXAMPLE_LOG"; then
  echo 'status-serve example unexpectedly disabled finality verification despite canonical genesis' >&2
  cat "$STATUS_EXAMPLE_LOG" >&2
  exit 1
fi
kill "$STATUS_EXAMPLE_PID" >/dev/null 2>&1 || true
wait "$STATUS_EXAMPLE_PID" >/dev/null 2>&1 || true
printf 'PASS status_example_config_starts\n'

GENESIS_MISMATCH_SRC_DIR="$WORK_DIR/genesis-mismatch-src/mempool"
mkdir -p "$GENESIS_MISMATCH_SRC_DIR"
"$GENESIS_BOOTSTRAP_BIN" --mempool-dir "$GENESIS_MISMATCH_SRC_DIR" --network-name ci-runtime-check-mismatch >/dev/null
GENESIS_MISMATCH_NOTE_PATH="$GENESIS_MISMATCH_SRC_DIR/genesis_note.bin"
test -f "$GENESIS_MISMATCH_NOTE_PATH"
STATUS_MISMATCH_LOG="$WORK_DIR/status-serve-genesis-mismatch.log"
set +e
"$NODE_BIN" status-serve --config "$STATUS_EXAMPLE_CFG" --genesis-note "$GENESIS_MISMATCH_NOTE_PATH" >"$STATUS_MISMATCH_LOG" 2>&1
status_mismatch_rc=$?
set -e
test "$status_mismatch_rc" -ne 0
if ! grep -q 'genesis_note passt nicht zu mempool_dir/genesis_note.bin' "$STATUS_MISMATCH_LOG"; then
  echo 'status-serve mismatch run did not fail with the expected genesis mismatch error' >&2
  cat "$STATUS_MISMATCH_LOG" >&2
  exit 1
fi
printf 'PASS status_genesis_mismatch_rejected\n'

STATUS_CFG="$WORK_DIR/status-serve.toml"
cat > "$STATUS_CFG" <<EOF
config_version = 1
addr = "127.0.0.1:${STATUS_PORT}"
mempool_dir = "${MEMPOOL_DIR}"
store_dir = "${STORE_DIR}"
fsync = true
require_auth = true
auth_token_file = "${AUTH_TOKEN_FILE}"
tls_cert = "${SERVER_CERT}"
tls_key = "${SERVER_KEY}"
EOF

STATUS_LOG="$WORK_DIR/status-serve.log"
RUST_LOG=info "$NODE_BIN" status-serve --config "$STATUS_CFG" --genesis-note "$GENESIS_NOTE_PATH" >"$STATUS_LOG" 2>&1 &
PIDS+=("$!")
wait_https_with_ca "$CA_CERT" "https://127.0.0.1:${STATUS_PORT}/readyz"
wait_https_with_ca "$CA_CERT" "https://127.0.0.1:${STATUS_PORT}/status"
test ! -e "$STORE_DIR/server.crt"
test ! -e "$STORE_DIR/server.key"
if grep -q 'Finalitäts-Verifikation deaktiviert' "$STATUS_LOG"; then
  echo 'status-serve unexpectedly disabled finality verification despite canonical genesis' >&2
  cat "$STATUS_LOG" >&2
  exit 1
fi
printf 'PASS genesis_present_enables_finality_verification\n'

VALIDATOR_PAYLOAD="$WORK_DIR/validator-control.json"
cat > "$VALIDATOR_PAYLOAD" <<EOF
{"version":1,"kill_switch":false,"maintenance":true,"manual_disable":false,"auto_reenable":true,"reason":"ci-runtime-check","updated_at":0,"cooldown_until":0,"last_changed_by":"ci"}
EOF

VALIDATOR_POST_RESP="$WORK_DIR/validator-post.json"
VALIDATOR_GET_RESP="$WORK_DIR/validator-get.json"
VALIDATOR_NOAUTH_STATUS="$WORK_DIR/validator-noauth.status"
TOKEN="$(tr -d '\n' < "$AUTH_TOKEN_FILE")"
curl --silent --show-error --output /dev/null --write-out '%{http_code}' --cacert "$CA_CERT" "https://127.0.0.1:${STATUS_PORT}/validator/control" > "$VALIDATOR_NOAUTH_STATUS"
test "$(cat "$VALIDATOR_NOAUTH_STATUS")" = "401"
printf 'PASS status_auth_401_without_token\n'
curl --silent --show-error --fail --cacert "$CA_CERT" -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" --data @"$VALIDATOR_PAYLOAD" "https://127.0.0.1:${STATUS_PORT}/validator/control" > "$VALIDATOR_POST_RESP"
curl --silent --show-error --fail --cacert "$CA_CERT" -H "Authorization: Bearer ${TOKEN}" "https://127.0.0.1:${STATUS_PORT}/validator/control" > "$VALIDATOR_GET_RESP"
CONTROL_FILE="$STORE_DIR/validator_control.json"
python3 - <<PY
import json
from pathlib import Path
post = json.loads(Path("$VALIDATOR_POST_RESP").read_text())
assert post["ok"] is True, post
saved = json.loads(Path("$CONTROL_FILE").read_text())
assert saved["version"] == 1, saved
assert saved["maintenance"] is True, saved
assert saved["manual_disable"] is False, saved
assert saved["auto_reenable"] is True, saved
assert saved["last_changed_by"] == "rpc", saved
assert saved["updated_at"] > 0, saved
preview = json.loads(Path("$VALIDATOR_GET_RESP").read_text())
assert preview["maintenance"] is True, preview
assert preview["manual_disable"] is False, preview
PY
printf 'PASS validator_control_persisted\n'

MINER_VALID_CFG="$WORK_DIR/miner-valid.toml"
sed \
  -e "s|https://127.0.0.1:8443|https://127.0.0.1:${STATUS_PORT}|" \
  -e "s|/etc/phantom-coin/certs/ca.crt|${CA_CERT}|" \
  "$ROOT_DIR/configs/miner.toml" > "$MINER_VALID_CFG"
MINER_VALID_LOG="$WORK_DIR/miner-valid.log"
set +e
run_with_timeout 6s env RUST_LOG=info "$MINER_BIN" run --config "$MINER_VALID_CFG" >"$MINER_VALID_LOG" 2>&1
miner_valid_rc=$?
set -e
test "$miner_valid_rc" -eq 124
if ! grep -q 'node status' "$MINER_VALID_LOG"; then
  echo 'miner valid-cert run did not reach successful status polling' >&2
  cat "$MINER_VALID_LOG" >&2
  exit 1
fi
printf 'PASS miner_valid_ca\n'

MINER_BAD_CFG="$WORK_DIR/miner-bad.toml"
sed \
  -e "s|https://127.0.0.1:8443|https://127.0.0.1:${STATUS_PORT}|" \
  -e "s|/etc/phantom-coin/certs/ca.crt|${WRONG_CA_CERT}|" \
  "$ROOT_DIR/configs/miner.toml" > "$MINER_BAD_CFG"
MINER_BAD_LOG="$WORK_DIR/miner-bad.log"
set +e
run_with_timeout 6s env RUST_LOG=info "$MINER_BIN" run --config "$MINER_BAD_CFG" >"$MINER_BAD_LOG" 2>&1
miner_bad_rc=$?
set -e
test "$miner_bad_rc" -eq 124
if ! grep -q 'status request failed' "$MINER_BAD_LOG"; then
  echo 'miner wrong-ca run did not produce request failure' >&2
  cat "$MINER_BAD_LOG" >&2
  exit 1
fi
if grep -q 'node status' "$MINER_BAD_LOG"; then
  echo 'miner wrong-ca run unexpectedly reached successful status polling' >&2
  cat "$MINER_BAD_LOG" >&2
  exit 1
fi
printf 'PASS miner_wrong_ca_rejected\n'

STATUS_HTTP_STORE="$WORK_DIR/status-http-store"
STATUS_HTTP_PRIME_LOG="$WORK_DIR/status-http-prime.log"
set +e
run_with_timeout 5s env RUST_LOG=info "$NODE_BIN" run --role fullnode --store-dir "$STATUS_HTTP_STORE" --addr "127.0.0.1:19000" >"$STATUS_HTTP_PRIME_LOG" 2>&1
status_http_prime_rc=$?
set -e
test "$status_http_prime_rc" -eq 124
test -f "$STATUS_HTTP_STORE/utxo/CURRENT"
STATUS_HTTP_LOG="$WORK_DIR/status-http.log"
RUST_LOG=info "$STATUS_HTTP_BIN" --addr "127.0.0.1:${STATUS_HTTP_PORT}" --store-dir "$STATUS_HTTP_STORE" >"$STATUS_HTTP_LOG" 2>&1 &
PIDS+=("$!")
wait_https_insecure "https://127.0.0.1:${STATUS_HTTP_PORT}/status"
test -f "$STATUS_HTTP_STORE/server.crt"
test -f "$STATUS_HTTP_STORE/server.key"
STATUS_HTTP_OK="$WORK_DIR/status-http-ok.json"
curl --silent --show-error --fail --insecure "https://127.0.0.1:${STATUS_HTTP_PORT}/status" > "$STATUS_HTTP_OK"
python3 - <<PY
import json
from pathlib import Path
payload = json.loads(Path("$STATUS_HTTP_OK").read_text())
assert payload["ok"] is True, payload
assert payload["service"] == "phantom-node", payload
PY
set +e
curl --silent --show-error --fail "https://127.0.0.1:${STATUS_HTTP_PORT}/status" >/dev/null 2>"$WORK_DIR/status-http-plain-fail.log"
status_http_plain_rc=$?
set -e
test "$status_http_plain_rc" -ne 0
printf 'PASS status_http_local_helper_boundary\n'

printf 'ALL_RUNTIME_CHECKS_PASSED\n'
