#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NODE_BIN="${NODE_BIN:-$ROOT_DIR/target/debug/phantom-node}"
GENESIS_BOOTSTRAP_BIN="${GENESIS_BOOTSTRAP_BIN:-$ROOT_DIR/target/debug/genesis_bootstrap}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
UNIT_NAME="${UNIT_NAME:-phantom-ci-status-$RANDOM}"
STATUS_PORT="${STATUS_PORT:-28443}"
TOKEN_VALUE="ci-status-token"

cleanup() {
  sudo journalctl -u "$UNIT_NAME" --no-pager > "$WORK_DIR/journal.log" 2>/dev/null || true
  sudo systemctl status "$UNIT_NAME" --no-pager > "$WORK_DIR/systemctl-status.log" 2>/dev/null || true
  sudo systemctl stop "$UNIT_NAME" >/dev/null 2>&1 || true
  sudo systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
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

wait_https_with_ca() {
  local ca="$1"
  local url="$2"
  local attempts="${3:-120}"
  for _ in $(seq 1 "$attempts"); do
    if curl --silent --show-error --fail --cacert "$ca" "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  sudo systemctl status "$UNIT_NAME" --no-pager || true
  echo "timeout waiting for $url" >&2
  return 1
}

require_executable "$NODE_BIN"
require_executable "$GENESIS_BOOTSTRAP_BIN"
command -v curl >/dev/null 2>&1
command -v openssl >/dev/null 2>&1
command -v python3 >/dev/null 2>&1
command -v systemctl >/dev/null 2>&1
command -v systemd-run >/dev/null 2>&1
command -v sudo >/dev/null 2>&1

if ! systemctl show-environment >/dev/null 2>&1; then
  echo "systemd is not available on this runner" >&2
  exit 1
fi

BIN_DIR="$WORK_DIR/opt/phantom-coin/bin"
ETC_DIR="$WORK_DIR/etc/phantom-coin"
CERT_DIR="$ETC_DIR/certs"
DATA_DIR="$WORK_DIR/var/lib/phantom-coin/data"
MEMPOOL_DIR="$DATA_DIR/mempool"
GENESIS_SRC_DIR="$WORK_DIR/genesis-src/mempool"
mkdir -p "$BIN_DIR" "$CERT_DIR" "$MEMPOOL_DIR" "$GENESIS_SRC_DIR"
install -m 0755 "$NODE_BIN" "$BIN_DIR/phantom-node"

CA_KEY="$CERT_DIR/ca.key"
CA_CERT="$CERT_DIR/ca.crt"
SERVER_KEY="$CERT_DIR/server.key"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CERT="$CERT_DIR/server.crt"
SERVER_EXT="$CERT_DIR/server.ext"

openssl genrsa -out "$CA_KEY" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 2 -subj "/CN=Phantom CI Systemd CA" -out "$CA_CERT" >/dev/null 2>&1
openssl genrsa -out "$SERVER_KEY" 2048 >/dev/null 2>&1
openssl req -new -key "$SERVER_KEY" -subj "/CN=127.0.0.1" -out "$SERVER_CSR" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$SERVER_EXT"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 2 -sha256 -extfile "$SERVER_EXT" >/dev/null 2>&1
chmod 600 "$SERVER_KEY"

AUTH_TOKEN_FILE="$ETC_DIR/status-auth.token"
printf '%s\n' "$TOKEN_VALUE" > "$AUTH_TOKEN_FILE"
chmod 600 "$AUTH_TOKEN_FILE"

"$GENESIS_BOOTSTRAP_BIN" --mempool-dir "$GENESIS_SRC_DIR" --network-name ci-systemd-check >/dev/null
GENESIS_NOTE_PATH="$GENESIS_SRC_DIR/genesis_note.bin"
test -f "$GENESIS_NOTE_PATH"
cp "$GENESIS_NOTE_PATH" "$ETC_DIR/genesis_note.bin"

STATUS_CFG="$ETC_DIR/status-serve.toml"
cat > "$STATUS_CFG" <<EOF
config_version = 1
addr = "127.0.0.1:${STATUS_PORT}"
mempool_dir = "${MEMPOOL_DIR}"
store_dir = "${DATA_DIR}"
fsync = true
require_auth = true
auth_token_file = "${AUTH_TOKEN_FILE}"
tls_cert = "${SERVER_CERT}"
tls_key = "${SERVER_KEY}"
EOF

sudo systemd-run --unit "$UNIT_NAME" --property=User="$(id -un)" --property=Group="$(id -gn)" --property=WorkingDirectory="$WORK_DIR/opt/phantom-coin" --property=Environment="RUST_LOG=info" --property=NoNewPrivileges=true --property=PrivateTmp=true --property=ProtectSystem=strict --property=ProtectHome=true --property=ReadWritePaths="$DATA_DIR" --property=ReadOnlyPaths="$ETC_DIR" "$BIN_DIR/phantom-node" status-serve --config "$STATUS_CFG" --genesis-note "$ETC_DIR/genesis_note.bin" >/dev/null
wait_https_with_ca "$CA_CERT" "https://127.0.0.1:${STATUS_PORT}/readyz"
wait_https_with_ca "$CA_CERT" "https://127.0.0.1:${STATUS_PORT}/status"

VALIDATOR_PAYLOAD="$WORK_DIR/validator-control.json"
cat > "$VALIDATOR_PAYLOAD" <<EOF
{"version":1,"kill_switch":false,"maintenance":true,"manual_disable":false,"auto_reenable":true,"reason":"ci-systemd-check","updated_at":0,"cooldown_until":0,"last_changed_by":"ci"}
EOF
VALIDATOR_POST_RESP="$WORK_DIR/validator-post.json"
VALIDATOR_NOAUTH_STATUS="$WORK_DIR/validator-noauth.status"
TOKEN="$(tr -d '\n' < "$AUTH_TOKEN_FILE")"
curl --silent --show-error --output /dev/null --write-out '%{http_code}' --cacert "$CA_CERT" "https://127.0.0.1:${STATUS_PORT}/validator/control" > "$VALIDATOR_NOAUTH_STATUS"
test "$(cat "$VALIDATOR_NOAUTH_STATUS")" = "401"
printf 'PASS systemd_status_auth_401_without_token\n'
curl --silent --show-error --fail --cacert "$CA_CERT" -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" --data @"$VALIDATOR_PAYLOAD" "https://127.0.0.1:${STATUS_PORT}/validator/control" > "$VALIDATOR_POST_RESP"
CONTROL_FILE="$DATA_DIR/validator_control.json"
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
PY
printf 'PASS systemd_validator_control_persisted\n'
