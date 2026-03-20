# Testnet-0 (Single-Shard) – Runbook

Ziel: Minimaler Bring-up eines Single-Shard-Testnets (tn0) mit generierter Genesis, Health-Checks und `status-serve`.

## Voraussetzungen
- Rust toolchain (stable), Cargo
- Netzwerkzugriff lokal (Ports frei, z. B. 18080)
- Workspace-Root: Repository-Wurzel

## Genesis erzeugen
Verwendet `phantom-node::genesis_bootstrap` via Skript `scripts/testnets/genesis_tn0.sh`.

```bash
# Standardparameter: NETWORK_NAME=tn0, SHARDS_INITIAL=1, COMMITTEE_K=21, TXS_PER_PAYLOAD=256
bash scripts/testnets/genesis_tn0.sh

# Beispiele (Override per Env):
NETWORK_NAME=tn0-dev SHARDS_INITIAL=1 COMMITTEE_K=21 TXS_PER_PAYLOAD=256 \
  bash scripts/testnets/genesis_tn0.sh
```

Erwartetes Artefakt:
- `${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0/mempool/genesis_note.bin` (oder per `MEMPOOL_DIR` Override)

## status-serve starten (lokal)
Startet den eingebauten Status-/Metrikserver.

```bash
RUST_LOG=info cargo run -q -p phantom-node -- \
  status-serve \
  --addr 127.0.0.1:18080 \
  --mempool-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0/mempool" \
  --store-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0" \
  --fsync
```

## Health-Checks
```bash
# Readiness
curl -sf http://127.0.0.1:18080/readyz

# Status (JSON)
curl -s http://127.0.0.1:18080/status | jq .

# Metrics (Prometheus)
curl -s http://127.0.0.1:18080/metrics | grep -E "pc_network_id|pc_genesis_height"
```

Hinweise:
- `pc_network_id` und `pc_genesis_height` sollten in den Metriken vorhanden sein.
- Für automatisierte E2E-Validierung steht `crates/phantom-node/scripts/e2e_genesis.sh` bereit.

## Aufräumen
Beenden Sie den `status-serve`-Prozess (Ctrl+C) und entfernen Sie ggf. temporäre Daten unter `${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0`.
