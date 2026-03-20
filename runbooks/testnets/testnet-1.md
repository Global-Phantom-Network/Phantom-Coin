# Testnet-1 (S=64, k=21, Attestoren) – Runbook

Ziel: Bring-up eines 64‑Shard‑Testnets (tn1) mit generierter Genesis, `status-serve`-Smoke-Test und Basisprüfungen.

## Voraussetzungen
- Rust toolchain (stable), Cargo
- Ports lokal frei (z. B. 18080)
- Workspace‑Root: Repository‑Wurzel

## Genesis erzeugen
Erzeugt `genesis_note.bin` über `phantom-node::genesis_bootstrap` via Skript `scripts/testnets/genesis_tn1.sh`.

```bash
# Standardparameter: NETWORK_NAME=tn1, SHARDS_INITIAL=64, COMMITTEE_K=21, TXS_PER_PAYLOAD=256
bash scripts/testnets/genesis_tn1.sh

# Beispiele (Override per Env):
NETWORK_NAME=tn1-dev SHARDS_INITIAL=64 COMMITTEE_K=21 TXS_PER_PAYLOAD=256 \
  bash scripts/testnets/genesis_tn1.sh
```

Erwartetes Artefakt:
- `${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1/mempool/genesis_note.bin` (oder per `MEMPOOL_DIR` Override)

## status-serve starten (lokal)
Start des integrierten Status-/Metrikservers.

```bash
RUST_LOG=info cargo run -q -p phantom-node -- \
  status-serve \
  --addr 127.0.0.1:18080 \
  --mempool-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1/mempool" \
  --store-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1" \
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
- `pc_network_id` und `pc_genesis_height` müssen vorhanden sein.
- Für einen automatisierten Smoke‑Test steht `crates/phantom-node/scripts/e2e_genesis.sh` zur Verfügung (erzeugt Genesis, startet `status-serve`, bootstrapped und prüft Endpunkte).

## Aufräumen
Prozess beenden (Ctrl+C) und temporäre Daten unter `${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1` löschen, falls erforderlich.
