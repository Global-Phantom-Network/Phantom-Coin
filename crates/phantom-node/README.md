# phantom-node

Status-/Broadcast-HTTP-Server und Node-Runtime-Hilfen.

## Endpunkte
- GET `/status` → `{ "ok": true, "service": "phantom-node", "ts": <unix> }`
- GET `/healthz` → `{ "ok": true }`
- GET `/readyz` → `{ "ok": true }` wenn `mempool_dir` erreichbar ist, sonst 503
- GET `/metrics` → Prometheus-Text (u. a. Broadcast-Zähler)
- POST `/tx/broadcast` (Content-Type: `application/octet-stream`) → akzeptiert finalisierte `MicroTx` (pc-codec binär)
  - Antwort: `{ "ok": true, "txid": "<hex>", "status": "accepted|duplicate", "ts": <unix> }`
  - Optional: Bearer-Auth erzwingen (`--require-auth`), Header: `Authorization: Bearer <TOKEN>`

## Start per CLI
```bash
cargo run -p phantom-node -- \
  StatusServe \
  --addr 127.0.0.1:8080 \
  --mempool-dir pc-data/mempool \
  --fsync true \
  --require-auth true \
  --auth-token supersecret
```

## Start per Config (TOML)
Beispiel: `node.toml`
```toml
addr = "127.0.0.1:8080"
mempool_dir = "pc-data/mempool"
fsync = true
require_auth = true
auth_token = "supersecret"
```
Start:
```bash
cargo run -p phantom-node -- StatusServe --config node.toml
```

## Hinweis zu Performance
- HTTP-Server liegt außerhalb des Konsens-/P2P-Hotpaths. Broadcast/IO beeinträchtigt nicht das 1M TPS‑Ziel.
- Disk-Persistenz (fsync optional) ist für Haltbarkeit ausgelegt.

## Start-Szenarien (CLI)

### QUIC: Listener starten (vollständiger Node-Flow)
```bash
cargo run -p phantom-node -- \
  P2pQuicListen \
  --addr 127.0.0.1:9000 \
  --store_dir pc-data \
  --fsync true \
  --k 21 \
  # optional \
  --genesis genesis.toml \
  --tx_proposer true \
  --tx_proposer_interval_ms 5000 \
  --pow_miner false \
  --mint_amount 100000 \
  --mint_lock 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```
- `--store_dir`: Persistenz für Header/Payloads und Mempool.
- `--tx_proposer`: baut periodisch Payloads aus Mempool-TXs und announced sie.
- `--pow_miner`: einfacher Mint-PoW (Dev) – nur für lokale Experimente.
- `--k`: Committee-Größe (Sitzanzahl), überschreibt ggf. `genesis.toml`.

### QUIC: Client verbinden
```bash
cargo run -p phantom-node -- \
  P2pQuicConnect \
  --addr 127.0.0.1:9000 \
  --cert_file server.der
```

### libp2p: P2P-Service (Gossipsub je Shard)
```bash
cargo run -p phantom-node -- \
  P2pRun \
  --max_peers 128
```

### P2P-Metriken bereitstellen (Prometheus)
```bash
cargo run -p phantom-node -- \
  P2pMetricsServe \
  --addr 127.0.0.1:9100

curl -s http://127.0.0.1:9100/metrics | head
```

### Payload bauen (offline) und Root ausgeben
```bash
cargo run -p phantom-node -- \
  BuildPayload \
  --store_dir pc-data \
  --from_mempool true \
  --out_file payload.bin
```
- Optional via Dateien: `--microtx_file txs.bin`, `--mints_file mints.bin`, `--claims_file claims.bin`, `--evidences_file evidences.bin`.

### Konsens-Tools: Ack-Distanzen und Payout-Root
```bash
# Ack-Distanzen aus Header-Datei (ack_id = 32B Hex)
cargo run -p phantom-node -- \
  ConsensusAckDists \
  --ack_id <hex32> \
  --headers_file headers.bin \
  --k 21

# Committee+Attestors Payout-Root (deterministisch)
cargo run -p phantom-node -- \
  ConsensusPayoutRoot \
  --ack_id <hex32> \
  --headers_file headers.bin \
  --k 21 \
  --fees 1000000 \
  --recipients <hex32,hex32,...> \
  --proposer_index 0
```

### Status-/RPC-Server (erweitert)
- Bereits oben dokumentiert (`StatusServe`). Zusätzlich vorhanden:
  - `POST /state/apply_mint_with_index` → Mint+Index in globalen UTXO-State schreiben.
  - `POST /stake/bond` → UTXOs binden (Bond), uhrfreie Maturity-Logik.
  - `POST /stake/unbond` → Unbonding gemäß Schwelle.
  - `GET /mint/template`, `POST /mint/submit`, `GET /mint/status/{id}` → PoW/Mint-RPCs.
- Auth (optional): `--require-auth true` und `--auth-token <TOKEN>`; dann `Authorization: Bearer <TOKEN>` senden.
- TLS/mTLS (optional): `--tls_cert`, `--tls_key`, `--tls_client_ca`.

### Hinweise zu Keys und Signer
- Schlüssel werden in `phantom-signer` getrennt geführt: `seat | bond | payout`.
- Siehe `crates/phantom-signer/README.md` für Keygen/Import/HWI/PSBT/Broadcast.
