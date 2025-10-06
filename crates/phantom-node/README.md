# phantom-node

Status-/Broadcast-HTTP-Server und Node-Runtime-Hilfen.

## Endpunkte
- GET `/status` → `{ "ok": true, "service": "phantom-node", "ts": <unix>, "genesis": { "network_id": <hex>, "network_name": <string>, "version": <u8>, "params": { ... } } }`
- GET `/healthz` → `{ "ok": true }`
- GET `/readyz` → `{ "ok": true }` wenn `mempool_dir` erreichbar ist, sonst 503
- GET `/metrics` → Prometheus-Text (u. a. Broadcast-Zähler, Genesis-/Netzwerk-Metriken)
- POST `/tx/broadcast` (Content-Type: `application/octet-stream`) → akzeptiert finalisierte `MicroTx` (pc-codec binär)
  - Antwort: `{ "ok": true, "txid": "<hex>", "status": "accepted|duplicate", "ts": <unix> }`
  - Optional: Bearer-Auth erzwingen (`--require-auth`), Header: `Authorization: Bearer <TOKEN>`

- POST `/consensus/select_committee` (Content-Type: `application/json`)
  - Zweck: VRF‑basierte Committee‑Selektion (Determinismus, Anti‑Kollokation, Attendance/Cooldown)
  - Request:
    ```json
    {
      "k": 21,
      "current_anchor_index": 12345,
      "epoch_len": 10000,
      "network_id": "<hex32>",
      "last_anchor_id": "<hex32>",
      "rotation": { "cooldown_anchors": 10000, "min_attendance_pct": 50 },
      "candidates": [
        {
          "recipient_id": "<hex32>",
          "operator_id": "<hex32>",
          "bls_pk": "<hex48>",
          "last_selected_at": 10000,
          "attendance_recent_pct": 100,
          "vrf_proof": "<hex96>"
        }
      ]
    }
    ```

- POST `/consensus/attestor_aggregate_sigs` (Content-Type: `application/json`)
  - Zweck: Aggregiert mehrere BLS‑Signaturen (G2) für dieselbe Nachricht.
  - Request:
    ```json
    { "parts": ["<hex96>", "<hex96>"] }
    ```
  - Response: `{ "ok": true, "agg_sig": "<hex96>" }`

- POST `/consensus/attestor_fast_verify` (Content-Type: `application/json`)
  - Zweck: Schnelle Verifikation einer Aggregat‑Signatur für dieselbe Nachricht über mehrere Public Keys.
  - Request:
    ```json
    {
      "network_id": "<hex32>",
      "epoch": 1,
      "topic": "<hex>",
      "bls_pks": ["<hex48>", "<hex48>"],
      "agg_sig": "<hex96>"
    }
    ```
  - Response: `{ "ok": true, "valid": true }`

- POST `/consensus/attestor_fast_verify_seats` (Content-Type: `application/json`)
  - Zweck: Wie `attestor_fast_verify`, jedoch werden die Public Keys aus `seats`-Einträgen bezogen (z. B. aus der Auswahl zurückgeliefert).
  - Request:
    ```json
    {
      "network_id": "<hex32>",
      "epoch": 1,
      "topic": "<hex>",
      "seats": [{"bls_pk":"<hex48>"}, {"bls_pk":"<hex48>"}],
      "agg_sig": "<hex96>"
    }
    ```
  - Response: `{ "ok": true, "valid": true }`

- GET `/consensus/config`
  - Liefert die effektive Rotation-Konfiguration (inkl. Defaults oder CLI-Overrides):
    ```json
    { "ok": true, "rotation": { "epoch_len": 10000, "cooldown_anchors": 10000, "min_attendance_pct": 50 } }
    ```

- GET `/consensus/current_committee`
  - Gibt das zuletzt persistierte Komitee zurück (siehe Auto‑Rotation). 404 falls nicht vorhanden.
  - Form:
    ```json
    { "ok": true, "epoch": 1, "current_anchor_index": 12345, "seed": "<hex32>", "n_selected": 21, "seats": [ ... ], "ts": 1700000000 }
    ```

- POST `/consensus/select_committee_persist` (Content-Type: `application/json`)
  - Wie `/consensus/select_committee`, aber persistiert das Ergebnis als `vrf_committee.json` im `mempool_dir`.
  - Body entspricht der Select‑Anfrage inkl. `network_id` und `last_anchor_id`.

- POST `/consensus/select_attestors` (Content-Type: `application/json`)
  - Zweck: VRF‑basierte Stichprobe von Attestoren (Determinismus, Anti‑Kollokation, Attendance/Cooldown)
  - Request:
    ```json
    {
      "m": 128,
      "current_anchor_index": 12345,
      "epoch_len": 10000,
      "network_id": "<hex32>",
      "last_anchor_id": "<hex32>",
      "rotation": { "cooldown_anchors": 10000, "min_attendance_pct": 50 },
      "candidates": [
        {
          "recipient_id": "<hex32>",
          "operator_id": "<hex32>",
          "bls_pk": "<hex48>",
          "last_selected_at": 10000,
          "attendance_recent_pct": 100,
          "vrf_proof": "<hex96>"
        }
      ]
    }
    ```
  - Response: `{ "ok": true, "epoch": <u64>, "seed": "<hex32>", "n_selected": <usize>, "seats": [{"recipient_id":"<hex32>","operator_id":"<hex32>","bls_pk":"<hex48>","score":"<hex32>"}] }`

- POST `/consensus/select_attestors_fair` (Content-Type: `application/json`)
  - Zweck: Faire Stichprobe mit Caps/Performance‑Index.
  - Zusätzlich zu obigem Body:
    ```json
    {
      "cap_limit_per_op": 2,
      "recent_op_selection_count": [{ "operator_id": "<hex32>", "count": 1 }],
      "perf_index": [{ "operator_id": "<hex32>", "score": 100 }]
    }
    ```
  - Response: identisch zu `/consensus/select_attestors`.

- POST `/consensus/attestor_payout_root` (Content-Type: `application/json`)
  - Zweck: Ermittelt die Merkle‑Root des Attestor‑Topfes für eine gegebene Seats‑Liste.
  - Request:
    ```json
    {
      "fees_total": 1000000,
      "fee_params": {"p_base_bp":6500,"p_prop_bp":1000,"p_perf_bp":1500,"p_att_bp":1000,"d_max":8,"perf_weights":[10000,6000,3600,2160,1296,777,466,280]},
      "seats": [{"recipient_id":"<hex32>"}]
    }
    ```
    `fee_params` optional; Default: `FeeSplitParams::recommended()`.
  - Response: `{ "ok": true, "payout_root": "<hex32>", "n_seats": <usize> }`

- POST `/consensus/attestor_payout_proof` (Content-Type: `application/json`)
  - Zweck: Liefert einen Merkle‑Proof für einen konkreten Empfänger innerhalb der Attestor‑Payout‑Verteilung.
  - Request:
    ```json
    {
      "fees_total": 1000000,
      "fee_params": null,
      "seats": [{"recipient_id":"<hex32>"}, {"recipient_id":"<hex32>"}],
      "recipient_id": "<hex32>"
    }
    ```
  - Response:
    ```json
    {
      "ok": true,
      "index": 0,
      "leaf": "<hex32>",
      "payout_root": "<hex32>",
      "proof": [{"hash":"<hex32>", "right": true}]
    }
    ```

- POST `/consensus/set_rotation_context` (Content-Type: `application/json`)
  - Setzt den Kontext für Auto‑Rotation:
    ```json
    { "k": 21, "current_anchor_index": 12345, "epoch_len": 10000, "network_id": "<hex32>", "last_anchor_id": "<hex32>" }
    ```
  - Persistiert nach `mempool_dir/vrf_rotation_ctx.json`.

- POST `/consensus/set_candidates` (Content-Type: `application/json`)
  - Setzt die Kandidatenliste für Auto‑Rotation und persistiert nach `mempool_dir/vrf_candidates.json`.
  - Body: `[{ "recipient_id":"<hex32>", "operator_id":"<hex32>", "bls_pk":"<hex48>", "last_selected_at":10000, "attendance_recent_pct":100, "vrf_proof":"<hex96>" }, ...]`
  - Response:
    ```json
    {
      "ok": true,
      "epoch": 1,
      "seed": "<hex32>",
      "n_selected": 21,
      "seats": [ { "recipient_id": "<hex32>", "operator_id": "<hex32>", "bls_pk": "<hex48>", "score": "<hex32>" } ]
    }
    ```

- POST `/genesis/bootstrap`
  - Zweck: Bootstrap der Genesis (A0) aus `genesis_note.bin` im `mempool_dir`.
  - Verhalten: Baut `AnchorPayloadV2` (mit `genesis_note`) und `AnchorHeaderV2` (mit `network_id`), validiert mit `validate_genesis_anchor()`.
  - Antwort bei Erfolg: `{ "ok": true, "network_id": "<hex>", "message": "genesis bootstrap validated" }`
  - Antwort bei Fehler: `{ "ok": false, "error": "..." }`

## Start per CLI
```bash
cargo run -p phantom-node -- \
  StatusServe \
  --addr 127.0.0.1:8080 \
  --mempool-dir pc-data/mempool \
  --fsync true \
  --require-auth true \
  --auth-token supersecret \
  # optionale VRF-Overrides (ersetzen Config-Werte) \
  --vrf-epoch-len 10000 \
  --vrf-cooldown-anchors 10000 \
  --vrf-min-attendance-pct 50 \
```

## Start per Config (TOML)
Beispiel: `node.toml`
```toml
addr = "127.0.0.1:8080"
mempool_dir = "pc-data/mempool"
fsync = true
require_auth = true
auth_token = "supersecret"

[consensus]

[consensus.rotation]
# Optional: Epochenlänge (Anzahl Anker pro Epoche). 0 oder nicht gesetzt → Default 10000
epoch_len = 10000
# Cooldown (Anker‑Abstand) seit letzter Auswahl
cooldown_anchors = 10000
# Mindest‑Attendance in Prozent
min_attendance_pct = 50
```
Start:
```bash
cargo run -p phantom-node -- StatusServe --config node.toml
```

## Hinweis zu Performance
- HTTP-Server liegt außerhalb des Konsens-/P2P-Hotpaths. Broadcast/IO beeinträchtigt nicht das 1M TPS‑Ziel.
- Disk-Persistenz (fsync optional) ist für Haltbarkeit ausgelegt.

## VRF Auto‑Rotation

- **Ablauf**
  - Hintergrundtask prüft periodisch (`~1.5s`), ob `mempool_dir/vrf_rotation_ctx.json` (Kontext) und `mempool_dir/vrf_candidates.json` (Kandidaten) vorhanden sind.
  - Bei Epochenwechsel wird `committee_select_vrf()` aufgerufen und das Ergebnis als `mempool_dir/vrf_committee.json` persistiert.
  - Abfrage über `GET /consensus/current_committee`.
- **Kontext setzen**: `POST /consensus/set_rotation_context` (siehe oben)
- **Kandidaten setzen**: `POST /consensus/set_candidates` (siehe oben)
- **Konfig-Quelle**
  - Defaults bzw. Werte aus `configs/node.toml` unter `[consensus.rotation]`.
  - CLI‑Overrides: `--vrf-epoch-len`, `--vrf-cooldown-anchors`, `--vrf-min-attendance-pct`.

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

# Committee+Attestors Payout-Root (deterministisch)
cargo run -p phantom-node consensus-payout-root \
  --ack_id <hex32> \
  --headers_file headers.bin \
  --k 21 \
  --fees 1000000 \
  --recipients <hex32,hex32,...> \
  --proposer_index 0 \

  - `POST /state/apply_mint_with_index` → Mint+Index in global UTXO state.
  - `POST /stake/bond` → Bond UTXOs (Bond), free maturity logic.
  - `POST /stake/unbond` → Unbonding according to request.
  - Auth (optional): `--require-auth true` und `--auth-token <TOKEN>`; dann `Authorization: Bearer <TOKEN>` senden.
  - TLS/mTLS (optional): `--tls_cert`, `--tls_key`, `--tls_client_ca`.

#### Metrik-Details
- **pc_network_id{network="<name>"} 1**: Kennzeichnet, dass eine `genesis_note` erfolgreich gelesen werden konnte; Label `network` zeigt den `network_name`.

### Hinweise zu Keys und Signer
- Schlüssel werden in `phantom-signer` getrennt geführt: `seat | bond | payout`.
- Siehe `crates/phantom-signer/README.md` für Keygen/Import/HWI/PSBT/Broadcast.
