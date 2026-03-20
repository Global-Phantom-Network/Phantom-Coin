# phantom-node

## English version

HTTP status/broadcast server and node runtime helpers.

Provides HTTP/JSON APIs for status, health, metrics, transaction broadcast, consensus utilities, VRF committee selection, DA gating and various node runtime helpers around `phantom-node`.

### Quickstart

```bash
cargo run -p phantom-node -- run --role fullnode --store-dir /var/lib/phantom-coin/data --addr 127.0.0.1:9000
cargo run -p phantom-node -- status-serve --addr 127.0.0.1:8080 --store-dir /var/lib/phantom-coin/data --mempool-dir /var/lib/phantom-coin/data/mempool
cargo run -p phantom-node -- p2p-metrics-serve --addr 127.0.0.1:9100
```

Without a subcommand, `phantom-node` starts `Run` with role `fullnode`. The status server only binds to 127.0.0.1 or ::1.
Runtime data defaults to an OS-specific app-data directory outside the repository tree. Override it via `PHANTOM_STORE_DIR` or an explicit absolute `--store-dir`.

## Deutsche Version

Status-/Broadcast-HTTP-Server und Node-Runtime-Hilfen.

### Schnellstart

```bash
cargo run -p phantom-node -- run --role fullnode --store-dir /var/lib/phantom-coin/data --addr 127.0.0.1:9000
cargo run -p phantom-node -- status-serve --addr 127.0.0.1:8080 --store-dir /var/lib/phantom-coin/data --mempool-dir /var/lib/phantom-coin/data/mempool
cargo run -p phantom-node -- p2p-metrics-serve --addr 127.0.0.1:9100
```

Ohne Subcommand startet `phantom-node` automatisch im `Run`-Modus mit Rolle `fullnode`. Der Status-Server bindet nur an 127.0.0.1 oder ::1.
Runtime-Daten landen standardmäßig in einem OS-spezifischen App-Data-Verzeichnis außerhalb des Repository-Baums. Überschreibe das bei Bedarf über `PHANTOM_STORE_DIR` oder einen expliziten absoluten `--store-dir`.

## Kanonische Dokumentation

Die aktuellen Live-Dokumente liegen unter [docs/README.md](../../docs/README.md).
Fuer Emission, Mining und Betrieb sind vor allem diese Dateien kanonisch:

- [docs/SPEC_POW.md](../../docs/SPEC_POW.md)
- [docs/mining-api.md](../../docs/mining-api.md)
- [docs/observability.md](../../docs/observability.md)
- [docs/SPEC_CODEC.md](../../docs/SPEC_CODEC.md)

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
          "bls_pop": "<hex96>",
          "last_selected_at": 10000,
          "attendance_recent_pct": 100,
          "vrf_proof": "<hex96>"
        }
      ]
    }
    ```

## Authentifizierung

Wenn der Server mit `--require-auth` gestartet wird, müssen alle geschützten Endpoints mit einem Bearer‑Token aufgerufen werden.

- Header: `Authorization: Bearer <TOKEN>`
- Token-Konfiguration: bevorzugt via `--auth-token-file <PATH>`, `PHANTOM_STATUS_AUTH_TOKEN` oder Config.

### cURL‑Beispiele

- Attestoren‑Selektion:
```bash
curl -sS -X POST \
  -H "Authorization: Bearer <STATUS_TOKEN>" \
  -H "Content-Type: application/json" \
  --data '{
    "m": 128,
    "current_anchor_index": 12345,
    "epoch_len": 10000,
    "network_id": "<hex32>",
    "last_anchor_id": "<hex32>",
    "rotation": {"cooldown_anchors":10000, "min_attendance_pct":50},
    "candidates": [{
      "recipient_id": "<hex32>",
      "operator_id": "<hex32>",
      "bls_pk": "<hex48>",
      "bls_pop": "<hex96>",
      "last_selected_at": 0,
      "attendance_recent_pct": 100,
      "vrf_proof": "<hex96>"
    }]
  }' \
  http://127.0.0.1:8080/consensus/select_attestors
```

- BLS‑Aggregation:
```bash
curl -sS -X POST \
  -H "Authorization: Bearer <STATUS_TOKEN>" \
  -H "Content-Type: application/json" \
  --data '{"parts":["<hex96>","<hex96>"]}' \
  http://127.0.0.1:8080/consensus/attestor_aggregate_sigs
```

- Fast‑Aggregate‑Verify:
```bash
curl -sS -X POST \
  -H "Authorization: Bearer <STATUS_TOKEN>" \
  -H "Content-Type: application/json" \
  --data '{
    "network_id":"<hex32>",
    "epoch":1,
    "topic":"<hex>",
    "bls_pks":["<hex48>","<hex48>"],
    "agg_sig":"<hex96>"
  }' \
  http://127.0.0.1:8080/consensus/attestor_fast_verify
```

- Fast‑Verify (Seats‑basiert):
```bash
curl -sS -X POST \
  -H "Authorization: Bearer <STATUS_TOKEN>" \
  -H "Content-Type: application/json" \
  --data '{
    "network_id":"<hex32>",
    "epoch":1,
    "topic":"<hex>",
    "seats":[{"bls_pk":"<hex48>"},{"bls_pk":"<hex48>"}],
    "agg_sig":"<hex96>"
  }' \
  http://127.0.0.1:8080/consensus/attestor_fast_verify_seats
```

## Rate Limiting

- Optional über `[http_rate]` in der Node‑Config steuerbar (pro Endpoint Token‑Bucket).
- Felder pro Regel:
  - `capacity`: maximale Token im Bucket.
  - `refill_per_sec`: Auffüllrate pro Sekunde.
- Verhalten:
  - Bei überschrittenem Limit Antwort `429` mit `{ "ok": false, "error": "rate limited" }`.
  - In Prometheus unter `/metrics` werden Totals und Fehlerzähler pro Endpoint exponiert, z. B. `phantom_node_consensus_select_committee_total` und `phantom_node_consensus_select_committee_errors_total`.
  - Auth (falls `--require-auth`/`auth_token` aktiv): fehlendes/invalides Bearer‑Token führt zu `401` und erhöht den jeweiligen Fehlerzähler.
- mTLS‑Policy:
  - Wenn `tls_client_ca` gesetzt ist, werden alle Pfade unter `/consensus/*` auf Plain‑HTTP geblockt (`403` mit `{ "ok": false, "error": "mtls_required" }`). Diese Endpoints sind dann nur via TLS+mTLS erreichbar.

Beispiel `node.toml` Ausschnitt:

```toml
[http_rate]
select_committee = { capacity = 10, refill_per_sec = 5 }
select_committee_persist = { capacity = 5, refill_per_sec = 2 }
select_attestors = { capacity = 20, refill_per_sec = 10 }
select_attestors_fair = { capacity = 20, refill_per_sec = 10 }
attestor_payout_root = { capacity = 10, refill_per_sec = 5 }
attestor_payout_proof = { capacity = 10, refill_per_sec = 5 }
attestor_aggregate_sigs = { capacity = 30, refill_per_sec = 15 }
attestor_fast_verify = { capacity = 30, refill_per_sec = 15 }
attestor_fast_verify_seats = { capacity = 30, refill_per_sec = 15 }
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
  - Liefert die effektive Rotation- und DA‑Gating‑Konfiguration (inkl. Defaults oder Config/CLI‑Overrides):
    ```json
    {
      "ok": true,
      "rotation": { "epoch_len": 10000, "cooldown_anchors": 10000, "min_attendance_pct": 50 },
      "da_gating": {
        "payload_wait_timeout_secs": 10,
        "retry_initial_delay_ms": 500,
        "retry_max_delay_ms": 5000,
        "retry_max_retries": 5,
        "retry_jitter_pct": 10
      }
    }
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
          "bls_pop": "<hex96>",
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
- Body: `[{ "recipient_id":"<hex32>", "operator_id":"<hex32>", "bls_pk":"<hex48>", "bls_pop":"<hex96>", "last_selected_at":10000, "attendance_recent_pct":100, "vrf_proof":"<hex96>" }, ...]`
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
  status-serve \
  --addr 127.0.0.1:8080 \
  --store-dir /var/lib/phantom-coin/data \
  --mempool-dir /var/lib/phantom-coin/data/mempool \
  --fsync \
  --require-auth \
  --auth-token-file /etc/phantom-coin/status-auth.token \
  # optionale VRF-Overrides (ersetzen Config-Werte) \
  --vrf-epoch-len 10000 \
  --vrf-cooldown-anchors 10000 \
  --vrf-min-attendance-pct 50 \
```

## Start per Config (TOML)
Beispiel: `status-serve.toml`
```toml
config_version = 1
addr = "127.0.0.1:8080"
mempool_dir = "/var/lib/phantom-coin/data/mempool"
store_dir = "/var/lib/phantom-coin/data"
fsync = true
require_auth = true
auth_token_file = "/etc/phantom-coin/status-auth.token"

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
cargo run -p phantom-node -- status-serve --config status-serve.toml
```

## DA‑Gating (Finalisierung erst nach lokaler Payload)

In `configs/node.toml` unter `[consensus.da_gating]` konfigurierbar:

```toml
[consensus.da_gating]
# Timeout pro Warteversuch (Sekunden) auf Payload-Ankunft
payload_wait_timeout_secs = 10
# Exponentielles Backoff: initiale Wartezeit zwischen Retries (ms)
retry_initial_delay_ms = 500
# Obergrenze der Wartezeit zwischen Retries (ms)
retry_max_delay_ms = 5000
# Maximale Anzahl an Retries, bevor aufgegeben wird
retry_max_retries = 5
# Jitter-Prozentsatz (0..=100) für Backoff-Schlafdauer (Default 10)
retry_jitter_pct = 10
```

- Effekt: Bei finalem Header wird die Finalisierung blockiert, bis die zugehörige Payload lokal vorliegt (Pull‑then‑Finalize).
- Sichtbarkeit: Werte sind über `GET /consensus/config` abrufbar.

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
  p2p-quic-listen \
  --addr 127.0.0.1:9000 \
  --store-dir /var/lib/phantom-coin/data \
  --fsync \
  --k 21 \
  # optional \
  --genesis genesis.toml \
  --tx-proposer \
  --tx-proposer-interval-ms 5000 \
  # optional: wenn leer/weg, wird der Reward automatisch aus der Mint-Höhe berechnet \
  --mint-amount 100000 \
  --mint-lock 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```
- `--store-dir`: Persistenz für Header/Payloads und Mempool.
- `--tx-proposer`: baut periodisch Payloads aus Mempool-TXs und announced sie.
- `--pow-miner`: einfacher Mint-PoW (Dev) – nur für lokale Experimente.
- `--mint-amount`: optional; wenn nicht gesetzt, wird der Reward automatisch aus der Mint-Höhe berechnet (Halvings inklusive).
- `--k`: Committee-Größe (Sitzanzahl), überschreibt ggf. `genesis.toml`.

### QUIC: Client verbinden
```bash
cargo run -p phantom-node -- \
  p2p-quic-connect \
  --addr 127.0.0.1:9000 \
  --cert-file server.der
```

### libp2p: P2P-Service (Gossipsub je Shard)
```bash
cargo run -p phantom-node -- \
  p2p-run \
  --max-peers 128
```
Optionen:
- `--bootstrap-peer` (Multiaddr mit `/p2p/<peer_id>`; mehrfach nutzbar)
- `--kad-bootstrap-interval-secs` (Intervall in Sekunden, Standard: 60)

### P2P-Metriken bereitstellen (Prometheus)
```bash
cargo run -p phantom-node -- \
  p2p-metrics-serve \
  --addr 127.0.0.1:9100

curl -s http://127.0.0.1:9100/metrics | head
```

### Payload bauen (offline) und Root ausgeben
```bash
cargo run -p phantom-node -- \
  build-payload \
  --store-dir /var/lib/phantom-coin/data \
  --from-mempool \
  --out-file payload.bin
```
- Optional via Dateien: `--microtx-file txs.bin`, `--mints-file mints.bin`, `--claims-file claims.bin`, `--evidences-file evidences.bin`.

### Konsens-Tools: Ack-Distanzen und Payout-Root
```bash
# Ack-Distanzen aus Header-Datei (ack_id = 32B Hex)
cargo run -p phantom-node -- \
  consensus-ack-dists \
  --ack-id <hex32> \
  --headers-file headers.bin \

# Committee+Attestors Payout-Root (deterministisch)
cargo run -p phantom-node -- consensus-payout-root \
  --ack-id <hex32> \
  --headers-file headers.bin \
  --k 21 \
  --fees 1000000 \
  --recipients <hex32,hex32,...> \
  --proposer-index 0 \

  - `GET /mint/template`, `POST /mint/submit`, `GET /mint/status[/<hex_id>]` → Emissionspfad über Mint-Runden.
  - Direkte State-Mutationspfade für Mints sind entfernt; Mints müssen über Emissionsrunden in den Graphen finalisieren.
  - `POST /stake/bond` → Bond UTXOs (Bond), free maturity logic.
  - `POST /stake/unbond` → Unbonding according to request.
  - Auth (optional): `--require-auth` und `--auth-token-file <PATH>`; dann `Authorization: Bearer <TOKEN>` senden.
  - TLS/mTLS (optional): `--tls-cert`, `--tls-key`, `--tls-client-ca`.

#### Metrik-Details
- **pc_network_id{network="<name>"} 1**: Kennzeichnet, dass eine `genesis_note` erfolgreich gelesen werden konnte; Label `network` zeigt den `network_name`.

- **HTTP-Latenzen** (`phantom_node_http_request_seconds`): Node-weites Histogramm über alle HTTP‑Requests (Status‑Server). Buckets in Sekunden: 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, +Inf.
  - Beispiel‑Zeilen im Prometheus‑Output (`/metrics`):
    - `phantom_node_http_request_seconds_bucket{le="0.001"} <n>`
    - `phantom_node_http_request_seconds_bucket{le="0.005"} <n>`
    - `...`
    - `phantom_node_http_request_seconds_bucket{le="+Inf"} <n>`
    - `phantom_node_http_request_seconds_sum <seconds>`
    - `phantom_node_http_request_seconds_count <total>`
  - Hinweis: Aggregiert ohne Endpoint‑Label (geringe Kardinalität). Totals/Fehler pro Konsensus‑Endpoint werden separat als Counter exponiert (siehe Abschnitt „Rate Limiting“ bzw. `/metrics`).

- **DA‑Gating**: Finalisierung erst nach lokaler Payload; exponierte Metriken:
  - Counter
    - `phantom_node_da_gating_requests_total`
    - `phantom_node_da_gating_successes_total`
    - `phantom_node_da_gating_timeouts_total`
    - `phantom_node_da_gating_retries_total`
  - Histogramm (`phantom_node_da_gating_wait_seconds`)
    - Buckets (Sekunden): 0.001, 0.005, 0.010, 0.050, 0.100, 0.500, +Inf
    - `..._sum`, `..._count` enthalten die Gesamtwartezeit bzw. Anzahl der beobachteten Wartefälle

### Hinweise zu Keys und Signer
- Schlüssel werden in `phantom-signer` getrennt geführt: `seat | bond | payout`.
- Siehe `crates/phantom-signer/README.md` für Keygen/Import/HWI/PSBT/Broadcast.
