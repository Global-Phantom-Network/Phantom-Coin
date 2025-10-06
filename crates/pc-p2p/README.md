# pc-p2p

High-Performance P2P-Service mit libp2p-Integration, Gossip (INV) und Request/Response (REQ/RESP). Beinhaltet Criterion-Benchmarks und einen Aggregator.

## Features
- `async`: Tokio-basierter interner Service (`pc_p2p::async_svc`).
- `libp2p`: Gossipsub + Request-Response Integration (`spawn_with_libp2p`).
- `quic`: QUIC Transport-Hilfen (separat, nicht für die libp2p-Benches erforderlich).

## Benchmarks
Die Benches messen End-to-End INV→REQ→RESP sowie RPC-Latenzen und Verhalten unter Backpressure.

- `benches/p2p_libp2p_e2e.rs` (INV→REQ→RESP über libp2p, Gossip- und Direkt-Injection-Varianten)
- `benches/p2p_libp2p_rpc.rs` (RPC GetPayloads/GetHeaders über libp2p request_response)
- `benches/p2p_backpressure_bench.rs` (INV→REQ unter künstlicher Outbox-Backpressure)

### V2-Typen
Alle Benches und APIs sind auf V2 umgestellt:
- `AnchorHeaderV2` (inkl. Feld `network_id: [u8; 32]`)
- `AnchorPayloadV2` (inkl. Feld `genesis_note: Option<...>`)
- `payload_merkle_root_v2()`

### Bench-Mode und OneShot-Watcher
In `pc_p2p::async_svc`:
- `set_bench_mode(true)`: deaktiviert Anti-Entropy-Tick für stabilere Messungen.
- `watch_header(id)` / `watch_payload(root)`: OneShot-Watcher, die bei Empfang der passenden `RespMsg` genau einmal ausgelöst werden. Verdrahtung über `dispatch_watchers()` im Response-Handling.

Die Benches sind bereits so umgestellt, dass sie `set_bench_mode(true)` setzen und statt eines Subscribe-Streams die OneShot-Watcher nutzen. Dadurch sinkt die Timeout-Rate und P50/P95 stabilisieren sich.

### Benchmark-Defaults
Die Benchmarks bringen vernünftige Criterion-Defaults mit, sodass i. d. R. keine CLI-Flags nötig sind:

- sample_size: 10
- measurement_time: 20s
- warm_up_time: 2s

Hinweis: Flags auf der Kommandozeile (z. B. `--sample-size`, `--measurement-time`) überschreiben diese Defaults.

### Ausführen
Voraussetzungen: Rust Toolchain, Netzwerk-Loopback frei.

- libp2p-Benches (erfordern Features `async libp2p`):
```bash
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_e2e
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_rpc
```

- Backpressure-Bench (erfordert nur `async`):
```bash
cargo bench -p pc-p2p --features "async" --bench p2p_backpressure_bench
```

Optional lassen sich weitere Benches aus `Cargo.toml` aufrufen (z. B. `p2p_quic_bench`, `p2p_libp2p_extra`), abhängig von den jeweiligen Feature-Mengen.

### Persistierte Rohdaten und Timeouts
Die Benches schreiben zusätzlich zu Criterion-Rohdaten eigene Rohdaten/Timeouts:
- Rohdaten: `target/criterion_raw/<bench>.csv`
- Timeouts: `target/criterion_raw/<bench>_timeouts.txt`

Erweiterung zur Netzwerkkontextbindung:
- Beide Dateien beginnen beim ersten Write mit einer Kommentarzeile `# network_id=<hex>` (falls `pc-data/mempool/genesis_note.bin` gefunden und dekodiert werden kann).
- Die CSV enthält anschließend Nanosekunden pro erfolgreich gemessenem Sample. Die Timeouts-Datei enthält pro Run eine Zeile mit der Anzahl der Timeouts; Kommentarzeilen werden bei der Aggregation ignoriert.

### Aggregation
Der Aggregator liest `target/criterion/` (estimates.json) sowie bevorzugt die Rohdaten unter `target/criterion_raw/`.

- Binärdatei: `src/bin/bench_agg.rs`
- Ausgabe: `target/criterion_agg.json`, `target/criterion_agg.csv` und zusätzlich ein Kurzreport `target/criterion_agg.md` (Tabelle mit `p50`, `p95`, `timeout_rate`, `n`, `timeouts`).

Netzwerkkontext in den Aggregaten:
- Aus `# network_id=<hex>` in Roh-/Timeout-Dateien wird `network_id` extrahiert.
- JSON enthält pro Bench das Feld `network_id`.
- CSV enthält eine zusätzliche Spalte `network_id` direkt nach `bench`.

Start:
```bash
cargo run -p pc-p2p --bin bench_agg
```

Die CSV enthält pro Bench u. a. `mean`, `p50`, `stddev`, `p95`, `p95_excl_timeouts`, `n`, `timeouts`, `timeout_rate`, sowie einfache Ausreißer-Counts. Falls keine Rohdaten vorhanden sind, wird `p95_approx` via `mean + 1.645*stddev` bereitgestellt.

### Regression-Gate
- Binärdatei: `src/bin/bench_gate.rs`
- Vergleicht aktuelle Aggregation (`target/criterion_agg.csv`) gegen Baseline (`crates/pc-p2p/benches/baselines/*/criterion_agg.csv`).
- Schwellwerte (per Env variierbar):
  - `BENCH_P50_TOL` (default 0.10)
  - `BENCH_P95_TOL` (default 0.10)
  - `BENCH_TIMEOUT_TOL` (default 0.02)
- Nutzung (lokal):
  - Standard (nimmt jüngste Baseline): `cargo run -p pc-p2p --bin bench_gate`
  - Mit expliziter Baseline: `cargo run -p pc-p2p --bin bench_gate -- --baseline crates/pc-p2p/benches/baselines/<ts>/criterion_agg.csv`

### Baselines
- Baselines werden unter `crates/pc-p2p/benches/baselines/<timestamp>/` abgelegt.
- Inhalt: `criterion_agg.{json,csv,md}` sowie optional `criterion_raw/` für Detailanalysen.
- Das Regression-Gate wählt automatisch die jüngste Baseline, falls keine explizit übergeben wird.

### CI-Workflows
- Kurze Benches: `.github/workflows/benches.yml` (RPC/E2E/QUIC kurz, Aggregation, Regression-Gate, Artefakte).
- Nightly: `.github/workflows/benches-nightly.yml` (längere Läufe, Aggregation, Regression-Gate, Artefakte).
- Artefakte: `criterion-agg` (agg.*) und `criterion-raw` (Rohdaten) im jeweiligen Run.

### Hinweise für stabile Messungen
- Kurze Verbindungs-Setup-Wartezeiten sind in den Benches bereits enthalten (z. B. 800ms), um Spitzen zu glätten.
- Timeouts: in den Benches typischerweise 500–800ms (`tokio::time::timeout(...)`). Bei schwacher Umgebung ggf. erhöhen.
- Logging optional via `RUST_LOG=info` (einige Benches initialisieren `tracing_subscriber`).

### Referenzwerte (p50/p95)
- Hinweis: Zeiten in µs (aus Aggregation der Criterion-Rohdaten).
- RPC (libp2p):
  - `p2p_libp2p_rpc_get_payloads`: p50 ~371 µs, p95 ~579 µs, timeouts 0, n 117
  - `p2p_libp2p_rpc_get_headers`: p50 ~421 µs, p95 ~706 µs, timeouts 0, n 117
- E2E INV→REQ→RESP (libp2p):
  - Headers: p50 ~269 µs, p95 ~461 µs, timeouts 0
  - Payloads: p50 ~394 µs, p95 ~648 µs, timeouts 0
  - + Gossip: Headers p50 ~673 µs, p95 ~1.27 ms; Payloads p50 ~645 µs, p95 ~1.17 ms
- QUIC (RPC warm):
  - Headers: p50 ~285 µs, p95 ~497 µs
  - Payloads: p50 ~303 µs, p95 ~562 µs
- Kaltstart (Erwartung):
  - `p2p_rpc_cold_start_get_headers`: p50 ~1.89 ms, p95 ~2.52 ms, timeout_rate ~0.01% (1 von ~10k)

## API-Hinweise
- `pc_p2p::spawn_with_libp2p(P2pConfig, Libp2pConfig)` startet internen Service + libp2p-Swarm. Rückgabe: `(P2pService, svc_handle, swarm_handle)`.
- `P2pService`:
  - Outbound Gossip: `publish_payload_inv()`, `publish_headers_inv()`.
  - Outbound RPC: `send_req()`.
  - Lokale Preloads: `put_header()`, `put_payload()`, `put_tx()`.
  - Synchrone lokale RPC-Brücke: `rpc_call()`.
  - Shutdown: `shutdown()`.

## Lizenz
AGPL-3.0-only.
