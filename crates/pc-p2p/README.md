# pc-p2p

## English version

High-performance P2P service with libp2p integration, gossip (INV) and request/response (REQ/RESP). Includes Criterion benchmarks and an aggregator.

### Features

- `async`: Tokio-based internal service (`pc_p2p::async_svc`).
- `quic`: QUIC transport helpers (separate, not required for the libp2p benches).

### Benchmarks

The benches measure end-to-end INV→REQ→RESP flows as well as RPC latencies and behaviour under backpressure.

Header traffic is explicitly staged in the current wire protocol:
- `PrevoteAnnounce` / `PrecommitAnnounce` for gossip
- `PrevoteHeaders` / `PrecommitHeaders` / `StagedHeaders` for `GetHeaders` RPC responses

-– `benches/p2p_libp2p_e2e.rs` (INV→REQ→RESP über libp2p, Gossip- und Direkt-Injection-Varianten)
– `benches/p2p_libp2p_rpc.rs` (RPC GetPayloads/GetHeaders über libp2p request_response)
– `benches/p2p_backpressure_bench.rs` (INV→REQ unter künstlicher Outbox-Backpressure)
– `benches/p2p_throughput_bench.rs` (Throughput für RPC GetHeaders über libp2p; misst ops/s, schreibt nach `*_tp.txt`; konfigurierbar via Env wie `TP_DURATION_SEC`, `TP_CONC`, `TP_TIMEOUT_MS`, `TP_SHARD_IDS`)

### V2-Typen
Alle Benches und APIs nutzen die aktuellen Anchor-Typen:
- `AnchorHeaderV2` (inkl. Feld `network_id: [u8; 32]`)
- `AnchorPayloadV3`
{{ ... }}
Hinweis: Flags auf der Kommandozeile (z. B. `--sample-size`, `--measurement-time`) überschreiben diese Defaults.

### Ausführen
Voraussetzungen: Rust Toolchain, Netzwerk-Loopback frei.

-– libp2p-Benches (erfordern Features `async libp2p`):
```bash
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_e2e
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_rpc
```

– Throughput (Headers RPC über libp2p, konfigurierbar via Env):
```bash
# Beispiel i9: 10s, 64 Concurrency, 800ms Timeout, eine Shard-ID 0
TP_DURATION_SEC=10 TP_CONC=64 TP_TIMEOUT_MS=800 TP_SHARD_IDS=0 \
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_throughput_bench

# Beispiel RPi-5 (länger, ggf. geringere Concurrency):
TP_DURATION_SEC=20 TP_CONC=32 TP_TIMEOUT_MS=1200 TP_SHARD_IDS=0 \
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_throughput_bench
```

- Backpressure-Bench (erfordert nur `async`):
```bash
cargo bench -p pc-p2p --features "async" --bench p2p_backpressure_bench
```

{{ ... }}
Erweiterung zur Netzwerkkontextbindung:
- Beide Dateien beginnen beim ersten Write mit einer Kommentarzeile `# network_id=<hex>` (falls `genesis_note.bin` unter `<store-dir>/mempool/` gefunden und dekodiert werden kann; `PHANTOM_STORE_DIR` überschreibt den Default-Suchpfad).
- Die CSV enthält anschließend Nanosekunden pro erfolgreich gemessenem Sample. Die Timeouts-Datei enthält pro Run eine Zeile mit der Anzahl der Timeouts; Kommentarzeilen werden bei der Aggregation ignoriert.

### Aggregation
– Der Aggregator liest `target/criterion/` (estimates.json) sowie bevorzugt die Rohdaten unter `target/criterion_raw/`.

- Binärdatei: `src/bin/bench_agg.rs`
- Ausgabe: `target/criterion_agg.json`, `target/criterion_agg.csv` und zusätzlich ein Kurzreport `target/criterion_agg.md` (Tabelle mit `p50`, `p95`, `timeout_rate`, `tp_ops`, `n`, `timeouts`).

Netzwerkkontext in den Aggregaten:
- Aus `# network_id=<hex>` in Roh-/Timeout-Dateien wird `network_id` extrahiert.
- JSON enthält pro Bench das Feld `network_id`.
- CSV enthält eine zusätzliche Spalte `network_id` direkt nach `bench`.

Start:
```bash
cargo run -p pc-p2p --bin bench_agg
```
Robustheit der Aggregation:
- Outlier-Filter: Rohwerte > 10s (Nanosekunden) werden ignoriert, um p95 und Statistiken gegen korrupt/unplausible Samples zu stabilisieren.
- Rohdaten-Priorisierung: p95 wird aus `target/criterion_raw/*.csv` bevorzugt berechnet (falls vorhanden). `timeout_rate` wird aus `<bench>_timeouts.txt` und der Anzahl numerischer CSV-Zeilen (erfolgreiche Samples) abgeleitet.

- Die CSV enthält pro Bench u. a. `mean`, `p50`, `stddev`, `p95`, `p95_excl_timeouts`, `n`, `timeouts`, `timeout_rate`, `tp_ops` (falls vorhanden), sowie einfache Ausreißer-Counts. Falls keine Rohdaten vorhanden sind, wird `p95_approx` via `mean + 1.645*stddev` bereitgestellt.

### Regression-Gate
- Binärdatei: `src/bin/bench_gate.rs`
- Vergleicht aktuelle Aggregation (`target/criterion_agg.csv`) gegen Baseline (`crates/pc-p2p/benches/baselines/*/criterion_agg.csv`).
-– Schwellwerte (per Env variierbar):
  - Latenzen: `BENCH_P50_TOL`, `BENCH_P95_TOL`, `BENCH_TIMEOUT_TOL`
  - Throughput: `BENCH_TP_TOL_NEG` (max. relativer Rückgang, z. B. `0.10` = −10%)
  - Absolutes Minimum ops/s: `BENCH_TP_ABS_MIN` (z. B. i9 `40000`, RPi‑5 `15000`)
  - Bench-spezifisch: `BENCH_TP_TOL_NEG_OVERRIDES`, `BENCH_TP_ABS_MIN_OVERRIDES`
- Nutzung (lokal):
  - Standard (nimmt jüngste Baseline): `cargo run -p pc-p2p --bin bench_gate`
  - Mit expliziter Baseline: `cargo run -p pc-p2p --bin bench_gate -- --baseline crates/pc-p2p/benches/baselines/<ts>/criterion_agg.csv`

### Budget-Gate (absolute)
- Binärdatei: `src/bin/bench_ci_gate.rs`
- Zweck: Prüft `target/criterion_agg.json` gegen feste Budgets (p95-Limits in ns, maximale `timeout_rate`, minimale `tp_ops`).
- Nutzung (lokal):
  - Aggregation erzeugen: `cargo run -p pc-p2p --bin bench_agg --release`
  - Absolute Budgets prüfen: `cargo run -p pc-p2p --bin bench_ci_gate --release`
  - Debug-Ausgabe: `BENCH_GATE_DEBUG=1 cargo run -p pc-p2p --bin bench_ci_gate --release`
  - Rohdaten & Outlier-Filter: p95 wird aus `target/criterion_raw/*.csv` bevorzugt; Ausreißer > 10s (ns) werden ignoriert. `timeout_rate` wird aus `<bench>_timeouts.txt` und numerischen CSV-Zeilen ermittelt.
- CI-Integration:
  - `.github/workflows/benches-agg.yml`: Strict-Gate auf `main`/Schedule (blocking); auf PR non‑blocking.
  - `.github/workflows/benches.yml` und `.github/workflows/bench.yml`: non‑blocking nach Aggregation.
  - `.github/workflows/benches-nightly.yml`: Budget-Gate (absolute, blocking) zusätzlich zum Regression-Gate.
- Budgets (Kurzüberblick):
  - `p2p_libp2p_rpc_get_headers`: p95 ≤ 800000 ns; `timeout_rate` ≤ 0.001
  - `p2p_libp2p_rpc_get_payloads`: p95 ≤ 900000 ns; `timeout_rate` ≤ 0.001
  - `p2p_libp2p_e2e_inv_to_resp_{headers,payloads}{,_gossip}`: p95 ≤ 1200000 ns; `timeout_rate` ≤ 0.005 (RR) bzw. ≤ 0.01 (Gossip)
  - `p2p_header_announce_gossip{,_relaxed}`: p95 ≤ 25000000 ns; `p2p_header_announce_gossip_hb_1s`: p95 ≤ 40000000 ns
  - `p2p_batch_headers_inv_rr`: p95 ≤ 2000000 ns; `p2p_rpc_warm_start_get_headers`/`p2p_rpc_parallel_get_payloads_8`: p95 ≤ 1500000 ns
  - `p2p_rpc_payload_size_sweep`: p95 ≤ 20000000 ns
  - `p2p_throughput_headers`: `tp_ops` ≥ 4000; `timeout_rate` ≤ 0.02
  - Keine harten Budgets: Backpressure/RateLimit/Retry/Two-Hop/Dedupe (Eigenschaftstests)

### Baselines
{{ ... }}
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

### Regression gate & CI integration

- `bench_gate`: compares the current aggregation (`target/criterion_agg.csv`) against a baseline.
- Thresholds via env vars, e.g. `BENCH_P50_TOL`, `BENCH_P95_TOL`, `BENCH_TIMEOUT_TOL`, `BENCH_TP_TOL_NEG`, `BENCH_TP_ABS_MIN`.
- CI workflows (`benches*.yml`) enforce or report gates depending on branch and schedule.

### Budget gate (absolute)

- `bench_ci_gate`: checks `target/criterion_agg.json` against fixed budgets (p95 limits, timeout rate, minimum `tp_ops`).
- Intended for strict CI budgets on nightly/longer runs.

### API notes

- `pc_p2p::spawn_with_libp2p(P2pConfig, Libp2pConfig)` starts the internal service plus libp2p swarm. Returns `(P2pService, svc_handle, swarm_handle)`.
- `P2pService`:
  - Outbound gossip: `publish_payload_inv()`, `publish_headers_inv()`.
  - Outbound RPC: `send_req()`.
  - Local preloads: `put_header()`, `put_payload()`, `put_tx()`.
  - Synchronous local RPC bridge: `rpc_call()`.
  - Shutdown: `shutdown()`.

### License

AGPL-3.0-only.

## Deutsche Version

High-Performance P2P-Service mit libp2p-Integration, Gossip (INV) und Request/Response (REQ/RESP). Beinhaltet Criterion-Benchmarks und einen Aggregator.

## Features
- `async`: Tokio-basierter interner Service (`pc_p2p::async_svc`).
- `quic`: QUIC Transport-Hilfen (separat, nicht für die libp2p-Benches erforderlich).

## Benchmarks
Die Benches messen End-to-End INV→REQ→RESP sowie RPC-Latenzen und Verhalten unter Backpressure.
