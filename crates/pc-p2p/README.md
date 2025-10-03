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

### Bench-Mode und OneShot-Watcher
In `pc_p2p::async_svc`:
- `set_bench_mode(true)`: deaktiviert Anti-Entropy-Tick für stabilere Messungen.
- `watch_header(id)` / `watch_payload(root)`: OneShot-Watcher, die bei Empfang der passenden `RespMsg` genau einmal ausgelöst werden. Verdrahtung über `dispatch_watchers()` im Response-Handling.

Die Benches sind bereits so umgestellt, dass sie `set_bench_mode(true)` setzen und statt eines Subscribe-Streams die OneShot-Watcher nutzen. Dadurch sinkt die Timeout-Rate und P50/P95 stabilisieren sich.

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

Die CSV enthält Nanosekunden pro erfolgreich gemessenem Sample. Timeouts werden als Zähler je Run protokolliert.

### Aggregation
Der Aggregator liest `target/criterion/` (estimates.json) sowie bevorzugt die Rohdaten unter `target/criterion_raw/`.

- Binärdatei: `src/bin/bench_agg.rs`
- Ausgabe: `target/criterion_agg.json` und `target/criterion_agg.csv`

Start:
```bash
cargo run -p pc-p2p --bin bench_agg
```

Die CSV enthält pro Bench u. a. `mean`, `p50`, `stddev`, `p95`, `p95_excl_timeouts`, `n`, `timeouts`, `timeout_rate`, sowie einfache Ausreißer-Counts. Falls keine Rohdaten vorhanden sind, wird `p95_approx` via `mean + 1.645*stddev` bereitgestellt.

### Hinweise für stabile Messungen
- Kurze Verbindungs-Setup-Wartezeiten sind in den Benches bereits enthalten (z. B. 300ms), um Spitzen zu glätten.
- Timeouts: in den Benches typischerweise 300–800ms (`tokio::time::timeout(...)`). Bei schwacher Umgebung ggf. erhöhen.
- Logging optional via `RUST_LOG=info` (einige Benches initialisieren `tracing_subscriber`).

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
