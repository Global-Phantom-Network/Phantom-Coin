# Phantom-Coin

## English version

Phantom-Coin is a modular, asynchronous Rust codebase for a DAG-based Layer 1 with no Unix time in the consensus or protocol path. Goals: predictable, high finality throughput (via sharding; target ≥1M events/s ≈ TPS), durable persistence, QUIC-based P2P transport, and first-class Prometheus observability. The monetary supply is hard-capped at 50,000,000 PC (1 PC = 100,000,000 units).

Coins are issued exclusively via Proof-of-Work (emission only). After issuance, ordering and finality are provided by a leaderless DAG + aBFT engine with O(1) finality; Unix time is never part of the consensus path.

- **Core assumptions (v0)**
  - L1: pure UTXO (eUTXO predicates v0), no EVM on the hot path; PoW only for emission.
  - Consensus: leaderless DAG + aBFT, O(1) finality using u64 `vote_mask`; total order by `(consensus_time, event_id)`; no Unix time in consensus.
  - Sharding: initial S≈64; committee per shard k≈21 (k≤64); parents P≤4 (≥1 cross-link for k≥2).
  - Fees/Payouts: deterministic fee split via Merkle payout root; basis floor + small proposer share + capped performance bonus (ack distance) + attestor pool.
  - Monetary policy: hard cap 50,000,000 PC; divisibility 1 PC = 100,000,000 units.
  - Decentralization: fully leaderless and coordinator-free consensus; no central authority in the hot path.
  - Time rule: Unix time may be used for UI/logs only, never consensus-relevant.

## Crates (selected)

- `pc-p2p`: P2P protocol, QUIC transport (optional), async service, metrics, inbound observer.
- `pc-consensus`: DAG/aBFT core (v0), finality checks, fees/rewards helpers.
- `pc-store`: FileStore for `AnchorHeader`/`AnchorPayload` (atomic writes, optional fsync).
- `pc-state`: UTXO state engine backends (e.g. RocksDB/InMemory) used by `phantom-node`.
- `pc-types`/`pc-codec`: canonical types and encodings.
- `pc-crypto`: cryptographic primitives (e.g. BLAKE3 digests, signature helpers).
- `phantom-node`: binaries/CLI (QUIC listener, metrics server, consensus tools), integrates store/state.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test --workspace --all-targets
```

Optional BitBox WebAssembly verification runs separately and does not gate the native
desktop/node build:

```bash
scripts/verify_bitbox_wasm_ci.sh
```

## Quick start

Start a QUIC listener with persistence and metrics:

```bash
phantom-node p2p-quic-listen \
  --addr 127.0.0.1:9000 \
  --genesis ./genesis.toml \
  --store-dir /var/lib/phantom-coin/data \
  --fsync \
  --tx-proposer \
  --tx-proposer-interval-ms 5000 \
  --txs-per-payload 1024 \
  --payload-budget-bytes 1048576
```

- Optional QUIC certificate export: `--cert-out server.der`
- Prometheus metrics endpoint: `curl -s http://127.0.0.1:9100/metrics` (see `p2p-metrics-serve`)

### Localnet mit Observability (Prometheus + Grafana)

Einfacher lokaler Start (baut falls nötig, erzeugt `genesis.toml`, startet Metriken und Observability):

```bash
./scripts/start_localnet.sh
```

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (mit `GRAFANA_USER` / `GRAFANA_PASSWORD` aus deiner Umgebung)
- Metrics Endpoint: http://127.0.0.1:9100/metrics

See also `docs/observability/docker-compose.yml`, `docs/prometheus/prometheus.yml`, `docs/grafana/phantom-node-mempool-dashboard.json`.

## Benchmarks & Referenzen

- Detaillierte P2P-Bench-Anweisungen und Referenzwerte (p50/p95) in `crates/pc-p2p/README.md`.
- CI-Workflows, Aggregation, Regression-Gate und Overrides: siehe `docs/benchmarks.md`.
- Aggregation: `cargo run -p pc-p2p --bin bench_agg` erzeugt `target/criterion_agg.{json,csv,md}`.
- Regression-Gate: `cargo run -p pc-p2p --bin bench_gate -- --baseline crates/pc-p2p/benches/baselines/<ts>/criterion_agg.csv`.

Cross-links:

- `pc-p2p::bench_agg`: aggregates `target/criterion_agg.{json,csv,md}` from multiple runs.
- `pc-p2p::bench_gate`: compares current performance to a baseline CSV file.

Serve metrics on a dedicated HTTP endpoint:

```bash
phantom-node p2p-metrics-serve --addr 127.0.0.1:9100
```

## Genesis (authoritative configuration)

The genesis file fixes consensus‑critical parameters and is cryptographically validated. `k` (committee size) is read from genesis (if present) and overrides CLI/config.

- Detailed guide: `docs/GENESIS.md`
- Example:

```toml
genesis_note = "<64-hex-bytes>"
commitment   = "<64-hex-bytes>" # blake3_32(genesis_note_raw)

[consensus]
k = 21
```

Log (on successful load):

```
{"type":"genesis_loaded","k":<value>,"commitment":"<hex64>"}
```

## Consensus tools

- Ack distances:

```bash
phantom-node consensus-ack-dists \
  --ack-id <hex32> \
  --headers-file headers.bin \
  --genesis ./genesis.toml
```

- Committee payout root:

```bash
phantom-node consensus-payout-root \
  --ack-id <hex32> \
  --headers-file headers.bin \
  --fees 1000000 \
  --recipients <hex32>,<hex32>,... \
  --proposer-index 0 \
  --genesis ./genesis.toml
```

If `--genesis` is omitted, `k` falls back to CLI/config (local development only).

## Mempool & proposer policy

The optional tx‑proposer periodically builds payloads from the mempool:

- CLI flags: `--tx-proposer`, `--tx-proposer-interval-ms`, `--txs-per-payload`, `--payload-budget-bytes`.
- Selection policy: prefer smaller txs first, then older; avoid input conflicts; skip txs already queued in pending payloads.
- Fairness: round‑robin across LockCommitment groups (first output lock) to avoid starvation.
- Deterministic sorting: final tx list is sorted by `digest_microtx()` before building the payload.

## Observability

- Prometheus metrics
  - P2P: `pc_p2p_*` (inbound/outbound, drops, latencies, errors, outbox enq/deq)
  - Node: `pc_node_*` (mempool size/accepted/rejected/duplicate/evictions/invalidated, proposer built/last_size/errors/pending)
  - Store timings: `pc_node_store_header_read_seconds`, `pc_node_store_payload_read_seconds` (histograms)
- Grafana dashboard: `docs/grafana/phantom-node-mempool-dashboard.json`
  - Includes panels for evictions, invalidations, proposer stats, and P2P flows
- Alerts (Prometheus): `docs/prometheus/phantom-node-alerts.yaml`
- Optional local stack (Prometheus + Grafana): `docs/observability/docker-compose.yml`

## Persistence

- `pc-store::FileStore`: atomic writes under `headers/` and `payloads/` with optional `--fsync`.
- Access is delegated from async tasks via `spawn_blocking` to avoid stalling the hot path.

Security notes:

- Strict symlink policy: `store_dir` as well as `headers/` and `payloads/` must not be symlinks. This is enforced at open time and is not configurable.
- Unix-only permission hardening: created directories are `0700`, created files are `0600`. On Windows, ACLs are not modified (policy remains: no symlinks).

## Node cache (LRU)

Optional LRU caches reduce disk I/O for headers/payloads.

Config (TOML):

```toml
[node.cache]
header_cap = 10000   # 0 = disabled
payload_cap = 5000   # 0 = disabled
```

CLI overrides (take precedence):

```bash
phantom-node p2p-quic-listen \
  --addr 127.0.0.1:9000 \
  --config ./node.toml \
  --store-dir /var/lib/phantom-coin/data \
  --fsync \
  --cache-hdr-cap 20000 \
  --cache-pl-mb 200
```

Metrics: `pc_node_cache_headers_hits_total`, `pc_node_cache_headers_misses_total`, `pc_node_cache_payloads_hits_total`, `pc_node_cache_payloads_misses_total`.

## CacheBench (micro-benchmark)

Measures cache hit/miss effects and runtime against FileStore using existing files in `store_dir/headers|payloads`.

```bash
# Headers
phantom-node cache-bench \
  --store-dir /var/lib/phantom-coin/data \
  --mode headers \
  --sample 1000 \
  --iterations 5 \
  --cache-hdr-cap 10000 \
  --cache-pl-mb 0

# Payloads
phantom-node cache-bench \
  --store-dir /var/lib/phantom-coin/data \
  --mode payloads \
  --sample 800 \
  --iterations 5 \
  --cache-hdr-cap 0 \
  --cache-pl-mb 200
```

JSON output includes `hdr_hits`, `hdr_misses`, `pl_hits`, `pl_misses`, `elapsed_ms`.

## CI & Releases

- CI: `.github/workflows/ci.yml` (fmt, clippy −D warnings, build, tests, feature checks)
- Release: `.github/workflows/release.yml` (tagged builds `v*.*.*`, Linux/macOS artifacts)

## Security & performance notes

- No Unix time in consensus/protocol path (UI/logs only).
- Async, multi‑core friendly (Tokio). Targets include Raspberry Pi 5.
- For sustained throughput, tune `--fsync` and consider DB backends/caches.

### Further specs

- Maturity (uhrfrei, globaler Anchor‑Index): `docs/SPEC_MATURITY.md`
- Slashing (Equivocation 100%; Vote‑invalid 50–100%; Conflicting‑DA 25/50/100): `docs/SPEC_SLASHING.md`
- Fees & Payout (Floor/Proposer/Perf/Attestor, α/D_max, Merkle‑Root): `docs/SPEC_FEES.md`
- PoW (Emission, Mint‑Kette, Leading‑Zero‑Bits): `docs/SPEC_POW.md`

## Fuzzing

Fuzz-Tests existieren für `pc-codec`, `pc-types` und `pc-p2p`. Seeds (Corpora) werden deterministisch erzeugt und in den Crate-Verzeichnissen abgelegt. Dictionaries leiten libFuzzer bei der Eingabegenerierung.

- Seeds erzeugen (lokal):

```bash
cargo +nightly run -p pc-codec --bin mk_fuzz_seeds
cargo +nightly run -p pc-types --bin mk_types_fuzz_seeds
cargo +nightly run -p pc-p2p   --bin mk_p2p_fuzz_seeds
```

- Fuzzer ausführen (Beispiele):

```bash
# pc-codec
(cd crates/pc-codec/fuzz && cargo +nightly fuzz run codec_varint -- -dict=dictionaries/codec_varint.dict)
(cd crates/pc-codec/fuzz && cargo +nightly fuzz run codec_vec    -- -dict=dictionaries/codec_vec.dict)

# pc-types
(cd crates/pc-types/fuzz && cargo +nightly fuzz run types_anchor_header_v2  -- -dict=dictionaries/types_header_v2.dict)
(cd crates/pc-types/fuzz && cargo +nightly fuzz run types_anchor_payload_v2 -- -dict=dictionaries/types_payload_v2.dict)
(cd crates/pc-types/fuzz && cargo +nightly fuzz run types_evidence_event    -- -dict=dictionaries/types_evidence_event.dict)

# pc-p2p
(cd crates/pc-p2p/fuzz && cargo +nightly fuzz run p2p_message_decode -- -dict=dictionaries/p2p_message_decode.dict)
(cd crates/pc-p2p/fuzz && cargo +nightly fuzz run reqmsg_decode      -- -dict=dictionaries/p2p_message_decode.dict)
(cd crates/pc-p2p/fuzz && cargo +nightly fuzz run respmsg_decode     -- -dict=dictionaries/p2p_message_decode.dict)
(cd crates/pc-p2p/fuzz && cargo +nightly fuzz run payloads_vec_decode)
(cd crates/pc-p2p/fuzz && cargo +nightly fuzz run headers_vec_decode)
(cd crates/pc-p2p/fuzz && cargo +nightly fuzz run txs_vec_decode)
```

- Corpora-/Artefakt-Pfade:
  - Corpora: `crates/<crate>/fuzz/corpus/<target>/`
  - Findings: `crates/<crate>/fuzz/{artifacts,crashes}/`
  - CI nutzt einen globalen Cache-Key für Corpora-Reuse zwischen Branches.

- CI (Smoke Fuzz):
  - `.github/workflows/fuzz.yml` führt 30s-Smoketests pro Fuzz-Target aus, erzeugt Seeds, nutzt Dictionaries und kommentiert PRs mit einer kurzen Corpus-Zusammenfassung.

## Deutsche Version

Phantom-Coin ist eine modulare, asynchrone Rust-Codebasis für ein DAG-basiertes Layer-1-Protokoll, das vollständig ohne Unix-Zeit im Konsens- oder Protokollpfad auskommt. Ziele sind vorhersehbarer Durchsatz mit hoher Finalität (via Sharding; Ziel ≥1M Events/s ≈ TPS), dauerhafte Persistenz, QUIC-basiertes P2P-Transport-Layer und erstklassige Prometheus-Observability. Die monetäre Geldmenge ist hart auf 50.000.000 PC begrenzt (1 PC = 100.000.000 Einheiten).

Wichtige Annahmen (v0):

- L1: reines UTXO (eUTXO-Predicates v0), kein EVM im Hotpath; PoW nur für Emission.
- Konsens: leaderloser DAG + aBFT mit O(1)-Finalität über ein u64 `vote_mask`; Total-Order nach `(consensus_time, event_id)`; keine Unix-Zeit im Konsenspfad.
- Sharding: initial ca. 64 Shards; Committee pro Shard k≈21 (k≤64); Eltern P≤4 (mindestens ein Cross-Link für k≥2).
- Fees/Payouts: deterministische Gebühren- und Payout-Verteilung via Merkle-Payout-Root (Basis-Floor, kleiner Proposer-Share, gedeckelter Performance-Bonus über Ack-Distanz, Attestor-Pool).

Ausgewählte Crates:

- `pc-p2p`: P2P-Protokoll mit optionalem QUIC-Transport, asynchronem Service, Metriken und Inbound-Observer.
- `pc-consensus`: DAG/aBFT-Kern (v0), Finalitätsprüfungen, Fee-/Reward-Helper.
- `pc-store`: FileStore für `AnchorHeader`/`AnchorPayload` (atomare Writes, optionales fsync).
- `pc-state`: UTXO-State-Engine-Backends (z. B. RocksDB/InMemory), die von `phantom-node` genutzt werden.
- `pc-types`/`pc-codec`: kanonische Typen und Encodings.
- `pc-crypto`: Kryptoprimitive (z. B. BLAKE3-Digests, Signatur-Helper).
- `phantom-node`: Binaries/CLI (QUIC-Listener, Metrik-Server, Konsens-Tools), integriert Store/State.

Weitere Details zu Genesis, Benchmarks, Observability, Node-Cache, Fuzzing und CI sind in den oben referenzierten Unterdokumenten (`docs/GENESIS.md`, `docs/benchmarks.md`, `docs/observability`, `docs/SPEC_*`, Fuzzing-Readmes der Crates) beschrieben.

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See `LICENSE`.
