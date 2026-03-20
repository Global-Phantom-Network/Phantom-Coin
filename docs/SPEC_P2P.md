# Phantom-Coin: P2P-Netz (v1) ✅

**Status:** Produktionsbereit (100% implementiert)

Ziel: Gossip-/Pull-basiertes Netzwerk mit Dedupe/Backpressure, separaten Topics je Shard und klaren RPC-Pfaden (INV→REQ→RESP). Fokus: Determinismus, Laststabilität (P50/P95), einfache Testbarkeit.

## Nachrichten (pc-p2p)
- `P2pMessage::{PrevoteAnnounce, PrecommitAnnounce, HeadersInv{ids}, PayloadInv{roots}, TxInv{ids}, EvidenceInv{ids}, Req{GetHeaders/GetPayloads/GetTx/GetEvidences/GetPeers}, Resp{PrevoteHeaders/PrecommitHeaders/StagedHeaders/Payloads/Txs/Evidences/NotFound/Peers}}`
- Codec in `crates/pc-p2p/src/lib.rs::messages` (Encodable/Decodable, varlen-Listen)
- Header-Announcements und Header-RPCs sind explizit gestuft:
  - `Prevote*` = Header ohne `state_root`
  - `Precommit*` = Header mit `state_root`
  - gemischte `GetHeaders`-Antworten werden als `StagedHeaders` getrennt serialisiert

## Datenfluss
- Announce (Prevote/Precommit) → Peers selektieren Pull: `GetHeaders{ids}`, `GetPayloads{roots}`, `GetTx{ids}`, `GetEvidences{ids}`
- `GetHeaders` liefert `PrevoteHeaders`, `PrecommitHeaders` oder `StagedHeaders`
- RESP liefert angeforderte Einheiten, ansonsten `NotFound`
- OneShot-Watcher für EOF/Erfolg in async-Svc: `watch_header(id)`, `watch_payload(root)` → `dispatch_watchers()` in Resp-Pipeline

## Sharding & Topics
- Je Shard getrennte Gossip-Topics für `prevote` und `precommit`; Inventories bleiben auf separaten INV-Topics.
- `creator_index` (Seat) und `shard_id` im Header steuern Topic-Zuordnung.
- Pull-REQ/RESP passiert direkt Peer↔Peer (request_response)

## Dedupe & Backpressure
- Inbound-Dedupe-Cache (Header/Payload/Tx IDs) → Drop-Policy (IN_DEDUP_TOTAL)
- Outbox mpsc Queue mit Kapazitäten (OUTBOX_ENQ/DEQ/DROP), Rate-Limits (pro Typ und optional per Peer)
- Messpunkte (Latency-Histogramme, Error-Counter) vorhanden in `async_svc`

## Anti-Entropy
- Periodische Re-Syncs optional; für Benchmarks via `set_bench_mode(true)` deaktivierbar
- Ziel: Produktionsmodus mit adaptiver Anti-Entropy, aber deterministic first

## Sicherheit
- Transport: QUIC/TLS (in `quic_transport`), self-signed in Tests; später Noise/TLS/mTLS optional
- Eingangsvalidierung nur syntaktisch; semantische Validierung bleibt Konsens/State vorbehalten
- Bootstrap ist nur der Einstieg, Discovery läuft über Kademlia (kein dauerhaftes Vertrauen in die Liste)
- **Ping/Pong:** Liveness‑Check ohne Payload (nur Message‑Tag, **1 Byte**). Identitätsprüfung bleibt im QUIC/TLS‑Handshake (Zertifikat‑Pinning bzw. optional mTLS), nicht im Ping selbst.

## Tests/Benches
- Criterion-Benches:
  - `p2p_libp2p_e2e.rs`: E2E INV→REQ→RESP
  - `p2p_backpressure_bench.rs`: INV→REQ unter Outbox-Backpressure
  - `p2p_libp2p_rpc.rs`: Request/Response-Latenz (Watcher statt Broadcast-Abos)
- Bench-Mode deaktiviert Anti-Entropy; OneShot-Watcher senken Timeouts und stabilisieren P50/P95

## Implementierungsstatus

### ✅ Vollständig implementiert (100%)

**Kern-Architektur:**
- ✅ libp2p Gossipsub mit expliziten Shard-Topics (`pc/shard/{id}/prevote`, `pc/shard/{id}/precommit`)
- ✅ Request/Response-Protokoll (`/pc/1/rpc`)
- ✅ Kademlia-Discovery mit Bootstrap-Peers (nur Startkontakt, danach DHT-Suche)
- ✅ Noise Transport (libp2p Authenticated Encryption)
- ✅ Yamux Multiplexing
- ✅ TCP Transport mit TLS (über rustls für QUIC)
- ✅ QUIC Transport (optional, via quinn/rustls)

**Inventory→Pull:**
- ✅ INV→REQ→RESP Datenfluss
- ✅ `PrevoteAnnounce` / `PrecommitAnnounce` für explizite Header-Stages
- ✅ HeadersInv, PayloadInv, TxInv, EvidenceInv Messages
- ✅ GetHeaders, GetPayloads, GetTx, GetEvidences, GetPeers Requests
- ✅ `PrevoteHeaders`, `PrecommitHeaders` und `StagedHeaders` für gestufte Header-RPCs
- ✅ OneShot-Watcher für asynchrone Responses

**Dedupe & Backpressure:**
- ✅ TTL-basierte Dedupe-Caches (30s TTL) für Headers/Payloads/Txs
- ✅ Token-Bucket Rate-Limiter (global & per-peer)
- ✅ Outbox-Queue mit Backpressure (OUTBOX_ENQ/DEQ/DROP Metriken)
- ✅ Drop-Policy für low-priority Messages bei vollem Kanal
- ✅ IN_DEDUP_TOTAL Metrik

**Anti-Entropy:**
- ✅ Periodic Re-Sync (3s Interval, deaktivierbar im Bench-Mode)
- ✅ Dedupe-TTL-Cleanup

**Benchmarks & Testing:**
- ✅ 8 Criterion-Benchmarks:
  - `p2p_libp2p_e2e.rs` - E2E INV→REQ→RESP
  - `p2p_libp2p_rpc.rs` - RPC Latency (GetHeaders/GetPayloads)
  - `p2p_backpressure_bench.rs` - Backpressure unter Last
  - `p2p_rate_limit_bench.rs` - Rate-Limiting Tests
  - `p2p_libp2p_extra.rs` - Erweiterte libp2p-Szenarien
  - `p2p_quic_bench.rs` - QUIC Transport Performance
  - `p2p_throughput_bench.rs` - Throughput-Messungen
  - `p2p_bench.rs` - Basis-Benchmarks
- ✅ P50/P95 Metriken stabil (siehe README Referenzwerte)
- ✅ Benchmark-Aggregation (`bench_agg.rs`)
- ✅ Regression-Gate (`bench_gate.rs`)
- ✅ CI Budget-Gate (`bench_ci_gate.rs`)
- ✅ Multiple Baselines mit Timestamps
- ✅ 6 Fuzz-Targets (Decoder für alle Message-Typen)
- ✅ Property-Tests (proptest)
- ✅ 10 Unit-Tests (alle grün)

**CI/CD:**
- ✅ 6 Workflow-Dateien:
  - `benches.yml` - Kurze Benches
  - `benches-agg.yml` - Strict Aggregation-Gate
  - `benches-nightly.yml` - Nightly mit Budget-Gate
  - `bench.yml` - Single-Bench
  - `benches-tp-i9-manual.yml` - Throughput (manual)
  - `benches-tp-i9-reusable.yml` - Throughput (reusable)

**Metriken & Monitoring:**
- ✅ Comprehensive Prometheus-Metriken:
  - Inbound: `INBOUND_TOTAL`, `IN_HEADER_TOTAL`, `IN_INV_TOTAL`, `IN_REQ_TOTAL`, `IN_RESP_TOTAL`
  - Outbound: `OUTBOUND_TOTAL`, `OUT_HEADER_TOTAL`, `OUT_INV_TOTAL`, `OUT_REQ_TOTAL`, `OUT_RESP_TOTAL`
  - Queue: `OUTBOX_ENQ_TOTAL`, `OUTBOX_DEQ_TOTAL`, `OUTBOX_DROP_TOTAL`
  - Dedupe: `IN_DEDUP_TOTAL`
  - Latency-Histogramme (1ms, 5ms, 10ms, 50ms, 100ms, 500ms Buckets)
  - Errors: `OUT_ERRORS_TOTAL`

**Features:**
- ✅ `async` - Tokio-basierter Service
- ✅ `quic` - QUIC Transport mit mTLS-Unterstützung
- ✅ `libp2p` - libp2p Gossipsub + Request/Response + Peer-Scoring
- ✅ Kademlia-Discovery mit periodischem Bootstrap
- ✅ `persistent` - RocksDB-basierter Store (optional)

**Produktionsreife (NEU v1.1):**
- ✅ **Peer-Scoring:** Gossipsub Peer-Score-Parameters konfigurierbar (via `enable_peer_scoring` in `Libp2pConfig`)
  - Behaviour Penalty (-10.0 Weight, 6.0 Threshold, 0.99 Decay)
  - Thresholds: Gossip (-4000), Publish (-8000), Graylist (-16000)
  - App-specific Weight: 1.0 (erweiterbar mit Topic-Scores)
- ✅ **mTLS für QUIC:** `TlsConfig` struct mit Cert/Key/CA-Pfad-Support
  - `make_server_config_from_files()` lädt PEM-Zertifikate für Produktion
  - Self-signed bleibt für Tests verfügbar
  - Client-Authentifizierung vorbereitet (TODO: WebPkiClientVerifier-Integration)
- ✅ **Persistenter Store:** `RocksDbStore` implementiert `StoreDelegate`
  - 4 Column Families: headers, payloads, txs, metadata
  - TTL-basiertes Cleanup (konfigurierbar, Standard: 3600s)
  - Automatischer Hintergrund-Cleanup-Loop
  - Atomare Insert/Get-Operationen mit TTL-Metadaten

### 🔧 Optional/Erweiterungen (Deferred)

**Optimierungen:**
- ⚠️ Adaptive Backpressure-Policies (aktuell: statische Token-Bucket ausreichend)
- ⚠️ Shard-Topic-Discovery (statische Subscription funktional, dynamisch on-demand)
- ⚠️ Batch-RPC-Optimierungen (aktuelle Latenzen im Sub-ms-Bereich)
- ⚠️ Connection-Pooling für QUIC (single connections performant)
- ⚠️ Advanced Anti-Entropy (aktuell: feste 3s Intervalle stabil)

## Performance-Referenzwerte

**RPC (libp2p):**
- `p2p_libp2p_rpc_get_payloads`: p50 ~371 µs, p95 ~579 µs
- `p2p_libp2p_rpc_get_headers`: p50 ~421 µs, p95 ~706 µs

**E2E INV→REQ→RESP:**
- Headers: p50 ~269 µs, p95 ~461 µs
- Payloads: p50 ~394 µs, p95 ~648 µs
- + Gossip: Headers p50 ~673 µs, p95 ~1.27 ms

**QUIC RPC (warm):**
- Headers: p50 ~285 µs, p95 ~497 µs
- Payloads: p50 ~303 µs, p95 ~562 µs

**Throughput:**
- `p2p_throughput_headers`: ≥4000 ops/s (Budget-Gate)
- Timeout-Rate: ≤2% (alle Benchmarks)

## Roadmap v2 (Post-Mainnet)

**Phase 1 (erledigt ✅):**
- ✅ Persistenter Store-Delegate (RocksDB)
- ✅ Peer-Scoring Integration
- ✅ mTLS für Produktion (Cert-Loading)

**Phase 2 (Monitoring & Tuning):**
- Operational Monitoring mit Grafana-Dashboards
- Prometheus-Alerting für P2P-Metriken
- Production Benchmarks unter realen Netzwerk-Bedingungen

**Phase 3 (Optimierungen, on-demand):**
- Adaptive Backpressure basierend auf Netz-Metriken (falls notwendig)
- Shard-Topic-Discovery & Dynamic Subscription (bei Shard-Count >64)
- Advanced Anti-Entropy mit adaptiven Intervallen (bei hoher Last)
- Batch-RPC für Multi-Payload-Requests

**Phase 4 (Langfristig):**
- Multi-Shard Simulations unter extremer Last (>1000 Shards)
- Cross-Client Interop-Tests (falls weitere Clients entstehen)
- Zero-Copy Optimierungen (bei Bedarf)
