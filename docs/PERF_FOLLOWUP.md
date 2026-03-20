# Performance-Follow-up (V2)

## Überblick (ns)
Aus `target/criterion_agg.csv`/`target/criterion_agg.md`:

- QUIC warm: GetHeaders ~140k, GetPayloads ~146k
- libp2p RPC: GetHeaders ~278k, GetPayloads ~258k
- libp2p Gossip E2E: ~429k–434k
- Warm-Start GetHeaders: ~375k
- Cold-Start GetHeaders: ~3.0e9 (inkl. Dial/Handshake)
- Backpressure INV→REQ: ~1.30e9 (erwartbar, Outbox-Druck)

Alle Werte in Nanosekunden (1_000_000 ns = 1 ms).

## Zielmetriken (Richtwerte)
- QUIC warm: p50 ≤ 160k, p95 ≤ 230k
- libp2p RPC: p50 ≤ 300k, p95 ≤ 450k
- Gossip E2E: p50 ≤ 520k, p95 ≤ 650k
- Warm-Start GET_HEADERS: p50 ≤ 420k, p95 ≤ 700k
- Cold-Start: Fokus auf Robustheit, Minderung der Erstlaufzeit durch Pre-Dial/Pooling
- Timeout-Rate: ≤ 1% (regelmäßig 0% im Warmbetrieb)

## Maßnahmenvorschläge

### 1) Cold-Start optimieren
- Pre-Dialing/Connection-Pooling: Bereits beim Start selektiv zu Peers verbinden, die wahrscheinlich Daten liefern.
- Persistente Connections: Keep-alive Einstellungen prüfen, um Re-Dials zu vermeiden.
- Bench-Warmup: In Benches existiert bereits eine kurze Wartezeit (z. B. 300ms); je nach Umgebung anpassen.

### 2) Gossip feinjustieren
- Heartbeat-Intervall: Kürzere Intervalle können INV-Propagation beschleunigen (Trade-off: Netzwerklast). Gossipsub-Konfigurationspunkte prüfen.
- Mesh-Parameter: Mesh-Grad/Outbound-Bandbreite anpassen, um propagation path zu stabilisieren.
- Strict-Validation: Für reine Messungen ggf. deaktiviert lassen (bereits in einigen Benches gesetzt), in Produktion wieder aktivieren.

### 3) RPC/Transport
- QUIC: MTU/Stream-Konfiguration prüfen (z. B. Congestion Control), um Latenzspitzen zu glätten.
- libp2p Request-Response: Zeitouts/Retry-Tuning gemäß den gemessenen P95-Werten prüfen.

### 4) Payload-Size Pfade
- Encoding/Decoding: Zero-Copy-Pfade im Codec evaluieren; unnötige Kopien vermeiden.
- Optional: Kompression experimentell messen (nur falls CPU-Overhead sich lohnt).

### 5) Bench-Stabilität
- OneShot-Watcher und `set_bench_mode(true)` sind aktiv (Anti-Entropy off). Beibehalten für reproduzierbare Messungen.
- Timeouts in Benches: Derzeit ~300–800ms; je nach CI/Hardware ggf. anheben, um False-Timeouts zu vermeiden.

## How-To

1. Benches (libp2p):
```bash
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_rpc
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_e2e
```
2. Benches (quic):
```bash
cargo bench -p pc-p2p --features "async quic" --bench p2p_quic_bench
```
3. Aggregation:
```bash
cargo run -p pc-p2p --bin bench_agg
# Output: target/criterion_agg.{json,csv,md}
```

## CI
- Workflow: `.github/workflows/bench.yml`
- Jobs: `benches-libp2p`, `benches-quic`
- Artefakte: `target/criterion_raw/**`, `target/criterion_agg.{json,csv,md}`

## Nächste Schritte
- Optional: Parameter-Tuning per Feature-Flag/Env-Variablen messbar machen.
- Baseline-vs-Head Vergleich in Aggregator integrieren (Delta-Spalten).
