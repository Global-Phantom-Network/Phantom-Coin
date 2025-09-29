# Phantom-Coin

Phantom-Coin ist eine modulare, asynchrone Rust-Codebasis für einen DAG-basierten L1 ohne Unix-Zeit im Konsenspfad. Ziel: hohe Finalisierungsraten (≥1M Events/s via Sharding), sichere Persistenz (FileStore), QUIC-P2P-Transport und Prometheus-Metriken.

- Crates (Auswahl):
  - `pc-p2p`: P2P-Protokoll, QUIC-Transport (optional), Async-Service, Metriken, Inbound-Observer.
  - `pc-consensus`: DAG/aBFT-Kern (v0), Finalität, Fees/Rewards-Hilfsfunktionen.
  - `pc-store`: FileStore-Persistenz für `AnchorHeader`/`AnchorPayload` (atomare Writes, fsync-Option).
  - `phantom-node`: Binaries/CLI (QUIC-Listener, Metrik-Server, Konsens-Tools), Store-Integration via Delegate.

## Build

```bash
cargo build --release
```

Tests:

```bash
cargo test
```

## Start: QUIC-Listener (mit Persistenz und Metriken)

```bash
phantom-node P2pQuicListen \
  --addr 127.0.0.1:9000 \
  --genesis ./genesis.toml \
  --store_dir pc-data \
  --fsync true
```

- Zertifikat ausgeben (optional): `--cert_out server.der`
- Prometheus-Metriken: `curl -s http://127.0.0.1:9100/metrics` (siehe `P2pMetricsServe` bzw. Kombi-Binary, falls vorhanden)
- Persistenz-Metriken (node-spezifisch): `pc_node_*`-Counter

## Genesis (verbindliche Konfiguration)

Die Genesis-Datei legt konsenskritische Parameter fest und wird kryptographisch validiert. k (Committee-Größe) wird strikt aus Genesis gezogen (falls angegeben) und überschreibt CLI/Config.

- Detaillierte Anleitung: `docs/GENESIS.md`
- Format (Auszug):

```toml
[consensus]
k = 21

genesis_note = "<64-hex-bytes>"
commitment   = "<64-hex-bytes>" # blake3_32(genesis_note_raw)
```

Logs bei erfolgreichem Laden:

```
{"type":"genesis_loaded","k":<wert>,"commitment":"<hex64>"}
```

## Konsens-Tools

- Ack-Distanzen:

```bash
phantom-node ConsensusAckDists \
  --ack_id <hex32> \
  --headers_file headers.bin \
  --genesis ./genesis.toml
```

- Committee-Payout-Root:

```bash
phantom-node ConsensusPayoutRoot \
  --ack_id <hex32> \
  --headers_file headers.bin \
  --fees 1000000 \
  --recipients <hex32>,<hex32>,... \
  --proposer_index 0 \
  --genesis ./genesis.toml
```

Ohne `--genesis` fällt k auf CLI zurück (nur für lokale Entwicklung empfohlen).

## Metriken (Prometheus)

- P2P: `pc_p2p_*` (Inbound/Outbound, Drops, Latenzen, Errors, Buckets)
- Node-spezifisch: `pc_node_*` (Persistenz-Erfolge/-Fehler, Observer-Lag, Cache-Hits/-Misses)
- HTTP-Endpunkt liefert nur auf Pfad `/metrics` (text/plain; version=0.0.4)

Zusätzlich exportiert der Node die Disk-Read-Latenzen des Stores als Histogramme:

- `pc_node_store_header_read_seconds` (Histogram)
- `pc_node_store_payload_read_seconds` (Histogram)

Buckets: `le="0.001"`, `0.005`, `0.01`, `0.05`, `0.1`, `0.5`, `+Inf`; zudem `*_sum`, `*_count`.

## Persistenz

- `pc-store::FileStore`: atomic writes, Verzeichnisstruktur `headers/` und `payloads/`, optional `fsync`.
- Integration über `StoreDelegate` (im `pc-p2p` Async-Service); I/O erfolgt außerhalb des Async-Hotpaths via `spawn_blocking`.

## Node-Cache (LRU)

- Optionaler LRU-Cache vor `pc-store::FileStore` reduziert Disk-I/O für Header/Payloads.
- Konfiguration über TOML:

```toml
[node.cache]
header_cap = 10000   # 0=aus
payload_cap = 5000   # 0=aus
```

- CLI-Override (hat Vorrang vor Config):

```bash
phantom-node P2pQuicListen \
  --addr 127.0.0.1:9000 \
  --config ./node.toml \
  --store_dir pc-data \
  --fsync true \
  --cache_hdr_cap 20000 \
  --cache_pl_cap 5000
```

- Metriken: `pc_node_cache_headers_hits_total`, `pc_node_cache_headers_misses_total`, `pc_node_cache_payloads_hits_total`, `pc_node_cache_payloads_misses_total`.
- Hinweis: RAM-Bedarf skaliert mit Kapazitäten; auf Raspberry Pi 5 konservativ starten (z. B. header≈10k, payload≈2–5k) und per Metriken/Bench feinjustieren.

## CacheBench (Benchmark)

Misst Cache-Hit/Miss-Effekte und Laufzeit gegen FileStore anhand vorhandener Dateien in `store_dir/headers|payloads`.

```bash
# Headers
phantom-node CacheBench \
  --store_dir pc-data \
  --mode headers \
  --sample 1000 \
  --iterations 5 \
  --cache_hdr_cap 10000 \
  --cache_pl_cap 0

# Payloads
phantom-node CacheBench \
  --store_dir pc-data \
  --mode payloads \
  --sample 800 \
  --iterations 5 \
  --cache_hdr_cap 0 \
  --cache_pl_cap 5000
```

Output (JSON): Felder u. a. `hdr_hits`, `hdr_misses`, `pl_hits`, `pl_misses`, `elapsed_ms`.

## Sicherheit & Performance

- Keine Unix-Zeit im Konsens-/Protokollpfad (nur Logging/UI).
- Asynchrone, Multi-Core-fähige Architektur (Tokio). Zielplattform inkl. Raspberry Pi 5.
- Für hohe Durchsätze: fsync konfigurieren (`--fsync true/false`) und später Cache/DB-Backends erwägen.

## Lizenz

MIT oder Apache-2.0 (dual).
