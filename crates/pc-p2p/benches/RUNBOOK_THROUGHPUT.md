# Runbook: pc-p2p Throughput (Headers RPC über libp2p)

Dieses Runbook beschreibt Setup, Ausführung, Artefaktsammlung, Baseline-Ablage und Auswertung für Throughput-Messungen (ops/s) des RPC GetHeaders über libp2p.

## Voraussetzungen
- Rust Toolchain stable, Cargo verfügbar
- Netzwerk-Loopback frei (127.0.0.1)
- Optional: `genesis_note` generieren, damit `network_id` in Rohdateien persistiert wird

```bash
a) cargo check --locked
b) # optional, erzeugt ${PHANTOM_STORE_DIR:-${TMPDIR:-/tmp}/phantom-coin/p2p-benches/data}/mempool/genesis_note.bin
   cargo run -p phantom-node --bin genesis_bootstrap -- \
     --mempool-dir "${PHANTOM_STORE_DIR:-${TMPDIR:-/tmp}/phantom-coin/p2p-benches/data}/mempool" \
     --network-name "bench" \
     --shards-initial 64 \
     --committee-k 21 \
     --txs-per-payload 256 \
     --features 0
```

## Benchmark: p2p_throughput_bench
- Datei: `crates/pc-p2p/benches/p2p_throughput_bench.rs`
- Name: `p2p_throughput_headers`
- Ergebnisdateien:
  - Throughput (ops/s): `target/criterion_raw/p2p_throughput_headers_tp.txt`
  - Timeouts: `target/criterion_raw/p2p_throughput_headers_timeouts.txt`

### Parameter (via Env)
- `TP_DURATION_SEC` (u64, Standard 10): Messdauer in Sekunden
- `TP_CONC` (usize, Standard 64): Anzahl paralleler Workers
- `TP_TIMEOUT_MS` (u64, Standard 800): Timeout pro Anfrage
- `TP_SHARD_IDS` (CSV von u16, Standard `0`): Shard-IDs, über die Preloads verteilt werden, z. B. `0,1,2,3`

### Ausführen (Beispiele)
- i9 Schnelltest:
```bash
TP_DURATION_SEC=10 TP_CONC=64 TP_TIMEOUT_MS=800 TP_SHARD_IDS=0 \
 cargo bench -p pc-p2p --features "async libp2p" --bench p2p_throughput_bench
```
- RPi‑5 (länger, konservativer):
```bash
TP_DURATION_SEC=20 TP_CONC=32 TP_TIMEOUT_MS=1200 TP_SHARD_IDS=0 \
 cargo bench -p pc-p2p --features "async libp2p" --bench p2p_throughput_bench
```

## Benchmark-Matrix (T18)
Zielbereiche: RPi‑5 15–20k ops/s, i9 40–70k ops/s (als Startziel, kalibrieren nach ersten Läufen).

- RPi‑5 Baseline
  - Läufe (min 3):
    - `TP_DURATION_SEC=20`, `TP_CONC=32`, `TP_TIMEOUT_MS=1200`, `TP_SHARD_IDS=0`
- i9 Skalierung je Shard-Count in [1, 4, 16, 64]
  - Läufe (min 3 pro Konfiguration):
    - 1 Shard:   `TP_DURATION_SEC=10`, `TP_CONC=64`,  `TP_TIMEOUT_MS=800`,  `TP_SHARD_IDS=0`
    - 4 Shards:  `TP_DURATION_SEC=10`, `TP_CONC=64`,  `TP_TIMEOUT_MS=800`,  `TP_SHARD_IDS=0,1,2,3`
    - 16 Shards: `TP_DURATION_SEC=10`, `TP_CONC=96`,  `TP_TIMEOUT_MS=800`,  `TP_SHARD_IDS=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15`
    - 64 Shards: `TP_DURATION_SEC=10`, `TP_CONC=128`, `TP_TIMEOUT_MS=800`,  `TP_SHARD_IDS=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63`

Hinweise:
- `TP_CONC` ggf. je nach Maschine variieren (Sättigung beobachten: Timeouts sollten möglichst gering bleiben).
- Läufe mindestens 3× wiederholen, um Ausreißer zu glätten.

## Aggregation
- Aggregation ausführen:
```bash
cargo run -p pc-p2p --bin bench_agg
```
- Artefakte:
  - `target/criterion_agg.json`
  - `target/criterion_agg.csv` (enthält Spalte `tp_ops`)
  - `target/criterion_agg.md` (Tabelle mit `tp_ops`)

## Regression-Gate (Gates)
- Ziele:
  - RPi‑5: `tp_ops` ≥ 15k/s (Startwert)
  - i9:    `tp_ops` ≥ 40k/s (Startwert)
- Umgebung:
```bash
# Beispiel i9 Gate
BENCH_TP_ABS_MIN=40000 BENCH_TP_TOL_NEG=0.10 \
 cargo run -p pc-p2p --bin bench_gate -- --agg target/criterion_agg.csv

# Beispiel RPi‑5 Gate
BENCH_TP_ABS_MIN=15000 BENCH_TP_TOL_NEG=0.10 \
 cargo run -p pc-p2p --bin bench_gate -- --agg target/criterion_agg.csv
```
- Weitere Env:
  - `BENCH_TP_TOL_NEG_OVERRIDES` (pro Bench), z. B. `p2p_throughput_headers=0.15`
  - `BENCH_TP_ABS_MIN_OVERRIDES` (pro Bench), z. B. `p2p_throughput_headers=45000`
  - Latenz-Gates bleiben aktiv (`BENCH_P50_TOL`, `BENCH_P95_TOL`, `BENCH_TIMEOUT_TOL`)

## Baseline-Ablage
Baselines liegen unter `crates/pc-p2p/benches/baselines/<timestamp>/`.

```bash
TS=$(date -u +%Y%m%d_%H%M%S)
BASE=crates/pc-p2p/benches/baselines/$TS
mkdir -p "$BASE/criterion_raw"
cp -v target/criterion_agg.json "$BASE/" || true
cp -v target/criterion_agg.csv  "$BASE/" || true
cp -v target/criterion_agg.md   "$BASE/" || true
cp -vr target/criterion_raw/*   "$BASE/criterion_raw/" || true
```

## Report-Template (Markdown)
```markdown
# pc-p2p Throughput Report

- Plattform: <RPi-5|i9>
- Parameter: duration=${TP_DURATION_SEC}s, conc=${TP_CONC}, timeout=${TP_TIMEOUT_MS}ms, shards=[${TP_SHARD_IDS}]
- Datum (UTC): $(date -u +%F %T)

## Zusammenfassung
| bench | tp_ops | p50 | p95 | timeout_rate | n | timeouts |
|---|---:|---:|---:|---:|---:|---:|
| p2p_throughput_headers | <ops/s> | <µs> | <µs> | <rate> | <n> | <count> |

## Artefakte
- agg: target/criterion_agg.{json,csv,md}
- raw: target/criterion_raw/
```

## Troubleshooting
- Durchsatz zu niedrig:
  - `TP_CONC` anheben, bis `timeout_rate` steigt → anschließend leicht reduzieren.
  - `TP_TIMEOUT_MS` erhöhen, falls `timeout_rate` dauerhaft > 0.5% ist.
- `network_id` fehlt: `genesis_bootstrap` Schritt vor Bench ausführen.
- CI: Durchsatzläufe nur auf passenden self-hosted Runnern (rpi5/i9) einplanen.
