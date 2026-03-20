# Bench-Workflows: Architektur, Trigger, Gates, Baselines

Dieser Leitfaden dokumentiert die pc-p2p Bench-Workflows, deren Trigger, die Aggregation, die Gates (absolut/Regression) sowie den Umgang mit Baselines und Artefakten.

## Übersicht der relevanten Workflows

- **`/.github/workflows/benches-nightly.yml`** — Nightly-Bench-Suite (stabil, mit Auti-Baseline). Name: `pc-p2p nightly benches`.
- **`/.github/workflows/benches-agg.yml`** — Aggregations-/Gate-Workflow für pc-p2p. Name: `pc-p2p benches aggregation gate`.
- **`/.github/workflows/benches.yml`** — Kurz-Benchmarks für pc-p2p (manuell oder auf main). Name: `pc-p2p short benches`.
- **`/.github/workflows/p2p-benches.yml`** — Manuelle/gezielte Bench-Ausführung + Aggregation. Name: `pc-p2p Benches & Aggregation`.
 - **`/.github/workflows/benches-agg.yml` → Job `benches_perf_hosted` (optional)** — Perf-Track auf GitHub-hosted Runnern mit CPU-optimierten Flags; nur wenn `BENCH_PERF_ENABLE=1` gesetzt ist.

Begleitend wichtig:
- `crates/pc-p2p/src/bin/bench_agg.rs` — Aggregator: sammelt Rohdaten und erzeugt `criterion_agg.json/csv/md`.
- `crates/pc-p2p/src/bin/bench_ci_gate.rs` — Absolutes Gate: prüft feste Budgets (z. B. p95, timeouts, throughput-Minima).
- `crates/pc-p2p/src/bin/bench_gate.rs` — Regression-Gate: vergleicht aktuelle Aggregation gegen Baseline (CSV).

## Trigger-Matrix (gehärtet)

- Nightly (`benches-nightly.yml`):
  - `schedule` (UTC 02:00) und `workflow_dispatch` (manuell). Keine PR-Trigger.
- Aggregation/Gate (`benches-agg.yml`):
  - `push` auf `main`, `schedule`, `workflow_dispatch`. Keine PR-Trigger.
- Kurz-Benches (`benches.yml`):
  - `push` auf `main`, `workflow_dispatch`. Keine PR-Trigger.
- P2P-Benches (`p2p-benches.yml`):
  - `push` auf `main`, `workflow_dispatch`. Keine PR-Trigger.

Damit blockieren Bench-Workflows keine PRs und erzeugen keine unnötigen Checks in PRs.

## Nightly-Pipeline im Detail (`benches-nightly.yml`)

Relevante Schritte (Auszug):
- `cargo check` (schneller Sanity-Check).
- Bench-Suite (libp2p RPC/E2E, QUIC, EXTRA, Throughput):
  - `p2p_libp2p_rpc`, `p2p_libp2p_e2e`, `p2p_quic_bench`
  - `p2p_libp2p_extra` (stabilisiert: `--measurement-time 30 --sample-size 12`)
  - `p2p_throughput_bench` mit festen ENVs (reproduzierbar):
    - `TP_DURATION_SEC=20`, `TP_CONC=64`, `TP_TIMEOUT_MS=800`
- Aggregation: `cargo run -p pc-p2p --bin bench_agg`
- Absolutes Gate: `cargo run -p pc-p2p --bin bench_ci_gate --release`
- Baseline-Vorbereitung:
  - Stellt sicher, dass `gh` verfügbar ist (wird nur installiert, falls nicht vorhanden).
  - Lädt Artefakt des letzten erfolgreichen Nightly (`criterion-agg-nightly`) und setzt `BASELINE_ARG`, sofern passend.
  - Baseline-Key-Match: Nur wenn `BASELINE_KEY_BLOB` (siehe unten) zum aktuellen Workflow-Blob-Hash passt, wird das Regression-Gate ausgeführt.
- Regression-Gate: `cargo run -p pc-p2p --bin bench_gate -- --agg target/criterion_agg.csv ${BASELINE_ARG}`
  - Zusätzliches Hard-Minimum: `BENCH_TP_ABS_MIN=6000` (ops/s).
- Uploads (immer):
  - `criterion-agg-nightly` inkl. `target/criterion_agg.meta`
  - `criterion-raw-nightly` (rohe Criterion-Daten)

Timeout: 90 Minuten, um längere Messungen zu ermöglichen.

## Performance-Track (optional)

- Ziel: Richtung 1M TPS testen, ohne die stabilen Gates/Trigger zu beeinflussen.
- Aktivierung: Repo-Variable `BENCH_PERF_ENABLE=1` setzt Job `benches_perf_hosted` in `benches-agg.yml` aktiv.
- Flags/Umgebung:
  - Hosted (x86_64): `RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none -C target-cpu=skylake -C target-feature=+avx2"`
  - Self-hosted (falls `benches_tp_selfhosted` aktiv): `RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none -C target-cpu=native"`
- Messparameter (Throughput Headers): `TP_DURATION_SEC=10`, `TP_CONC=64`, `TP_TIMEOUT_MS=800`, Shards per `TP_SHARD_IDS`.
- Artefakte: `criterion-agg-perf-hosted`, `criterion-raw-perf-hosted` werden hochgeladen.
- Gates: Perf-Track läuft ohne Regression/Budget-Gates (nur Aggregation/Artefakte). Die Gates bleiben im Aggregations-Job erhalten und sind vom Perf-Track entkoppelt.

## Baseline-Mechanik

- Baseline-Artefakt: `criterion-agg-nightly`
  - Inhalte: `target/criterion_agg.json`, `target/criterion_agg.csv`, `target/criterion_agg.md`, `target/criterion_agg.meta`
- Metadatei: `target/criterion_agg.meta`
  - Schlüssel: `BASELINE_KEY_BLOB=<blob-hash-von-benches-nightly.yml>`
  - Dieser Blob-Hash wird zur Laufzeit via `git rev-parse :'.github/workflows/benches-nightly.yml'` berechnet und im ENV `BASELINE_KEY` gesetzt.
  - Nur bei Match (`BASELINE_KEY_BLOB == BASELINE_KEY`) wird die Baseline für das Regression-Gate akzeptiert. Bei Mismatch wird das Regression-Gate übersprungen (Absolut-Gate läuft weiterhin).
- Fallback: Falls keine passende Baseline gefunden wird, läuft `bench_gate` ohne expliziten `--baseline`-Pfad und nutzt ggf. Repo-basierte Baselines (siehe Implementierung in `bench_gate.rs`).

## Gates: Parameter und Wirkung
- Absolutes Gate (`bench_ci_gate.rs`):
  - Prüft absolute Budgets (z. B. `p95_max_ns`, `timeout_rate_max`, `tp_min_ops`).
  - Erwartet vollständige Messabdeckung aus den Benches (EXTRA, RPC/E2E, QUIC, Throughput).
- Regression-Gate (`bench_gate.rs`):
  - Vergleicht `target/criterion_agg.csv` gegen eine Baseline-CSV.
  - Toleranzen (ENV, Defaults in Code):
    - `BENCH_P50_TOL` (Default 0.10)
    - `BENCH_P95_TOL` (Default 0.10)
    - `BENCH_TIMEOUT_TOL` (Default 0.02)
    - `BENCH_TP_ABS_MIN` (optional absolut, hier: 6000)
  - Per-Bench-Overrides sind möglich (z. B. `BENCH_P50_TOL_OVERRIDES`) und werden im Nightly bei Bedarf gezielt eingesetzt, um breitbandige Runner-Varianz temporär zu entschärfen; grundsätzlich bevorzugen wir stabile Messparameter und Baseline-Updates.

## Artefakte und Auswertung

- Aggregations-Artefakte:
  - `criterion-agg-nightly` (Nightly) bzw. `criterion-agg` (andere Workflows)
- Rohdaten:
  - `criterion-raw-nightly` (Nightly) bzw. `criterion-raw`
  - Enthalten: Criterion-Verzeichnisse mit Messungen, z. B. `target/criterion/**/estimates.json`
- Auswertung in den Logs:
  - `bench_ci_gate`: meldet Budget-Verstöße (p95, timeouts, tp_min)
  - `bench_gate`: meldet Regressionen gegenüber Baseline (p50/p95-Drifts, timeout_rate, tp-Drops)

## Manuelles Auslösen

- Nightly manuell starten (auf `main`):

```bash
gh workflow run "pc-p2p nightly benches" -r main
```

- Fortschritt/Status prüfen:

```bash
# Liste der letzten Runs
gh run list --workflow="benches-nightly.yml" --limit 5 \
  --json databaseId,workflowName,status,conclusion,headBranch,createdAt \
  --jq '.[] | [.databaseId, .status, .conclusion, .headBranch, .createdAt] | @tsv'

# Details/Schritte
gh run view <RUN_ID> --json status,conclusion,jobs \
  --jq '{status,conclusion,jobs: [.jobs[] | {name, id: .databaseId, status, conclusion}]}'

# Logs
gh run view <RUN_ID> --job <JOB_ID> --log
```

## Parametrisierung/Stabilität

- Stabilere Messungen (EXTRA): `--measurement-time 30`, `--sample-size 12` reduziert Varianz für p50/p95.
- Throughput-Bench (Headers) mit festen ENVs: `TP_DURATION_SEC=20`, `TP_CONC=64`, `TP_TIMEOUT_MS=800`.
- Absolute Durchsatz-Grenze: `BENCH_TP_ABS_MIN=6000` (nur im Regression-Gate, optional weiter schärfbar, ggf. per Repo-Variable).
- Performance-Track ist optional und beeinflusst die Gates nicht; für Gate-Verschärfungen zuerst Nightly stabilisieren und Baseline neu messen.
- Uploads laufen stets (`if: always()`), mit `retention-days: 14` und `if-no-files-found: warn`.

## Pflege und Best Practices

- Bei signifikanter Code-/Workflow-Änderung: Nightly/Baseline neu einmessen lassen, damit Regressionen nicht durch technische Mismatches entstehen.
- Baselines werden automatisch aus dem letzten grünen Nightly-Run geladen; Baseline-Key minimiert Mismatch-Risiken.
- Workflows sind PR-neutral (keine PR-Trigger). Für PRs ggf. separate, rein-kompilierende Checks verwenden (bereits vorhanden).
- Für noch engere Toleranzen: dedizierte Runner (weniger Noise) und/oder längere Messzeiten.

## Troubleshooting

- `bench_ci_gate` meldet fehlende Messwerte:
  - Prüfe, ob `p2p_libp2p_extra` und `p2p_throughput_bench` tatsächlich gelaufen sind.
  - Prüfe Rohdaten unter `target/criterion_raw/`.
- `bench_gate` schlägt fehl (Drifts):
  - Prüfe, ob Baseline korrekt geladen wurde (`BASELINE_ARG` gesetzt) und ob `BASELINE_KEY_BLOB` zum Workflow-Blob-Hash passt.
  - Erhöhe Messzeit/Sample-Size gezielt für flakey Benches.
  - Als letztes Mittel Toleranzen vorsichtig anpassen (global), keine dauerhaften per-Bench-Overrides im Nightly.

---

Stand: Automatisierte Nightly-Benchs stabil, Baseline-gesteuert, PR-neutral und mit robusten Artefakt-Uploads. Änderungen an den Workflows finden sich in den referenzierten Dateien unter `/.github/workflows/`.
