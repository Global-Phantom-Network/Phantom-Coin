# Benchmarks, Aggregation & Gate

Kurzübersicht über die P2P‑Bench‑Pipelines, Artefakte und das Regression‑Gate.

- Autoritatives Gate: `/.github/workflows/benches-agg.yml`
- Short‑Signal (schnell): `/.github/workflows/benches.yml`
- Gate‑Logik (Vergleich vs. Baseline): `crates/pc-p2p/src/bin/bench_gate.rs`

## Workflows

- `/.github/workflows/benches-agg.yml`
  - Trigger: push auf `main`, nightly (03:17 UTC), `workflow_dispatch`.
  - Steps: `cargo check` → Benches (RPC/E2E/QUIC) → `bench_agg` → `bench_gate` (strict) → Summary → Upload Artefakte.
  - Slack: nur bei Fehlern, wenn `SLACK_WEBHOOK_URL` gesetzt ist.

- `/.github/workflows/benches.yml`
  - Short‑Benches mit 25/25: stabileres Signal bei moderater Laufzeit.
  - Steps: `cargo check` → `cargo bench ... --measurement-time 25 --sample-size 25 --warm-up-time 2` (RPC/E2E/QUIC) → `bench_agg` → Summary → Upload Artefakte.
  - Optionales Short‑Gate (standardmäßig AUS):
    - Bedingung: `${{ github.ref == 'refs/heads/main' && vars.SHORT_BENCH_GATE == 'true' }}`
    - Befehl: `cargo run -p pc-p2p --bin bench_gate -- --agg target/criterion_agg.csv`

## Artefakte

- Aggregation `criterion-agg`:
  - `target/criterion_agg.{json,csv,md}`
- Rohdaten `criterion-raw`:
  - `target/criterion_raw/**`

## Baseline & Gate

- Baselines: `crates/pc-p2p/benches/baselines/<timestamp>/criterion_agg.csv`
- Gate wählt per Default die lexikographisch letzte Baseline (siehe `find_latest_baseline_csv()` in `bench_gate.rs`).
- Verglichen werden `p50`, `p95`, `timeout_rate` (CSV‑Spalten).

### Toleranzen (Defaults) und Overrides

- Defaults (über ENV, Fallback in Klammern):
  - `BENCH_P50_TOL` (0.10)
  - `BENCH_P95_TOL` (0.10)
  - `BENCH_TIMEOUT_TOL` (0.02)
- Per‑Bench‑Overrides (Repo‑Variablen/ENV, Format `bench=0.xx` kommagetrennt):
  - `BENCH_P50_TOL_OVERRIDES`
  - `BENCH_P95_TOL_OVERRIDES`
  - `BENCH_TIMEOUT_TOL_OVERRIDES`

Beispiel Overrides:
```
BENCH_P50_TOL_OVERRIDES="p2p_quic_rpc_warm_get_headers=0.20,p2p_libp2p_rpc_get_payloads=0.12"
```

## Slack

- Secret: `SLACK_WEBHOOK_URL` (Repo → Settings → Secrets and variables → Actions).
- `benches-agg.yml`: Benachrichtigung nur bei `failure()`.
- Preflight (optional): über Repo‑Variable `SLACK_PREFLIGHT` steuerbar (Default `'0'`). Auf `'1'` setzen, um vor dem POST DNS‑ und HTTP‑HEAD‑Checks zu loggen; im Normalbetrieb aus lassen (weniger Log‑Noise).
- Sicherheit: Falls eine Webhook‑URL geleakt wurde, in Slack unter „Incoming Webhooks“ den alten Webhook revoken/löschen, neuen Webhook anlegen und die neue URL als Secret `SLACK_WEBHOOK_URL` hinterlegen.
- Testen: Da der Slack‑Step nur bei Fehlern läuft, für Tests in einem kurzlebigen Branch temporär einen absichtlichen Fail‑Step einfügen und anschließend wieder entfernen (nicht in `main` mergen).

## Hinweise

- Autoritatives Signal kommt aus `benches-agg.yml` (längere Messung, robuste Toleranzen).
- Short‑Benches liefern frühes Signal, sind aber varianzempfindlicher (p50 sensibler).
