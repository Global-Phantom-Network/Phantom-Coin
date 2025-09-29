# Phantom-Coin Roadmap (v0.1.x)

## Goals
- Stable public release pipeline (CI/Release) with reproducible builds
- Performance baselines per shard; scale via sharding
- Robust observability (Prometheus + Grafana + Alerts)
- Strict security posture (AGPL-3.0-only, audit/deny checks)

## v0.1.1
- CI hardening: cargo-audit, cargo-deny
- SPDX license headers across crates
- Public docs: README, GENESIS, observability stack
- Example configs and start script

## v0.1.2 (planned)
- Payload builder: configurable fairness/policies via TOML
- More mempool metrics and proposer breakdowns
- Benchmarks: sustained throughput scenarios and profiling recipes

## v0.1.3 (planned)
- RocksDB tuning guide and default options
- QUIC backpressure tuning and rate-limits presets
- Extended alerts and SLO panels

## Longer-term (beyond v0.1.x)
- Sharding orchestration (committee assignments)
- Attestor-pool sampling/aggregation protocol
- Slashing events pipeline and Merkle-claim tooling
