# Changelog

## v0.1.2 (2025-10-11)

- State/UTXO
  - t15_utxo_state abgeschlossen: InMemory- und RocksDB-Backends (NVMe-freundliche Optionen), deterministische Apply-Pipeline inkl. Maturity/Stake, Merkle-Root (`UtxoState::root()`), Snapshots/Restore (`snapshot_to_*`/`restore_from_*`).
  - Tests: `rocksdb_snapshot_roundtrip`, `rocksdb_state_root_changes` (Feature `rocksdb`).
  - CI: RocksDB-Feature-Build/Test in `.github/workflows/ci.yml`.
- Docs
  - `docs/PHANTOMCOIN_TODO_PLAN.md`: t15 auf "completed" gesetzt, Done-Notiz mit Quellcode-/CI-/Test-Verweisen ergänzt.

## v0.1.1 (2025-09-30)

- Lizenz & Compliance
  - SPDX-License-Identifier in allen Rust-Quelltexten ergänzt (AGPL-3.0-only)
  - `deny.toml` hinzugefügt und CI mit `cargo-deny` integriert
- CI/CD
  - CI-Hardening: fmt, clippy (-D warnings), build, tests, Feature-Checks
  - Security-Checks: `cargo-audit` integriert inkl. Lockfile-Generierung
  - Release-Workflow erweitert: Linux x86_64, macOS universal und Linux ARM64 (aarch64)
- Community & Security
  - `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md` hinzugefügt
- Dokumentation
  - `README.md` erweitert (Localnet-Quickstart, Observability-Hinweise)
  - `docs/GENESIS.md` vervollständigt
  - `ROADMAP.md` für v0.1.x hinzugefügt
- Observability
  - `docs/observability/docker-compose.yml`, Prometheus `prometheus.yml` und Alerts
  - Grafana-Dashboard + Provisioning hinzugefügt
  - Runbook-URLs in Alerts korrigiert
- Konfiguration & Tools
  - Beispiel `configs/node.toml`
  - `scripts/start_localnet.sh` zum lokalen Start (Genesis-Erzeugung, Metriken, Observability)
- Tests
  - Negativtests und Invarianten für FeeSplit/Recipients/Acks/Proposer-Index in `pc-consensus`
