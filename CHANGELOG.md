# Changelog

## v0.1.3 (2026-03-06)

- Dynamisches Sharding (Schritte 1–8 aus `sharding_umsetzungsplan.txt`)
  - `NetworkScale { num_shards, k }` + `compute_network_scale(pool_size)` in `pc-consensus`
  - `committee_select_vrf_sharded`: VRF-Committee-Auswahl pro Shard mit globalem Seed + Re-Hash
  - `RotationManager`: Shard-Committees, `committee_for_shard()`, `get_active_shards_for_validator()`
  - `quic_server.rs`: `num_shards_state` und `k` dynamisch aus `StakeRegistry` berechnet
  - `my_shard_id` → `my_shard_ids: HashSet<u16>` (Multi-Shard-fähig)
  - Mempool-Kapazität dynamisch: `mempool_cap_per_shard(num_shards_state)`
  - Proposer-Loop iteriert nur über eigene Shards
  - `verify_header_finality` nutzt dynamisches `k` aus `initial_scale`
- Tests
  - 10 neue/erweiterte Tests in `rotation_manager` (Multi-Shard, Validator-Zuordnung)
  - Audit-Evidence-Tests (f1, f5–f15, f82) auf korrekte Source-Dateien nach Refactoring umgestellt
  - `f19_f20_mint_rpc_standalone`: akzeptiert beide korrekten Fehlermeldungen bei Seed-Replay

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
