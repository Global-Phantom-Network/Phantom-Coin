# Production Readiness Verification 2026-03-12

Stand: 2026-03-12

Diese Datei dokumentiert die tatsächlich ausgeführten Verifikationen für den aktuellen Produktions-Readiness-Stand.

## Lokal ausgeführte Nachweise

1. Guard-/Repo-Härtung

   Kommando:
   `bash scripts/verify_prod_readiness_guards.sh`

   Ergebnis:
   `prod-readiness-guards: ok`

2. Hosted Runtime-Pfade

   Kommando:
   `bash scripts/verify_runtime_paths_ci.sh`

   Ergebnis:
   - `PASS status_serve_help`
   - `PASS p2p_quic_listen_help`
   - `PASS p2p_metrics_serve_help`
   - `PASS node_example_config_starts`
   - `PASS status_example_config_starts`
   - `PASS status_genesis_mismatch_rejected`
   - `PASS genesis_present_enables_finality_verification`
   - `PASS status_auth_401_without_token`
   - `PASS validator_control_persisted`
   - `PASS miner_valid_ca`
   - `PASS miner_wrong_ca_rejected`
   - `PASS status_http_local_helper_boundary`
   - `ALL_RUNTIME_CHECKS_PASSED`

3. Tauri Release-Build und packaged App Smoke

   Kommando:
   `bash scripts/verify_tauri_release_ci.sh`

   Ergebnis:
   - `PASS tauri_release_config_hardened`
   - `PASS tauri_release_bundle_built`
   - `PASS tauri_packaged_app_smoke`

4. Compose-/Staging-Smoke mit Produktionsimage

   Vorbedingung:
   `phantom-node:local` wurde per Dockerfile gebaut.

   Kommando:
   `SKIP_COMPOSE_BUILD=1 bash scripts/verify_compose_stacks_ci.sh`

   Ergebnis:
   - `PASS root_compose_smoke`
   - `PASS deploy_compose_smoke`
   - `ALL_COMPOSE_SMOKE_CHECKS_PASSED`

5. P2P Rate-Limit Runtime-Nachweis

   Kommando:
   `cargo test -p phantom-node --test p2p_metrics_smoke`

   Ergebnis:
   - `test p2p_quic_listen_metrics_smoke ... ok`
   - `test p2p_quic_listen_rate_limit_smoke ... ok`

   Abgedeckt:
   - Burst/Flood erzeugt `pc_p2p_inbound_dropped_rate > 0`
   - `pc_p2p_outbox_depth` bleibt klein
   - `pc_node_process_rss_bytes` bleibt unter der gesetzten Schranke

6. Gesamt-Compile

   Kommando:
   `cargo check --workspace --all-targets`

   Ergebnis:
   `Finished 'dev' profile [optimized + debuginfo] target(s)`

## Repo-/CI-Verankerung

- `/.github/workflows/prod-readiness-guards.yml`
- `/.github/workflows/runtime-verification.yml`
- `/.github/workflows/compose-smoke.yml`
- `/.github/workflows/tauri-release-verification.yml`

## Systemd-spezifischer Nachweis

Der systemd-Nachweis ist als dedizierter self-hosted Linux/systemd-Pfad implementiert:

- `scripts/verify_systemd_runtime_ci.sh`
- `.github/workflows/runtime-verification.yml`

Auf diesem macOS-Host ist `systemctl` lokal nicht verfügbar. Der Nachweis ist deshalb im Repo/CI-Pfad verankert, aber nicht als lokaler macOS-Lauf reproduzierbar.
