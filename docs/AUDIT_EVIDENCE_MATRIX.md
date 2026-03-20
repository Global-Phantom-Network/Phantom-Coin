# Phantom-Coin Audit Evidence Matrix

Generated: 2026-02-13 19:48:42

Historical note:
- This matrix is a point-in-time audit snapshot, not the canonical live specification.
- Code anchors, line numbers and symbol names may drift as the implementation changes.
- For current operational behaviour, prefer the source tree plus `docs/devops/production-readiness-*.md`.

Verification baseline (run manually before trusting this document):
- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo test --workspace --all-targets --no-run`

Repo state:
- HEAD: `840a9dc750e4ee31115cd17c63668b004eec4b80`
- Branch: `security/a1-a3-a9-a10`

Legend:
- `Code Evidence` points to an anchor inside the audit-referenced file(s) when possible.
- `Test Evidence` only lists real Rust tests (functions preceded by `#[test]`/`#[tokio::test]`).

## F1 (P0) — TLS-Branch Code-Duplizierung → Auth-Bypass-Risiko

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(HTTP+TLS-Endpoint-Setup, ~Z.800-2500)`
- Code Evidence: `crates/phantom-node/src/main.rs:2209 (anchor: status_serve_handle_request_inner)`
- Test Evidence: `crates/phantom-node/tests/f1_status_serve_single_handler.rs:8 (test: f1_status_serve_http_and_tls_share_one_inner_handler)`

## F2 (P0) — apply_mint_with_index mutiert State ueber HTTP

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.3200-3400, /state/apply_mint_with_index Endpoint)`
- Code Evidence: `crates/phantom-node/src/main.rs:3065 (anchor: apply_mint_with_index)`
- Test Evidence: `crates/phantom-node/tests/future_time_attack_a2.rs:21 (test: a2_rejects_removed_apply_mint_with_future_telemetry_time)`
- Current status: Historical finding. The HTTP endpoint was removed and now returns `410 Gone`.

## F3 (P0) — Metrics-Endpoint auf Non-Loopback ohne Auth

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.8000-8100, run_p2p_metrics_serve)`
- Code Evidence: `crates/phantom-node/src/main.rs:8895 (anchor: metrics_addr)`
- Test Evidence: `crates/phantom-node/tests/p2p_metrics_smoke.rs:34 (test: p2p_quic_listen_metrics_smoke)`

## F4 (P1) — Journal-Append nicht atomar

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.5700-5750, journal_append)`
- Code Evidence: `crates/phantom-node/src/main.rs:5258 (anchor: journal_append)`
- Test Evidence: `crates/phantom-node/src/main.rs:5862 (test: journal_recovery_roundtrip)`

## F5 (P1) — Mempool-Eviction O(n) sort bei jedem Insert

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.10800-10900)`
- Code Evidence: `crates/phantom-node/src/main.rs:13326 (anchor: Eviction)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:13 (test: f5_mempool_eviction_is_o1_and_fifo)`

## F6 (P1) — Proposer hat keinen Random-Jitter

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.10500, Proposer-Tick)`
- Code Evidence: `crates/phantom-node/src/main.rs:1345 (anchor: Proposer)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:27 (test: f6_proposer_tick_has_random_jitter)`

## F7 (P1) — P2P Peer-Discovery nutzt mutable Vektor ohne Lock

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.9200-9300)`
- Code Evidence: `crates/phantom-node/src/main.rs:40 (anchor: Peer)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:40 (test: f7_peer_discovery_mutations_are_locked)`

## F8 (P1) — PoW-Miner blockiert bei nicht-finalem prev_mint_id

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.9400-9500, PoW Miner Task)`
- Code Evidence: `crates/phantom-node/src/main.rs:8861 (anchor: Miner)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:53 (test: f8_pow_miner_does_not_block_the_runtime)`

## F9 (P2) — StatusServeArgs Default-Bind 0.0.0.0

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `(~Z.5500, StatusServeArgs)`
- Code Evidence: `crates/phantom-node/src/main.rs:5290 (anchor: StatusServeArgs)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:63 (test: f9_status_serve_default_binds_to_loopback)`

## F10 (P2) — Hardcoded MAX_PAYLOAD_MICROTX

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Code Evidence: `crates/phantom-node/src/main.rs:64 (anchor: MAX_PAYLOAD_MICROTX)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:73 (test: f10_max_payload_microtx_is_not_hardcoded_in_node_binary)`

## F11 (P2) — read_hex32_files_in kein Size-Limit

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Code Evidence: `crates/phantom-node/src/main.rs:9437 (anchor: read_hex32_files_in)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:86 (test: f11_read_hex32_files_in_is_name_based_and_capped)`

## F12 (P2) — DB-Repair/Reset ohne Confirmation

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Code Evidence: `crates/phantom-node/src/main.rs:10441 (anchor: /Reset)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:113 (test: f12_db_reset_requires_yes_flag)`

## F13 (P2) — Atomic-Counter Relaxed Ordering

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Code Evidence: `crates/phantom-node/src/main.rs:84 (anchor: Atomic)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:137 (test: f13_relaxed_ordering_is_documented_as_metrics_only)`

## F14 (P2) — P2P-Forward Task unbounded Channel

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Code Evidence: `crates/phantom-node/src/main.rs:1770 (anchor: Task)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:148 (test: f14_broadcast_backpressure_is_observable_via_lagged_metric)`

## F15 (P2) — backup_dir keine Fehlerbehandlung

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Code Evidence: `crates/phantom-node/src/main.rs:13606 (anchor: backup_dir)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:163 (test: f15_backup_dir_propagates_errors)`

## F17 (P0) — Seed-Reservation Race vor File-Lock (mint_rpc.rs)

- Module: `mint_rpc (Modul)`
- Audit File: `crates/phantom-node/src/mint_rpc.rs`
- Audit Lines: `(~Z.200-280)`
- Code Evidence: `crates/phantom-node/src/mint_rpc.rs:226 (anchor: mint_seeds)`
- Test Evidence: `crates/phantom-node/tests/f17_seed_reservation_race.rs:52 (test: f17_parallel_mint_submissions_with_same_seed_only_one_is_accepted)`

## F19 (P0) — Standalone mint_rpc persistiert Mint NICHT → nie propagiert

- Module: `bin/mint_rpc (Standalone Binary)`
- Audit File: `crates/phantom-node/src/bin/mint_rpc.rs`
- Audit Lines: `(~Z.400-500, handle_mint_submit)`
- Code Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:496 (anchor: Persist mint into mempool_dir/mints)`
- Test Evidence: `crates/phantom-node/tests/f19_f20_mint_rpc_standalone.rs:63 (test: f19_f20_standalone_mint_rpc_persists_mint_and_rejects_seed_replay)`

## F20 (P0) — Standalone mint_rpc: Keine Seed-Reservation → Replay

- Module: `bin/mint_rpc (Standalone Binary)`
- Audit File: `crates/phantom-node/src/bin/mint_rpc.rs`
- Audit Lines: `(~Z.400-500)`
- Code Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:441 (anchor: mint_seeds)`
- Test Evidence: `crates/phantom-node/tests/f19_f20_mint_rpc_standalone.rs:63 (test: f19_f20_standalone_mint_rpc_persists_mint_and_rejects_seed_replay)`

## F21 (P1) — Standalone mint_rpc: SupplyState Mutex statt atomarer Persist

- Module: `bin/mint_rpc`
- Audit File: `crates/phantom-node/src/bin/mint_rpc.rs`
- Audit Lines: `(~Z.350-400)`
- Code Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:637 (anchor: mint_rpc)`
- Test Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:948 (test: f21_supply_state_is_refreshed_from_disk_per_request)`

## F22 (P1) — Standalone mint_rpc: --mempool-dir Warnung aber kein Enforce

- Module: `bin/mint_rpc`
- Audit File: `crates/phantom-node/src/bin/mint_rpc.rs`
- Audit Lines: `(~Z.100-120)`
- Code Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:48 (anchor: --mempool-dir)`
- Test Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:941 (test: f22_mempool_dir_equal_without_force_is_ok)`

## F23 (P2) — Standalone mint_rpc: Connection Semaphore hart 128

- Module: `bin/mint_rpc`
- Audit File: `crates/phantom-node/src/bin/mint_rpc.rs`
- Code Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:637 (anchor: mint_rpc)`
- Test Evidence: `crates/phantom-node/src/bin/mint_rpc.rs:1016 (test: f23_max_connections_is_configurable_with_cli_default)`

## F24 (P0) — --secret-hex leakt Key in Prozessliste

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.1127-1154 (Commands::Import)`
- Code Evidence: `crates/phantom-signer/src/main.rs:390 (anchor: resolve_import_secret_hex)`
- Test Evidence: `crates/phantom-signer/src/main.rs:514 (test: resolve_import_secret_hex_rejects_secret_hex_in_release_builds)`

## F25 (P0) — Seed-Anzeige auf stderr ohne TTY-Check → Log-Leak

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.4919-4934 (Commands::WalletInit)`
- Code Evidence: `crates/phantom-signer/src/main.rs:5397 (anchor: stderr().is_terminal)`
- Test Evidence: `crates/phantom-signer/tests/f25_wallet_init_tty.rs:7 (test: f25_wallet_init_refuses_seed_output_without_tty_on_stderr)`

## F26 (P1) — HWI SignMessage → Argument-Injection

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.2797-2825 (Commands::HwiSignMessage)`
- Code Evidence: `crates/phantom-signer/src/main.rs:1370 (anchor: Commands)`
- Test Evidence: `crates/phantom-signer/tests/f26_hwi_signmessage_injection.rs:9 (test: f26_hwi_signmessage_rejects_message_starting_with_dash)`

## F27 (P1) — BitBox2 Signer ENV relativer Pfad → Binary Planting

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.3100-3106 (Commands::HwiSignTx, PHANTOM_BITBOX2_SIGNER)`
- Code Evidence: `crates/phantom-signer/src/main.rs:1370 (anchor: Commands)`
- Test Evidence: `crates/phantom-signer/src/main.rs:639 (test: resolve_bitbox2_signer_rejects_relative_env_path_in_release_builds)`

## F28 (P1) — Keystore-Write nicht atomar

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.1991-2010 (save_keystore)`
- Code Evidence: `crates/phantom-signer/src/main.rs:660 (anchor: save_keystore)`
- Test Evidence: `crates/phantom-signer/src/main.rs:652 (test: f28_keystore_write_is_atomic_and_owner_only_mode)`

## F29 (P1) — WalletSend UTXO-Race (UX)

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.3942-3965 (Commands::WalletSend, UTXO-Selektion)`
- Code Evidence: `crates/phantom-signer/src/main.rs:1370 (anchor: Commands)`
- Test Evidence: `crates/phantom-signer/src/main.rs:531 (test: classify_broadcast_state_error_double_spend)`

## F30 (P1) — Seed-/XpubStore-Write nicht atomar

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `Z.545-595 (save_seed_store_encrypted),`
- Code Evidence: `crates/phantom-signer/src/main.rs:705 (anchor: save_seed_store_encrypted)`
- Test Evidence: `crates/phantom-signer/src/main.rs:696 (test: f30_seedstore_and_xpubstore_use_atomic_secure_write)`

## F31 (P1) — XpubStore Auto-Migration ohne Backup

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.2107-2191 (load_xpub_store, Migration)`
- Code Evidence: `crates/phantom-signer/src/main.rs:2651 (anchor: load_xpub_store)`
- Test Evidence: `crates/phantom-signer/src/main.rs:748 (test: f31_xpubstore_legacy_migration_creates_backup_before_overwrite)`

## F32 (P2) — validate_passphrase prueft nur Mindestlaenge

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.1881-1888`
- Code Evidence: `crates/phantom-signer/src/main.rs:768 (anchor: validate_passphrase)`
- Test Evidence: `crates/phantom-signer/src/main.rs:768 (test: f32_validate_passphrase_enforces_min_length_and_warns_only)`

## F33 (P2) — Config auth_token im TOML (Klartext)

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.160-167 (SignerConfig)`
- Code Evidence: `crates/phantom-signer/src/main.rs:158 (anchor: SignerConfig)`
- Test Evidence: `crates/phantom-signer/src/main.rs:776 (test: f33_signer_config_warns_on_plaintext_auth_token)`

## F34 (P2) — Boilerplate Node-URL/Auth/TLS Resolution

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Code Evidence: `crates/phantom-signer/src/main.rs:4434 (anchor: Auth)`
- Test Evidence: `crates/phantom-signer/src/main.rs:555 (test: resolve_node_config_uses_config_node_url_when_cli_is_default)`

## F35 (P2) — BIP39-Passphrase immer leer

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `Z.601 (derive_xpub_from_mnemonic), Z.2301`
- Code Evidence: `crates/phantom-signer/src/main.rs:1142 (anchor: derive_xpub_from_mnemonic)`
- Test Evidence: `crates/phantom-signer/src/main.rs:789 (test: f35_bip39_passphrase_is_always_empty_string)`

## F36 (P2) — PayJoin Derivation-Placeholder

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.3395-3400 (Commands::PayjoinRespond)`
- Code Evidence: `crates/phantom-signer/src/main.rs:1370 (anchor: Commands)`
- Test Evidence: `crates/phantom-signer/src/main.rs:802 (test: f36_payjoin_respond_requires_derivation_paths_for_added_inputs)`

## F37 (P2) — lock_from_pc_address hardcoded HRP "pc"

- Module: `phantom-signer`
- Audit File: `crates/phantom-signer/src/main.rs`
- Audit Lines: `~Z.2205-2227`
- Code Evidence: `crates/phantom-signer/src/main.rs:819 (anchor: lock_from_pc_address)`
- Test Evidence: `crates/phantom-signer/src/main.rs:819 (test: f37_lock_from_pc_address_accepts_non_pc_hrp)`

## F38 (P0) — HSM Vote-Domain weicht von main.rs ab → ungueltige Signaturen

- Module: `pkcs11_sign`
- Audit File: `crates/phantom-signer/src/pkcs11_sign.rs`
- Audit Lines: `Z.122-132 (seat_vote_sign_with_hsm)`
- Code Evidence: `crates/phantom-signer/src/pkcs11_sign.rs:102 (anchor: seat_vote_sign_with_hsm)`
- Test Evidence: `crates/phantom-signer/src/pkcs11_sign.rs:147 (test: f38_seat_vote_sign_with_hsm_is_fail_closed_and_returns_no_signature)`
- Note: PKCS#11 seat vote signing is fail-closed (Schnorr required). This is consensus-safe, but HSM voting is disabled until a Schnorr-capable mechanism exists.

## F39 (P1) — PayJoin validiert Sender-Outputs nicht → Fund-Theft

- Module: `payjoin`
- Audit File: `crates/phantom-signer/src/payjoin.rs`
- Audit Lines: `Z.227-296 (validate_payjoin_response)`
- Code Evidence: `crates/phantom-signer/src/payjoin.rs:225 (anchor: validate_payjoin_response)`
- Test Evidence: `crates/phantom-signer/src/payjoin.rs:630 (test: test_validate_response_rejects_sender_output_replacement)`

## F40 (P1) — PayJoin Duplicate-Amount-Check blockiert legitime TXs

- Module: `payjoin`
- Audit File: `crates/phantom-signer/src/payjoin.rs`
- Audit Lines: `Z.67-76 (validate_no_zero_change)`
- Code Evidence: `crates/phantom-signer/src/payjoin.rs:69 (anchor: validate_no_zero_change)`
- Test Evidence: `crates/phantom-signer/src/payjoin.rs:511 (test: test_privacy_validator_allows_duplicate_amounts)`

## F41 (P1) — walletdb enc_key nicht zeroized bei Drop

- Module: `walletdb`
- Audit File: `crates/phantom-signer/src/walletdb.rs`
- Audit Lines: `Z.81-86 (struct WalletDb)`
- Code Evidence: `crates/phantom-signer/src/walletdb.rs:113 (anchor: WalletDb)`
- Test Evidence: `crates/phantom-signer/src/walletdb.rs:469 (test: f41_walletdb_drop_zeroizes_enc_key)`

## F42 (P1) — walletdb: Kein Passphrase-Verifikationsmarker

- Module: `walletdb`
- Audit File: `crates/phantom-signer/src/walletdb.rs`
- Audit Lines: `Z.172-292 (open_locked)`
- Code Evidence: `crates/phantom-signer/src/walletdb.rs:225 (anchor: open_locked)`
- Test Evidence: `crates/phantom-signer/src/walletdb.rs:541 (test: open_locked_rejects_wrong_passphrase_with_marker)`

## F43 (P2) — PayJoin URI kein URL-Decoding

- Module: `payjoin`
- Audit File: `crates/phantom-signer/src/payjoin.rs`
- Audit Lines: `Z.352-378 (parse_pc_uri)`
- Code Evidence: `crates/phantom-signer/src/payjoin.rs:366 (anchor: parse_pc_uri)`
- Test Evidence: `crates/phantom-signer/src/payjoin.rs:574 (test: test_pc_uri_parsing)`

## F44 (P2) — PayJoin Endpoint nicht HTTPS-validiert

- Module: `payjoin`
- Audit File: `crates/phantom-signer/src/payjoin.rs`
- Audit Lines: `Z.113-139 (initiate_payjoin)`
- Code Evidence: `crates/phantom-signer/src/payjoin.rs:108 (anchor: initiate_payjoin)`
- Test Evidence: `crates/phantom-signer/src/payjoin.rs:601 (test: test_initiate_rejects_non_https_non_loopback_endpoint)`

## F45 (P2) — PKCS#11 kein Logout bei Fehler

- Module: `pkcs11_sign`
- Audit File: `crates/phantom-signer/src/pkcs11_sign.rs`
- Audit Lines: `Z.28-93 (sign_with_hsm)`
- Code Evidence: `crates/phantom-signer/src/pkcs11_sign.rs:36 (anchor: sign_with_hsm)`
- Test Evidence: `crates/phantom-signer/src/pkcs11_sign.rs:168 (test: f45_sign_with_hsm_installs_logout_guard_after_login)`

## F46 (P2) — PSBT-Datei 0o644 statt 0o600

- Module: `psbt`
- Audit File: `crates/phantom-signer/src/psbt.rs`
- Audit Lines: `Z.130-144 (to_toml_file)`
- Code Evidence: `crates/phantom-signer/src/psbt.rs:87 (anchor: to_toml_file)`
- Test Evidence: `crates/phantom-signer/src/psbt.rs:87 (test: to_toml_file_sets_private_permissions)`

## F47 (P2) — Lockfile truncate vor Lock-Acquire

- Module: `slashdb + walletdb`
- Audit File: `crates/phantom-signer/src/slashdb.rs Z.82-83,`
- Code Evidence: `crates/phantom-signer/src/slashdb.rs:24 (anchor: Lock)`
- Test Evidence: `crates/phantom-signer/src/slashdb.rs:185 (test: f47_slashdb_lockfile_is_not_truncated_on_failed_lock_acquire)`

## F48 (P1) — pc-store: read_all ohne Groessenlimit → OOM-DoS

- Module: `pc-store`
- Audit File: `crates/pc-store/src/lib.rs`
- Audit Lines: `Z.144-149 (read_all / read_to_end)`
- Code Evidence: `crates/pc-store/src/lib.rs:204 (anchor: read_all)`
- Test Evidence: `crates/pc-store/src/lib.rs:505 (test: get_payload_rejects_oversized_file)`

## F49 (P1) — pc-codec: bool::decode akzeptiert Non-Canonical → Consensus-Split

- Module: `pc-codec`
- Audit File: `crates/pc-codec/src/lib.rs`
- Audit Lines: `Z.142-146 (impl Decodable for bool)`
- Code Evidence: `crates/pc-codec/src/lib.rs:57 (anchor: Decodable)`
- Test Evidence: `crates/pc-codec/src/lib.rs:341 (test: bool_decode_non_canonical_rejected)`

## F50 (P1) — phantom-miner-gui: Tokio-Runtime pro Mining-Iteration

- Module: `phantom-miner-gui`
- Audit File: `crates/phantom-miner-gui/src/main.rs`
- Audit Lines: `Z.598-639 (Mining-Thread-Loop)`
- Code Evidence: `crates/phantom-miner-gui/src/main.rs:5 (anchor: Mining)`
- Test Evidence: `crates/phantom-miner-gui/src/main.rs:177 (test: f50_no_tokio_runtime_is_created_in_the_mining_loop)`

## F51 (P2) — pc-store: TOCTOU bei Symlink-Pruefung

- Module: `pc-store`
- Audit File: `crates/pc-store/src/lib.rs`
- Audit Lines: `Z.62-95 (FileStore::open)`
- Code Evidence: `crates/pc-store/src/lib.rs:88 (anchor: FileStore)`
- Test Evidence: `crates/pc-store/src/lib.rs:550 (test: f51_unix_permissions_and_symlink_policy)`

## F52 (P2) — pc-crypto/bls: Legacy-PoP-Fallback schwaeecht Domain-Separation

- Module: `pc-crypto`
- Audit File: `crates/pc-crypto/src/bls.rs`
- Audit Lines: `Z.97-109 (bls_pop_verify)`
- Code Evidence: `crates/pc-crypto/src/bls.rs:96 (anchor: bls_pop_verify)`
- Test Evidence: `crates/pc-crypto/src/bls.rs:144 (test: f52_bls_sign_verify_roundtrip_and_pop_domain_separation)`

## F53 (P2) — pc-crypto/stealth: Feste Even-Parity-Annahme bei ECDH

- Module: `pc-crypto`
- Audit File: `crates/pc-crypto/src/stealth.rs`
- Audit Lines: `Z.38 (compute_shared_secret)`
- Code Evidence: `crates/pc-crypto/src/stealth.rs:26 (anchor: compute_shared_secret)`
- Test Evidence: `crates/pc-crypto/src/stealth.rs:180 (test: f53_ecdh_shared_secret_is_parity_invariant)`

## F54 (P2) — phantom-miner-gui: Default-Adresse ohne --address → Funds-Loss

- Module: `phantom-miner-gui`
- Audit File: `crates/phantom-miner-gui/src/main.rs`
- Audit Lines: `Z.276-280`
- Code Evidence: `crates/phantom-miner-gui/src/main.rs:156 (anchor: --address)`
- Test Evidence: `crates/phantom-miner-gui/src/main.rs:154 (test: f54_cli_requires_address)`

## F55 (P2) — phantom-config: now_secs() gibt 0 bei Clock-Fehler

- Module: `phantom-config`
- Audit File: `crates/phantom-config/src/lib.rs`
- Audit Lines: `Z.12-17 (now_secs)`
- Code Evidence: `crates/phantom-config/src/lib.rs:20 (anchor: now_secs)`
- Test Evidence: `crates/phantom-config/src/lib.rs:76 (test: f55_secs_since_epoch_rejects_pre_epoch)`

## F56 (P2) — bitbox02-signer: Fingerprint nur 32-Bit Collision-Resistance

- Module: `bitbox02-signer`
- Audit File: `crates/bitbox02-signer/src/main.rs`
- Audit Lines: `Z.571-581 (compute_fingerprint)`
- Code Evidence: `crates/bitbox02-signer/src/main.rs:259 (anchor: compute_fingerprint)`
- Test Evidence: `crates/bitbox02-signer/src/main.rs:588 (test: f56_fingerprint_is_8_bytes_hex_encoded)`

## F57 (P2) — phantom-miner-gui: logs.remove(0) ist O(n)

- Module: `phantom-miner-gui`
- Audit File: `crates/phantom-miner-gui/src/main.rs`
- Audit Lines: `Z.463`
- Code Evidence: `crates/phantom-miner-gui/src/main.rs:33 (anchor: VecDeque)`
- Test Evidence: `crates/phantom-miner-gui/src/main.rs:160 (test: f57_logs_do_not_use_vec_remove_0_and_use_vecdeque)`

## F58 (P0) — pc-p2p: Massive Code-Duplikation im P2P-Loop (Divergenz)

- Module: `pc-p2p`
- Audit File: `crates/pc-p2p/src/lib.rs`
- Audit Lines: `Z.2233-4335 (run_p2p_loop)`
- Code Evidence: `crates/pc-p2p/src/lib.rs:3910 (anchor: inbound_incoming_and_incomingfrom_are_equivalent)`
- Test Evidence: `crates/pc-p2p/src/lib.rs:3910 (test: inbound_incoming_and_incomingfrom_are_equivalent)`

## F59 (P0) — pc-p2p: rocksdb_store TTL-Cleanup-Assertion auskommentiert

- Module: `pc-p2p`
- Audit File: `crates/pc-p2p/src/rocksdb_store.rs`
- Audit Lines: `Test rocksdb_store_ttl_cleanup`
- Code Evidence: `crates/pc-p2p/src/rocksdb_store.rs:349 (anchor: rocksdb_store_ttl_cleanup)`
- Test Evidence: `crates/pc-p2p/src/rocksdb_store.rs:349 (test: rocksdb_store_ttl_cleanup)`

## F60 (P0) — pc-p2p: dedupe_insert_capped Eviction unter adversarial Load

- Module: `pc-p2p`
- Audit File: `crates/pc-p2p/src/lib.rs`
- Audit Lines: `Z.2277-2308`
- Code Evidence: `crates/pc-p2p/src/lib.rs:2298 (anchor: dedupe_insert_capped)`
- Test Evidence: `crates/pc-p2p/src/lib.rs:2335 (test: f60_dedupe_insert_capped_keeps_new_key_and_caps_len)`

## F61 (P1) — pc-p2p/libp2p_node: pending-Map hat kein Timeout

- Module: `pc-p2p`
- Audit File: `crates/pc-p2p/src/libp2p_node.rs`
- Audit Lines: `Z.820 (pending HashMap)`
- Code Evidence: `crates/pc-p2p/src/libp2p_node.rs:24 (anchor: HashMap)`
- Test Evidence: `crates/pc-p2p/src/libp2p_node.rs:1100 (test: f61_pending_requests_have_ttl_cleanup)`

## F62 (P1) — phantom-tui/tools: arbitrary command execution (Debug)

- Module: `phantom-tui`
- Audit File: `crates/phantom-tui/src/tools.rs`
- Audit Lines: `Z.304-341`
- Code Evidence: `crates/phantom-tui/src/tools.rs:36 (anchor: Debug)`
- Test Evidence: `crates/phantom-tui/src/tools.rs:395 (test: f62_tools_command_allowlist_blocks_arbitrary_programs)`

## F63 (P1) — phantom-tui/node: beliebige Binary-Pfade (Debug)

- Module: `phantom-tui`
- Audit File: `crates/phantom-tui/src/node.rs`
- Audit Lines: `Z.686-692`
- Code Evidence: `crates/phantom-tui/src/node.rs:618 (anchor: Binary)`
- Test Evidence: `crates/phantom-tui/src/node.rs:796 (test: f63_node_binary_allowlist_blocks_arbitrary_binaries)`

## F64 (P1) — pc-p2p/peer_store: kein Rate-Limit auf merge (Eclipse)

- Module: `pc-p2p`
- Audit File: `crates/pc-p2p/src/peer_store.rs`
- Audit Lines: `Z.1-330`
- Code Evidence: `crates/pc-p2p/src/peer_store.rs:219 (anchor: Peers)`
- Test Evidence: `crates/pc-p2p/src/peer_store.rs:343 (test: merge_limits_new_peers_per_call)`

## F65 (P1) — phantom-tui/wallet: Seed-Store-Pfad unsicher konstruiert

- Module: `phantom-tui`
- Audit File: `crates/phantom-tui/src/wallet.rs`
- Audit Lines: `Z.776`
- Code Evidence: `crates/phantom-tui/src/wallet.rs:146 (anchor: /wallet)`
- Test Evidence: `crates/phantom-tui/src/wallet.rs:900 (test: seed_store_path_for_wallet_db_ok)`

## F66 (P1) — pc-p2p: InMemoryStore ohne Groessenbegrenzung

- Module: `pc-p2p`
- Audit File: `crates/pc-p2p/src/lib.rs`
- Audit Lines: `Z.2060-2136 (InMemoryStore)`
- Code Evidence: `crates/pc-p2p/src/lib.rs:2030 (anchor: InMemoryStore)`
- Test Evidence: `crates/pc-p2p/src/lib.rs:2360 (test: f66_inmemory_store_caps_headers_len)`

## F67 (P2) — libp2p_node: blocked_peers nicht persistiert

- Module: `pc-p2p`
- Audit File: `crates/pc-p2p/src/libp2p_node.rs`
- Audit Lines: `Z.866-884`
- Code Evidence: `crates/pc-p2p/src/libp2p_node.rs:1103 (anchor: libp2p_node)`
- Test Evidence: `crates/pc-p2p/src/libp2p_node.rs:1121 (test: blocked_peers_persist_roundtrip_and_expiry)`

## F68 (P2) — pc-netsim: thread_rng() nicht reproduzierbar

- Module: `pc-netsim`
- Audit File: `crates/pc-netsim/src/lib.rs`
- Audit Lines: `Z.82-83`
- Code Evidence: `crates/pc-netsim/src/lib.rs:13 (anchor: StdRng)`
- Test Evidence: `crates/pc-netsim/src/lib.rs:187 (test: deterministic_with_fixed_seed)`

## F69 (P2) — phantom-tui/wallet: Blocking HTTP in TUI-Thread

- Module: `phantom-tui`
- Audit File: `crates/phantom-tui/src/wallet.rs`
- Audit Lines: `Z.666-707`
- Code Evidence: `crates/phantom-tui/src/wallet.rs:146 (anchor: /wallet)`
- Test Evidence: `crates/phantom-tui/src/wallet.rs:958 (test: f69_refresh_history_is_offloaded_to_background_thread)`

## F70 (P2) — phantom-tui/node: is_local_host und is_loopback_host identisch

- Module: `phantom-tui`
- Audit File: `crates/phantom-tui/src/node.rs`
- Audit Lines: `Z.22-34`
- Code Evidence: `crates/phantom-tui/src/node.rs:809 (anchor: is_local_host)`
- Test Evidence: `crates/phantom-tui/src/node.rs:803 (test: f70_node_rs_has_no_duplicate_loopback_helper_functions)`

## F71 (P2) — bitbox-api-rs: Private Key nicht zeroized in NoiseConfigData

- Module: `bitbox-api-rs (3rd-party)`
- Audit File: `crates/bitbox-api-rs/src/noise.rs`
- Audit Lines: `Z.27-31`
- Code Evidence: `crates/bitbox-api-rs/src/noise.rs:36 (anchor: NoiseConfigData)`
- Test Evidence: `crates/bitbox-api-rs/src/noise.rs:151 (test: f71_noise_configdata_privkey_is_zeroizing_and_debug_redacts)`

## F72 (P2) — bitbox-api-rs: unwrap() in U2fHidCommunication::write

- Module: `bitbox-api-rs (3rd-party)`
- Audit File: `crates/bitbox-api-rs/src/communication.rs`
- Audit Lines: `Z.64`
- Code Evidence: `crates/bitbox-api-rs/src/communication.rs:46 (anchor: U2fHidCommunication)`
- Test Evidence: `crates/bitbox-api-rs/src/communication.rs:326 (test: u2fhid_write_rejects_oversized_message_without_panic)`

## F73 (P2) — phantom-tui/wallet: Passphrase im Klartext in AppState

- Module: `phantom-tui`
- Audit File: `crates/phantom-tui/src/wallet.rs`
- Audit Lines: `Z.189`
- Code Evidence: `crates/phantom-tui/src/wallet.rs:146 (anchor: /wallet)`
- Test Evidence: `crates/phantom-tui/src/wallet.rs:978 (test: f73_appstate_passphrase_is_zeroizing_string)`

## F74 (P0) — Stealth scan_stealth_payments liefert Tweak statt Spending-Key

- Module: `stealth (phantom-signer)`
- Audit File: `crates/phantom-signer/src/stealth.rs`
- Audit Lines: `Z.194 (scan_stealth_payments)`
- Code Evidence: `crates/phantom-signer/src/stealth.rs:177 (anchor: scan_stealth_payments requires spend_secret)`
- Test Evidence: `crates/phantom-signer/src/stealth.rs:447 (test: test_scan_without_spend_secret_is_rejected)`

## F75 (P1) — pc-state: OverlayBackend::del gibt immer true zurueck

- Module: `pc-state`
- Audit File: `crates/pc-state/src/lib.rs`
- Audit Lines: `Z.389-392 (impl StateBackend for OverlayBackend, fn del)`
- Code Evidence: `crates/pc-state/src/lib.rs:234 (anchor: StateBackend)`
- Test Evidence: `crates/pc-state/src/lib.rs:2430 (test: overlay_del_reports_true_only_when_key_exists)`

## F76 (P1) — phantom-node: readyz nutzt sync I/O im async-Kontext

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `~Z.2101 (/readyz Handler)`
- Code Evidence: `crates/phantom-node/src/main.rs:9700 (anchor: /O)`
- Test Evidence: `crates/phantom-node/src/main.rs:7435 (test: readyz_check_mempool_dir_uses_blocking_bridge_and_reports_errors)`

## F77 (P1) — phantom-node: supply_state Persist-Fehler still ignoriert

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `~Z.585-592 (persist_supply_state_sync)`
- Code Evidence: `crates/phantom-node/src/main.rs:691 (anchor: persist_supply_state_sync)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:182 (test: f77_persist_supply_state_logs_on_serialize_or_write_error)`

## F78 (P1) — phantom-node: committee_seed_anchor Fallback [0u8; 32]

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `~Z.1110-1127 (committee_seed_anchor_from_mempool)`
- Code Evidence: `crates/phantom-node/src/main.rs:1707 (anchor: committee_seed_anchor_from_mempool)`
- Test Evidence: `crates/phantom-node/src/main.rs:5995 (test: committee_seed_anchor_none_without_finalized_root_or_genesis)`

## F79 (P2) — Stealth-Keys werden unverschluesselt gespeichert

- Module: `stealth (phantom-signer)`
- Audit File: `crates/phantom-signer/src/stealth.rs`
- Audit File: `vollstaendiger Verlust der`
- Audit Lines: `Z.292-316 (save_stealth_keys)`
- Code Evidence: `crates/phantom-signer/src/stealth.rs:269 (anchor: save_stealth_keys)`
- Test Evidence: `crates/phantom-signer/src/stealth.rs:459 (test: test_save_stealth_keys_is_encrypted_on_disk)`

## F80 (P2) — PKCS#11 HSM nutzt ECDSA-Mechanism fuer Schnorr-Votes

- Module: `pkcs11_sign (phantom-signer)`
- Audit File: `crates/phantom-signer/src/pkcs11_sign.rs`
- Audit Lines: `Z.136 (seat_vote_sign_with_hsm, Mechanism::ECDSA)`
- Code Evidence: `crates/phantom-signer/src/pkcs11_sign.rs:102 (anchor: seat_vote_sign_with_hsm)`
- Test Evidence: `crates/phantom-signer/src/pkcs11_sign.rs:126 (test: f80_seat_vote_sign_with_hsm_is_fail_closed_without_schnorr_mechanism)`

## F81 (P2) — walletdb Legacy-Migration ohne Verifikation

- Module: `walletdb (phantom-signer)`
- Audit File: `crates/phantom-signer/src/walletdb.rs`
- Audit Lines: `Z.238-285 (open_locked, Legacy-Migration)`
- Code Evidence: `crates/phantom-signer/src/walletdb.rs:225 (anchor: open_locked)`
- Test Evidence: `crates/phantom-signer/src/walletdb.rs:501 (test: open_locked_rejects_malformed_legacy_entry_during_migration)`

## F82 (P2) — Config-Datei wird dreimal geparst (TOCTOU)

- Module: `phantom-node`
- Audit File: `crates/phantom-node/src/main.rs`
- Audit Lines: `~Z.1800-1822 (run_status_serve, Config-Loading)`
- Code Evidence: `crates/phantom-node/src/main.rs:5290 (anchor: run_status_serve)`
- Test Evidence: `crates/phantom-node/tests/audit_evidence_f5_f15_f77_f82.rs:195 (test: f82_status_serve_parses_config_once_and_reuses_it)`

## F83 (P1) — pc-state: restore_snapshot loescht bestehenden State nicht

- Module: `pc-state`
- Audit File: `crates/pc-state/src/lib.rs`
- Audit Lines: `Z.2067-2109 (restore_snapshot)`
- Code Evidence: `crates/pc-state/src/lib.rs:2323 (anchor: restore_snapshot)`
- Test Evidence: `crates/pc-state/src/lib.rs:2465 (test: restore_snapshot_clears_existing_state_before_apply)`

## F84 (P1) — pc-consensus/committee_hash: Keine Tests fuer Committee-Selection

- Module: `pc-consensus`
- Audit File: `crates/pc-consensus/src/committee_hash.rs`
- Audit Lines: `Z.1-107 (gesamte Datei)`
- Code Evidence: `crates/pc-consensus/src/committee_hash.rs:61 (anchor: committee_hash)`
- Test Evidence: `crates/pc-consensus/tests/committee_hash_smoke.rs:32 (test: committee_seed_is_deterministic)`

## F85 (P2) — pc-consensus/attestor_claims: ClaimTracker ohne Groessenlimit

- Module: `pc-consensus`
- Audit File: `crates/pc-consensus/src/attestor_claims.rs`
- Audit Lines: `Z.240-242 (ClaimTracker)`
- Code Evidence: `crates/pc-consensus/src/attestor_claims.rs:241 (anchor: ClaimTracker)`
- Test Evidence: `crates/pc-consensus/src/attestor_claims.rs:551 (test: f85_claim_tracker_capacity_limit_is_enforced)`

## F86 (P2) — pc-state: prune_old_utxos ignoriert UTXOs ohne minted_at

- Module: `pc-state`
- Audit File: `crates/pc-state/src/lib.rs`
- Audit Lines: `Z.2000-2018 (prune_old_utxos)`
- Code Evidence: `crates/pc-state/src/lib.rs:2255 (anchor: prune_old_utxos)`
- Test Evidence: `crates/pc-state/src/lib.rs:2546 (test: prune_old_utxos_removes_entries_without_minted_at)`

## F87 (P2) — pc-state: Validator-Register iter O(n) bei Duplicate-Check

- Module: `pc-state`
- Audit File: `crates/pc-state/src/lib.rs`
- Audit Lines: `Z.1448-1454 (can_apply_micro_tx, Validator-Register)`
- Code Evidence: `crates/pc-state/src/lib.rs:101 (anchor: can_apply_micro_tx)`
- Test Evidence: `crates/pc-state/src/lib.rs:2564 (test: validator_stake_lock_index_tracks_put_update_and_delete)`

## F88 (P1) — GUI: Fragiles args-Vec-Mutation-Pattern in Closures

- Module: `phantom-gui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs`
- Audit Lines: `Z.5024-5052, Z.5141-5169, Z.5867-5892`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs:8492 (anchor: Closure)`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8652 (test: f88_validator_stake_args_do_not_accumulate_across_calls)`

## F89 (P1) — GUI+TUI: Passphrase als Klartext-String (kein Zeroize)

- Module: `phantom-gui-wallet, phantom-tui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs  Z.5302-5304`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs:4081 (anchor: Passphrase)`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8664 (test: f89_passphrase_fields_are_zeroizing_strings)`

## F90 (P2) — GUI: 4x duplizierte Statusbar-Farblogik

- Module: `phantom-gui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs`
- Audit Lines: `Z.6020-6149`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs:1340 (anchor: status_color)`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8628 (test: status_color_keywords)`

## F91 (P2) — GUI: HTTP-Client wird pro Request neu gebaut

- Module: `phantom-gui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs`
- Audit Lines: `Z.5339-5466 (open_wallet, refresh_history_for_selected)`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs:4125 (anchor: open_wallet)`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8678 (test: f91_wallet_http_client_is_cached_and_reused)`

## F92 (P1) — GUI: Blocking HTTP auf UI-Thread → GUI-Freeze

- Module: `phantom-gui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs`
- Audit Lines: `Z.5920-5946, Z.6001`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs:862 (anchor: Thread)`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8693 (test: f92_history_fetch_is_offloaded_to_background_thread)`

## F93 (P1) — GUI: Mnemonic/Seed als String ohne Zeroize

- Module: `phantom-gui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs`
- Audit Lines: `Z.5206-5290`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs:22 (anchor: Mnemonic)`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8704 (test: f93_mnemonic_and_seed_words_are_zeroizing)`

## F94 (P1) — TUI: Hardcodierter Keystore-Pfad ../seeds/default.toml

- Module: `phantom-tui-wallet`
- Audit File: `crates/phantom-tui-wallet/src/main.rs`
- Audit Lines: `Z.620-622`
- Code Evidence: `crates/phantom-tui-wallet/src/main.rs:55 (anchor: Pfad)`
- Test Evidence: `crates/phantom-tui-wallet/src/main.rs:875 (test: seed_store_path_resolves_to_phantom_seeds_dir)`

## F95 (P2) — TUI: Adress-Index Overflow bei u32::MAX

- Module: `phantom-tui-wallet`
- Audit File: `crates/phantom-tui-wallet/src/main.rs`
- Audit Lines: `Z.503-504`
- Code Evidence: `crates/phantom-tui-wallet/src/main.rs:246 (anchor: Adress)`
- Test Evidence: `crates/phantom-tui-wallet/src/main.rs:904 (test: next_address_index_errors_on_overflow)`

## F96 (P1) — TUI: Integer-Overflow bei amount + fee

- Module: `phantom-tui-wallet`
- Audit File: `crates/phantom-tui-wallet/src/main.rs`
- Audit Lines: `Z.586`
- Code Evidence: `crates/phantom-tui-wallet/src/main.rs:317 (anchor: checked_add)`
- Test Evidence: `crates/phantom-tui-wallet/src/main.rs:919 (test: execute_send_errors_on_amount_plus_fee_overflow)`

## F97 (P2) — TUI: Stille Fee-Parse-Fehler (unwrap_or(0))

- Module: `phantom-tui-wallet`
- Audit File: `crates/phantom-tui-wallet/src/main.rs`
- Audit Lines: `Z.575`
- Code Evidence: `crates/phantom-tui-wallet/src/main.rs:19 (anchor: Parse)`
- Test Evidence: `crates/phantom-tui-wallet/src/main.rs:965 (test: execute_send_errors_on_invalid_fee_instead_of_silent_zero)`

## F98 (P2) — GUI+TUI: ~6 duplizierte Utility-Funktionen ohne Shared-Crate

- Module: `phantom-gui-wallet, phantom-tui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs  Z.577-616, Z.327-352`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8717 (test: f98_gui_uses_shared_wallet_common_helpers)`

## F99 (P2) — GUI: Seed-Woerter pro Frame geklont, nicht zeroed

- Module: `phantom-gui-wallet`
- Audit File: `crates/phantom-gui-wallet/src/main.rs`
- Audit Lines: `Z.6649-6731`
- Code Evidence: `crates/phantom-gui-wallet/src/main.rs:6003 (anchor: Frame)`
- Test Evidence: `crates/phantom-gui-wallet/src/main.rs:8726 (test: f99_seed_words_are_arc_shared_and_zeroizing)`

## F100 (P2) — status_http: constant_time_eq leakt Token-Laenge via Early-Return

- Module: `phantom-node (bin/status_http)`
- Audit File: `crates/phantom-node/src/bin/status_http.rs`
- Audit Lines: `122-131`
- Code Evidence: `crates/phantom-node/src/bin/status_http.rs:1042 (anchor: status_http)`
- Test Evidence: `crates/phantom-node/src/bin/status_http.rs:1656 (test: f100_constant_time_eq_does_not_early_return_on_len_mismatch)`

## F101 (P1) — status_http: Full UTXO-Iteration unter Mutex blockiert alle Requests

- Module: `phantom-node (bin/status_http)`
- Audit File: `crates/phantom-node/src/bin/status_http.rs`
- Audit Lines: `380-390 (/consensus/validators), 501-511 (/consensus/committee)`
- Code Evidence: `crates/phantom-node/src/bin/status_http.rs:1042 (anchor: status_http)`
- Test Evidence: `crates/phantom-node/src/bin/status_http.rs:1681 (test: f101_consensus_validators_uses_stake_cache_snapshot)`

## F102 (P1) — status_http: Sync File-I/O in async Context (atomic_write, journal_append)

- Module: `phantom-node (bin/status_http)`
- Audit File: `crates/phantom-node/src/bin/status_http.rs`
- Audit Lines: `654-760 (/tx/broadcast), 762-847 (/evidence/broadcast)`
- Code Evidence: `crates/phantom-node/src/bin/status_http.rs:1042 (anchor: status_http)`
- Test Evidence: `crates/phantom-node/src/bin/status_http.rs:1698 (test: f102_broadcast_endpoints_use_spawn_blocking_for_disk_io)`

## F103 (P1) — status_http: /evidence/broadcast ohne State-Validierung

- Module: `phantom-node (bin/status_http)`
- Audit File: `crates/phantom-node/src/bin/status_http.rs`
- Audit Lines: `762-847`
- Code Evidence: `crates/phantom-node/src/bin/status_http.rs:1184 (anchor: /evidence/broadcast)`
- Test Evidence: `crates/phantom-node/src/bin/status_http.rs:1791 (test: f103_evidence_broadcast_rejects_bad_slash_ticket_signature)`

## F104 (P2) — status_http: Duplizierte Stake-Aggregationslogik

- Module: `phantom-node (bin/status_http)`
- Audit File: `crates/phantom-node/src/bin/status_http.rs`
- Audit Lines: `380-390 vs. 501-511`
- Code Evidence: `crates/phantom-node/src/bin/status_http.rs:1042 (anchor: status_http)`
- Test Evidence: `crates/phantom-node/src/bin/status_http.rs:1716 (test: f104_aggregate_stake_by_lock_sums_and_counts_only_staked_utxos)`

## F105 (P1) — TUI-Signer: Entschluesselte Secret-Key-Bytes nicht gezeroed

- Module: `phantom-tui (signer)`
- Audit File: `crates/phantom-tui/src/signer.rs`
- Audit Lines: `822 (run_sign), 945 (run_psbt_sign), 1106 (run_seat_vote_sign)`
- Code Evidence: `crates/phantom-tui/src/signer.rs:962 (anchor: run_sign)`
- Test Evidence: `crates/phantom-tui/src/signer.rs:2201 (test: f105_decrypted_secrets_are_wrapped_in_zeroizing)`

## F106 (P1) — TUI-Signer: secret_hex Import-Feld wird im Klartext angezeigt

- Module: `phantom-tui (signer)`
- Audit File: `crates/phantom-tui/src/signer.rs`
- Audit Lines: `186`
- Code Evidence: `crates/phantom-tui/src/signer.rs:77 (anchor: Signer)`
- Test Evidence: `crates/phantom-tui/src/signer.rs:2218 (test: f106_import_secret_hex_field_is_marked_secret)`

## F107 (P2) — TUI-Signer: Form-Values inkl. Passphrases ohne Zeroize geklont

- Module: `phantom-tui (signer)`
- Audit File: `crates/phantom-tui/src/signer.rs`
- Audit Lines: `642`
- Code Evidence: `crates/phantom-tui/src/signer.rs:77 (anchor: Signer)`
- Test Evidence: `crates/phantom-tui/src/signer.rs:2237 (test: f107_secret_fields_are_masked_in_ui_rendering)`

## F108 (P2) — TUI-Signer: env::set_var unsound in Multi-Thread-Context

- Module: `phantom-tui (signer)`
- Audit File: `crates/phantom-tui/src/signer.rs`
- Audit Lines: `1165-1166`
- Code Evidence: `crates/phantom-tui/src/signer.rs:77 (anchor: Signer)`
- Test Evidence: `crates/phantom-tui/src/signer.rs:2246 (test: f108_signer_does_not_use_env_set_var)`

## F109 (P2) — TUI-Signer: HWI signmessage leakt Message-Inhalt in Prozess-argv

- Module: `phantom-tui (signer)`
- Audit File: `crates/phantom-tui/src/signer.rs`
- Audit Lines: `1221`
- Code Evidence: `crates/phantom-tui/src/signer.rs:77 (anchor: Signer)`
- Test Evidence: `crates/phantom-tui/src/signer.rs:2255 (test: f109_hwi_signmessage_does_not_leak_message_via_process_argv)`

## F110 (P1) — node.rs: auth_token-Feld ohne Maskierung (secret: false)

- Module: `phantom-tui (node)`
- Audit File: `crates/phantom-tui/src/node.rs`
- Audit Lines: `188-193`
- Code Evidence: `crates/phantom-tui/src/node.rs:106 (anchor: auth_token)`
- Test Evidence: `crates/phantom-tui/src/node.rs:814 (test: f110_auth_token_field_is_marked_secret_in_forms)`

## F111 (P1) — wallet.rs: Passphrase als plain String ohne Zeroize

- Module: `phantom-tui (wallet)`
- Audit File: `crates/phantom-tui/src/wallet.rs`
- Audit Lines: `189, 217, 609`
- Code Evidence: `crates/phantom-tui/src/wallet.rs:551 (anchor: Passphrase)`
- Test Evidence: `crates/phantom-tui/src/wallet.rs:994 (test: f111_wallet_passphrase_is_zeroizing_and_not_plain_string)`

## F112 (P1) — miner.rs: Tokio-Runtime pro Hash-Iteration (Hashrate-Killer)

- Module: `phantom-tui (miner)`
- Audit File: `crates/phantom-tui/src/miner.rs`
- Audit Lines: `641-648`
- Code Evidence: `crates/phantom-tui/src/miner.rs:150 (anchor: Runtime)`
- Test Evidence: `crates/phantom-tui/src/miner.rs:882 (test: f112_miner_uses_single_tokio_runtime_and_std_rwlock_for_seed)`

## F113 (P1) — wallet.rs: Blocking HTTP auf UI-Thread friert TUI ein

- Module: `phantom-tui (wallet)`
- Audit File: `crates/phantom-tui/src/wallet.rs`
- Audit Lines: `612-625, 299, 711-726`
- Code Evidence: `crates/phantom-tui/src/wallet.rs:659 (anchor: fetch_history)`
- Test Evidence: `crates/phantom-tui/src/wallet.rs:1011 (test: f113_wallet_history_fetch_does_not_block_ui_thread)`

## F114 (P2) — wallet.rs: Fee unwrap_or(0) — stille Null-Fee

- Module: `phantom-tui (wallet)`
- Audit File: `crates/phantom-tui/src/wallet.rs`
- Audit Lines: `742-746`
- Code Evidence: `crates/phantom-tui/src/wallet.rs:146 (anchor: unwrap_or)`
- Test Evidence: `crates/phantom-tui/src/wallet.rs:1029 (test: f114_invalid_fee_is_rejected_instead_of_silent_zero)`

## F115 (P2) — wallet.rs: Hardcodierter Keystore-Pfad relativ zu wallet_db_path

- Module: `phantom-tui (wallet)`
- Audit File: `crates/phantom-tui/src/wallet.rs`
- Audit Lines: `776`
- Code Evidence: `crates/phantom-tui/src/wallet.rs:538 (anchor: Pfad)`
- Test Evidence: `crates/phantom-tui/src/wallet.rs:1056 (test: f115_seed_store_path_is_resolved_relative_to_wallet_parent)`

## F116 (P2) — miner.rs: Vec::remove(0) O(n) statt VecDeque fuer Logs

- Module: `phantom-tui (miner)`
- Audit File: `crates/phantom-tui/src/miner.rs`
- Audit Lines: `452-454, 541-543, 547-549, 563-565`
- Code Evidence: `crates/phantom-tui/src/miner.rs:2 (anchor: VecDeque)`
- Test Evidence: `crates/phantom-tui/src/miner.rs:899 (test: f116_logs_use_vecdeque_and_do_not_shift_with_remove0)`

## F117 (P2) — node.rs + wallet.rs + miner.rs: ~15 duplizierte Utility-Funktionen

- Module: `phantom-tui (node, wallet, miner)`
- Audit File: `crates/phantom-tui/src/{node,wallet,miner}.rs`
- Audit Lines: `diverse`
- Code Evidence: `crates/phantom-tui/src/node.rs:1 (anchor: http_util)`
- Test Evidence: `crates/phantom-tui/src/node.rs:830 (test: f117_tui_util_functions_are_not_duplicated_across_modules)`

## F118 (P2) — da_gating/mod.rs: Available(vec![]) Asymmetrie Fast-Path vs. Pending-Path

- Module: `pc-da (da_gating)`
- Audit File: `crates/pc-da/src/da_gating/mod.rs`
- Audit Lines: `100-107 vs. 189`
- Code Evidence: `crates/pc-da/src/da_gating/mod.rs:293 (anchor: da_gating)`
- Test Evidence: `crates/pc-da/src/da_gating/mod.rs:335 (test: pending_dedup_attaches_waiters)`

## F119 (P2) — da_gating/mod.rs: handle_payload_response speichert nicht-angeforderte Payloads

- Module: `pc-da (da_gating)`
- Audit File: `crates/pc-da/src/da_gating/mod.rs`
- Audit Lines: `167-194`
- Code Evidence: `crates/pc-da/src/da_gating/mod.rs:293 (anchor: da_gating)`
- Test Evidence: `crates/pc-da/src/da_gating/mod.rs:376 (test: unsolicited_payload_response_is_ignored)`
