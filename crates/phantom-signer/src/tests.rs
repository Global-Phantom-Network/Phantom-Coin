use super::*;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn read_signer_source(file: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
#[cfg(debug_assertions)]
fn resolve_import_secret_hex_allows_secret_hex_in_debug_builds() {
    let got = resolve_import_secret_hex(Some("  deadbeef  ".to_string()), None, None)
        .expect("secret_hex must be allowed in debug builds");
    assert_eq!(got, "deadbeef");
}

#[test]
#[cfg(not(debug_assertions))]
fn resolve_import_secret_hex_rejects_secret_hex_in_release_builds() {
    let err = resolve_import_secret_hex(Some("deadbeef".to_string()), None, None)
        .expect_err("secret_hex must be rejected in release builds");
    let msg = format!("{err:?}");
    assert!(msg.contains("--secret-hex ist in Release-Builds deaktiviert"));
}

#[test]
fn classify_broadcast_state_error_missing_input() {
    let body = r#"{"ok":false,"error":"tx rejected by state","state_error":"missing_input"}"#;
    assert_eq!(
        classify_broadcast_state_error(body),
        Some(BroadcastStateErrorKind::MissingInput)
    );
}

#[test]
fn classify_broadcast_state_error_double_spend() {
    let body = r#"{"ok":false,"error":"tx rejected by state","state_error":"double_spend"}"#;
    assert_eq!(
        classify_broadcast_state_error(body),
        Some(BroadcastStateErrorKind::DoubleSpend)
    );
}

#[test]
fn classify_broadcast_state_error_unknown_code() {
    let body = r#"{"ok":false,"error":"tx rejected by state","state_error":"something_else"}"#;
    assert_eq!(
        classify_broadcast_state_error(body),
        Some(BroadcastStateErrorKind::Other)
    );
}

#[test]
fn classify_broadcast_state_error_absent_field() {
    let body = r#"{"ok":false,"error":"tx rejected by state"}"#;
    assert_eq!(classify_broadcast_state_error(body), None);
}

#[test]
fn resolve_node_config_uses_config_node_url_when_cli_is_default() {
    let cfg = SignerConfig {
        node_url: Some("https://node.example:9999".to_string()),
        auth_token: None,
        auth_token_file: None,
        tls_ca: None,
        tls_client_pem: None,
    };

    let rc = resolve_node_config(
        "https://127.0.0.1:8080".to_string(),
        "https://127.0.0.1:8080",
        None,
        None,
        None,
        None,
        Some(&cfg),
    )
    .expect("resolve_node_config");
    assert_eq!(rc.node_url, "https://node.example:9999");
}

#[test]
fn resolve_node_config_prefers_cli_node_url_when_non_default() {
    let cfg = SignerConfig {
        node_url: Some("https://node.example:9999".to_string()),
        auth_token: None,
        auth_token_file: None,
        tls_ca: None,
        tls_client_pem: None,
    };

    let rc = resolve_node_config(
        "https://custom.example:1234".to_string(),
        "https://127.0.0.1:8080",
        None,
        None,
        None,
        None,
        Some(&cfg),
    )
    .expect("resolve_node_config");
    assert_eq!(rc.node_url, "https://custom.example:1234");
}

#[test]
fn resolve_node_config_prefers_cli_tls_over_config() {
    let cfg = SignerConfig {
        node_url: None,
        auth_token: None,
        auth_token_file: None,
        tls_ca: Some("/cfg/ca.pem".to_string()),
        tls_client_pem: Some("/cfg/client.pem".to_string()),
    };

    let rc = resolve_node_config(
        "https://127.0.0.1:8080".to_string(),
        "https://127.0.0.1:8080",
        None,
        None,
        Some(PathBuf::from("/cli/ca.pem")),
        Some(PathBuf::from("/cli/client.pem")),
        Some(&cfg),
    )
    .expect("resolve_node_config");
    assert_eq!(rc.tls_ca.as_deref(), Some(Path::new("/cli/ca.pem")));
    assert_eq!(
        rc.tls_client_pem.as_deref(),
        Some(Path::new("/cli/client.pem"))
    );
}

#[test]
#[cfg(debug_assertions)]
fn resolve_bitbox2_signer_allows_relative_env_path_in_debug_builds() {
    let _g = ENV_LOCK.lock().expect("ENV_LOCK poisoned");
    std::env::set_var("PHANTOM_BITBOX2_SIGNER", "relative/bitbox02-signer");
    let got = resolve_bitbox2_signer_binary(None).expect("relative env path must be allowed");
    assert_eq!(got, PathBuf::from("relative/bitbox02-signer"));
    std::env::remove_var("PHANTOM_BITBOX2_SIGNER");
}

#[test]
#[cfg(not(debug_assertions))]
fn resolve_bitbox2_signer_rejects_relative_env_path_in_release_builds() {
    let _g = ENV_LOCK.lock().expect("ENV_LOCK poisoned");
    std::env::set_var("PHANTOM_BITBOX2_SIGNER", "relative/bitbox02-signer");
    let err = resolve_bitbox2_signer_binary(None)
        .expect_err("relative env path must be rejected in release builds");
    assert!(
        err.to_string().contains("muss ein absoluter Pfad sein"),
        "unexpected error: {err:#}"
    );
    std::env::remove_var("PHANTOM_BITBOX2_SIGNER");
}

#[test]
fn f28_keystore_write_is_atomic_and_owner_only_mode() -> Result<()> {
    let td = tempfile::tempdir()?;
    let path = td.path().join("keystore.toml");

    let mut ks1 = Keystore::default();
    ks1.key_type = "test".to_string();
    ks1.algo = "schnorr".to_string();
    ks1.pub_hex = "aa".repeat(32);
    save_keystore(&ks1, &path)?;
    assert!(path.exists(), "keystore must be written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keystore must be 0o600, got {:o}", mode);
    }

    let mut ks2 = Keystore::default();
    ks2.key_type = "test2".to_string();
    ks2.algo = "schnorr".to_string();
    ks2.pub_hex = "bb".repeat(32);
    save_keystore(&ks2, &path)?;

    let raw = std::fs::read_to_string(&path)?;
    assert!(
        raw.contains("pub_hex") && raw.contains("bbbb"),
        "expected updated keystore contents"
    );

    // No leftover temp files from atomic write.
    for e in std::fs::read_dir(td.path())? {
        let p = e?.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert!(
            !name.ends_with(".tmp"),
            "atomic write must not leave tmp files behind: {}",
            p.display()
        );
    }
    Ok(())
}

#[test]
fn f30_seedstore_and_xpubstore_use_atomic_secure_write() -> Result<()> {
    let td = tempfile::tempdir()?;
    let seed_path = td.path().join("seed.toml");
    let xpub_path = td.path().join("xpub.toml");

    let mnemonic = Mnemonic::parse_in(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )?;
    save_seed_store_encrypted(&mnemonic, &seed_path, "test-passphrase", false)?;
    assert!(seed_path.exists(), "seed store must be written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&seed_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "seed store must be 0o600, got {:o}", mode);
    }

    let xs = XpubStore {
        version: 1,
        kind: "xpub".to_string(),
        algo: "schnorr".to_string(),
        xpub: "xpub-test".to_string(),
        derivation: "m/86'/12345'/0'".to_string(),
        fingerprint: None,
        hrp: "pc".to_string(),
    };
    save_xpub_store_with_passphrase(&xs, &xpub_path, "test-passphrase", false)?;
    assert!(xpub_path.exists(), "xpub store must be written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&xpub_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "xpub store must be 0o600, got {:o}", mode);
    }

    // No leftover temp files from atomic write.
    for e in std::fs::read_dir(td.path())? {
        let p = e?.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert!(
            !name.ends_with(".tmp"),
            "atomic write must not leave tmp files behind: {}",
            p.display()
        );
    }
    Ok(())
}

#[test]
fn f31_xpubstore_legacy_migration_creates_backup_before_overwrite() {
    let src = read_signer_source("keystore.rs");

    let i_copy = src
        .find("fs::copy(path, &backup_path)")
        .expect("migration must create .bak via fs::copy");
    let i_write = src[i_copy..]
        .find("write_file_atomic_secure(path, data.as_bytes())")
        .map(|idx| i_copy + idx)
        .expect("migration must atomically overwrite xpubstore");
    assert!(
        i_copy < i_write,
        "backup must be created before overwrite (copy index {i_copy} < write index {i_write})"
    );
}

#[test]
fn f32_validate_passphrase_enforces_min_length_and_warns_only() {
    // Too short must be rejected.
    assert!(validate_passphrase("1234567").is_err());
    // Weak-but-long-enough must be accepted (warning only).
    assert!(validate_passphrase("12345678").is_ok());
}

#[test]
fn f33_signer_config_warns_on_plaintext_auth_token() {
    let src = read_signer_source("helpers.rs");
    assert!(
        src.contains("auth_token in TOML-Config ist Klartext"),
        "expected warning for plaintext auth_token in config"
    );
}

#[test]
fn f35_bip39_passphrase_is_always_empty_string() {
    assert!(
        read_signer_source("keystore.rs").contains("mnemonic.to_seed(\"\")"),
        "expected keystore BIP39 passphrase to be the empty string"
    );
    assert!(
        read_signer_source("wallet_ops.rs").contains("mnemonic.to_seed(\"\")"),
        "expected wallet_ops BIP39 passphrase to be the empty string"
    );
}

#[test]
fn f36_payjoin_respond_requires_derivation_paths_for_added_inputs() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("main.rs");
    let src =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert!(
        src.contains("missing --add-paths"),
        "expected PayJoin responder to require --add-paths"
    );
    assert!(
        src.contains("must match number of additional inputs"),
        "expected PayJoin responder to enforce add_paths length"
    );
}

#[test]
fn f37_lock_from_pc_address_accepts_non_pc_hrp() -> Result<()> {
    use bech32::ToBase32 as _;
    let prog = [7u8; 32];
    let mut data = vec![bech32::u5::try_from_u8(1).map_err(|_| anyhow!("u5"))?];
    data.extend_from_slice(&prog.to_base32());
    let addr = bech32::encode("xx", data, bech32::Variant::Bech32m)
        .map_err(|e| anyhow!("bech32 encode: {e}"))?;
    let lock = lock_from_pc_address(&addr)?;
    assert_eq!(lock.0, prog);
    Ok(())
}
