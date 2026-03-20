// SPDX-License-Identifier: AGPL-3.0-only
use assert_cmd::prelude::*;
use predicates::str::contains;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn seat_vote_sign_noninteractive_env_ok() {
    let td = tempdir().expect("tmpdir");
    let dbdir = td.path().join("sdb");
    let ks_path = td.path().join("seat.toml");

    let pass_env = "KS_PASS";
    let pass_val = "super-secure-pass";

    // Import Keystore (Schnorr Seat) non-interaktiv via ENV
    let secret_env = "SEAT_SECRET_HEX";
    let secret_hex = hex::encode([0x77u8; 32]);
    let out_import = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"))
        .env(pass_env, pass_val)
        .env(secret_env, &secret_hex)
        .args([
            "import",
            "--type",
            "seat",
            "--algo",
            "schnorr",
            "--secret-env",
            secret_env,
            "--out",
            ks_path.to_str().expect("keystore path must be valid UTF-8"),
            "--passphrase-env",
            pass_env,
        ])
        .output()
        .expect("run import");
    assert!(
        out_import.status.success(),
        "import stderr: {}",
        String::from_utf8_lossy(&out_import.stderr)
    );

    // Slashing-DB init (kebab-case)
    Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"))
        .args([
            "slash-db-init",
            "--db-dir",
            dbdir.to_str().expect("db dir must be valid UTF-8"),
        ])
        .assert()
        .success()
        .stdout(contains("OK"));

    let epoch = 1u64;
    let shard = 0u16;
    let round = 7u64;
    let header_hex = hex::encode([0x11u8; 32]);

    // seat-vote-sign non-interaktiv
    let out_sign = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"))
        .env(pass_env, pass_val)
        .args([
            "seat-vote-sign",
            "--db-dir",
            dbdir.to_str().expect("db dir must be valid UTF-8"),
            "--epoch",
            &epoch.to_string(),
            "--shard",
            &shard.to_string(),
            "--round",
            &round.to_string(),
            "--header-hex",
            &header_hex,
            "--keystore",
            ks_path.to_str().expect("keystore path must be valid UTF-8"),
            "--passphrase-env",
            pass_env,
        ])
        .output()
        .expect("run seat-vote-sign");
    assert!(
        out_sign.status.success(),
        "sign stderr: {}",
        String::from_utf8_lossy(&out_sign.stderr)
    );
    let sig_hex = String::from_utf8_lossy(&out_sign.stdout).trim().to_string();
    assert_eq!(
        hex::decode(&sig_hex)
            .expect("signature hex must decode to bytes")
            .len(),
        64
    );

    // export-pub lesen (xonly hex)
    let out_pub = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"))
        .args([
            "export-pub",
            "--keystore",
            ks_path.to_str().expect("keystore path must be valid UTF-8"),
        ])
        .output()
        .expect("run export-pub");
    assert!(
        out_pub.status.success(),
        "export-pub stderr: {}",
        String::from_utf8_lossy(&out_pub.stderr)
    );
    let pub_hex = String::from_utf8_lossy(&out_pub.stdout).trim().to_string();

    // verify OK
    Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"))
        .args([
            "seat-vote-verify",
            "--epoch",
            &epoch.to_string(),
            "--shard",
            &shard.to_string(),
            "--round",
            &round.to_string(),
            "--header-hex",
            &header_hex,
            "--pub-hex",
            &pub_hex,
            "--sig-hex",
            &sig_hex,
        ])
        .assert()
        .success()
        .stdout(contains("OK"));
}
