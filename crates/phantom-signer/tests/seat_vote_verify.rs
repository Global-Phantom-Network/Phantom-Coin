// SPDX-License-Identifier: AGPL-3.0-only
use assert_cmd::prelude::*;
use predicates::str::contains;
use std::process::Command;

use pc_crypto::{blake3_32, schnorr, Hash32};

fn canon_msg(epoch: u64, shard: u16, round: u64, header: [u8; 32]) -> Vec<u8> {
    const DOMAIN: &[u8] = b"pc:vote:seat:v1\x01";
    let mut msg = Vec::with_capacity(DOMAIN.len() + 8 + 2 + 8 + 32);
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&shard.to_le_bytes());
    msg.extend_from_slice(&round.to_le_bytes());
    msg.extend_from_slice(&header);
    msg
}

#[test]
fn seat_vote_verify_ok_and_fail() {
    // Testvektoren
    let epoch: u64 = 1;
    let shard: u16 = 2;
    let round: u64 = 3;
    let header = [0x11u8; 32];

    // Deterministischer Secret (nur für Test)
    let sec = [0x77u8; 32];
    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec).expect("schnorr kp");
    let pub_xonly_hex = hex::encode(kp.public_xonly_bytes());

    let msg = canon_msg(epoch, shard, round, header);
    let digest: Hash32 = blake3_32(&msg);
    let sig = schnorr::schnorr_sign(&digest, &kp);
    let sig_hex = hex::encode(sig);

    let header_hex = hex::encode(header);

    // OK-Fall
    let mut cmd_ok = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"));
    cmd_ok
        .arg("seat-vote-verify")
        .arg("--epoch")
        .arg(epoch.to_string())
        .arg("--shard")
        .arg(shard.to_string())
        .arg("--round")
        .arg(round.to_string())
        .arg("--header-hex")
        .arg(&header_hex)
        .arg("--pub-hex")
        .arg(&pub_xonly_hex)
        .arg("--sig-hex")
        .arg(&sig_hex)
        .assert()
        .success()
        .stdout(contains("OK"));

    // FAIL-Fall: header-id ändern
    let bad_header_hex = hex::encode([0x22u8; 32]);
    let mut cmd_fail = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"));
    cmd_fail
        .arg("seat-vote-verify")
        .arg("--epoch")
        .arg(epoch.to_string())
        .arg("--shard")
        .arg(shard.to_string())
        .arg("--round")
        .arg(round.to_string())
        .arg("--header-hex")
        .arg(&bad_header_hex)
        .arg("--pub-hex")
        .arg(&pub_xonly_hex)
        .arg("--sig-hex")
        .arg(&sig_hex)
        .assert()
        .success()
        .stdout(contains("FAIL"));
}
