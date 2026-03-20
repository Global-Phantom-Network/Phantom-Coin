// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn f26_hwi_signmessage_rejects_message_starting_with_dash() {
    let td = tempfile::tempdir().expect("tempdir");
    let msg = td.path().join("msg.txt");
    std::fs::write(&msg, "--malicious-flag").expect("write msg file");

    Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"))
        .args([
            "hwi-sign-message",
            "--derivation",
            "m/86'/12345'/0'/0/0",
            "--msg",
            msg.to_string_lossy().as_ref(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Argument-Injection-Schutz"));
}
