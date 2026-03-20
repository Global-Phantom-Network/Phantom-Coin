// SPDX-License-Identifier: AGPL-3.0-only
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn f25_wallet_init_refuses_seed_output_without_tty_on_stderr() {
    // assert_cmd captures stderr (non-TTY). wallet-init must fail fast before any interactive prompts.
    Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"))
        .arg("wallet-init")
        .arg("--wallet-name")
        .arg("f25_tty_test_wallet")
        .arg("--force")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "wallet-init verweigert Seed-Anzeige ohne TTY",
        ));
}
