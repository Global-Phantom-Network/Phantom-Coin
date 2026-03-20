// SPDX-License-Identifier: AGPL-3.0-only
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn slashdb_put_get_and_equivocation() {
    let td = tempdir().expect("tmpdir");
    let dbdir = td.path().join("sdb");

    // init
    let mut cmd_init = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"));
    cmd_init
        .arg("slash-db-init")
        .arg("--db-dir")
        .arg(&dbdir)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    // get none -> leere Ausgabe (nur newline). Erlaube beliebige Whitespace.
    let mut cmd_get_none = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"));
    cmd_get_none
        .arg("slash-db-get")
        .arg("--db-dir")
        .arg(&dbdir)
        .arg("--epoch")
        .arg("1")
        .arg("--shard")
        .arg("0")
        .arg("--round")
        .arg("7")
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(r"^\s*$")
                .expect("regex pattern for empty/whitespace-only output must compile"),
        );

    // put header
    let header_hex = hex::encode([0x01u8; 32]);
    let mut cmd_put = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"));
    cmd_put
        .arg("slash-db-put")
        .arg("--db-dir")
        .arg(&dbdir)
        .arg("--epoch")
        .arg("1")
        .arg("--shard")
        .arg("0")
        .arg("--round")
        .arg("7")
        .arg("--header-hex")
        .arg(&header_hex)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    // get -> sollte header_hex liefern
    let mut cmd_get_some = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"));
    cmd_get_some
        .arg("slash-db-get")
        .arg("--db-dir")
        .arg(&dbdir)
        .arg("--epoch")
        .arg("1")
        .arg("--shard")
        .arg("0")
        .arg("--round")
        .arg("7")
        .assert()
        .success()
        .stdout(predicate::str::contains(&header_hex));

    // put mit anderem header -> erwartet Fehler (Equivocation)
    let bad_header_hex = hex::encode([0x02u8; 32]);
    let mut cmd_put_bad = Command::new(assert_cmd::cargo::cargo_bin!("phantom-signer"));
    cmd_put_bad
        .arg("slash-db-put")
        .arg("--db-dir")
        .arg(&dbdir)
        .arg("--epoch")
        .arg("1")
        .arg("--shard")
        .arg("0")
        .arg("--round")
        .arg("7")
        .arg("--header-hex")
        .arg(&bad_header_hex)
        .assert()
        .failure();
}
