// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn a1_status_serve_rejects_relative_mempool_dir_without_unsafe_confirm() {
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let out = Command::new(bin)
        .arg("status-serve")
        .arg("--addr")
        .arg("127.0.0.1:0")
        .arg("--mempool-dir")
        .arg("relative-mempool")
        .output()
        .expect("run phantom-node status-serve");

    assert!(!out.status.success(), "process must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mempool_dir muss ein absoluter Pfad sein"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn a1_status_serve_rejects_relative_tls_paths_without_unsafe_confirm() {
    let td = tempfile::tempdir().expect("tempdir");
    let mempool_dir = td.path().join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let out = Command::new(bin)
        .arg("status-serve")
        .arg("--addr")
        .arg("127.0.0.1:0")
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .arg("--tls-cert")
        .arg("relative-tls/server.crt")
        .arg("--tls-key")
        .arg("relative-tls/server.key")
        .output()
        .expect("run phantom-node status-serve");

    assert!(!out.status.success(), "process must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tls_cert muss ein absoluter Pfad sein")
            || stderr.contains("tls_key muss ein absoluter Pfad sein"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn a1_p2p_quic_listen_rejects_relative_store_dir_without_unsafe_confirm() {
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let out = Command::new(bin)
        .arg("p2p-quic-listen")
        .arg("--addr")
        .arg("127.0.0.1:0")
        .arg("--store-dir")
        .arg("relative-store")
        .output()
        .expect("run phantom-node p2p-quic-listen");

    assert!(!out.status.success(), "process must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("store_dir muss ein absoluter Pfad sein"),
        "unexpected stderr: {stderr}"
    );
}
