// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::Command;

fn cfg_base(addr: &str, mempool_dir: &str) -> String {
    format!(
        "addr = \"{}\"\n\
         mempool_dir = \"{}\"\n\
         fsync = true\n\
         require_auth = true\n",
        addr, mempool_dir
    )
}

#[test]
fn a10_rejects_config_without_version() {
    let td = tempfile::tempdir().expect("tempdir");
    let mempool_dir = td.path().join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    let addr = "127.0.0.1:0";
    let cfg_path = td.path().join("node.toml");
    let cfg = cfg_base(addr, &mempool_dir.to_string_lossy());
    std::fs::write(&cfg_path, cfg).expect("write config");

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let out = Command::new(bin)
        .arg("status-serve")
        .arg("--config")
        .arg(cfg_path.to_string_lossy().to_string())
        .output()
        .expect("run phantom-node");

    assert!(!out.status.success(), "process must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("config_version") || stderr.contains("parse config"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn a10_rejects_unknown_legacy_fields_like_tls_disabled() {
    let td = tempfile::tempdir().expect("tempdir");
    let mempool_dir = td.path().join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    let addr = "127.0.0.1:0";
    let cfg_path = td.path().join("node.toml");

    let mut cfg = String::new();
    cfg.push_str("config_version = 1\n");
    cfg.push_str("tls_disabled = true\n");
    cfg.push_str(&cfg_base(addr, &mempool_dir.to_string_lossy()));

    std::fs::write(&cfg_path, cfg).expect("write config");

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let out = Command::new(bin)
        .arg("status-serve")
        .arg("--config")
        .arg(cfg_path.to_string_lossy().to_string())
        .output()
        .expect("run phantom-node");

    assert!(!out.status.success(), "process must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tls_disabled")
            || stderr.contains("unknown field")
            || stderr.contains("parse config"),
        "unexpected stderr: {stderr}"
    );
}
