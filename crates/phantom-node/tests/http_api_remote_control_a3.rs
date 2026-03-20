// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::header::HOST;
use reqwest::Client;

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_http_a3_{}_{}", prefix, nanos))
}

#[tokio::test]
async fn a3_http_api_rejects_unauthorized_and_ignores_host_header() {
    let base = unique_tmp("e2e");
    let _ = std::fs::create_dir_all(&base);
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let p = l
            .local_addr()
            .expect("local_addr for ephemeral bind")
            .port();
        drop(l);
        p
    };
    let addr = format!("127.0.0.1:{}", port);

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let mut child = Command::new(bin)
        .arg("status-serve")
        .arg("--addr")
        .arg(addr.clone())
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .arg("--require-auth")
        .arg("--auth-token")
        .arg("test-token")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest client");

    async fn wait_ready(client: &Client, addr: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if Instant::now() > deadline {
                return false;
            }
            let url = format!("http://{}/readyz", addr);
            match client.get(url).send().await {
                Ok(resp) if resp.status().is_success() => return true,
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            panic!("server not ready in time");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("status-serve exited early: {:?}", status);
        }
        if wait_ready(&client, &addr, 1).await {
            break;
        }
    }

    let url_submit = format!("http://{}/mint/submit", addr);
    let resp = client
        .post(url_submit)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("/mint/submit resp");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let url_ready = format!("http://{}/readyz", addr);
    let resp = client
        .get(url_ready)
        .header(HOST, "evil.example")
        .send()
        .await
        .expect("/readyz bad host resp");
    assert!(resp.status().is_success());

    let _ = child.kill();
    let _ = child.wait();
}
