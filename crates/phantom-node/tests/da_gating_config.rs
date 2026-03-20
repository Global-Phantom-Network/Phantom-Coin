// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hyper::{Body, Client, Method, Request, StatusCode, Uri};

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_da_cfg_{}_{}", prefix, nanos))
}

#[tokio::test]
async fn config_da_gating_is_exposed() {
    // Temporary directories.
    // Temp-Verzeichnisse
    let base = unique_tmp("e2e");
    let _ = std::fs::create_dir_all(&base);
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // Choose a free port via ephemeral bind.
    // Wähle freien Port per Ephemeral-Bind
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

    // Config file with DA-gating values.
    // Config-Datei mit DA-Gating Werten
    let cfg_path = base.join("node.toml");
    let cfg = format!(
        r#"config_version = 1
           addr = "{addr}"
           mempool_dir = "{mempool}"
           fsync = true
           require_auth = false

           [consensus]
           k = 21

           [consensus.da_gating]
           payload_wait_timeout_secs = 3
           retry_initial_delay_ms = 100
           retry_max_delay_ms = 300
           retry_max_retries = 2
           retry_jitter_pct = 12
        "#,
        addr = addr,
        mempool = mempool_dir.to_string_lossy(),
    );
    std::fs::write(&cfg_path, cfg).expect("write config");

    // Start server.
    // Server starten
    let client: Client<hyper::client::HttpConnector> = Client::new();
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let mut child = Command::new(bin)
        .arg("status-serve")
        // Running status-serve without auth is intentionally gated and requires explicit confirmation.
        .arg("--unsafe-confirm")
        .arg("--config")
        .arg(cfg_path.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");

    // Wait for readiness.
    // Readiness abwarten
    async fn wait_ready(
        client: &Client<hyper::client::HttpConnector>,
        addr: &str,
        secs: u64,
    ) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if Instant::now() > deadline {
                return false;
            }
            let uri: Uri = format!("http://{}/readyz", addr)
                .parse()
                .expect("parse /readyz uri");
            match client.get(uri).await {
                Ok(resp) if resp.status() == StatusCode::OK => return true,
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

    // GET /consensus/config
    let uri_cfg: Uri = format!("http://{}/consensus/config", addr)
        .parse()
        .expect("parse /consensus/config uri");
    let req_cfg = Request::builder()
        .method(Method::GET)
        .uri(uri_cfg)
        .body(Body::empty())
        .expect("build /consensus/config request");
    let resp = client
        .request(req_cfg)
        .await
        .expect("/consensus/config resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = hyper::body::to_bytes(resp.into_body())
        .await
        .expect("read body");
    let v: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");

    // Check DA-gating fields and defaults.
    // Prüfe DA-Gating Felder und Defaults
    let da = v.get("da_gating").expect("da_gating field");
    assert_eq!(
        da.get("payload_wait_timeout_secs")
            .expect("payload_wait_timeout_secs")
            .as_u64()
            .expect("payload_wait_timeout_secs as u64"),
        3
    );
    assert_eq!(
        da.get("retry_initial_delay_ms")
            .expect("retry_initial_delay_ms")
            .as_u64()
            .expect("retry_initial_delay_ms as u64"),
        100
    );
    assert_eq!(
        da.get("retry_max_delay_ms")
            .expect("retry_max_delay_ms")
            .as_u64()
            .expect("retry_max_delay_ms as u64"),
        300
    );
    assert_eq!(
        da.get("retry_max_retries")
            .expect("retry_max_retries")
            .as_u64()
            .expect("retry_max_retries as u64"),
        2
    );
    assert_eq!(
        da.get("retry_jitter_pct")
            .expect("retry_jitter_pct")
            .as_u64()
            .expect("retry_jitter_pct as u64"),
        12
    );

    // Cleanup
    let _ = child.kill();
    let _ = child.wait();
}
