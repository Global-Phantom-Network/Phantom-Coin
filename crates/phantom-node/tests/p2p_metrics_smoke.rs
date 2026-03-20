// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hyper::{Client, StatusCode, Uri};
use pc_p2p::async_svc::OutboundSink;
use pc_p2p::messages::explicit_announce_for_header;
use pc_p2p::quic_transport::{client_config_from_cert, connect, QuicClientSink};
use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId, ParentList};

fn spawn_line_reader<R: std::io::Read + Send + 'static>(r: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(r);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

async fn http_get_text(client: &Client<hyper::client::HttpConnector>, url: &str) -> Option<String> {
    let uri: Uri = url.parse().ok()?;
    match client.get(uri).await {
        Ok(resp) if resp.status() == StatusCode::OK => {
            let bytes = hyper::body::to_bytes(resp.into_body()).await.ok()?;
            Some(String::from_utf8_lossy(&bytes).to_string())
        }
        _ => None,
    }
}

fn metric_value(text: &str, name: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let metric = parts.next()?;
        if metric != name {
            return None;
        }
        parts.next()?.parse::<f64>().ok()
    })
}

fn prevote_header(seed: u8) -> AnchorHeader {
    AnchorHeader {
        version: 4,
        shard_id: 0,
        parents: ParentList::default(),
        payload_hash: [seed; 32],
        creator_index: 0,
        vote_mask: 1,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0x22; 32],
        vote_epoch: 1,
        vote_round: u64::from(seed),
        state_root: None,
        attest_sig: None,
    }
}

#[tokio::test]
async fn p2p_quic_listen_metrics_smoke() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store_dir = tmp.path().to_path_buf();

    let udp_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp ephemeral");
        let p = s.local_addr().expect("udp local_addr").port();
        drop(s);
        p
    };
    let quic_addr = format!("127.0.0.1:{udp_port}");

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let mut child = Command::new(bin)
        .arg("p2p-quic-listen")
        .arg("--addr")
        .arg(&quic_addr)
        .arg("--store-dir")
        .arg(store_dir.to_string_lossy().to_string())
        .arg("--metrics-addr")
        .arg("127.0.0.1:0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node p2p-quic-listen");

    let rx = spawn_line_reader(child.stdout.take().expect("child stdout"));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut metrics_addr: Option<String> = None;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("p2p-quic-listen exited early: {status:?}");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if v.get("type").and_then(|t| t.as_str()) == Some("metrics_serve") {
                        if let Some(addr) = v.get("addr").and_then(|a| a.as_str()) {
                            metrics_addr = Some(addr.to_string());
                            break;
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let metrics_addr = metrics_addr.expect("metrics_serve addr");

    let client: Client<hyper::client::HttpConnector> = Client::new();
    let url = format!("http://{metrics_addr}/metrics");
    let deadline2 = Instant::now() + Duration::from_secs(10);
    let mut text = None;
    while Instant::now() < deadline2 {
        if let Some(t) = http_get_text(&client, &url).await {
            if !t.is_empty() {
                text = Some(t);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let text = text.expect("metrics text");

    // Smoke: verify a few key names that GUI/clients rely on.
    for needle in [
        "pc_p2p_inbound_total",
        "pc_p2p_inbound_bytes_total",
        "pc_p2p_outbox_depth",
        "pc_node_persist_headers_total",
        "pc_node_persist_seconds_bucket",
        "pc_node_process_cpu_percent",
        "pc_node_process_rss_bytes",
        "pc_node_validator_voting_enabled",
        "pc_node_da_gating_cfg_payload_wait_timeout_secs",
    ] {
        assert!(
            text.contains(needle),
            "expected metrics to contain '{needle}', got:\n{text}"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn p2p_quic_listen_rate_limit_smoke() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store_dir = tmp.path().to_path_buf();
    let cert_path = tmp.path().join("p2p.der");

    let udp_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp ephemeral");
        let p = s.local_addr().expect("udp local_addr").port();
        drop(s);
        p
    };
    let quic_addr = format!("127.0.0.1:{udp_port}");

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let mut child = Command::new(bin)
        .arg("p2p-quic-listen")
        .arg("--addr")
        .arg(&quic_addr)
        .arg("--store-dir")
        .arg(store_dir.to_string_lossy().to_string())
        .arg("--metrics-addr")
        .arg("127.0.0.1:0")
        .arg("--cert-out")
        .arg(cert_path.to_string_lossy().to_string())
        .arg("--hdr-capacity")
        .arg("1")
        .arg("--hdr-refill-per-sec")
        .arg("0")
        .arg("--inv-capacity")
        .arg("32")
        .arg("--inv-refill-per-sec")
        .arg("0")
        .arg("--req-capacity")
        .arg("32")
        .arg("--req-refill-per-sec")
        .arg("0")
        .arg("--resp-capacity")
        .arg("32")
        .arg("--resp-refill-per-sec")
        .arg("0")
        .arg("--bytes-capacity")
        .arg("4096")
        .arg("--bytes-refill-per-sec")
        .arg("0")
        .arg("--per-peer")
        .arg("true")
        .arg("--peer-ttl-secs")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node p2p-quic-listen");

    let rx = spawn_line_reader(child.stdout.take().expect("child stdout"));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut metrics_addr: Option<String> = None;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("p2p-quic-listen exited early: {status:?}");
        }
        if cert_path.is_file() && metrics_addr.is_some() {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if v.get("type").and_then(|t| t.as_str()) == Some("metrics_serve") {
                        if let Some(addr) = v.get("addr").and_then(|a| a.as_str()) {
                            metrics_addr = Some(addr.to_string());
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let metrics_addr = metrics_addr.expect("metrics_serve addr");
    assert!(cert_path.is_file(), "missing emitted QUIC cert");

    let cert_der = std::fs::read(&cert_path).expect("read cert");
    let client_cfg = client_config_from_cert(&cert_der).expect("client cfg");
    let conn = connect(
        quic_addr
            .parse::<std::net::SocketAddr>()
            .expect("socket addr"),
        client_cfg,
    )
    .await
    .expect("connect");
    let sink = QuicClientSink::new(conn);

    for seed in 1u8..=12 {
        sink.deliver(explicit_announce_for_header(prevote_header(seed)))
            .await
            .expect("deliver header burst");
    }

    let client: Client<hyper::client::HttpConnector> = Client::new();
    let url = format!("http://{metrics_addr}/metrics");
    let deadline2 = Instant::now() + Duration::from_secs(10);
    let mut text = None;
    while Instant::now() < deadline2 {
        if let Some(t) = http_get_text(&client, &url).await {
            let dropped = metric_value(&t, "pc_p2p_inbound_dropped_rate").unwrap_or_default();
            if dropped >= 1.0 {
                text = Some(t);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let text = text.expect("metrics text with dropped rate");

    let dropped = metric_value(&text, "pc_p2p_inbound_dropped_rate").expect("dropped metric");
    let rss = metric_value(&text, "pc_node_process_rss_bytes").expect("rss metric");
    let outbox_depth = metric_value(&text, "pc_p2p_outbox_depth").expect("outbox depth metric");

    assert!(
        dropped >= 1.0,
        "expected at least one rate-limited inbound message"
    );
    assert!(
        rss < 512.0 * 1024.0 * 1024.0,
        "rss grew unexpectedly under burst: {rss}"
    );
    assert!(
        outbox_depth < 128.0,
        "outbox depth grew unexpectedly under burst: {outbox_depth}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
