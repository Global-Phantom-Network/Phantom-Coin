#![cfg(all(feature = "async", feature = "libp2p"))]

use pc_p2p::async_svc::{set_bench_mode, watch_header};
use pc_p2p::messages::{header_response_headers, ReqMsg};
use pc_p2p::{spawn_with_libp2p, Libp2pConfig, P2pConfig};
use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId, ParentList};
use std::net::TcpListener;
use std::sync::OnceLock;
use tokio::time::{timeout, Duration};

static A8_TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn a8_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    A8_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp 0");
    listener.local_addr().expect("local_addr").port()
}

#[tokio::test]
async fn a8_max_peers_per_ip_rejects_second_peer_from_same_ip() {
    let _guard = a8_test_lock().await;
    set_bench_mode(true);

    let port_a = free_tcp_port();

    let cfg_service = P2pConfig {
        max_peers: 32,
        rate: None,
        peers_json_path: None,
        enable_peer_exchange: false,
        network_id: None,
    };

    let cfg_a = Libp2pConfig {
        listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
        shards: None,
        strict_validation: true,
        dial: None,
        enable_peer_scoring: true,
        identity_key_file: None,
        creator_peer_map_file: None,
        max_peers_per_ip: Some(1),
        bootstrap_peers: Vec::new(),
        kad_bootstrap_interval_secs: 0,
    };

    let (svc_a, handle_a, swarm_a) =
        spawn_with_libp2p(cfg_service.clone(), cfg_a).expect("spawn lp2p A");

    let parents = ParentList::default();
    let hdr = AnchorHeader {
        version: 2,
        shard_id: 0,
        parents,
        payload_hash: [0x42u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0u8; 32],
        vote_epoch: 0,
        vote_round: 0,
        state_root: None,
        attest_sig: None,
    };
    let id = AnchorId(hdr.id_digest());
    svc_a.put_header(hdr).await.expect("put header on A");

    let cfg_b = Libp2pConfig {
        listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()),
        shards: None,
        strict_validation: true,
        dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
        enable_peer_scoring: true,
        identity_key_file: None,
        creator_peer_map_file: None,
        max_peers_per_ip: None,
        bootstrap_peers: Vec::new(),
        kad_bootstrap_interval_secs: 0,
    };

    let (svc_b, handle_b, swarm_b) =
        spawn_with_libp2p(cfg_service.clone(), cfg_b).expect("spawn lp2p B");

    tokio::time::sleep(Duration::from_millis(900)).await;

    let rx_b = watch_header(id);
    svc_b
        .send_req(ReqMsg::GetHeaders { ids: vec![id] })
        .await
        .expect("send req from B");

    let resp_b = timeout(Duration::from_secs(3), rx_b)
        .await
        .expect("timeout waiting for B response")
        .expect("watcher recv");
    let headers_b = header_response_headers(&resp_b).expect("header response");
    assert!(headers_b.iter().any(|h| AnchorId(h.id_digest()) == id));

    let cfg_c = Libp2pConfig {
        listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()),
        shards: None,
        strict_validation: true,
        dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
        enable_peer_scoring: true,
        identity_key_file: None,
        creator_peer_map_file: None,
        max_peers_per_ip: None,
        bootstrap_peers: Vec::new(),
        kad_bootstrap_interval_secs: 0,
    };

    let (svc_c, handle_c, swarm_c) =
        spawn_with_libp2p(cfg_service.clone(), cfg_c).expect("spawn lp2p C");

    tokio::time::sleep(Duration::from_millis(900)).await;

    let rx_c = watch_header(id);
    svc_c
        .send_req(ReqMsg::GetHeaders { ids: vec![id] })
        .await
        .expect("send req from C");

    let resp_c = timeout(Duration::from_millis(900), rx_c).await;
    assert!(resp_c.is_err());

    let _ = svc_a.shutdown().await;
    let _ = svc_b.shutdown().await;
    let _ = svc_c.shutdown().await;

    let _ = handle_a.await;
    let _ = handle_b.await;
    let _ = handle_c.await;

    let _ = swarm_a.await;
    let _ = swarm_b.await;
    let _ = swarm_c.await;

    set_bench_mode(false);
}
