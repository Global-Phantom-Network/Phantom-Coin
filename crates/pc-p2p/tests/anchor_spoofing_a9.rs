#![cfg(all(feature = "async", feature = "libp2p"))]

use pc_p2p::async_svc::set_bench_mode;
use pc_p2p::messages::{header_response_headers, ReqMsg};
use pc_p2p::{spawn_with_libp2p, Libp2pConfig, P2pConfig};
use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId, ParentList};
use std::net::TcpListener;
use std::sync::OnceLock;
use tokio::time::{timeout, Duration};

static A9_TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn a9_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    A9_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp 0");
    listener.local_addr().expect("local_addr").port()
}

async fn wait_header_present(
    svc: &pc_p2p::async_svc::P2pService,
    id: AnchorId,
    wait: Duration,
) -> bool {
    let res = timeout(wait, async {
        loop {
            let r = svc
                .rpc_call(ReqMsg::GetHeaders { ids: vec![id] })
                .await
                .ok();
            if let Some(resp) = r {
                if let Some(headers) = header_response_headers(&resp) {
                    if headers.iter().any(|h| AnchorId(h.id_digest()) == id) {
                        return true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    matches!(res, Ok(true))
}

fn write_identity_key(path: &std::path::Path, kp: &libp2p::identity::Keypair) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let bytes = kp
        .to_protobuf_encoding()
        .expect("identity protobuf encoding");
    std::fs::write(path, bytes).expect("write identity key");
}

#[tokio::test]
async fn a9_anchor_spoofing_creator_index_is_rejected_when_map_is_set() {
    let _guard = a9_test_lock().await;
    set_bench_mode(true);

    let tmp = tempfile::tempdir().expect("tempdir");
    let port_a = free_tcp_port();

    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let kp_c = libp2p::identity::Keypair::generate_ed25519();

    let id_a = libp2p::PeerId::from(kp_a.public());
    let id_b = libp2p::PeerId::from(kp_b.public());
    let id_c = libp2p::PeerId::from(kp_c.public());

    let path_a = tmp.path().join("id_a.key");
    let path_b = tmp.path().join("id_b.key");
    let path_c = tmp.path().join("id_c.key");

    write_identity_key(&path_a, &kp_a);
    write_identity_key(&path_b, &kp_b);
    write_identity_key(&path_c, &kp_c);

    let creator_map_path = tmp.path().join("creator_peer_map.json");
    let map_json = serde_json::json!({
        "0": id_b.to_string(),
        "1": id_c.to_string()
    });
    std::fs::write(
        &creator_map_path,
        serde_json::to_vec(&map_json).expect("json"),
    )
    .expect("write map");

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
        identity_key_file: Some(path_a.to_string_lossy().to_string()),
        creator_peer_map_file: Some(creator_map_path.to_string_lossy().to_string()),
        enable_peer_scoring: true,
        max_peers_per_ip: None,
        bootstrap_peers: Vec::new(),
        kad_bootstrap_interval_secs: 0,
    };

    let (svc_a, handle_a, swarm_a) =
        spawn_with_libp2p(cfg_service.clone(), cfg_a).expect("spawn lp2p A");

    let cfg_b = Libp2pConfig {
        listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()),
        shards: None,
        strict_validation: true,
        dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
        identity_key_file: Some(path_b.to_string_lossy().to_string()),
        creator_peer_map_file: None,
        enable_peer_scoring: true,
        max_peers_per_ip: None,
        bootstrap_peers: Vec::new(),
        kad_bootstrap_interval_secs: 0,
    };

    let cfg_c = Libp2pConfig {
        listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()),
        shards: None,
        strict_validation: true,
        dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
        identity_key_file: Some(path_c.to_string_lossy().to_string()),
        creator_peer_map_file: None,
        enable_peer_scoring: true,
        max_peers_per_ip: None,
        bootstrap_peers: Vec::new(),
        kad_bootstrap_interval_secs: 0,
    };

    let (svc_b, handle_b, swarm_b) =
        spawn_with_libp2p(cfg_service.clone(), cfg_b).expect("spawn lp2p B");
    let (svc_c, handle_c, swarm_c) =
        spawn_with_libp2p(cfg_service.clone(), cfg_c).expect("spawn lp2p C");

    tokio::time::sleep(Duration::from_millis(900)).await;

    let parents = ParentList::default();

    let hdr_ok = AnchorHeader {
        version: 2,
        shard_id: 0,
        parents: parents.clone(),
        payload_hash: [0x11u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0u8; 32],
        vote_epoch: 0,
        vote_round: 0,
        state_root: None,
        attest_sig: None,
    };

    let ok_id = AnchorId(hdr_ok.id_digest());
    svc_b.announce_header(hdr_ok).await.expect("announce ok");
    let ok_present = wait_header_present(&svc_a, ok_id, Duration::from_secs(3)).await;
    assert!(ok_present);

    let hdr_spoof = AnchorHeader {
        version: 2,
        shard_id: 0,
        parents,
        payload_hash: [0x22u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0u8; 32],
        vote_epoch: 0,
        vote_round: 0,
        state_root: None,
        attest_sig: None,
    };

    let spoof_id = AnchorId(hdr_spoof.id_digest());
    svc_c
        .announce_header(hdr_spoof)
        .await
        .expect("announce spoof");
    let spoof_present = wait_header_present(&svc_a, spoof_id, Duration::from_millis(800)).await;
    assert!(!spoof_present);

    let _ = svc_a.shutdown().await;
    let _ = svc_b.shutdown().await;
    let _ = svc_c.shutdown().await;

    let _ = handle_a.await;
    let _ = handle_b.await;
    let _ = handle_c.await;

    let _ = swarm_a.await;
    let _ = swarm_b.await;
    let _ = swarm_c.await;

    let _ = id_a;

    set_bench_mode(false);
}
