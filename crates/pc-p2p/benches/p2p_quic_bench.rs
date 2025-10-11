// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(all(feature = "async", feature = "quic"))]

use criterion::{criterion_group, criterion_main, Criterion};
use pc_p2p::async_svc::{self, set_bench_mode, watch_header, watch_payload, OutboundSink};
use pc_p2p::messages::{ReqMsg, RespMsg};
use pc_p2p::P2pConfig;
use pc_types::{payload_merkle_root_v2 as payload_merkle_root, AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV2 as AnchorPayload, MicroTx, TxOut, LockCommitment, ParentList};
use std::net::{TcpListener, SocketAddr};
use std::time::{Duration, Instant};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::collections::HashSet;
use tokio::runtime::Runtime;
use tokio::time::timeout;

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp 0");
    listener.local_addr().unwrap().port()
}

// QUIC Warm-Start: A-Server (QUIC), B-Client (QUIC). RR GetPayloads warm.
fn bench_quic_rpc_warm_get_payloads(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_quic_rpc_warm_get_payloads", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            // Services
            let cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, mut out_a, h_a) = async_svc::spawn(cfg.clone());
            let (svc_b, mut out_b, h_b) = async_svc::spawn(cfg.clone());

            // QUIC Server (A)
            let port = free_tcp_port();
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
            let (endpoint, cert_der, h_srv, tx_srv) = pc_p2p::quic_transport::start_server(addr, svc_a.clone())
                .await
                .expect("start quic server");

            // Forward Outbox A → QUIC Broadcast
            let fwd_a = tokio::spawn(async move {
                while let Some(msg) = out_a.recv().await {
                    let _ = tx_srv.send(msg).await;
                }
            });

            // QUIC Client (B)
            let client_cfg = pc_p2p::quic_transport::client_config_from_cert(&cert_der).expect("client cfg");
            let conn = pc_p2p::quic_transport::connect(endpoint.local_addr().unwrap(), client_cfg)
                .await
                .expect("quic connect");
            // Inbound Reader: QUIC → svc_b
            let _r_b = pc_p2p::quic_transport::spawn_client_reader(conn.clone(), svc_b.clone());
            // Forward Outbox B → QUIC to A
            let sink_b = pc_p2p::quic_transport::QuicClientSink::new(conn.clone());
            let fwd_b = tokio::spawn(async move {
                while let Some(msg) = out_b.recv().await {
                    let _ = sink_b.deliver(msg).await;
                }
            });

            tokio::time::sleep(Duration::from_millis(800)).await;

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                // Payload auf A vorbereiten
                let micro_txs = vec![MicroTx { version: 1, inputs: vec![], outputs: vec![TxOut { amount: (i as u64) + 1, lock: LockCommitment([i as u8; 32]) }] }];
                let payload = AnchorPayload { version: 2, micro_txs, mints: vec![], claims: vec![], evidences: vec![], payout_root: [0u8; 32], genesis_note: None };
                let root = payload_merkle_root(&payload);
                svc_a.put_payload(payload).await.expect("put payload A");

                let rx = watch_payload(root);
                let t0 = Instant::now();
                let _ = svc_b.send_req(ReqMsg::GetPayloads { roots: vec![root] }).await;
                let ok = timeout(Duration::from_millis(1500), async {
                    rx.await.map(|resp| matches!(resp, RespMsg::Payloads { .. })).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            // Rohdaten/Timeouts persistieren
            append_raw("p2p_quic_rpc_warm_get_payloads", &samples);
            append_timeouts("p2p_quic_rpc_warm_get_payloads", timeouts_cnt);

            // Cleanup: QUIC sauber schließen und Tasks beenden
            endpoint.close(0u32.into(), b"bench shutdown");
            let _ = fwd_b.abort();
            let _ = fwd_a.abort();
            let _ = h_srv.abort();
            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await;
            let _ = h_b.await; let _ = h_a.await;
            total
        })
    });
}

fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(20))
        .warm_up_time(Duration::from_secs(2))
}

// QUIC Warm-Start: A-Server (QUIC), B-Client (QUIC). RR GetHeaders warm.
fn bench_quic_rpc_warm_get_headers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_quic_rpc_warm_get_headers", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            // Services
            let cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, mut out_a, h_a) = async_svc::spawn(cfg.clone());
            let (svc_b, mut out_b, h_b) = async_svc::spawn(cfg.clone());

            // QUIC Server (A)
            let port = free_tcp_port();
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
            let (endpoint, cert_der, h_srv, tx_srv) = pc_p2p::quic_transport::start_server(addr, svc_a.clone())
                .await
                .expect("start quic server");

            // Forward Outbox A → QUIC Broadcast
            let fwd_a = tokio::spawn(async move {
                while let Some(msg) = out_a.recv().await {
                    let _ = tx_srv.send(msg).await;
                }
            });

            // QUIC Client (B)
            let client_cfg = pc_p2p::quic_transport::client_config_from_cert(&cert_der).expect("client cfg");
            let conn = pc_p2p::quic_transport::connect(endpoint.local_addr().unwrap(), client_cfg)
                .await
                .expect("quic connect");
            // Inbound Reader: QUIC → svc_b
            let _r_b = pc_p2p::quic_transport::spawn_client_reader(conn.clone(), svc_b.clone());
            // Forward Outbox B → QUIC to A
            let sink_b = pc_p2p::quic_transport::QuicClientSink::new(conn.clone());
            let fwd_b = tokio::spawn(async move {
                while let Some(msg) = out_b.recv().await {
                    let _ = sink_b.deliver(msg).await;
                }
            });

            tokio::time::sleep(Duration::from_millis(800)).await;

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                // Header auf A vorbereiten
                let parents = ParentList::default();
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                svc_a.put_header(hdr.clone()).await.expect("put header A");
                let id = AnchorId(hdr.id_digest());

                let rx = watch_header(id);
                let t0 = Instant::now();
                let _ = svc_b.send_req(ReqMsg::GetHeaders { ids: vec![id] }).await;
                let ok = timeout(Duration::from_millis(1500), async {
                    rx.await.map(|resp| matches!(resp, RespMsg::Headers { .. })).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            // Rohdaten/Timeouts persistieren
            append_raw("p2p_quic_rpc_warm_get_headers", &samples);
            append_timeouts("p2p_quic_rpc_warm_get_headers", timeouts_cnt);

            // Cleanup: QUIC sauber schließen und Tasks beenden, um Hänger zu vermeiden
            endpoint.close(0u32.into(), b"bench shutdown");
            // Forwarder zuerst abbrechen (verhindert Backpressure)
            let _ = fwd_b.abort();
            let _ = fwd_a.abort();
            // Server-Accept-Task nicht awaiten (läuft sonst weiter, da ep_clone im Task lebt)
            let _ = h_srv.abort();
            // Services herunterfahren und JoinHandles einsammeln
            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await;
            let _ = h_b.await; let _ = h_a.await;
            total
        })
    });
}

fn append_timeouts(bench: &str, timeouts: u64) {
    static TIMEOUT_WRITTEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let set = TIMEOUT_WRITTEN.get_or_init(|| Mutex::new(HashSet::new()));

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("target");
    path.push("criterion_raw");
    let _ = std::fs::create_dir_all(&path);
    path.push(format!("{}_timeouts.txt", bench));

    let mut opts = OpenOptions::new();
    opts.create(true).write(true);
    let first = {
        let mut guard = set.lock().expect("lock TIMEOUT_WRITTEN");
        guard.insert(bench.to_string())
    };
    if first { opts.truncate(true); } else { opts.append(true); }
    if let Ok(mut f) = opts.open(path) {
        let _ = writeln!(f, "{}", timeouts);
    }
}

fn append_raw(bench: &str, samples_ns: &[u128]) {
    static WRITTEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let set = WRITTEN.get_or_init(|| Mutex::new(HashSet::new()));

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Gehe zwei Ebenen nach oben zum Workspace-Root
    path.push("..");
    path.push("..");
    path.push("target");
    path.push("criterion_raw");
    let _ = std::fs::create_dir_all(&path);
    path.push(format!("{}.csv", bench));

    let mut opts = OpenOptions::new();
    opts.create(true).write(true);
    let first_write_for_bench = {
        let mut guard = set.lock().expect("lock WRITTEN");
        guard.insert(bench.to_string())
    };
    if first_write_for_bench { opts.truncate(true); } else { opts.append(true); }
    if let Ok(mut f) = opts.open(path) {
        for v in samples_ns { let _ = writeln!(f, "{}", v); }
    }
}

criterion_group!(
    name = benches_quic;
    config = bench_config();
    targets = bench_quic_rpc_warm_get_headers, bench_quic_rpc_warm_get_payloads
);
criterion_main!(benches_quic);
