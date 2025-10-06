// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(all(feature = "async", feature = "libp2p"))]

use criterion::{criterion_group, criterion_main, Criterion};
use pc_p2p::messages::{ReqMsg, RespMsg};
use pc_p2p::{spawn_with_libp2p, Libp2pConfig, P2pConfig};
use pc_p2p::async_svc::{set_bench_mode, watch_header, watch_payload};
use pc_types::{payload_merkle_root_v2 as payload_merkle_root, AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV2 as AnchorPayload, ParentList};
use pc_types::{GenesisNote, digest_genesis_note};
use pc_codec::Decodable;
use std::net::TcpListener;
use std::time::{Duration, Instant};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::collections::HashSet;
use tokio::runtime::Runtime;
use tokio::time::timeout;
use std::sync::atomic::{AtomicU64, Ordering};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp 0");
    listener.local_addr().unwrap().port()
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
        if first {
            if let Some(nid_hex) = load_network_id_hex() {
                let _ = writeln!(f, "# network_id={}", nid_hex);
            }
        }
        let _ = writeln!(f, "{}", timeouts);
    }
}

fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(20))
        .warm_up_time(Duration::from_secs(2))
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
    if first_write_for_bench {
        opts.truncate(true);
    } else {
        opts.append(true);
    }
    if let Ok(mut f) = opts.open(path) {
        if first_write_for_bench {
            if let Some(nid_hex) = load_network_id_hex() {
                let _ = writeln!(f, "# network_id={}", nid_hex);
            }
        }
        for v in samples_ns {
            let _ = writeln!(f, "{}", v);
        }
    }
}

fn load_network_id_hex() -> Option<String> {
    // Default-Suchpfad: WorkspaceRoot/pc-data/mempool/genesis_note.bin
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(".."); p.push("..");
    p.push("pc-data"); p.push("mempool"); p.push("genesis_note.bin");
    let buf = std::fs::read(&p).ok()?;
    let mut s = &buf[..];
    let note = GenesisNote::decode(&mut s).ok()?;
    let nid = digest_genesis_note(&note);
    Some(hex::encode(nid))
}

fn bench_libp2p_rpc_get_payloads(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("p2p_libp2p_rpc_get_payloads", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let port_a = free_tcp_port();
            let cfg_lp2p_a = Libp2pConfig {
                listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
                shards: None,
                strict_validation: true,
                dial: None,
            };
            let cfg_lp2p_b = Libp2pConfig {
                listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()),
                shards: None,
                strict_validation: true,
                dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
            };

            let cfg_service = P2pConfig { max_peers: 16, rate: None };
            set_bench_mode(true);
            let (svc_a, svc_a_handle, swarm_a) = spawn_with_libp2p(cfg_service.clone(), cfg_lp2p_a).expect("spawn lp2p A");
            let (svc_b, svc_b_handle, swarm_b) = spawn_with_libp2p(cfg_service.clone(), cfg_lp2p_b).expect("spawn lp2p B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            // Preload Payloads auf A (V2, non-genesis)
            let mut roots: Vec<[u8; 32]> = Vec::with_capacity(iters as usize);
            for i in 0..iters {
                let mut payout_root = [0u8; 32];
                payout_root[..8].copy_from_slice(&i.to_be_bytes());
                let payload = AnchorPayload {
                    version: 2,
                    micro_txs: vec![],
                    mints: vec![],
                    claims: vec![],
                    evidences: vec![],
                    payout_root,
                    genesis_note: None,
                };
                let root = payload_merkle_root(&payload);
                svc_a.put_payload(payload).await.expect("put payload A");
                roots.push(root);
            }

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let root = roots[i];
                let rx = watch_payload(root);
                let t0 = Instant::now();
                let _ = svc_b
                    .send_req(ReqMsg::GetPayloads { roots: vec![root] })
                    .await;

                let ok = timeout(Duration::from_millis(800), async {
                    rx.await.map(|resp| match resp {
                        RespMsg::Payloads { payloads } => payloads.get(0).map(|p| payload_merkle_root(p) == root).unwrap_or(false),
                        _ => false,
                    }).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }
            append_raw("p2p_libp2p_rpc_get_payloads", &samples);
            append_timeouts("p2p_libp2p_rpc_get_payloads", timeouts_cnt);

            let _ = svc_a.shutdown().await;
            let _ = svc_b.shutdown().await;
            let _ = svc_a_handle.await;
            let _ = svc_b_handle.await;
            let _ = swarm_a.await;
            let _ = swarm_b.await;

            total
        })
    });
}

fn bench_libp2p_rpc_get_headers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("p2p_libp2p_rpc_get_headers", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let port_a = free_tcp_port();
            let cfg_lp2p_a = Libp2pConfig {
                listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
                shards: None,
                strict_validation: true,
                dial: None,
            };
            let cfg_lp2p_b = Libp2pConfig {
                listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()),
                shards: None,
                strict_validation: true,
                dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
            };

            let cfg_service = P2pConfig { max_peers: 16, rate: None };
            set_bench_mode(true);
            let (svc_a, svc_a_handle, swarm_a) = spawn_with_libp2p(cfg_service.clone(), cfg_lp2p_a).expect("spawn lp2p A");
            let (svc_b, svc_b_handle, swarm_b) = spawn_with_libp2p(cfg_service.clone(), cfg_lp2p_b).expect("spawn lp2p B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            // Preload Headers auf A (V2, eindeutige IDs pro iter_custom-Aufruf via RUN_COUNTER-Salt)
            let mut ids: Vec<AnchorId> = Vec::with_capacity(iters as usize);
            let run_id = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
            let base: u64 = run_id.saturating_mul(1_000_000);
            for i in 0..iters {
                let parents = ParentList::default();
                let mut ph = [0u8; 32];
                let idx = base.saturating_add(i as u64);
                ph[..8].copy_from_slice(&idx.to_be_bytes());
                let hdr = AnchorHeader {
                    version: 2,
                    shard_id: 0,
                    parents,
                    payload_hash: ph,
                    creator_index: 1,
                    vote_mask: 0,
                    ack_present: false,
                    ack_id: AnchorId(ph),
                    network_id: [0u8; 32],
                };
                svc_a.put_header(hdr.clone()).await.expect("put header A");
                let id = AnchorId(hdr.id_digest());
                ids.push(id);
            }

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let id = ids[i];
                let rx = watch_header(id);
                let t0 = Instant::now();
                let _ = svc_b
                    .send_req(ReqMsg::GetHeaders { ids: vec![id] })
                    .await;

                let ok = timeout(Duration::from_millis(800), async {
                    rx.await.map(|resp| match resp {
                        RespMsg::Headers { headers } => headers.get(0).map(|h| AnchorId(h.id_digest()) == id).unwrap_or(false),
                        _ => false,
                    }).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }
            append_raw("p2p_libp2p_rpc_get_headers", &samples);
            append_timeouts("p2p_libp2p_rpc_get_headers", timeouts_cnt);

            let _ = svc_a.shutdown().await;
            let _ = svc_b.shutdown().await;
            let _ = svc_a_handle.await;
            let _ = svc_b_handle.await;
            let _ = swarm_a.await;
            let _ = swarm_b.await;

            total
        })
    });
}

criterion_group!(
    name = benches;
    config = bench_config();
    targets = bench_libp2p_rpc_get_payloads, bench_libp2p_rpc_get_headers
);
criterion_main!(benches);
