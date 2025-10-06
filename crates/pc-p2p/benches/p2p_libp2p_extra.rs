// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(all(feature = "async", feature = "libp2p"))]

use criterion::{criterion_group, criterion_main, Criterion};
use futures::future::join_all;
use pc_p2p::async_svc::{set_bench_mode, watch_header, watch_payload, inbound_subscribe};
use pc_p2p::messages::{P2pMessage, RespMsg, ReqMsg};
use pc_p2p::{spawn_with_libp2p, Libp2pConfig, P2pConfig};
use pc_types::{payload_merkle_root_v2 as payload_merkle_root, AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV2 as AnchorPayload, ParentList};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::time::timeout;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::collections::HashSet;

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp 0");
    listener.local_addr().unwrap().port()
}

// A/B: HeaderAnnounce mit Heartbeat 1s (bench_mode=false)
fn bench_header_announce_gossip_hb_1s(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_header_announce_gossip_hb_1s", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            // bench_mode(false) → gossipsub heartbeat 1s
            set_bench_mode(false);
            let port_a = free_tcp_port();
            let shards = Some(vec![0u8]);
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: shards.clone(), strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(600)).await; // mehr Zeit bis erste Gossip-Runde

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let parents = ParentList::default();
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                let id = AnchorId(hdr.id_digest());
                let t0 = Instant::now();
                let _ = svc_a.announce_header(hdr).await;
                let ok = timeout(Duration::from_millis(3000), async {
                    loop {
                        if let Ok(RespMsg::Headers { headers }) = svc_b.rpc_call(ReqMsg::GetHeaders { ids: vec![id] }).await {
                            if !headers.is_empty() { return true; }
                        }
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_header_announce_gossip_hb_1s", &samples);
            append_timeouts("p2p_header_announce_gossip_hb_1s", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

// A/B: HeaderAnnounce mit strict_validation=false (relaxed)
fn bench_header_announce_gossip_relaxed(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_header_announce_gossip_relaxed", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let shards = Some(vec![0u8]);
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: shards.clone(), strict_validation: false, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards, strict_validation: false, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let parents = ParentList::default();
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                let id = AnchorId(hdr.id_digest());
                let t0 = Instant::now();
                let _ = svc_a.announce_header(hdr).await;
                let ok = timeout(Duration::from_millis(1500), async {
                    loop {
                        if let Ok(RespMsg::Headers { headers }) = svc_b.rpc_call(ReqMsg::GetHeaders { ids: vec![id] }).await {
                            if !headers.is_empty() { return true; }
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_header_announce_gossip_relaxed", &samples);
            append_timeouts("p2p_header_announce_gossip_relaxed", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

// 10) Retry-Pfad (RPC GetHeaders): erster Peer fällt aus → OutboundFailure → Retry zu zweitem Peer
fn bench_rpc_retry_get_headers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_rpc_retry_get_headers", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            // B lauscht, A_bad und A_good wählen B
            let port_b = free_tcp_port();
            let cfg_b = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_b)), shards: None, strict_validation: true, dial: None };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                // A_bad: verbindet zu B, liefert keine Daten (wird beendet)
                let cfg_bad = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_b)) };
                let (svc_bad, h_bad, sw_bad) = spawn_with_libp2p(svc_cfg.clone(), cfg_bad).expect("spawn bad");
                tokio::time::sleep(Duration::from_millis(200)).await;

                // Header vorbereiten (kommt erst mit A_good)
                let parents = ParentList::default();
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                let id = AnchorId(hdr.id_digest());

                let rx = watch_header(id);
                let t0 = Instant::now();
                // B sendet RR an irgendeinen Peer (zunächst nur A_bad verbunden)
                let _ = svc_b.send_req(ReqMsg::GetHeaders { ids: vec![id] }).await;
                // Erzwinge OutboundFailure: beende A_bad kurz nach SendReq
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = svc_bad.shutdown().await; let _ = h_bad.await; let _ = sw_bad.await;

                // A_good verbinden (hat Header)
                let cfg_good = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_b)) };
                let (svc_good, h_good, sw_good) = spawn_with_libp2p(svc_cfg.clone(), cfg_good).expect("spawn good");
                svc_good.put_header(hdr.clone()).await.expect("put header good");

                // Warte auf Antwort nach Retry (Timeout leicht > rr::request_timeout)
                let ok = timeout(Duration::from_millis(2500), async {
                    rx.await.map(|resp| matches!(resp, RespMsg::Headers { .. })).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;

                let _ = svc_good.shutdown().await; let _ = h_good.await; let _ = sw_good.await;
            }

            append_raw("p2p_rpc_retry_get_headers", &samples);
            append_timeouts("p2p_rpc_retry_get_headers", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = h_b.await; let _ = sw_b.await;
            total
        })
    });
}

// 9) Payload-Größe: Einfluss auf RPC GetPayloads (2KB, 8KB, 32KB, 128KB)
fn bench_rpc_payload_size_sweep(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_rpc_payload_size_sweep", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Zielgrößen (ungefähr) über Anzahl MicroTx (≈64B pro Tx grob geschätzt)
            let sizes_bytes = [2usize*1024, 8*1024, 32*1024, 128*1024];
            let counts: Vec<usize> = sizes_bytes.iter().map(|s| (*s / 64).max(1)).collect();

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for it in 0..iters as usize {
                let idx = it % counts.len();
                let n = counts[idx];
                // Payload mit n MicroTx erzeugen
                let mut micro_txs = Vec::with_capacity(n);
                for k in 0..n {
                    let lock = [((k as u8).wrapping_add(it as u8)); 32];
                    let tx = pc_types::MicroTx { version: 1, inputs: vec![], outputs: vec![pc_types::TxOut { amount: (k as u64)+1, lock: pc_types::LockCommitment(lock) }] };
                    micro_txs.push(tx);
                }
                let payload = AnchorPayload { version: 2, micro_txs, mints: vec![], claims: vec![], evidences: vec![], payout_root: [0u8; 32], genesis_note: None };
                let root = payload_merkle_root(&payload);
                svc_a.put_payload(payload).await.expect("put payload A");

                let rx = watch_payload(root);
                let t0 = Instant::now();
                let _ = svc_b.send_req(ReqMsg::GetPayloads { roots: vec![root] }).await;
                let ok = timeout(Duration::from_millis(2000), async {
                    rx.await.map(|resp| match resp { RespMsg::Payloads { payloads } => payloads.get(0).map(|p| payload_merkle_root(p) == root).unwrap_or(false), _ => false }).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_rpc_payload_size_sweep", &samples);
            append_timeouts("p2p_rpc_payload_size_sweep", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

// 7) Cold-Start: Zeit von Spawn (inkl. Dial) bis erster erfolgreicher GetHeaders-RPC
fn bench_rpc_cold_start_get_headers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_rpc_cold_start_get_headers", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let port_a = free_tcp_port();
                let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
                let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
                let svc_cfg = P2pConfig { max_peers: 16, rate: None };
                let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
                // Header auf A vorbereiten
                let parents = ParentList::default();
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                svc_a.put_header(hdr.clone()).await.expect("put header A");
                let id = AnchorId(hdr.id_digest());

                // Startzeit vor Spawn von B, um Dial/Handshake + erste RR zu messen
                let t0 = Instant::now();
                let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
                // Sende direkte RR-Anfrage von B → A und warte via OneShot-Watcher
                let rx = watch_header(id);
                let _ = svc_b.send_req(ReqMsg::GetHeaders { ids: vec![id] }).await;
                let ok = timeout(Duration::from_millis(3000), async {
                    rx.await.map(|resp| matches!(resp, RespMsg::Headers { .. })).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;

                let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            }
            append_raw("p2p_rpc_cold_start_get_headers", &samples);
            append_timeouts("p2p_rpc_cold_start_get_headers", timeouts_cnt);
            total
        })
    });
}

// 8) Warm-Start: Verbindung steht, wiederholte GetHeaders-RPCs (Watchers für sauberes Timing)
fn bench_rpc_warm_start_get_headers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_rpc_warm_start_get_headers", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(500)).await; // Verbindung stabilisieren

            // Header preloaden auf A
            let mut ids: Vec<AnchorId> = Vec::with_capacity(iters as usize);
            for i in 0..iters {
                let parents = ParentList::default();
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&i.to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                svc_a.put_header(hdr.clone()).await.expect("put header A");
                ids.push(AnchorId(hdr.id_digest()));
            }

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let id = ids[i];
                let rx = watch_header(id);
                let t0 = Instant::now();
                let _ = svc_b.send_req(ReqMsg::GetHeaders { ids: vec![id] }).await;
                let ok = timeout(Duration::from_millis(800), async {
                    rx.await.map(|resp| matches!(resp, RespMsg::Headers { .. })).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_rpc_warm_start_get_headers", &samples);
            append_timeouts("p2p_rpc_warm_start_get_headers", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

// 6) Dedupe-TTL: Mehrfache PayloadInv auf denselben Root innerhalb der TTL → nur 1× GetPayloads-REQ
fn bench_dedupe_ttl_payload_inv(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_dedupe_ttl_payload_inv", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                // Root, der NICHT auf A vorhanden ist
                let mut root = [0u8; 32]; root[..8].copy_from_slice(&(i as u64).to_be_bytes());
                // N-mal PayloadInv publizieren (innerhalb der TTL)
                let n_pubs = 5usize;
                let mut rx_in_a = inbound_subscribe();

                let t0 = Instant::now();
                // Publizieren in Task, um parallel REQs mitzulesen
                let svc_a_cl = svc_a.clone();
                let root_cl = root;
                let pub_task = tokio::spawn(async move {
                    for _ in 0..n_pubs {
                        let _ = svc_a_cl.publish_payload_inv(vec![root_cl]).await;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });

                // Zähle GetPayloads-REQs an A für root
                let mut req_count = 0u32;
                let _ = timeout(Duration::from_millis(1200), async {
                    loop {
                        if let Ok(msg) = rx_in_a.recv().await {
                            if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg {
                                if roots.iter().any(|r| *r == root) {
                                    req_count += 1;
                                }
                            }
                        } else { break; }
                        if req_count >= 2 { break; }
                    }
                }).await;

                let _ = pub_task.await;
                let dt = t0.elapsed();
                // Erfolg, wenn nur 1× REQ (oder 0 falls aus irgendeinem Grund B nicht req sendet)
                let ok = req_count <= 1;
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_dedupe_ttl_payload_inv", &samples);
            append_timeouts("p2p_dedupe_ttl_payload_inv", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

fn append_raw(bench: &str, samples_ns: &[u128]) {
    static WRITTEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let set = WRITTEN.get_or_init(|| Mutex::new(HashSet::new()));

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
        for v in samples_ns {
            let _ = writeln!(f, "{}", v);
        }
    }
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

// 3) Parallele RPC-Requests (8× GetPayloads)
fn bench_rpc_parallel_get_payloads_8(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_rpc_parallel_get_payloads_8", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            // Preload 8 Payloads je Iteration
            let mut roots: Vec<[u8; 32]> = Vec::with_capacity((iters as usize) * 8);
            for i in 0..((iters as usize) * 8) {
                let mut payout_root = [0u8; 32]; payout_root[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let payload = AnchorPayload { version: 2, micro_txs: vec![], mints: vec![], claims: vec![], evidences: vec![], payout_root, genesis_note: None };
                let root = payload_merkle_root(&payload);
                svc_a.put_payload(payload).await.expect("put payload A");
                roots.push(root);
            }

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for it in 0..iters as usize {
                let base = it * 8;
                let slice = &roots[base..base+8];
                // Watcher + SendReq parallel
                let mut futs = Vec::with_capacity(8);
                let t0 = Instant::now();
                for r in slice.iter().copied() {
                    let rx = watch_payload(r);
                    let svc_b_cl = svc_b.clone();
                    let fut = async move {
                        let _ = svc_b_cl.send_req(ReqMsg::GetPayloads { roots: vec![r] }).await;
                        timeout(Duration::from_millis(800), async {
                            rx.await.map(|resp| match resp { RespMsg::Payloads { payloads } => payloads.get(0).map(|p| payload_merkle_root(p) == r).unwrap_or(false), _ => false }).unwrap_or(false)
                        }).await.unwrap_or(false)
                    };
                    futs.push(fut);
                }
                let oks: Vec<bool> = join_all(futs).await;
                let dt = t0.elapsed();
                if oks.iter().all(|&b| b) { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_rpc_parallel_get_payloads_8", &samples);
            append_timeouts("p2p_rpc_parallel_get_payloads_8", timeouts_cnt);

            let _ = svc_a.shutdown().await; let _ = svc_b.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

// 4) NotFound-Pfad (Headers): A ohne Daten, B fragt per RR
fn bench_rpc_notfound_headers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_rpc_notfound_headers", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let id = AnchorId(ph);
                let mut rx_in = inbound_subscribe();
                let t0 = Instant::now();
                let _ = svc_b.send_req(ReqMsg::GetHeaders { ids: vec![id] }).await;
                let ok = timeout(Duration::from_millis(800), async {
                    loop {
                        if let Ok(msg) = rx_in.recv().await {
                            if let P2pMessage::Resp(RespMsg::NotFound { ty, ids }) = msg {
                                if ty == 1 && !ids.is_empty() { return true; }
                            }
                        } else { return false; }
                    }
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_rpc_notfound_headers", &samples);
            append_timeouts("p2p_rpc_notfound_headers", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

// 5) HeaderAnnounce-Propagation über Gossip (Shard 0)
fn bench_header_announce_gossip(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_header_announce_gossip", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let shards = Some(vec![0u8]);
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: shards.clone(), strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let parents = ParentList::default();
                let mut ph = [0u8; 32]; ph[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                let id = AnchorId(hdr.id_digest());
                let t0 = Instant::now();
                let _ = svc_a.announce_header(hdr).await;
                let ok = timeout(Duration::from_millis(1500), async {
                    loop {
                        if let Ok(RespMsg::Headers { headers }) = svc_b.rpc_call(ReqMsg::GetHeaders { ids: vec![id] }).await {
                            if !headers.is_empty() { return true; }
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_header_announce_gossip", &samples);
            append_timeouts("p2p_header_announce_gossip", timeouts_cnt);

            let _ = svc_b.shutdown().await; let _ = svc_a.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
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

// 1) Zwei-Hop Gossip: A -> B -> C (Headers)
fn bench_two_hop_headers_gossip(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_two_hop_headers_gossip", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            // Verkettete Dials: B->A, C->B
            let port_a = free_tcp_port();
            let port_b = free_tcp_port();
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_b)), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            // Preload Header auf A
            let mut ids: Vec<AnchorId> = Vec::with_capacity(iters as usize);
            for i in 0..iters {
                let parents = ParentList::default();
                let mut ph = [0u8; 32];
                ph[..8].copy_from_slice(&i.to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                svc_a.put_header(hdr.clone()).await.expect("put header A");
                ids.push(AnchorId(hdr.id_digest()));
            }

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for i in 0..iters as usize {
                let id = ids[i];
                // Sicherstellen: B besitzt den Header von A (sonst REQ→RESP von B gegen A)
                let mut have_b = false;
                for _ in 0..10 {
                    if let Ok(RespMsg::Headers { headers }) = svc_b.rpc_call(ReqMsg::GetHeaders { ids: vec![id] }).await {
                        have_b = !headers.is_empty();
                    }
                    if have_b { break; }
                    let _ = svc_a.publish_headers_inv(vec![id]).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }

                // Starte C (wählt B), B republisht zu C, C triggert RR→RESP gegen B
                let cfg_c = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_b)) };
                let (svc_c, h_c, sw_c) = spawn_with_libp2p(svc_cfg.clone(), cfg_c).expect("spawn C");
                tokio::time::sleep(Duration::from_millis(500)).await;

                let t0 = Instant::now();
                let _ = svc_b.publish_headers_inv(vec![id]).await;
                let ok = timeout(Duration::from_millis(800), async {
                    loop {
                        if let Ok(RespMsg::Headers { headers }) = svc_c.rpc_call(ReqMsg::GetHeaders { ids: vec![id] }).await {
                            if !headers.is_empty() { return true; }
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;

                let _ = svc_c.shutdown().await; let _ = h_c.await; let _ = sw_c.await;
            }
            append_raw("p2p_two_hop_headers_gossip", &samples);
            append_timeouts("p2p_two_hop_headers_gossip", timeouts_cnt);
            let _ = svc_a.shutdown().await; let _ = svc_b.shutdown().await;
            let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

// 2) Batchgrößen (Headers): N ∈ {1,8,32,128}
fn bench_batch_headers_gossip(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("p2p_batch_headers_inv_rr", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            set_bench_mode(true);
            let port_a = free_tcp_port();
            let cfg_a = Libp2pConfig { listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)), shards: None, strict_validation: true, dial: None };
            let cfg_b = Libp2pConfig { listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()), shards: None, strict_validation: true, dial: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)) };
            let svc_cfg = P2pConfig { max_peers: 16, rate: None };
            let (svc_a, h_a, sw_a) = spawn_with_libp2p(svc_cfg.clone(), cfg_a).expect("spawn A");
            let (svc_b, h_b, sw_b) = spawn_with_libp2p(svc_cfg.clone(), cfg_b).expect("spawn B");
            tokio::time::sleep(Duration::from_millis(800)).await;

            // Preload
            let per_iter = 128usize;
            let mut all_ids: Vec<AnchorId> = Vec::with_capacity((iters as usize) * per_iter);
            for i in 0..(iters as usize * per_iter) {
                let parents = ParentList::default();
                let mut ph = [0u8; 32];
                ph[..8].copy_from_slice(&i.to_be_bytes());
                let hdr = AnchorHeader { version: 2, shard_id: 0, parents, payload_hash: ph, creator_index: 1, vote_mask: 0, ack_present: false, ack_id: AnchorId(ph), network_id: [0u8;32] };
                svc_a.put_header(hdr.clone()).await.expect("put header A");
                all_ids.push(AnchorId(hdr.id_digest()));
            }
            let sizes = [1usize, 8, 32, 128];

            let mut total = Duration::ZERO;
            let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
            let mut timeouts_cnt: u64 = 0;
            for it in 0..iters as usize {
                let batch = sizes[it % sizes.len()];
                let base = it * per_iter;
                let ids: Vec<AnchorId> = all_ids[base..base+batch].to_vec();
                let rx = watch_header(ids[0]);
                let t0 = Instant::now();
                let _ = svc_a.publish_headers_inv(ids).await;
                let ok = timeout(Duration::from_millis(800), async {
                    rx.await.map(|resp| matches!(resp, RespMsg::Headers { .. })).unwrap_or(false)
                }).await.unwrap_or(false);
                let dt = t0.elapsed();
                if ok { samples.push(dt.as_nanos()); } else { timeouts_cnt += 1; }
                total += dt;
            }

            append_raw("p2p_batch_headers_inv_rr", &samples);
            append_timeouts("p2p_batch_headers_inv_rr", timeouts_cnt);
            let _ = svc_a.shutdown().await; let _ = svc_b.shutdown().await; let _ = h_a.await; let _ = h_b.await; let _ = sw_a.await; let _ = sw_b.await;
            total
        })
    });
}

criterion_group!(
    name = benches;
    config = bench_config();
    targets = bench_two_hop_headers_gossip, bench_batch_headers_gossip, bench_rpc_parallel_get_payloads_8, bench_rpc_notfound_headers, bench_header_announce_gossip, bench_header_announce_gossip_hb_1s, bench_header_announce_gossip_relaxed, bench_dedupe_ttl_payload_inv, bench_rpc_cold_start_get_headers, bench_rpc_warm_start_get_headers, bench_rpc_payload_size_sweep, bench_rpc_retry_get_headers
);
criterion_main!(benches);
