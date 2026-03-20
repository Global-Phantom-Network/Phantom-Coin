// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(all(feature = "async", feature = "libp2p"))]

use criterion::{criterion_group, criterion_main, Criterion};
use futures::future::join_all;
use pc_codec::Decodable;
use pc_p2p::async_svc::{set_bench_mode, watch_header};
use pc_p2p::messages::{header_response_headers, ReqMsg};
use pc_p2p::{spawn_with_libp2p, Libp2pConfig, P2pConfig};
use pc_types::{
    digest_genesis_note, AnchorHeaderV2 as AnchorHeader, AnchorId, GenesisNote, ParentList,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::time::timeout;

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp 0");
    listener.local_addr().expect("local_addr").port()
}

fn append_tp(bench: &str, ops_per_sec: f64) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("target");
    path.push("criterion_raw");
    let _ = std::fs::create_dir_all(&path);
    path.push(format!("{}_tp.txt", bench));

    let first = !path.exists();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open tp file");
    if first {
        if let Some(nid) = load_network_id_hex() {
            let _ = writeln!(f, "# network_id={}", nid);
        }
    }
    let _ = writeln!(f, "{:.3}", ops_per_sec);
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or(default)
}

fn parse_shard_ids() -> Vec<u16> {
    if let Ok(raw) = std::env::var("TP_SHARD_IDS") {
        let mut out = Vec::new();
        for p in raw.split(',') {
            if let Ok(v) = p.trim().parse::<u16>() {
                out.push(v);
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    vec![0]
}

fn load_network_id_hex() -> Option<String> {
    let mut p = bench_store_dir()?;
    p.push("mempool");
    p.push("genesis_note.bin");
    let buf = std::fs::read(&p).ok()?;
    let mut s = &buf[..];
    let note = GenesisNote::decode(&mut s).ok()?;
    let nid = digest_genesis_note(&note);
    Some(hex::encode(nid))
}

fn bench_store_dir() -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os("PHANTOM_STORE_DIR") {
        let raw = raw.to_string_lossy().trim().to_string();
        if !raw.is_empty() {
            return Some(PathBuf::from(raw));
        }
    }
    #[cfg(target_os = "macos")]
    {
        return std::env::var_os("HOME").map(PathBuf::from).map(|home| {
            home.join("Library")
                .join("Application Support")
                .join("phantom-coin")
                .join("data")
        });
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Some(PathBuf::from(appdata).join("Phantom-Coin").join("data"));
        }
        return std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .map(|home| {
                home.join("AppData")
                    .join("Roaming")
                    .join("Phantom-Coin")
                    .join("data")
            });
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return Some(PathBuf::from(xdg).join("phantom-coin").join("data"));
        }
        std::env::var_os("HOME").map(PathBuf::from).map(|home| {
            home.join(".local")
                .join("share")
                .join("phantom-coin")
                .join("data")
        })
    }
}

fn append_timeouts(bench: &str, timeouts: u64) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("target");
    path.push("criterion_raw");
    let _ = std::fs::create_dir_all(&path);
    path.push(format!("{}_timeouts.txt", bench));

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open timeouts file");
    // Falls Datei neu: network_id-Header schreiben
    let is_new = std::fs::metadata(&path)
        .map(|m| m.len() == 0)
        .unwrap_or(true);
    if is_new {
        if let Some(nid) = load_network_id_hex() {
            let _ = writeln!(f, "# network_id={}", nid);
        }
    }
    let _ = writeln!(f, "{}", timeouts);
}

async fn run_tp_headers(
    duration: Duration,
    conc: usize,
    timeout_ms: u64,
    shard_ids: &[u16],
) -> (u64, u64) {
    let port_a = free_tcp_port();
    let cfg_lp2p_a = Libp2pConfig {
        listen_on: Some(format!("/ip4/127.0.0.1/tcp/{}", port_a)),
        shards: None,
        strict_validation: true,
        dial: None,
        enable_peer_scoring: true,
        identity_key_file: None,
        creator_peer_map_file: None,
        max_peers_per_ip: None,
        bootstrap_peers: Vec::new(),
        kad_bootstrap_interval_secs: 0,
    };
    let cfg_lp2p_b = Libp2pConfig {
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

    let cfg_service = P2pConfig {
        max_peers: 64,
        rate: None,
        peers_json_path: None,
        enable_peer_exchange: false,
        network_id: None,
    };
    set_bench_mode(true);
    let (svc_a, svc_a_handle, swarm_a) =
        spawn_with_libp2p(cfg_service.clone(), cfg_lp2p_a).expect("spawn lp2p A");
    let (svc_b, svc_b_handle, swarm_b) =
        spawn_with_libp2p(cfg_service.clone(), cfg_lp2p_b).expect("spawn lp2p B");

    // Stabilisierung
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Preload: ausreichend viele Header
    let n_hdrs: usize = 2048;
    let run_id = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base: u64 = run_id.saturating_mul(10_000_000);
    let mut ids: Vec<AnchorId> = Vec::with_capacity(n_hdrs);
    for i in 0..n_hdrs {
        let parents = ParentList::default();
        let mut ph = [0u8; 32];
        let idx = base.saturating_add(i as u64);
        ph[..8].copy_from_slice(&idx.to_be_bytes());
        let shard = shard_ids.get(i % shard_ids.len()).copied().unwrap_or(0);
        let hdr = AnchorHeader {
            version: 2,
            shard_id: shard,
            parents,
            payload_hash: ph,
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: AnchorId(ph),
            network_id: [0u8; 32],
            vote_epoch: 0,
            vote_round: 0,
            state_root: None,
            attest_sig: None,
        };
        svc_a.put_header(hdr.clone()).await.expect("put header A");
        ids.push(AnchorId(hdr.id_digest()));
    }

    // Messung
    let start = Instant::now();
    let deadline = start + duration;
    let next_idx = Arc::new(AtomicUsize::new(0));
    let successes = AtomicUsize::new(0);
    let timeouts_total = AtomicUsize::new(0);

    let mut tasks = Vec::with_capacity(conc);
    for _ in 0..conc {
        let svc_b_cl = svc_b.clone();
        let ids_cl = ids.clone();
        let timeout_dur = Duration::from_millis(timeout_ms);
        let next_idx_cl = next_idx.clone();
        let task = tokio::spawn(async move {
            let mut succ = 0usize;
            let mut to = 0usize;
            while Instant::now() < deadline {
                let j = next_idx_cl.fetch_add(1, Ordering::Relaxed) % ids_cl.len();
                let id = match ids_cl.get(j).copied() {
                    Some(id) => id,
                    None => continue,
                };
                let rx = watch_header(id);
                let _ = svc_b_cl
                    .send_req(ReqMsg::GetHeaders { ids: vec![id] })
                    .await;
                let ok = timeout(timeout_dur, async {
                    rx.await
                        .map(|resp| {
                            header_response_headers(&resp)
                                .map(|headers| {
                                    headers
                                        .first()
                                        .map(|h| AnchorId(h.id_digest()) == id)
                                        .unwrap_or(false)
                                })
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                if ok {
                    succ += 1;
                } else {
                    to += 1;
                }
            }
            (succ, to)
        });
        tasks.push(task);
    }

    let results = join_all(tasks).await;
    for r in results.into_iter().flatten() {
        successes.fetch_add(r.0, Ordering::Relaxed);
        timeouts_total.fetch_add(r.1, Ordering::Relaxed);
    }

    let _ = svc_a.shutdown().await;
    let _ = svc_b.shutdown().await;
    let _ = svc_a_handle.await;
    let _ = svc_b_handle.await;
    let _ = swarm_a.await;
    let _ = swarm_b.await;

    (
        successes.load(Ordering::Relaxed) as u64,
        timeouts_total.load(Ordering::Relaxed) as u64,
    )
}

fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(120))
        .warm_up_time(Duration::from_secs(3))
}

fn bench_throughput_headers(c: &mut Criterion) {
    let rt = Runtime::new().expect("create tokio runtime");
    c.bench_function("p2p_throughput_headers", |b| {
        b.to_async(&rt).iter_custom(|_iters| async move {
            let duration_sec: u64 = parse_env("TP_DURATION_SEC", 10);
            let conc: usize = parse_env("TP_CONC", 64);
            let timeout_ms: u64 = parse_env("TP_TIMEOUT_MS", 800);
            let shard_ids = parse_shard_ids();

            let bench_name = "p2p_throughput_headers";
            let duration = Duration::from_secs(duration_sec);
            let t0 = Instant::now();
            let (succ, to) = run_tp_headers(duration, conc, timeout_ms, &shard_ids).await;
            let dt = t0.elapsed();
            let ops = succ as f64 / (dt.as_secs_f64());
            append_tp(bench_name, ops);
            append_timeouts(bench_name, to);
            dt
        })
    });
}

criterion_group!(name = benches; config = bench_config(); targets = bench_throughput_headers);
criterion_main!(benches);
