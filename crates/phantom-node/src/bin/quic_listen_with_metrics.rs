// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use pc_p2p::async_svc as p2p_async;
use pc_p2p::async_svc::{inbound_subscribe, metrics_snapshot, outbox_deq_inc};
use pc_p2p::messages::{P2pMessage, RespMsg};
use pc_p2p::quic_transport::start_server;
use pc_p2p::P2pConfig;
use pc_store::FileStore;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};
#[path = "../store_path.rs"]
mod store_path;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "quic_listen_with_metrics",
    version,
    about = "Run QUIC listener and Prometheus metrics in one process"
)]
struct Args {
    /// QUIC listen address, e.g. 127.0.0.1:9001.
    /// QUIC Listen-Adresse, z. B. 127.0.0.1:9001
    #[arg(long, default_value = "127.0.0.1:9001")]
    addr: String,
    /// HTTP listen address for Prometheus, e.g. 127.0.0.1:9101.
    /// HTTP Listen-Adresse für Prometheus, z. B. 127.0.0.1:9101
    #[arg(long, default_value = "127.0.0.1:9101")]
    metrics_addr: String,
    /// Persistence directory for headers/payloads (created if missing).
    /// Persistenz-Verzeichnis für Headers/Payloads (wird angelegt)
    #[arg(long, default_value_t = store_path::default_runtime_store_dir_string())]
    store_dir: String,
    /// Network-ID (32-Byte Hex) für das P2P-Overlay.
    #[arg(long)]
    network_id: String,
    /// Perform fsync() for file and directory operations (default: true).
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true)
    #[arg(long, default_value_t = true)]
    fsync: bool,
}

// Node-weite Metriken: Persistenz und Observer-Lag
static NODE_PERSIST_HEADERS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_HEADERS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_INBOUND_OBS_LAGGED_TOTAL: AtomicU64 = AtomicU64::new(0);

// Prozess-Metriken
static NODE_PROC_CPU_PCT_MICRO: AtomicU64 = AtomicU64::new(0);

// Persistenz-Latenz (Histogramm-Buckets in Sekunden: 1ms,5ms,10ms,50ms,100ms,500ms, +Inf)
static NODE_PERSIST_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_1MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_5MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_10MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);

fn observe_node_persist(dt: std::time::Duration) {
    let micros = dt.as_micros();
    let micros_u64 = u64::try_from(micros).unwrap_or(u64::MAX);
    NODE_PERSIST_SUM_MICROS.fetch_add(micros_u64, Ordering::Relaxed);
    NODE_PERSIST_COUNT.fetch_add(1, Ordering::Relaxed);
    if micros <= 1_000 {
        NODE_PERSIST_BUCKET_LE_1MS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if micros <= 5_000 {
        NODE_PERSIST_BUCKET_LE_5MS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if micros <= 10_000 {
        NODE_PERSIST_BUCKET_LE_10MS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if micros <= 50_000 {
        NODE_PERSIST_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if micros <= 100_000 {
        NODE_PERSIST_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if micros <= 500_000 {
        NODE_PERSIST_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    }
    // > 500ms: implicitly counted into the +Inf bucket via "count".
    // > 500ms: fließt implizit in den +Inf-Bucket via "count" ein
}

fn parse_hex32(label: &str, s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(anyhow!("{label}: expected 64 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| anyhow!("{label}: invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let store_dir = store_path::resolve_store_dir_value(&args.store_dir, false)?
        .to_string_lossy()
        .to_string();
    let network_id = parse_hex32("network_id", &args.network_id)?;
    // P2P Service
    let cfg = P2pConfig {
        max_peers: 256,
        rate: None,
        peers_json_path: None,
        enable_peer_exchange: false,
        network_id: Some(network_id),
    };
    let (svc, mut out_rx, handle) = p2p_async::spawn(cfg);

    // QUIC Server
    let addr: SocketAddr = args
        .addr
        .parse()
        .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
    let (_endpoint, cert_der, server_task, tx_broadcast) = start_server(addr, svc.clone(), 256)
        .await
        .map_err(|e| anyhow!("start_server failed: {e}"))?;
    // Schreibe Zertifikat
    let cert_path = "./qlm_server.der";
    std::fs::write(cert_path, &cert_der).map_err(|e| anyhow!("write cert failed: {e}"))?;
    println!("{{\"type\":\"quic_listen_with_metrics\",\"addr\":\"{}\",\"cert\":\"{}\",\"metrics_addr\":\"{}\"}}", args.addr, hex::encode(&cert_der), args.metrics_addr);

    // Forward Outbox -> Broadcast
    let forward_task = tokio::spawn(async move {
        while let Some(env) = out_rx.recv().await {
            outbox_deq_inc();
            let _ = tx_broadcast.send(env).await;
        }
        Ok::<(), anyhow::Error>(())
    });

    // Background task for process CPU usage (updated every second).
    // Prozess-CPU-Usage Hintergrund-Task (sekündlich aktualisieren)
    let _cpu_task = tokio::spawn(async move {
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new_all();
        loop {
            let _ = sys.refresh_process(pid);
            if let Some(p) = sys.process(pid) {
                let cpu = p.cpu_usage() as f64;
                let v = if cpu.is_finite() && cpu >= 0.0 {
                    (cpu * 1_000_000.0) as u64
                } else {
                    0
                };
                NODE_PROC_CPU_PCT_MICRO.store(v, Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Persistenz-Task: schreibe eingehende Header/Payloads auf Disk
    let mut rx_persist = inbound_subscribe();
    let store = FileStore::open(&store_dir, args.fsync)?;
    println!(
        "{{\"type\":\"store_opened\",\"dir\":\"{}\",\"fsync\":{}}}",
        &store_dir, args.fsync
    );
    let persist_task = tokio::spawn(async move {
        loop {
            match rx_persist.recv().await {
                Ok(P2pMessage::PrevoteAnnounce(h)) | Ok(P2pMessage::PrecommitAnnounce(h)) => {
                    let t0 = Instant::now();
                    let res = store.put_header_v2(&h);
                    let dt = t0.elapsed();
                    observe_node_persist(dt);
                    match res {
                        Ok(_) => {
                            NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_e) => {
                            NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Ok(P2pMessage::Resp(
                    RespMsg::PrevoteHeaders { headers } | RespMsg::PrecommitHeaders { headers },
                )) => {
                    for h in headers {
                        let t0 = Instant::now();
                        let res = store.put_header_v2(&h);
                        let dt = t0.elapsed();
                        observe_node_persist(dt);
                        match res {
                            Ok(_) => {
                                NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_e) => {
                                NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Ok(P2pMessage::Resp(RespMsg::StagedHeaders {
                    prevote_headers,
                    precommit_headers,
                })) => {
                    for h in prevote_headers
                        .into_iter()
                        .chain(precommit_headers.into_iter())
                    {
                        let t0 = Instant::now();
                        let res = store.put_header_v2(&h);
                        let dt = t0.elapsed();
                        observe_node_persist(dt);
                        match res {
                            Ok(_) => {
                                NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_e) => {
                                NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Ok(P2pMessage::Resp(RespMsg::Payloads { payloads })) => {
                    for p in payloads {
                        let t0 = Instant::now();
                        let res = store.put_payload_v3(&p);
                        let dt = t0.elapsed();
                        observe_node_persist(dt);
                        match res {
                            Ok(_) => {
                                NODE_PERSIST_PAYLOADS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_e) => {
                                NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    NODE_INBOUND_OBS_LAGGED_TOTAL.fetch_add(n, Ordering::Relaxed);
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Metrics HTTP
    let metrics_addr: SocketAddr = args
        .metrics_addr
        .parse()
        .map_err(|e| anyhow!("invalid metrics_addr '{}': {e}", &args.metrics_addr))?;

    if !metrics_addr.ip().is_loopback() {
        return Err(anyhow!(
            "metrics_addr darf nur auf 127.0.0.1/::1 binden (nicht öffentlich)"
        ));
    }

    let make_svc = make_service_fn(|_conn| async move {
        Ok::<_, anyhow::Error>(service_fn(|req: Request<Body>| async move {
            if req.uri().path() != "/metrics" {
                let mut resp = Response::new(Body::from("Not Found"));
                *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            let m = metrics_snapshot();
            let sum_sec = (m.in_handle_sum_micros as f64) / 1_000_000.0;
            let c1 = m.in_bucket_le_1ms;
            let c5 = c1 + m.in_bucket_le_5ms;
            let c10 = c5 + m.in_bucket_le_10ms;
            let c50 = c10 + m.in_bucket_le_50ms;
            let c100 = c50 + m.in_bucket_le_100ms;
            let c500 = c100 + m.in_bucket_le_500ms;
            let count = m.in_handle_count;
            let body = format!(
                "# HELP pc_p2p_inbound_total Total inbound messages\n# TYPE pc_p2p_inbound_total counter\npc_p2p_inbound_total {}\n\
# HELP pc_p2p_inbound_bytes_total Total inbound bytes (encoded message size)\n# TYPE pc_p2p_inbound_bytes_total counter\npc_p2p_inbound_bytes_total {}\n\
# HELP pc_p2p_inbound_dropped_rate Dropped inbound messages due to rate limiting\n# TYPE pc_p2p_inbound_dropped_rate counter\npc_p2p_inbound_dropped_rate {}\n\
# HELP pc_p2p_outbound_total Total outbound messages\n# TYPE pc_p2p_outbound_total counter\npc_p2p_outbound_total {}\n\
# HELP pc_p2p_outbound_bytes_total Total outbound bytes (encoded message size)\n# TYPE pc_p2p_outbound_bytes_total counter\npc_p2p_outbound_bytes_total {}\n\
# HELP pc_p2p_peer_rl_purged_total Purged per-peer rate limiters due to TTL\n# TYPE pc_p2p_peer_rl_purged_total counter\npc_p2p_peer_rl_purged_total {}\n\
# HELP pc_p2p_in_hdr_total Total inbound HeaderAnnounce\n# TYPE pc_p2p_in_hdr_total counter\npc_p2p_in_hdr_total {}\n\
# HELP pc_p2p_in_inv_total Total inbound PayloadInv\n# TYPE pc_p2p_in_inv_total counter\npc_p2p_in_inv_total {}\n\
# HELP pc_p2p_in_req_total Total inbound Req\n# TYPE pc_p2p_in_req_total counter\npc_p2p_in_req_total {}\n\
# HELP pc_p2p_in_resp_total Total inbound Resp\n# TYPE pc_p2p_in_resp_total counter\npc_p2p_in_resp_total {}\n\
# HELP pc_p2p_out_hdr_total Total outbound HeaderAnnounce\n# TYPE pc_p2p_out_hdr_total counter\npc_p2p_out_hdr_total {}\n\
# HELP pc_p2p_out_inv_total Total outbound PayloadInv\n# TYPE pc_p2p_out_inv_total counter\npc_p2p_out_inv_total {}\n\
# HELP pc_p2p_out_req_total Total outbound Req\n# TYPE pc_p2p_out_req_total counter\npc_p2p_out_req_total {}\n\
# HELP pc_p2p_out_resp_total Total outbound Resp\n# TYPE pc_p2p_out_resp_total counter\npc_p2p_out_resp_total {}\n\
# HELP pc_p2p_out_errors_total Total outbound transport errors (QUIC/network)\n# TYPE pc_p2p_out_errors_total counter\npc_p2p_out_errors_total {}\n\
# HELP pc_p2p_outbox_enq_total Total enqueued messages to outbox\n# TYPE pc_p2p_outbox_enq_total counter\npc_p2p_outbox_enq_total {}\n\
# HELP pc_p2p_outbox_deq_total Total dequeued messages from outbox\n# TYPE pc_p2p_outbox_deq_total counter\npc_p2p_outbox_deq_total {}\n\
# HELP pc_p2p_outbox_drop_total Total dropped messages due to backpressure\n# TYPE pc_p2p_outbox_drop_total counter\npc_p2p_outbox_drop_total {}\n\
# HELP pc_p2p_outbox_depth Current outbox depth\n# TYPE pc_p2p_outbox_depth gauge\npc_p2p_outbox_depth {}\n\
# HELP pc_p2p_in_dedup_total Total dropped inbound messages due to deduplication\n# TYPE pc_p2p_in_dedup_total counter\npc_p2p_in_dedup_total {}\n\
# HELP pc_p2p_in_handle_seconds Inbound message handling latency\n# TYPE pc_p2p_in_handle_seconds histogram\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_p2p_in_handle_seconds_sum {}\n\
pc_p2p_in_handle_seconds_count {}\n",
                m.inbound_total, m.inbound_bytes_total, m.inbound_dropped_rate, m.outbound_total,
                m.outbound_bytes_total,
                m.peer_rl_purged_total,
                m.in_hdr_total, m.in_inv_total, m.in_req_total, m.in_resp_total,
                m.out_hdr_total, m.out_inv_total, m.out_req_total, m.out_resp_total,
                m.out_errors_total, m.outbox_enq_total, m.outbox_deq_total, m.outbox_drop_total, m.outbox_depth, m.in_dedup_total,
                c1, c5, c10, c50, c100, c500, count, sum_sec, count
            );
            // Append node-level metrics.
            // Node-Metriken anhängen
            let n_hdr = NODE_PERSIST_HEADERS_TOTAL.load(Ordering::Relaxed);
            let n_hdr_err = NODE_PERSIST_HEADERS_ERRORS_TOTAL.load(Ordering::Relaxed);
            let n_pl = NODE_PERSIST_PAYLOADS_TOTAL.load(Ordering::Relaxed);
            let n_pl_err = NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.load(Ordering::Relaxed);
            let n_lag = NODE_INBOUND_OBS_LAGGED_TOTAL.load(Ordering::Relaxed);
            let node_metrics = format!(
                "# HELP pc_node_persist_headers_total Total persisted headers\n# TYPE pc_node_persist_headers_total counter\npc_node_persist_headers_total {}\n\
# HELP pc_node_persist_headers_errors_total Total errors persisting headers\n# TYPE pc_node_persist_headers_errors_total counter\npc_node_persist_headers_errors_total {}\n\
# HELP pc_node_persist_payloads_total Total persisted payloads\n# TYPE pc_node_persist_payloads_total counter\npc_node_persist_payloads_total {}\n\
# HELP pc_node_persist_payloads_errors_total Total errors persisting payloads\n# TYPE pc_node_persist_payloads_errors_total counter\npc_node_persist_payloads_errors_total {}\n\
# HELP pc_node_inbound_obs_lagged_total Total dropped messages in node inbound observer due to lag\n# TYPE pc_node_inbound_obs_lagged_total counter\npc_node_inbound_obs_lagged_total {}\n",
                n_hdr, n_hdr_err, n_pl, n_pl_err, n_lag
            );
            // Persistenz-Histogramm (kumulative Buckets exportieren)
            let b1 = NODE_PERSIST_BUCKET_LE_1MS.load(Ordering::Relaxed);
            let b5 = NODE_PERSIST_BUCKET_LE_5MS.load(Ordering::Relaxed);
            let b10 = NODE_PERSIST_BUCKET_LE_10MS.load(Ordering::Relaxed);
            let b50 = NODE_PERSIST_BUCKET_LE_50MS.load(Ordering::Relaxed);
            let b100 = NODE_PERSIST_BUCKET_LE_100MS.load(Ordering::Relaxed);
            let b500 = NODE_PERSIST_BUCKET_LE_500MS.load(Ordering::Relaxed);
            let p_count = NODE_PERSIST_COUNT.load(Ordering::Relaxed);
            let p_sum_sec = (NODE_PERSIST_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
            let pc1 = b1;
            let pc5 = pc1.saturating_add(b5);
            let pc10 = pc5.saturating_add(b10);
            let pc50 = pc10.saturating_add(b50);
            let pc100 = pc50.saturating_add(b100);
            let pc500 = pc100.saturating_add(b500);
            let persist_metrics = format!(
                "# HELP pc_node_persist_seconds Node persist latency\n# TYPE pc_node_persist_seconds histogram\n\
pc_node_persist_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_persist_seconds_sum {}\n\
pc_node_persist_seconds_count {}\n",
                pc1, pc5, pc10, pc50, pc100, pc500, p_count, p_sum_sec, p_count
            );

            // Prozess-CPU-Usage Gauge
            let cpu_pct = (NODE_PROC_CPU_PCT_MICRO.load(Ordering::Relaxed) as f64) / 1_000_000.0;
            let proc_metrics = format!(
                "# HELP pc_node_process_cpu_percent Process CPU usage percent\n# TYPE pc_node_process_cpu_percent gauge\npc_node_process_cpu_percent {}\n",
                cpu_pct
            );

            // PeerStore Rollen-Metriken
            let peer_metrics = format!(
                "# HELP pc_p2p_peers_known_total Total known peers in PeerStore\n# TYPE pc_p2p_peers_known_total gauge\npc_p2p_peers_known_total {}\n\
# HELP pc_p2p_peers_miner_total Known miner peers\n# TYPE pc_p2p_peers_miner_total gauge\npc_p2p_peers_miner_total {}\n\
# HELP pc_p2p_peers_validator_total Known validator peers\n# TYPE pc_p2p_peers_validator_total gauge\npc_p2p_peers_validator_total {}\n\
# HELP pc_p2p_peers_banned_total Banned peers\n# TYPE pc_p2p_peers_banned_total gauge\npc_p2p_peers_banned_total {}\n",
                m.peers_known_total, m.peers_miner_total, m.peers_validator_total, m.peers_banned_total
            );

            let mut resp = Response::new(Body::from(format!(
                "{}{}{}{}{}",
                body, node_metrics, persist_metrics, proc_metrics, peer_metrics
            )));
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"),
            );
            Ok::<_, anyhow::Error>(resp)
        }))
    });
    let server = Server::bind(&metrics_addr).serve(make_svc);
    println!(
        "{{\"type\":\"metrics_serve\",\"addr\":\"{}\"}}",
        metrics_addr
    );

    let graceful = server.with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });

    let _ = tokio::join!(forward_task, graceful);
    let _ = persist_task.await;
    let _ = server_task.await;
    let res = handle
        .await
        .map_err(|e| anyhow!("p2p task join error: {e}"))?;
    res.map_err(|e| anyhow!("p2p loop error: {e}"))
}
