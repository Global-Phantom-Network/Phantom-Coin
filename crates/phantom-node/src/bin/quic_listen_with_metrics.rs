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

#[derive(Debug, Clone, Parser)]
#[command(
    name = "quic_listen_with_metrics",
    version,
    about = "Run QUIC listener and Prometheus metrics in one process"
)]
struct Args {
    /// QUIC Listen-Adresse, z. B. 127.0.0.1:9001
    #[arg(long, default_value = "127.0.0.1:9001")]
    addr: String,
    /// HTTP Listen-Adresse für Prometheus, z. B. 127.0.0.1:9101
    #[arg(long, default_value = "127.0.0.1:9101")]
    metrics_addr: String,
    /// Persistenz-Verzeichnis für Headers/Payloads (wird angelegt)
    #[arg(long, default_value = "pc-data")]
    store_dir: String,
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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    // P2P Service
    let cfg = P2pConfig {
        max_peers: 256,
        rate: None,
    };
    let (svc, mut out_rx, handle) = p2p_async::spawn(cfg);

    // QUIC Server
    let addr: SocketAddr = args
        .addr
        .parse()
        .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
    let (_endpoint, cert_der, server_task, tx_broadcast) = start_server(addr, svc.clone())
        .await
        .map_err(|e| anyhow!("start_server failed: {e}"))?;
    // Schreibe Zertifikat
    let cert_path = "./qlm_server.der";
    std::fs::write(cert_path, &cert_der).map_err(|e| anyhow!("write cert failed: {e}"))?;
    println!("{{\"type\":\"quic_listen_with_metrics\",\"addr\":\"{}\",\"cert\":\"{}\",\"metrics_addr\":\"{}\"}}", args.addr, hex::encode(&cert_der), args.metrics_addr);

    // Forward Outbox -> Broadcast
    let forward_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            outbox_deq_inc();
            let _ = tx_broadcast.send(msg).await;
        }
        Ok::<(), anyhow::Error>(())
    });

    // Persistenz-Task: schreibe eingehende Header/Payloads auf Disk
    let mut rx_persist = inbound_subscribe();
    let store = FileStore::open(&args.store_dir, args.fsync)?;
    println!(
        "{{\"type\":\"store_opened\",\"dir\":\"{}\",\"fsync\":{}}}",
        &args.store_dir, args.fsync
    );
    let persist_task = tokio::spawn(async move {
        loop {
            match rx_persist.recv().await {
                Ok(P2pMessage::HeaderAnnounce(h)) => match store.put_header(&h) {
                    Ok(_) => {
                        NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_e) => {
                        NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Ok(P2pMessage::Resp(RespMsg::Headers { headers })) => {
                    for h in headers {
                        match store.put_header(&h) {
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
                        match store.put_payload(&p) {
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
                    NODE_INBOUND_OBS_LAGGED_TOTAL.fetch_add(n as u64, Ordering::Relaxed);
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
    let make_svc = make_service_fn(|_conn| async move {
        Ok::<_, anyhow::Error>(service_fn(|req: Request<Body>| async move {
            if req.uri().path() != "/metrics" {
                let mut resp = Response::builder()
                    .status(404)
                    .body(Body::from("Not Found"))
                    .unwrap();
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
# HELP pc_p2p_inbound_dropped_rate Dropped inbound messages due to rate limiting\n# TYPE pc_p2p_inbound_dropped_rate counter\npc_p2p_inbound_dropped_rate {}\n\
# HELP pc_p2p_outbound_total Total outbound messages\n# TYPE pc_p2p_outbound_total counter\npc_p2p_outbound_total {}\n\
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
                m.inbound_total, m.inbound_dropped_rate, m.outbound_total,
                m.peer_rl_purged_total,
                m.in_hdr_total, m.in_inv_total, m.in_req_total, m.in_resp_total,
                m.out_hdr_total, m.out_inv_total, m.out_req_total, m.out_resp_total,
                m.out_errors_total, m.outbox_enq_total, m.outbox_deq_total,
                c1, c5, c10, c50, c100, c500, count, sum_sec, count
            );
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
            let mut resp = Response::new(Body::from(format!("{}{}", body, node_metrics)));
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
