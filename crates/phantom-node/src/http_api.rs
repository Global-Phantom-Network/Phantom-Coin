use super::*;

// Simple token-bucket rate limiter implementation (per endpoint).
// Einfache Token-Bucket-Rate-Limiter-Implementierung (pro Endpoint).
struct SimpleRate {
    cap: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl SimpleRate {
    fn new(rule: &HttpRateRule) -> Self {
        let cap = rule.capacity as f64;
        let refill = rule.refill_per_sec as f64;
        SimpleRate {
            cap,
            refill_per_sec: refill,
            tokens: cap,
            last: std::time::Instant::now(),
        }
    }
}

async fn rate_allow(bucket: &tokio::sync::Mutex<SimpleRate>) -> bool {
    let mut b = bucket.lock().await;
    let now = std::time::Instant::now();
    let dt = now.saturating_duration_since(b.last).as_secs_f64();
    if dt > 0.0 {
        b.tokens = (b.tokens + dt * b.refill_per_sec).min(b.cap);
        b.last = now;
    }
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

#[allow(clippy::too_many_arguments)]
async fn status_serve_handle_request_inner(
    _peer_ip: IpAddr,
    is_tls: bool,
    req: Request<Body>,
    mempool_dir: String,
    store_dir: String,
    do_fsync: bool,
    network_id: Option<[u8; 32]>,
    require_auth: bool,
    auth_token: Option<String>,
    node_rot_cfg: Option<NodeRotationCfg>,
    node_da_cfg: Option<NodeDaGatingCfg>,
    _unsafe_confirm: bool,
    consensus_tls_only: bool,
    rl_pr: Option<Arc<tokio::sync::Mutex<SimpleRate>>>,
    rl_pp: Option<Arc<tokio::sync::Mutex<SimpleRate>>>,
    rl_as: Option<Arc<tokio::sync::Mutex<SimpleRate>>>,
    rl_fv: Option<Arc<tokio::sync::Mutex<SimpleRate>>>,
    rl_fvs: Option<Arc<tokio::sync::Mutex<SimpleRate>>>,
) -> Result<Response<Body>> {
    if !host_is_allowed(&req) {
        let mut resp = Response::new(Body::from("forbidden"));
        *resp.status_mut() = hyper::StatusCode::FORBIDDEN;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain"),
        );
        return Ok::<_, anyhow::Error>(resp);
    }

    // Global auth gate: protect everything except basic health/status/metrics.
    // Globales Auth-Gate: schuetzt alles ausser Health/Status/Metrics.
    if require_auth && !is_public_status_endpoint(req.uri().path(), req.method()) {
        let expected = auth_token.as_deref().unwrap_or("");
        if !bearer_auth_ok(&req, expected) {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"unauthorized\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
    }

    if req.uri().path() == "/status" && req.method() == hyper::Method::GET {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Versuche genesis_note aus mempool_dir/genesis_note.bin zu laden
        let mut root = serde_json::Map::new();
        root.insert("ok".into(), serde_json::Value::Bool(true));
        root.insert(
            "service".into(),
            serde_json::Value::String("phantom-node".to_string()),
        );
        root.insert("ts".into(), serde_json::Value::Number(ts.into()));

        let gpath = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
        let read_res = {
            let p = gpath.clone();
            tokio::task::spawn_blocking(move || std::fs::read(&p)).await
        };
        if let Ok(Ok(buf)) = read_res {
            if let Ok(note) = decode_genesis_note_exact(&buf) {
                let nid = digest_genesis_note(&note);
                let genesis = serde_json::json!({
                    "network_id": hex::encode(nid),
                    "params": {
                        "shards_initial": note.params.shards_initial,
                        "committee_k": note.params.committee_k,
                        "txs_per_payload": note.params.txs_per_payload,
                        "features": note.params.features
                    },
                    "network_name": String::from_utf8_lossy(&note.network_name).to_string(),
                    "version": note.version,
                    "genesis_message": String::from_utf8_lossy(&note.genesis_message).to_string(),
                    "genesis_message_hex": hex::encode(&note.genesis_message),
                    "genesis_message_bytes": note.genesis_message.len()
                });
                root.insert("genesis".into(), genesis);
            }
        }

        let body = serde_json::Value::Object(root).to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/validator/control" && req.method() == hyper::Method::GET {
        let store_dir = std::path::Path::new(&mempool_dir)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());
        let path = validator_control_path(&store_dir);
        let control = if path.exists() {
            load_validator_control(&path)
        } else {
            pcfg::default_validator_control_fail_closed().unwrap_or_else(|e| {
                warn!(err = %e, "now_secs failed; using updated_at=0 for fail-closed defaults");
                ValidatorControl::default_fail_closed_at(0)
            })
        };
        let body = serde_json::to_string(&control).unwrap_or_else(|_| "{\"ok\":false}".to_string());
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/validator/control" && req.method() == hyper::Method::POST {
        if !content_type_is_json(&req) {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"unsupported_media_type\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut control: ValidatorControl = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        if let Err(e) = control.validate() {
            let mut resp =
                Response::new(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e)));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let now = match pcfg::now_secs() {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"clock error: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        control.updated_at = now;
        control.last_changed_by = "rpc".to_string();
        let store_dir = std::path::Path::new(&mempool_dir)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());
        let path = validator_control_path(&store_dir);
        if let Err(e) = pcfg::save_validator_control_to_file(&control, &path) {
            let mut resp =
                Response::new(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e)));
            *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let mut resp = Response::new(Body::from("{\"ok\":true}".to_string()));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/healthz" && req.method() == hyper::Method::GET {
        let mut resp = Response::new(Body::from("{\"ok\":true}".to_string()));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/readyz" && req.method() == hyper::Method::GET {
        // Readiness: mempool_dir muss erreichbar sein
        match readyz_check_mempool_dir(&mempool_dir).await {
            Ok(()) => {
                let mut resp = Response::new(Body::from("{\"ok\":true}".to_string()));
                *resp.status_mut() = hyper::StatusCode::OK;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(e) => {
                let mut resp =
                    Response::new(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e)));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
    } else if req.uri().path() == "/metrics" && req.method() == hyper::Method::GET {
        // Prometheus-Format (Text)
        let mut out = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(
            &mut out,
            "# HELP phantom_node_rpc_broadcast_total RPC broadcast requests total"
        );
        let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_total counter");
        let _ = writeln!(
            &mut out,
            "phantom_node_rpc_broadcast_total {}",
            NODE_RPC_BROADCAST_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP phantom_node_rpc_broadcast_accepted_total RPC broadcast accepted total"
        );
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_rpc_broadcast_accepted_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_rpc_broadcast_accepted_total {}",
            NODE_RPC_BROADCAST_ACCEPTED_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP phantom_node_rpc_broadcast_duplicate_total RPC broadcast duplicates total"
        );
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_rpc_broadcast_duplicate_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_rpc_broadcast_duplicate_total {}",
            NODE_RPC_BROADCAST_DUP_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP phantom_node_rpc_broadcast_errors_total RPC broadcast errors total"
        );
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_rpc_broadcast_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_rpc_broadcast_errors_total {}",
            NODE_RPC_BROADCAST_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        // Consensus totals
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_committee_total Consensus select_committee requests total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_committee_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_committee_total {}",
            NODE_CONSENSUS_SELECT_COMMITTEE_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_committee_persist_total Consensus select_committee_persist requests total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_committee_persist_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_committee_persist_total {}",
            NODE_CONSENSUS_SELECT_COMMITTEE_PERSIST_TOTAL.load(Ordering::Relaxed)
        );

        // Consensus Endpoints
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_attestors_total Consensus select_attestors requests total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_attestors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_attestors_total {}",
            NODE_CONSENSUS_SELECT_ATTESTORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_attestors_fair_total Consensus select_attestors_fair requests total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_attestors_fair_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_attestors_fair_total {}",
            NODE_CONSENSUS_SELECT_ATTESTORS_FAIR_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_agg_sigs_total Consensus attestor_aggregate_sigs requests total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_agg_sigs_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_agg_sigs_total {}",
            NODE_CONSENSUS_AGG_SIGS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP phantom_node_consensus_fast_verify_total Consensus fast_verify requests total"
        );
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_fast_verify_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_fast_verify_total {}",
            NODE_CONSENSUS_FAST_VERIFY_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_fast_verify_valid_total Consensus fast_verify valid results total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_fast_verify_valid_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_fast_verify_valid_total {}",
            NODE_CONSENSUS_FAST_VERIFY_VALID_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_fast_verify_seats_total Consensus fast_verify_seats requests total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_fast_verify_seats_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_fast_verify_seats_total {}",
            NODE_CONSENSUS_FAST_VERIFY_SEATS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_fast_verify_seats_valid_total Consensus fast_verify_seats valid results total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_fast_verify_seats_valid_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_fast_verify_seats_valid_total {}",
            NODE_CONSENSUS_FAST_VERIFY_SEATS_VALID_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP phantom_node_consensus_payout_root_total Consensus payout_root requests total"
        );
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_payout_root_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_payout_root_total {}",
            NODE_CONSENSUS_PAYOUT_ROOT_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_payout_proof_total Consensus payout_proof requests total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_payout_proof_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_payout_proof_total {}",
            NODE_CONSENSUS_PAYOUT_PROOF_TOTAL.load(Ordering::Relaxed)
        );

        // Error counters
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_committee_errors_total Consensus select_committee errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_committee_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_committee_errors_total {}",
            NODE_CONSENSUS_SELECT_COMMITTEE_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_committee_persist_errors_total Consensus select_committee_persist errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_committee_persist_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_committee_persist_errors_total {}",
            NODE_CONSENSUS_SELECT_COMMITTEE_PERSIST_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_attestors_errors_total Consensus select_attestors errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_attestors_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_attestors_errors_total {}",
            NODE_CONSENSUS_SELECT_ATTESTORS_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_select_attestors_fair_errors_total Consensus select_attestors_fair errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_select_attestors_fair_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_select_attestors_fair_errors_total {}",
            NODE_CONSENSUS_SELECT_ATTESTORS_FAIR_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_agg_sigs_errors_total Consensus attestor_aggregate_sigs errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_agg_sigs_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_agg_sigs_errors_total {}",
            NODE_CONSENSUS_AGG_SIGS_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_fast_verify_errors_total Consensus fast_verify errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_fast_verify_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_fast_verify_errors_total {}",
            NODE_CONSENSUS_FAST_VERIFY_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_fast_verify_seats_errors_total Consensus fast_verify_seats errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_fast_verify_seats_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_fast_verify_seats_errors_total {}",
            NODE_CONSENSUS_FAST_VERIFY_SEATS_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_payout_root_errors_total Consensus payout_root errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_payout_root_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_payout_root_errors_total {}",
            NODE_CONSENSUS_PAYOUT_ROOT_ERRORS_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP phantom_node_consensus_payout_proof_errors_total Consensus payout_proof errors total");
        let _ = writeln!(
            &mut out,
            "# TYPE phantom_node_consensus_payout_proof_errors_total counter"
        );
        let _ = writeln!(
            &mut out,
            "phantom_node_consensus_payout_proof_errors_total {}",
            NODE_CONSENSUS_PAYOUT_PROOF_ERRORS_TOTAL.load(Ordering::Relaxed)
        );

        // Genesis/network metrics.
        // Genesis-/Netzwerk-Metriken.
        // pc_network_id{network="<name>"} 1, pc_genesis_height 0 (if genesis is present).
        // pc_network_id{network="<name>"} 1, pc_genesis_height 0 (falls Genesis vorhanden).
        let p = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
        let read_res = {
            let p2 = p.clone();
            tokio::task::spawn_blocking(move || std::fs::read(&p2)).await
        };
        if let Ok(Ok(buf)) = read_res {
            if let Ok(note) = decode_genesis_note_exact(&buf) {
                let _nid = digest_genesis_note(&note);
                let name = String::from_utf8_lossy(&note.network_name);
                let _ = writeln!(&mut out, "# HELP pc_network_id Network ID presence gauge");
                let _ = writeln!(&mut out, "# TYPE pc_network_id gauge");
                let _ = writeln!(&mut out, "pc_network_id{{network=\"{}\"}} 1", name);
                let _ = writeln!(&mut out, "# HELP pc_genesis_height Genesis anchor height");
                let _ = writeln!(&mut out, "# TYPE pc_genesis_height gauge");
                let _ = writeln!(&mut out, "pc_genesis_height 0");
            }
        }
        // End-to-end finality histogram (plain HTTP).
        // Finalitäts-Histogramm (Plain HTTP).
        let f_count = NODE_FINALITY_COUNT.load(Ordering::Relaxed);
        let f_sum_sec = (NODE_FINALITY_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
        let f50 = NODE_FINALITY_BUCKET_LE_50MS.load(Ordering::Relaxed);
        let f100 = f50 + NODE_FINALITY_BUCKET_LE_100MS.load(Ordering::Relaxed);
        let f500 = f100 + NODE_FINALITY_BUCKET_LE_500MS.load(Ordering::Relaxed);
        let f1s = f500 + NODE_FINALITY_BUCKET_LE_1S.load(Ordering::Relaxed);
        let f2s = f1s + NODE_FINALITY_BUCKET_LE_2S.load(Ordering::Relaxed);
        let f5s = f2s + NODE_FINALITY_BUCKET_LE_5S.load(Ordering::Relaxed);
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_finality_seconds End-to-end finality since mint"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_finality_seconds histogram");
        let _ = writeln!(
            &mut out,
            "pc_node_finality_seconds_bucket{{le=\"0.05\"}} {}",
            f50
        );
        let _ = writeln!(
            &mut out,
            "pc_node_finality_seconds_bucket{{le=\"0.1\"}} {}",
            f100
        );
        let _ = writeln!(
            &mut out,
            "pc_node_finality_seconds_bucket{{le=\"0.5\"}} {}",
            f500
        );
        let _ = writeln!(
            &mut out,
            "pc_node_finality_seconds_bucket{{le=\"1\"}} {}",
            f1s
        );
        let _ = writeln!(
            &mut out,
            "pc_node_finality_seconds_bucket{{le=\"2\"}} {}",
            f2s
        );
        let _ = writeln!(
            &mut out,
            "pc_node_finality_seconds_bucket{{le=\"5\"}} {}",
            f5s
        );
        let _ = writeln!(
            &mut out,
            "pc_node_finality_seconds_bucket{{le=\"+Inf\"}} {}",
            f_count
        );
        let _ = writeln!(&mut out, "pc_node_finality_seconds_sum {}", f_sum_sec);
        let _ = writeln!(&mut out, "pc_node_finality_seconds_count {}", f_count);
        // Finality events total (EPS via PromQL rate())
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_finality_events_total Finalization events observed"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_finality_events_total counter");
        let _ = writeln!(&mut out, "pc_node_finality_events_total {}", f_count);
        let _ = writeln!(&mut out, "# HELP pc_node_finalized_tx_total Total finalized transactions (micro_txs + mints + claims + evidences)");
        let _ = writeln!(&mut out, "# TYPE pc_node_finalized_tx_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_finalized_tx_total {}",
            NODE_FINALIZED_TX_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP pc_node_finality_mint_events_total Finalization events that contained at least one mint");
        let _ = writeln!(
            &mut out,
            "# TYPE pc_node_finality_mint_events_total counter"
        );
        let _ = writeln!(
            &mut out,
            "pc_node_finality_mint_events_total {}",
            NODE_FINALITY_MINT_EVENTS.load(Ordering::Relaxed)
        );
        // Verify-Histogramm (BLS fast aggregate verify)
        let v_count = NODE_VERIFY_COUNT.load(Ordering::Relaxed);
        let v_sum_sec = (NODE_VERIFY_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
        let v1 = NODE_VERIFY_BUCKET_LE_1MS.load(Ordering::Relaxed);
        let v5 = v1 + NODE_VERIFY_BUCKET_LE_5MS.load(Ordering::Relaxed);
        let v10 = v5 + NODE_VERIFY_BUCKET_LE_10MS.load(Ordering::Relaxed);
        let v50 = v10 + NODE_VERIFY_BUCKET_LE_50MS.load(Ordering::Relaxed);
        let v100 = v50 + NODE_VERIFY_BUCKET_LE_100MS.load(Ordering::Relaxed);
        let v500 = v100 + NODE_VERIFY_BUCKET_LE_500MS.load(Ordering::Relaxed);
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_verify_seconds BLS fast aggregate verify latency"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_verify_seconds histogram");
        let _ = writeln!(
            &mut out,
            "pc_node_verify_seconds_bucket{{le=\"0.001\"}} {}",
            v1
        );
        let _ = writeln!(
            &mut out,
            "pc_node_verify_seconds_bucket{{le=\"0.005\"}} {}",
            v5
        );
        let _ = writeln!(
            &mut out,
            "pc_node_verify_seconds_bucket{{le=\"0.01\"}} {}",
            v10
        );
        let _ = writeln!(
            &mut out,
            "pc_node_verify_seconds_bucket{{le=\"0.05\"}} {}",
            v50
        );
        let _ = writeln!(
            &mut out,
            "pc_node_verify_seconds_bucket{{le=\"0.1\"}} {}",
            v100
        );
        let _ = writeln!(
            &mut out,
            "pc_node_verify_seconds_bucket{{le=\"0.5\"}} {}",
            v500
        );
        let _ = writeln!(
            &mut out,
            "pc_node_verify_seconds_bucket{{le=\"+Inf\"}} {}",
            v_count
        );
        let _ = writeln!(&mut out, "pc_node_verify_seconds_sum {}", v_sum_sec);
        let _ = writeln!(&mut out, "pc_node_verify_seconds_count {}", v_count);
        let _ = writeln!(&mut out, "# HELP pc_node_votes_sent_total Votes (attestations) observed for finality verification");
        let _ = writeln!(&mut out, "# TYPE pc_node_votes_sent_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_votes_sent_total {}",
            NODE_VOTE_SENT_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_votes_accepted_total Votes accepted by finality verification"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_votes_accepted_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_votes_accepted_total {}",
            NODE_VOTE_ACCEPTED_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_votes_rejected_total Votes rejected by finality verification"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_votes_rejected_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_votes_rejected_total {}",
            NODE_VOTE_REJECTED_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP pc_node_votes_rate_limited_total Votes dropped by global finality-verify rate limit");
        let _ = writeln!(&mut out, "# TYPE pc_node_votes_rate_limited_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_votes_rate_limited_total {}",
            NODE_VOTE_RATE_LIMITED_TOTAL.load(Ordering::Relaxed)
        );

        // Debug: State-Task finalization pipeline step counters.
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_dbg_applycand_recv apply-candidate messages received by state task"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_dbg_applycand_recv counter");
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_recv {}",
            NODE_DBG_APPLYCAND_RECV.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_already_applied {}",
            NODE_DBG_APPLYCAND_ALREADY_APPLIED.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_headers_empty {}",
            NODE_DBG_APPLYCAND_HEADERS_EMPTY.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_payload_unavail {}",
            NODE_DBG_APPLYCAND_PAYLOAD_UNAVAIL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_sanity_fail {}",
            NODE_DBG_APPLYCAND_SANITY_FAIL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_mint_censor_fail {}",
            NODE_DBG_APPLYCAND_MINT_CENSOR_FAIL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_payout_fail {}",
            NODE_DBG_APPLYCAND_PAYOUT_FAIL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "pc_node_dbg_applycand_applied {}",
            NODE_DBG_APPLYCAND_APPLIED.load(Ordering::Relaxed)
        );

        // Anchor index (finalized state progress)
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_anchor_index Current finalized anchor index"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_anchor_index gauge");
        let _ = writeln!(
            &mut out,
            "pc_node_anchor_index {}",
            NODE_ANCHOR_INDEX.load(Ordering::Relaxed)
        );

        // Internal PoW-Miner metrics
        let _ = writeln!(&mut out, "# HELP pc_node_pow_mining_active Whether the internal PoW miner is actively mining (1=yes, 0=no)");
        let _ = writeln!(&mut out, "# TYPE pc_node_pow_mining_active gauge");
        let _ = writeln!(
            &mut out,
            "pc_node_pow_mining_active {}",
            NODE_POW_MINING_ACTIVE.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_pow_hashes_total Total hashes computed by internal PoW miner"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_pow_hashes_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_pow_hashes_total {}",
            NODE_POW_HASHES_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_pow_blocks_found_total Blocks (mints) found by internal PoW miner"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_pow_blocks_found_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_pow_blocks_found_total {}",
            NODE_POW_BLOCKS_FOUND_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP pc_node_pow_submit_ok_total Successful payload submissions by internal PoW miner");
        let _ = writeln!(&mut out, "# TYPE pc_node_pow_submit_ok_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_pow_submit_ok_total {}",
            NODE_POW_SUBMIT_OK_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(&mut out, "# HELP pc_node_pow_submit_stale_total Stale submissions (chain tip changed) by internal PoW miner");
        let _ = writeln!(&mut out, "# TYPE pc_node_pow_submit_stale_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_pow_submit_stale_total {}",
            NODE_POW_SUBMIT_STALE_TOTAL.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            &mut out,
            "# HELP pc_node_pow_submit_err_total Failed payload submissions by internal PoW miner"
        );
        let _ = writeln!(&mut out, "# TYPE pc_node_pow_submit_err_total counter");
        let _ = writeln!(
            &mut out,
            "pc_node_pow_submit_err_total {}",
            NODE_POW_SUBMIT_ERR_TOTAL.load(Ordering::Relaxed)
        );

        let mut resp = Response::new(Body::from(out));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/debug/pprof/profile" && req.method() == hyper::Method::GET {
        #[cfg(feature = "pprof")]
        {
            let secs = req
                .uri()
                .query()
                .and_then(|q| q.split('&').find(|kv| kv.starts_with("seconds=")))
                .and_then(|kv| kv.split('=').nth(1))
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(10);
            let guard = match pprof::ProfilerGuardBuilder::default()
                .frequency(100)
                .build()
            {
                Ok(g) => g,
                Err(e) => {
                    let mut resp = Response::new(Body::from(format!("pprof start error: {}", e)));
                    *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            match guard.report().build() {
                Ok(report) => match report.pprof() {
                    Ok(profile) => {
                        use prost::Message as _;
                        let bytes = profile.encode_to_vec();
                        let mut resp = Response::new(Body::from(bytes));
                        *resp.status_mut() = hyper::StatusCode::OK;
                        resp.headers_mut().insert(
                            hyper::header::CONTENT_TYPE,
                            hyper::header::HeaderValue::from_static("application/octet-stream"),
                        );
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    Err(e) => {
                        let mut resp =
                            Response::new(Body::from(format!("pprof encode error: {}", e)));
                        *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok::<_, anyhow::Error>(resp);
                    }
                },
                Err(e) => {
                    let mut resp = Response::new(Body::from(format!("pprof report error: {}", e)));
                    *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok::<_, anyhow::Error>(resp);
                }
            }
        }
        #[cfg(not(feature = "pprof"))]
        {
            let mut resp = Response::new(Body::from("pprof feature not enabled".to_string()));
            *resp.status_mut() = hyper::StatusCode::NOT_IMPLEMENTED;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
    } else if !is_tls && req.uri().path().starts_with("/consensus/") && consensus_tls_only {
        // Wenn mTLS (tls_client_ca) aktiv ist, blocke Konsensus-Endpoints auf Plain-HTTP
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"mtls_required\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::FORBIDDEN;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/state/root" && req.method() == hyper::Method::GET {
        let state_root_file = std::path::Path::new(&store_dir).join("state_root");
        match std::fs::read_to_string(&state_root_file) {
            Ok(s) => {
                let hex_str = s.trim().to_string();
                let body = serde_json::json!({ "ok": true, "state_root": hex_str }).to_string();
                let mut resp = Response::new(Body::from(body));
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(e) => {
                let body = serde_json::json!({ "ok": false, "error": format!("state_root not available: {}", e) }).to_string();
                let mut resp = Response::new(Body::from(body));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
    } else if req.uri().path() == "/consensus/committee" && req.method() == hyper::Method::GET {
        let query = req.uri().query().unwrap_or("");
        let epoch = match query_param(query, "epoch").and_then(|s| s.parse::<u64>().ok()) {
            Some(v) => v,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"missing_epoch\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let nid = match network_id {
            Some(n) => n,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"network_id_not_configured\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let note = match load_genesis_note_from_mempool(&mempool_dir) {
            Some(note) => note,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"genesis_note_unavailable\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let k = note.params.committee_k;
        if k == 0 || k > 64 {
            let mut resp = Response::new(Body::from(format!(
                "{{\"ok\":false,\"error\":\"committee_k_invalid\",\"detail\":\"{}\"}}",
                k
            )));
            *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let role_policy = match global_role_policy(&mempool_dir) {
            Ok(p) => p,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"role_policy_error\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let seed_anchor = committee_seed_anchor_from_mempool(&mempool_dir)
            .unwrap_or_else(|| pc_types::genesis_payload_root(&note));
        let committee = match global_utxo_view(&store_dir) {
            Ok(st_mutex) => {
                let st = st_mutex.lock().await;
                #[cfg(feature = "rocksdb")]
                {
                    let _ = st.backend().try_catch_up_with_primary();
                }
                let stake_by_lock =
                    super::committee_selection::aggregate_stake_by_lock(st.backend());
                super::committee_selection::select_effective_committee_from_backend(
                    st.backend(),
                    &note,
                    &stake_by_lock,
                    k,
                    epoch,
                    seed_anchor,
                    nid,
                    role_policy.as_deref(),
                )
            }
            Err(_) => {
                let empty_backend = pc_state::InMemoryBackend::new();
                let stake_by_lock = std::collections::HashMap::new();
                super::committee_selection::select_effective_committee_from_backend(
                    &empty_backend,
                    &note,
                    &stake_by_lock,
                    k,
                    epoch,
                    seed_anchor,
                    nid,
                    role_policy.as_deref(),
                )
            }
        };
        let bootstrap_mode = committee.bootstrap_mode;
        let n_fee_eligible = committee
            .fee_eligible
            .iter()
            .filter(|eligible| **eligible)
            .count();
        let seats: Vec<serde_json::Value> = committee
            .seats
            .iter()
            .enumerate()
            .map(|(idx, seat)| {
                serde_json::json!({
                    "index": idx,
                    "recipient_id": hex::encode(seat.recipient_id),
                    "bls_pk": hex::encode(seat.bls_pk.to_bytes()),
                })
            })
            .collect();
        let body = serde_json::json!({
            "ok": true,
            "network_id": hex::encode(nid),
            "epoch": epoch,
            "seed_anchor": hex::encode(seed_anchor),
            "k": k,
            "bootstrap_mode": bootstrap_mode,
            "n_fee_eligible": n_fee_eligible,
            "n_selected": seats.len(),
            "seats": seats,
        })
        .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/local_prevote_context"
        && req.method() == hyper::Method::GET
    {
        let query = req.uri().query().unwrap_or("");
        let payload_root =
            match query_param(query, "payload_root").and_then(|s| parse_hex32(s).ok()) {
                Some(root) => root,
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"payload_root_invalid\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
        let bls_pk_hex = match query_param(query, "bls_pk") {
            Some(v) if !v.trim().is_empty() => v,
            _ => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bls_pk_invalid\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let nid = match network_id {
            Some(n) => n,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"network_id_not_configured\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let role_policy = match global_role_policy(&mempool_dir) {
            Ok(p) => p,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"role_policy_error\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let utxo_mutex = match global_utxo_view(&store_dir) {
            Ok(s) => s,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"utxo_view_unavailable\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut st = utxo_mutex.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }
        let precheck = match super::finality_pipeline::precheck_local_prevote_by_bls_pk(
            &mut st,
            &mempool_dir,
            &store_dir,
            do_fsync,
            nid,
            payload_root,
            bls_pk_hex,
            node_rot_cfg.as_ref(),
            role_policy.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let detail = e.to_string();
                let status = if detail.starts_with("payload_unavailable") {
                    hyper::StatusCode::NOT_FOUND
                } else if detail.starts_with("genesis_note_unavailable")
                    || detail.starts_with("committee_k_invalid")
                {
                    hyper::StatusCode::SERVICE_UNAVAILABLE
                } else {
                    hyper::StatusCode::BAD_REQUEST
                };
                let error = if detail.starts_with("payload_unavailable") {
                    "payload_unavailable"
                } else {
                    "local_prevote_precheck_failed"
                };
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"{}\",\"detail\":\"{}\"}}",
                    error, detail
                )));
                *resp.status_mut() = status;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let ctx = super::finality_pipeline::build_local_prevote_context(&precheck);
        let body = serde_json::json!({
            "ok": true,
            "network_id": hex::encode(ctx.network_id),
            "payload_root": hex::encode(ctx.payload_root),
            "next_anchor_index": ctx.next_anchor_index,
            "vote_epoch": ctx.vote_epoch,
            "creator_index": ctx.creator_index,
            "vote_mask": ctx.vote_mask,
        })
        .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/local_precommit_context"
        && req.method() == hyper::Method::GET
    {
        let query = req.uri().query().unwrap_or("");
        let payload_root =
            match query_param(query, "payload_root").and_then(|s| parse_hex32(s).ok()) {
                Some(root) => root,
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"payload_root_invalid\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
        let bls_pk_hex = match query_param(query, "bls_pk") {
            Some(v) if !v.trim().is_empty() => v,
            _ => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bls_pk_invalid\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let nid = match network_id {
            Some(n) => n,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"network_id_not_configured\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let role_policy = match global_role_policy(&mempool_dir) {
            Ok(p) => p,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"role_policy_error\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let utxo_mutex = match global_utxo_view(&store_dir) {
            Ok(s) => s,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"utxo_view_unavailable\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut st = utxo_mutex.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }
        let precheck = match super::finality_pipeline::precheck_local_precommit_by_bls_pk(
            &mut st,
            &mempool_dir,
            &store_dir,
            do_fsync,
            nid,
            payload_root,
            bls_pk_hex,
            node_rot_cfg.as_ref(),
            role_policy.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let detail = e.to_string();
                let status = if detail.starts_with("payload_unavailable") {
                    hyper::StatusCode::NOT_FOUND
                } else if detail.starts_with("genesis_note_unavailable")
                    || detail.starts_with("committee_k_invalid")
                {
                    hyper::StatusCode::SERVICE_UNAVAILABLE
                } else {
                    hyper::StatusCode::BAD_REQUEST
                };
                let error = if detail.starts_with("payload_unavailable") {
                    "payload_unavailable"
                } else {
                    "local_precommit_precheck_failed"
                };
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"{}\",\"detail\":\"{}\"}}",
                    error, detail
                )));
                *resp.status_mut() = status;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let ctx = match super::finality_pipeline::build_local_precommit_context(
            &mut st,
            &mempool_dir,
            precheck,
            role_policy.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"local_precommit_context_failed\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let body = serde_json::json!({
            "ok": true,
            "network_id": hex::encode(ctx.network_id),
            "payload_root": hex::encode(ctx.payload_root),
            "next_anchor_index": ctx.next_anchor_index,
            "vote_epoch": ctx.vote_epoch,
            "creator_index": ctx.creator_index,
            "vote_mask": ctx.vote_mask,
            "post_state_root": hex::encode(ctx.committed_state_root),
        })
        .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/precommit_state_root"
        && req.method() == hyper::Method::GET
    {
        let query = req.uri().query().unwrap_or("");
        let payload_root =
            match query_param(query, "payload_root").and_then(|s| parse_hex32(s).ok()) {
                Some(root) => root,
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"payload_root_invalid\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
        let creator_index = match query_param(query, "creator_index") {
            Some(v) => match v.parse::<u8>() {
                Ok(idx) => idx,
                Err(_) => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"creator_index_invalid\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            },
            None => 0,
        };
        let nid = match network_id {
            Some(n) => n,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"network_id_not_configured\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let role_policy = match global_role_policy(&mempool_dir) {
            Ok(p) => p,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"role_policy_error\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let utxo_mutex = match global_utxo_view(&store_dir) {
            Ok(s) => s,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"utxo_view_unavailable\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut st = utxo_mutex.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }
        let precheck = match super::finality_pipeline::precheck_local_precommit_by_creator_index(
            &mut st,
            &mempool_dir,
            &store_dir,
            do_fsync,
            nid,
            payload_root,
            creator_index,
            node_rot_cfg.as_ref(),
            role_policy.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let detail = e.to_string();
                let status = if detail.starts_with("payload_unavailable") {
                    hyper::StatusCode::NOT_FOUND
                } else if detail.starts_with("genesis_note_unavailable")
                    || detail.starts_with("committee_k_invalid")
                {
                    hyper::StatusCode::SERVICE_UNAVAILABLE
                } else {
                    hyper::StatusCode::BAD_REQUEST
                };
                let error = if detail.starts_with("payload_unavailable") {
                    "payload_unavailable"
                } else {
                    "precommit_precheck_failed"
                };
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"{}\",\"detail\":\"{}\"}}",
                    error, detail
                )));
                *resp.status_mut() = status;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let ctx = match super::finality_pipeline::build_local_precommit_context(
            &mut st,
            &mempool_dir,
            precheck,
            role_policy.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"precommit_context_failed\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let body = serde_json::json!({
            "ok": true,
            "payload_root": hex::encode(ctx.payload_root),
            "creator_index": ctx.creator_index,
            "post_state_root": hex::encode(ctx.committed_state_root),
        })
        .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/genesis/bootstrap" && req.method() == hyper::Method::POST {
        // Bootstrap: Lade genesis_note.bin, baue V2-Payload/Header und validiere A0
        let gpath = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
        let buf = match std::fs::read(&gpath) {
            Ok(b) => b,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read genesis_note: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let note = match decode_genesis_note_exact(&buf) {
            Ok(n) => n,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"decode genesis_note: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let payload = pc_types::AnchorPayloadV2 {
            version: 2,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: genesis_payload_root(&note),
            genesis_note: Some(note.clone()),
        };
        let header = AnchorHeaderV2 {
            version: 2,
            shard_id: 0,
            parents: pc_types::ParentList::default(),
            payload_hash: genesis_payload_root(&note),
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
            network_id: digest_genesis_note(&note),
            vote_epoch: 0,
            vote_round: 0,
            attest_sig: None,
            state_root: None,
        };
        match validate_genesis_anchor(&header, &payload) {
            Ok(nid) => {
                let body = serde_json::json!({
                    "ok": true,
                    "network_id": hex::encode(nid),
                    "message": "genesis bootstrap validated"
                })
                .to_string();
                let mut resp = Response::new(Body::from(body));
                *resp.status_mut() = hyper::StatusCode::OK;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(_e) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"genesis validation failed\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
    } else if req.uri().path() == "/state/apply_mint_with_index"
        && req.method() == hyper::Method::POST
    {
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"unsupported\",\"detail\":\"/state/apply_mint_with_index was removed; mints must finalize through emission rounds and graph finality\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::GONE;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/stake/bond" && req.method() == hyper::Method::POST {
        if !content_type_is_json(&req) {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"unsupported_media_type\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        #[derive(serde::Deserialize)]
        struct OpRef {
            txid: String,
            vout: u32,
        }
        #[derive(serde::Deserialize)]
        struct BondReq {
            ops: Vec<OpRef>,
            current: u64,
            threshold: u64,
            allow_unripe_bond: Option<bool>,
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let reqv: BondReq = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut ops: Vec<OutPoint> = Vec::with_capacity(reqv.ops.len());
        for r in reqv.ops.iter() {
            let txid = match parse_hex32(&r.txid) {
                Ok(v) => v,
                Err(_) => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"bad txid\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            ops.push(OutPoint { txid, vout: r.vout });
        }
        let st_mutex = match global_state(&mempool_dir) {
            Ok(s) => s,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"state_db_unavailable\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut st = st_mutex.lock().await;
        let allow = reqv.allow_unripe_bond.unwrap_or(false);
        match st.bond_outpoints(&ops, reqv.current, reqv.threshold, allow) {
            Ok(()) => {
                let mut resp = Response::new(Body::from("{\"ok\":true}".to_string()));
                *resp.status_mut() = hyper::StatusCode::OK;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(e) => {
                let mut resp =
                    Response::new(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e)));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
    } else if req.uri().path() == "/stake/unbond_challenge" && req.method() == hyper::Method::GET {
        let q = req.uri().query().unwrap_or("");
        let mut lock_hex: Option<&str> = None;
        for part in q.split('&') {
            if let Some((k, v)) = part.split_once('=') {
                if k == "lock" {
                    lock_hex = Some(v);
                    break;
                }
            }
        }
        let lock_hex = match lock_hex {
            Some(v) => v,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"missing lock\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let raw = match hex::decode(lock_hex) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad lock hex: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        if raw.len() != 32 {
            let mut resp = Response::new(Body::from(format!(
                "{{\"ok\":false,\"error\":\"bad lock length: {}\"}}",
                raw.len()
            )));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let mut lock_b = [0u8; 32];
        lock_b.copy_from_slice(&raw);
        let lock = LockCommitment(lock_b);
        let st_mutex = match global_state(&mempool_dir) {
            Ok(s) => s,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"state_db_unavailable\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let st = st_mutex.lock().await;
        let seq = st.unbond_sequence_for_lock(&lock);
        let nonce = st.unbond_nonce_for_lock(&lock);
        let body = serde_json::json!({
            "ok": true,
            "lock": hex::encode(lock_b),
            "sequence": seq,
            "nonce": hex::encode(nonce)
        })
        .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/stake/unbond" && req.method() == hyper::Method::POST {
        if !content_type_is_json(&req) {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"unsupported_media_type\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        #[derive(serde::Deserialize)]
        struct OpRef {
            txid: String,
            vout: u32,
        }
        #[derive(serde::Deserialize)]
        struct UnbondReq {
            ops: Vec<OpRef>,
            signatures: Vec<String>,
            public_keys: Vec<String>,
            nonce: String,
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let reqv: UnbondReq = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut ops: Vec<OutPoint> = Vec::with_capacity(reqv.ops.len());
        for r in reqv.ops.iter() {
            let txid = match parse_hex32(&r.txid) {
                Ok(v) => v,
                Err(_) => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"bad txid\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            ops.push(OutPoint { txid, vout: r.vout });
        }
        let mut signatures: Vec<[u8; 64]> = Vec::with_capacity(reqv.signatures.len());
        for s in reqv.signatures.iter() {
            let raw = match hex::decode(s) {
                Ok(v) => v,
                Err(e) => {
                    let mut resp = Response::new(Body::from(format!(
                        "{{\"ok\":false,\"error\":\"bad signature hex: {}\"}}",
                        e
                    )));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            if raw.len() != 64 {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad signature length: {}\"}}",
                    raw.len()
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&raw);
            signatures.push(arr);
        }
        let mut public_keys: Vec<[u8; 32]> = Vec::with_capacity(reqv.public_keys.len());
        for s in reqv.public_keys.iter() {
            let raw = match hex::decode(s) {
                Ok(v) => v,
                Err(e) => {
                    let mut resp = Response::new(Body::from(format!(
                        "{{\"ok\":false,\"error\":\"bad public_key hex: {}\"}}",
                        e
                    )));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            if raw.len() != 32 {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad public_key length: {}\"}}",
                    raw.len()
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            public_keys.push(arr);
        }
        let nonce_raw = match hex::decode(&reqv.nonce) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad nonce hex: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        if nonce_raw.len() != 32 {
            let mut resp = Response::new(Body::from(format!(
                "{{\"ok\":false,\"error\":\"bad nonce length: {}\"}}",
                nonce_raw.len()
            )));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_raw);
        if ops.len() != signatures.len() || ops.len() != public_keys.len() {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"ops/signatures/public_keys length mismatch\"}"
                    .to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let st_mutex = match global_state(&mempool_dir) {
            Ok(s) => s,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"state_db_unavailable\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut st = st_mutex.lock().await;
        match st.unbond_outpoints_with_auth(&ops, &signatures, &public_keys, &nonce) {
            Ok(()) => {
                let mut resp = Response::new(Body::from("{\"ok\":true}".to_string()));
                *resp.status_mut() = hyper::StatusCode::OK;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(e) => {
                let mut resp =
                    Response::new(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e)));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
    } else if req.uri().path().starts_with("/mint/") {
        let resp = handle_mint_request(
            req,
            &mempool_dir,
            network_id,
            do_fsync,
            require_auth,
            &auth_token,
        )
        .await?;
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/config" && req.method() == hyper::Method::GET {
        // Return effective rotation/DA-gating config (with defaults).
        // Effektive Rotation-/DA-Gating-Config zurückgeben (mit Defaults).
        let epoch_len = node_rot_cfg
            .as_ref()
            .and_then(|r| r.epoch_len)
            .unwrap_or(10_000);
        let cooldown_anchors = node_rot_cfg
            .as_ref()
            .and_then(|r| r.cooldown_anchors)
            .unwrap_or(10_000);
        let min_attendance_pct = node_rot_cfg
            .as_ref()
            .and_then(|r| r.min_attendance_pct)
            .unwrap_or(50);
        let payload_wait_timeout_secs = node_da_cfg
            .as_ref()
            .and_then(|d| d.payload_wait_timeout_secs)
            .unwrap_or(3);
        let retry_initial_delay_ms = node_da_cfg
            .as_ref()
            .and_then(|d| d.retry_initial_delay_ms)
            .unwrap_or(100);
        let retry_max_delay_ms = node_da_cfg
            .as_ref()
            .and_then(|d| d.retry_max_delay_ms)
            .unwrap_or(300);
        let retry_max_retries = node_da_cfg
            .as_ref()
            .and_then(|d| d.retry_max_retries)
            .unwrap_or(2);
        let retry_jitter_pct = node_da_cfg
            .as_ref()
            .and_then(|d| d.retry_jitter_pct)
            .unwrap_or(12);
        let body = serde_json::json!({
            "ok": true,
            "rotation": {
                "epoch_len": epoch_len,
                "cooldown_anchors": cooldown_anchors,
                "min_attendance_pct": min_attendance_pct
            },
            "da_gating": {
                "payload_wait_timeout_secs": payload_wait_timeout_secs,
                "retry_initial_delay_ms": retry_initial_delay_ms,
                "retry_max_delay_ms": retry_max_delay_ms,
                "retry_max_retries": retry_max_retries,
                "retry_jitter_pct": retry_jitter_pct
            }
        })
        .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/set_rotation_context"
        && req.method() == hyper::Method::POST
    {
        // Deprecated: committee selection is on-chain (validator registry + staked UTXOs).
        // Deprecated: Committee-Auswahl ist on-chain (Validator-Registry + gestakte UTXOs).
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"deprecated\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::GONE;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/set_candidates" && req.method() == hyper::Method::POST
    {
        // Deprecated: candidate lists must be derived from the on-chain validator registry.
        // Deprecated: Kandidatenlisten muessen aus der on-chain Validator-Registry kommen.
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"deprecated\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::GONE;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/select_committee"
        && req.method() == hyper::Method::POST
    {
        // Deprecated: committee selection is derived from on-chain state.
        // Deprecated: Committee-Auswahl wird aus dem on-chain State abgeleitet.
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"deprecated\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::GONE;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if (req.uri().path() == "/consensus/select_attestors"
        || req.uri().path() == "/consensus/select_attestors_fair")
        && req.method() == hyper::Method::POST
    {
        // Deprecated: off-chain VRF candidate inputs are removed.
        // Deprecated: Off-chain VRF Kandidaten-Inputs sind entfernt.
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"deprecated\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::GONE;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/attestor_payout_root"
        && req.method() == hyper::Method::POST
    {
        NODE_CONSENSUS_PAYOUT_ROOT_TOTAL.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = rl_pr.as_ref() {
            if !rate_allow(r).await {
                NODE_CONSENSUS_PAYOUT_ROOT_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"rate limited\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::TOO_MANY_REQUESTS;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
        #[derive(serde::Deserialize)]
        struct FeeParamsIn {
            p_base_bp: u16,
            p_prop_bp: u16,
            p_perf_bp: u16,
            p_att_bp: u16,
            d_max: u8,
            perf_weights: Vec<u32>,
        }
        #[derive(serde::Deserialize)]
        struct SeatIn {
            recipient_id: String,
        }
        #[derive(serde::Deserialize)]
        struct RootReq {
            fees_total: u64,
            fee_params: Option<FeeParamsIn>,
            seats: Vec<SeatIn>,
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_PAYOUT_ROOT_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_PAYOUT_ROOT_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let reqv: RootReq = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_PAYOUT_ROOT_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };

        fn hex32(s: &str) -> Option<[u8; 32]> {
            let mut out = [0u8; 32];
            if s.len() != 64 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 32 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        let params = if let Some(p) = reqv.fee_params {
            pc_consensus::FeeSplitParams {
                p_base_bp: p.p_base_bp,
                p_prop_bp: p.p_prop_bp,
                p_perf_bp: p.p_perf_bp,
                p_att_bp: p.p_att_bp,
                d_max: p.d_max,
                perf_weights: p.perf_weights,
            }
        } else {
            pc_consensus::FeeSplitParams::recommended()
        };
        if params.validate().is_err() {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"invalid fee params\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        if reqv.seats.is_empty() {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"empty seats\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(reqv.seats.len());
        for s in reqv.seats.iter() {
            if let Some(id) = hex32(&s.recipient_id) {
                ids.push(id);
            } else {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
        let set = match compute_attestor_payout(reqv.fees_total, &params, &ids) {
            Ok(s) => s,
            Err(_) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"payout failed\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let root = set.payout_root();
        let body =
            serde_json::json!({"ok":true, "payout_root": hex::encode(root), "n_seats": ids.len() })
                .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/attestor_payout_proof"
        && req.method() == hyper::Method::POST
    {
        NODE_CONSENSUS_PAYOUT_PROOF_TOTAL.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = rl_pp.as_ref() {
            if !rate_allow(r).await {
                NODE_CONSENSUS_PAYOUT_PROOF_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"rate limited\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::TOO_MANY_REQUESTS;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
        #[derive(serde::Deserialize)]
        struct FeeParamsIn {
            p_base_bp: u16,
            p_prop_bp: u16,
            p_perf_bp: u16,
            p_att_bp: u16,
            d_max: u8,
            perf_weights: Vec<u32>,
        }
        #[derive(serde::Deserialize)]
        struct SeatIn {
            recipient_id: String,
        }
        #[derive(serde::Deserialize)]
        struct ProofReq {
            fees_total: u64,
            fee_params: Option<FeeParamsIn>,
            seats: Vec<SeatIn>,
            recipient_id: String,
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_PAYOUT_PROOF_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_PAYOUT_PROOF_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let reqv: ProofReq = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_PAYOUT_PROOF_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };

        fn hex32(s: &str) -> Option<[u8; 32]> {
            let mut out = [0u8; 32];
            if s.len() != 64 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 32 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        let params = if let Some(p) = reqv.fee_params {
            pc_consensus::FeeSplitParams {
                p_base_bp: p.p_base_bp,
                p_prop_bp: p.p_prop_bp,
                p_perf_bp: p.p_perf_bp,
                p_att_bp: p.p_att_bp,
                d_max: p.d_max,
                perf_weights: p.perf_weights,
            }
        } else {
            pc_consensus::FeeSplitParams::recommended()
        };
        if params.validate().is_err() {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"invalid fee params\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        if reqv.seats.is_empty() {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"empty seats\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }
        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(reqv.seats.len());
        for s in reqv.seats.iter() {
            if let Some(id) = hex32(&s.recipient_id) {
                ids.push(id);
            } else {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
        let set = match compute_attestor_payout(reqv.fees_total, &params, &ids) {
            Ok(s) => s,
            Err(_) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"payout failed\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let target = match hex32(&reqv.recipient_id) {
            Some(v) => v,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(set.entries.len());
        let mut idx: Option<usize> = None;
        for (i, e) in set.entries.iter().enumerate() {
            leaves.push(payout_leaf_hash(&e.recipient_id, e.amount));
            if e.recipient_id == target {
                idx = Some(i);
            }
        }
        let index = if let Some(i) = idx {
            i
        } else {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"recipient not found\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        };
        let leaf = if let Some(v) = leaves.get(index) {
            *v
        } else {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"internal: bad index\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        };
        let proof = merkle_build_proof(&leaves, index);
        let root = set.payout_root();
        #[derive(serde::Serialize)]
        struct StepOut {
            hash: String,
            right: bool,
        }
        let steps: Vec<StepOut> = proof
            .into_iter()
            .map(|s| StepOut {
                hash: hex::encode(s.hash),
                right: s.right,
            })
            .collect();
        let body = serde_json::json!({
            "ok": true,
            "index": index,
            "leaf": hex::encode(leaf),
            "payout_root": hex::encode(root),
            "proof": steps
        })
        .to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/attestor_aggregate_sigs"
        && req.method() == hyper::Method::POST
    {
        NODE_CONSENSUS_AGG_SIGS_TOTAL.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = rl_as.as_ref() {
            if !rate_allow(r).await {
                NODE_CONSENSUS_AGG_SIGS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"rate limited\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::TOO_MANY_REQUESTS;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
        #[derive(serde::Deserialize)]
        struct AggReq {
            parts: Vec<String>,
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_AGG_SIGS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_AGG_SIGS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let reqv: AggReq = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_AGG_SIGS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let mut sigs: Vec<[u8; 96]> = Vec::with_capacity(reqv.parts.len());
        for s in reqv.parts.iter() {
            if s.len() != 192 {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad sig length\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            let mut arr = [0u8; 96];
            match hex::decode(s) {
                Ok(b) if b.len() == 96 => {
                    arr.copy_from_slice(&b);
                    sigs.push(arr);
                }
                _ => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"bad sig hex\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            }
        }
        match attestor_aggregate_sigs(&sigs) {
            Some(agg) => {
                let body = serde_json::json!({"ok":true, "agg_sig": hex::encode(agg)}).to_string();
                let mut resp = Response::new(Body::from(body));
                *resp.status_mut() = hyper::StatusCode::OK;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"aggregate failed\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
    } else if req.uri().path() == "/consensus/attestor_fast_verify"
        && req.method() == hyper::Method::POST
    {
        NODE_CONSENSUS_FAST_VERIFY_TOTAL.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = rl_fv.as_ref() {
            if !rate_allow(r).await {
                NODE_CONSENSUS_FAST_VERIFY_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"rate limited\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::TOO_MANY_REQUESTS;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
        #[derive(serde::Deserialize)]
        struct VerifyReq {
            network_id: String,
            epoch: u64,
            topic: String,
            bls_pks: Vec<String>,
            agg_sig: String,
        }
        fn hex32(s: &str) -> Option<[u8; 32]> {
            let mut out = [0u8; 32];
            if s.len() != 64 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 32 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        fn hex48(s: &str) -> Option<[u8; 48]> {
            let mut out = [0u8; 48];
            if s.len() != 96 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 48 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        fn hex96(s: &str) -> Option<[u8; 96]> {
            let mut out = [0u8; 96];
            if s.len() != 192 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 96 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_FAST_VERIFY_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_FAST_VERIFY_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let reqv: VerifyReq = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_FAST_VERIFY_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let nid = match hex32(&reqv.network_id) {
            Some(v) => v,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad network_id\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let topic_bytes = match hex::decode(&reqv.topic) {
            Ok(v) => v,
            Err(_) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad topic hex\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let msg = attestation_message(&nid, reqv.epoch, &topic_bytes);
        let mut pks: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(reqv.bls_pks.len());
        for s in reqv.bls_pks.iter() {
            let kb = match hex48(s) {
                Some(v) => v,
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            let pk = match bls_pk_from_bytes(&kb) {
                Some(p) => p,
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            pks.push(pk);
        }
        let agg = match hex96(&reqv.agg_sig) {
            Some(v) => v,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad agg_sig\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let t0 = Instant::now();
        let ok = bls_fast_aggregate_verify(&msg, &agg, &pks);
        observe_verify(t0.elapsed());
        if ok {
            NODE_CONSENSUS_FAST_VERIFY_VALID_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        let body = serde_json::json!({"ok": true, "valid": ok}).to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/attestor_fast_verify_seats"
        && req.method() == hyper::Method::POST
    {
        NODE_CONSENSUS_FAST_VERIFY_SEATS_TOTAL.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = rl_fvs.as_ref() {
            if !rate_allow(r).await {
                NODE_CONSENSUS_FAST_VERIFY_SEATS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"rate limited\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::TOO_MANY_REQUESTS;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        }
        #[derive(serde::Deserialize)]
        struct SeatIn {
            bls_pk: String,
        }
        #[derive(serde::Deserialize)]
        struct VerifySeatsReq {
            network_id: String,
            epoch: u64,
            topic: String,
            seats: Vec<SeatIn>,
            agg_sig: String,
        }
        fn hex32(s: &str) -> Option<[u8; 32]> {
            let mut out = [0u8; 32];
            if s.len() != 64 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 32 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        fn hex48(s: &str) -> Option<[u8; 48]> {
            let mut out = [0u8; 48];
            if s.len() != 96 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 48 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        fn hex96(s: &str) -> Option<[u8; 96]> {
            let mut out = [0u8; 96];
            if s.len() != 192 {
                return None;
            }
            let raw = hex::decode(s).ok()?;
            if raw.len() != 96 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_HTTP_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => v,
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::TooLarge) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"body too large\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_FAST_VERIFY_SEATS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
            Err(ReadBodyError::Hyper(e)) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_FAST_VERIFY_SEATS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let reqv: VerifySeatsReq = match serde_json::from_slice(&whole) {
            Ok(v) => v,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"bad json: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_CONSENSUS_FAST_VERIFY_SEATS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let nid = match hex32(&reqv.network_id) {
            Some(v) => v,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad network_id\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let topic_bytes = match hex::decode(&reqv.topic) {
            Ok(v) => v,
            Err(_) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad topic hex\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let msg = attestation_message(&nid, reqv.epoch, &topic_bytes);
        let mut pks: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(reqv.seats.len());
        for s in reqv.seats.iter() {
            let kb = match hex48(&s.bls_pk) {
                Some(v) => v,
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            let pk = match bls_pk_from_bytes(&kb) {
                Some(p) => p,
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
            pks.push(pk);
        }
        let agg = match hex96(&reqv.agg_sig) {
            Some(v) => v,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"bad agg_sig\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let t0 = Instant::now();
        let ok = bls_fast_aggregate_verify(&msg, &agg, &pks);
        observe_verify(t0.elapsed());
        let body = serde_json::json!({"ok": true, "valid": ok}).to_string();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/select_committee_persist"
        && req.method() == hyper::Method::POST
    {
        // Deprecated: no more vrf_committee.json persistence (committee is on-chain).
        // Deprecated: kein vrf_committee.json mehr (Committee ist on-chain).
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"deprecated\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::GONE;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/consensus/current_committee"
        && req.method() == hyper::Method::GET
    {
        // Deprecated: committee is derived from on-chain state, no vrf_committee.json.
        // Deprecated: Committee kommt aus dem on-chain State, kein vrf_committee.json.
        let mut resp = Response::new(Body::from(
            "{\"ok\":false,\"error\":\"deprecated\"}".to_string(),
        ));
        *resp.status_mut() = hyper::StatusCode::GONE;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/tx/broadcast" && req.method() == hyper::Method::POST {
        NODE_RPC_BROADCAST_TOTAL.fetch_add(1, Ordering::Relaxed);
        if !content_type_is_octet_stream(&req) {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"unsupported_media_type\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Ok::<_, anyhow::Error>(resp);
        }
        // Limit request body size while streaming (protect against overly large bodies).
        // Begrenze Request-Body bereits beim Streaming (Schutz gegen zu große Bodies).
        let max = 1_000_000usize; // 1 MB Limit (decimal)
        let limit = std::cmp::min(max, MAX_HTTP_BODY_BYTES);
        let whole =
            match read_body_limited_timeout(req.into_body(), limit, Duration::from_secs(5)).await {
                Ok(b) => b,
                Err(ReadBodyError::Timeout) => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    return Ok::<_, anyhow::Error>(resp);
                }
                Err(ReadBodyError::TooLarge) => {
                    let mut resp = Response::new(Body::from(
                        "{\"ok\":false,\"error\":\"payload too large\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    return Ok::<_, anyhow::Error>(resp);
                }
                Err(ReadBodyError::Hyper(e)) => {
                    let mut resp = Response::new(Body::from(format!(
                        "{{\"ok\":false,\"error\":\"read body: {}\"}}",
                        e
                    )));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    return Ok::<_, anyhow::Error>(resp);
                }
            };
        // Decode MicroTx strictly (no trailing bytes).
        let tx = match pc_codec::decode_exact::<MicroTx>(&whole) {
            Ok(t) => t,
            Err(_e) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"invalid tx\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        if let Err(_e) = validate_microtx_sanity(&tx) {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"tx sanity failed\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok::<_, anyhow::Error>(resp);
        }

        // Stateful validation (prevents disk churn from invalid tx floods).
        // Stateful-Validierung (verhindert Disk-Churn durch ungueltige TX-Floods).
        let nid = match network_id {
            Some(n) => n,
            None => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"network_id_not_configured\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let utxo_mutex = match global_utxo_view(&store_dir) {
            Ok(s) => s,
            Err(e) => {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"utxo_view_unavailable\",\"detail\":\"{}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Ok::<_, anyhow::Error>(resp);
            }
        };
        let st_view = utxo_mutex.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st_view.backend().try_catch_up_with_primary();
        }
        if let Err(e) = st_view.can_apply_micro_tx(&tx, &nid) {
            // Keep "error" stable for backward compatibility; add a structured
            // code so clients can present a useful UX (e.g. UTXO races).
            let state_error = match e {
                pc_state::StateError::MissingInput(_) => "missing_input",
                pc_state::StateError::DoubleSpend(_) => "double_spend",
                pc_state::StateError::AmountMismatch => "amount_mismatch",
                pc_state::StateError::InvalidWitness(_) => "invalid_witness",
                pc_state::StateError::UnbondBadNonce => "unbond_bad_nonce",
                pc_state::StateError::UnsupportedTxVersion(_) => "unsupported_tx_version",
                pc_state::StateError::NotMature(_, _) => "not_mature",
                pc_state::StateError::AlreadyStaked(_) => "already_staked",
                pc_state::StateError::NotStaked(_) => "not_staked",
                pc_state::StateError::Locked(_) => "locked",
                pc_state::StateError::SlashReplay(_) => "slash_replay",
                pc_state::StateError::SlashInvalidBp(_) => "slash_invalid_bp",
                pc_state::StateError::SlashUnknownValidator(_) => "slash_unknown_validator",
                pc_state::StateError::SlashNoStake(_) => "slash_no_stake",
                pc_state::StateError::SlashAmountZero(_) => "slash_amount_zero",
                pc_state::StateError::SnapshotIntegrityError => "snapshot_integrity_error",
                pc_state::StateError::MintedAtFuture(_, _) => "minted_at_future",
                pc_state::StateError::AmountOverflow => "amount_overflow",
            };
            let body = serde_json::json!({
                "ok": false,
                "error": "tx rejected by state",
                "state_error": state_error,
            })
            .to_string();
            let mut resp = Response::new(Body::from(body));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Ok::<_, anyhow::Error>(resp);
        }
        drop(st_view);

        let id = digest_microtx(&tx);
        // Persistenz in Mempool: Datei + Journal (id.hex.bin)
        let _ = tokio::task::spawn_blocking({
            let d = mempool_dir.clone();
            move || std::fs::create_dir_all(&d)
        })
        .await;
        let fname = format!("{}.bin", hex::encode(id));
        let path = std::path::Path::new(&mempool_dir).join(&fname);
        let status = if path.exists() {
            NODE_RPC_BROADCAST_DUP_TOTAL.fetch_add(1, Ordering::Relaxed);
            "duplicate"
        } else {
            let mut buf = Vec::new();
            if let Err(e) = tx.encode(&mut buf) {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"encode: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            if let Err(e) = atomic_write_async(&path, buf.clone(), do_fsync).await {
                let mut resp = Response::new(Body::from(format!(
                    "{{\"ok\":false,\"error\":\"persist: {}\"}}",
                    e
                )));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok::<_, anyhow::Error>(resp);
            }
            let journal = std::path::Path::new(&mempool_dir).join("mempool.journal");
            let _ = journal_append(&journal, do_fsync, b'A', &id);
            NODE_RPC_BROADCAST_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            "accepted"
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let body = format!(
            "{{\"ok\":true,\"txid\":\"{}\",\"status\":\"{}\",\"ts\":{}}}",
            hex::encode(id),
            status,
            ts
        );
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    } else if req.uri().path() == "/api/network_map" && req.method() == hyper::Method::GET {
        let store_parent = std::path::Path::new(&mempool_dir)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| mempool_dir.clone());
        let peers_path = std::path::Path::new(&store_parent).join("peers.json");
        let store = pc_p2p::peer_store::PeerStore::load(&peers_path);
        let counts = store.count_by_role();
        let mut peers_json = Vec::new();
        for p in store.peers.values() {
            let ip_only = p.addr.split(':').next().unwrap_or(&p.addr);
            let role = match p.role_flags {
                1 => "validator",
                2 => "miner",
                _ => "fullnode",
            };
            peers_json.push(format!(
                "{{\"ip\":\"{}\",\"role\":\"{}\",\"last_seen_anchor\":{}}}",
                ip_only, role, p.last_seen_anchor
            ));
        }
        let body = format!(
            "{{\"ok\":true,\"total\":{},\"fullnode\":{},\"validator\":{},\"miner\":{},\"peers\":[{}]}}",
            counts.total, counts.fullnode, counts.validator, counts.miner,
            peers_json.join(",")
        );
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = hyper::StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        return Ok::<_, anyhow::Error>(resp);
    }
    // Fallback 404 (ohne unwrap)
    let mut resp = Response::new(Body::from("Not Found"));
    *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain"),
    );
    Ok::<_, anyhow::Error>(resp)
}

pub(crate) fn run_status_serve(args: &StatusServeArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let from_config_file = args.config.is_some();
        let parsed_cfg: Option<StatusConfig> = if let Some(cfgp) = args.config.as_ref() {
            let raw = std::fs::read_to_string(cfgp).map_err(|e| anyhow!("read config: {e}"))?;
            let cfg: StatusConfig =
                toml::from_str(&raw).map_err(|e| anyhow!("parse config: {e}"))?;
            if cfg.config_version != 1 {
                return Err(anyhow!(
                    "config_version {} wird nicht unterstützt",
                    cfg.config_version
                ));
            }
            Some(cfg)
        } else {
            None
        };
        // Load configuration (file has priority, CLI as fallback).
        // Konfiguration laden (Datei hat Vorrang, CLI fallback).
        let (
            addr_str,
            raw_mempool_dir,
            store_dir_opt,
            do_fsync,
            require_auth,
            auth_token,
            auth_token_file,
            tls_cert,
            tls_key,
            tls_client_ca,
        ) = if let Some(cfg) = parsed_cfg.as_ref() {
            (
                cfg.addr.clone(),
                cfg.mempool_dir.clone(),
                cfg.store_dir.clone(),
                cfg.fsync,
                cfg.require_auth,
                cfg.auth_token.clone(),
                cfg.auth_token_file.clone(),
                cfg.tls_cert.clone(),
                cfg.tls_key.clone(),
                cfg.tls_client_ca.clone(),
            )
        } else {
            (
                args.addr.clone(),
                args.mempool_dir.clone(),
                args.store_dir.clone(),
                args.fsync,
                args.require_auth,
                args.auth_token.clone(),
                args.auth_token_file.clone(),
                args.tls_cert.clone(),
                args.tls_key.clone(),
                args.tls_client_ca.clone(),
            )
        };

        let unsafe_confirm = args.unsafe_confirm;
        let mempool_dir_is_default = raw_mempool_dir.trim().is_empty()
            || raw_mempool_dir.trim() == crate::store_path::LEGACY_MEMPOOL_DIR_SENTINEL;
        let store_dir_path = if let Some(ref p) = store_dir_opt {
            crate::store_path::resolve_store_dir_value(p, unsafe_confirm)?
        } else if mempool_dir_is_default {
            crate::store_path::default_runtime_store_dir()?
        } else {
            let mempool_path =
                crate::store_path::resolve_explicit_dir_value(&raw_mempool_dir, unsafe_confirm, "mempool_dir")?;
            mempool_path
                .parent()
                .ok_or_else(|| anyhow!("mempool_dir hat kein Parent-Verzeichnis"))?
                .to_path_buf()
        };
        let mempool_dir_path = if mempool_dir_is_default {
            store_dir_path.join("mempool")
        } else {
            crate::store_path::resolve_explicit_dir_value(&raw_mempool_dir, unsafe_confirm, "mempool_dir")?
        };
        let store_dir = store_dir_path.to_string_lossy().to_string();
        let mempool_dir = mempool_dir_path.to_string_lossy().to_string();
        if let Some(ref p) = auth_token_file {
            ensure_absolute_path("auth_token_file", p, unsafe_confirm)?;
        }
        if let Some(ref p) = tls_cert {
            ensure_absolute_path("tls_cert", p, unsafe_confirm)?;
        }
        if let Some(ref p) = tls_key {
            ensure_absolute_path("tls_key", p, unsafe_confirm)?;
        }
        if let Some(ref p) = tls_client_ca {
            ensure_absolute_path("tls_client_ca", p, unsafe_confirm)?;
        }

        // Best-effort hardening: ensure secret files aren't world-readable.
        // Best-Effort Härtung: Secret-Files nicht world-readable lassen.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fn fix_0600(p: &str) {
                if let Ok(md) = std::fs::metadata(p) {
                    let mode = md.permissions().mode() & 0o777;
                    if (mode & 0o077) != 0 {
                        let mut perms = md.permissions();
                        perms.set_mode(0o600);
                        let _ = std::fs::set_permissions(p, perms);
                    }
                }
            }
            if let Some(ref p) = auth_token_file {
                fix_0600(p);
            }
            if let Some(ref p) = tls_key {
                fix_0600(p);
            }
        }

        if !from_config_file
            && !cfg!(debug_assertions)
            && auth_token.is_some()
            && auth_token_file.is_none()
        {
            return Err(anyhow!(
                "--auth-token ist in Release-Builds deaktiviert (Token-Leak via Prozessliste). Nutze --auth-token-file oder PHANTOM_STATUS_AUTH_TOKEN."
            ));
        }

        // Resolve auth token: file overrides inline token. Env is used as a fallback.
        // Auth-Token aufloesen: Datei hat Vorrang vor Inline-Token. Env ist Fallback.
        let mut auth_token: Option<String> = auth_token;
        if let Some(p) = auth_token_file.as_ref() {
            let raw = std::fs::read_to_string(p).map_err(|e| anyhow!("read auth_token_file: {e}"))?;
            let t = raw.trim().to_string();
            auth_token = Some(t);
        }
        if auth_token.as_deref().unwrap_or("").trim().is_empty() {
            auth_token = None;
        }
        if auth_token.is_none() {
            if let Ok(env_t) = std::env::var("PHANTOM_STATUS_AUTH_TOKEN") {
                let tt = env_t.trim().to_string();
                if !tt.is_empty() {
                    auth_token = Some(tt);
                }
            }
        }

        // CLI override: --no-require-auth always disables auth (still requires --unsafe-confirm below).
        // CLI Override: --no-require-auth deaktiviert Auth immer (erfordert weiterhin --unsafe-confirm).
        let mut require_auth: bool = require_auth;
        if args.no_require_auth {
            require_auth = false;
        }

        // Enforce explicit confirmation for running without auth.
        // Explizite Bestaetigung erzwingen, falls ohne Auth gestartet wird.
        if !require_auth && !unsafe_confirm {
            return Err(anyhow!(
                "StatusServe ohne Auth ist unsicher. Setze require_auth=true oder starte mit --unsafe-confirm."
            ));
        }
        if require_auth {
            let expected = auth_token.as_deref().unwrap_or("").trim();
            if expected.is_empty() {
                return Err(anyhow!(
                    "require_auth=true, aber auth_token/auth_token_file ist leer oder fehlt"
                ));
            }
        }
        if let Some(ref p) = args.genesis_note {
            ensure_absolute_path("genesis_note", p, unsafe_confirm)?;

            let target = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
            let buf = match tokio::task::spawn_blocking({
                let p2 = p.clone();
                move || std::fs::read(&p2)
            })
            .await
            {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    return Err(anyhow!("kann genesis_note '{}' nicht lesen: {e}", p))
                }
                Err(e) => return Err(anyhow!("kann genesis_note '{}' nicht lesen: {e}", p)),
            };

            let note = decode_genesis_note_exact(&buf)
                .map_err(|e| anyhow!("genesis_note '{}' ist ungültig: {e}", p))?;
            let _nid = digest_genesis_note(&note);

            match tokio::task::spawn_blocking({
                let t = target.clone();
                move || std::fs::read(&t)
            })
            .await
            {
                Ok(Ok(cur)) => {
                    if cur != buf {
                        return Err(anyhow!(
                            "genesis_note passt nicht zu mempool_dir/genesis_note.bin"
                        ));
                    }
                }
                Ok(Err(e)) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        atomic_write_async(&target, buf, do_fsync)
                            .await
                            .map_err(|e| anyhow!("kann genesis_note.bin nicht schreiben: {e}"))?;
                    } else {
                        return Err(anyhow!("kann genesis_note.bin nicht lesen: {e}"));
                    }
                }
                Err(e) => return Err(anyhow!("kann genesis_note.bin nicht lesen: {e}")),
            }
        }
        // Load VRF rotation config (optional).
        // VRF-Rotation-Config laden (optional).
        let mut node_rot_cfg: Option<NodeRotationCfg> = parsed_cfg
            .as_ref()
            .and_then(|cfg| cfg.consensus.as_ref().and_then(|c| c.rotation.clone()));
        // Load DA gating config (optional).
        // DA-Gating-Config laden (optional).
        let node_da_cfg: Option<NodeDaGatingCfg> = parsed_cfg
            .as_ref()
            .and_then(|cfg| cfg.consensus.as_ref().and_then(|c| c.da_gating.clone()));
        // Load HTTP rate limits (optional).
        // HTTP-Rate-Limits laden (optional).
        let http_rate_cfg: Option<HttpRateCfg> =
            parsed_cfg.as_ref().and_then(|cfg| cfg.http_rate.clone());
        // Apply CLI overrides (if set).
        // CLI-Overrides anwenden (falls gesetzt).
        if let Some(v) = args.vrf_epoch_len {
            if let Some(ref mut r) = node_rot_cfg { r.epoch_len = Some(v); }
            else { node_rot_cfg = Some(NodeRotationCfg{ epoch_len: Some(v), cooldown_anchors: None, min_attendance_pct: None }); }
        }
        if let Some(v) = args.vrf_cooldown_anchors {
            if let Some(ref mut r) = node_rot_cfg { r.cooldown_anchors = Some(v); }
            else { node_rot_cfg = Some(NodeRotationCfg{ epoch_len: None, cooldown_anchors: Some(v), min_attendance_pct: None }); }
        }
        if let Some(v) = args.vrf_min_attendance_pct {
            if let Some(ref mut r) = node_rot_cfg { r.min_attendance_pct = Some(v); }
            else { node_rot_cfg = Some(NodeRotationCfg{ epoch_len: None, cooldown_anchors: None, min_attendance_pct: Some(v) }); }
        }
        // bootstrap_k1 is not used.
        // bootstrap_k1 wird nicht verwendet.

        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &addr_str))?;
        if !addr.ip().is_loopback() {
            return Err(anyhow!(
                "status server darf nur auf 127.0.0.1 oder ::1 binden"
            ));
        }
        let consensus_tls_only = tls_client_ca.is_some();

        let network_id: Option<[u8; 32]> = {
            let p = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
            match std::fs::read(&p) {
                Ok(buf) => {
                    match decode_genesis_note_exact(&buf) {
                        Ok(note) => Some(digest_genesis_note(&note)),
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            }
        };
        // Clones for HTTP server branch (plain HTTP).
        // Klone für HTTP-Server-Branch (Plain-HTTP).
        let mempool_dir_http = mempool_dir.clone();
        let store_dir_http = store_dir.clone();
        let auth_token_http = auth_token.clone();
        let node_rot_cfg_http = node_rot_cfg.clone();
        let node_da_cfg_http = node_da_cfg.clone();
        let network_id_http = network_id;
        let unsafe_confirm_http = unsafe_confirm;
        // HTTP rate limiter buckets (optional).
        // HTTP Rate-Limiter Buckets (optional).
        let rl_pr = http_rate_cfg.as_ref().and_then(|h| h.attestor_payout_root.as_ref()).map(|r| Arc::new(tokio::sync::Mutex::new(SimpleRate::new(r))));
        let rl_pp = http_rate_cfg.as_ref().and_then(|h| h.attestor_payout_proof.as_ref()).map(|r| Arc::new(tokio::sync::Mutex::new(SimpleRate::new(r))));
        let rl_as = http_rate_cfg.as_ref().and_then(|h| h.attestor_aggregate_sigs.as_ref()).map(|r| Arc::new(tokio::sync::Mutex::new(SimpleRate::new(r))));
        let rl_fv = http_rate_cfg.as_ref().and_then(|h| h.attestor_fast_verify.as_ref()).map(|r| Arc::new(tokio::sync::Mutex::new(SimpleRate::new(r))));
        let rl_fvs = http_rate_cfg.as_ref().and_then(|h| h.attestor_fast_verify_seats.as_ref()).map(|r| Arc::new(tokio::sync::Mutex::new(SimpleRate::new(r))));
        // Keep a copy for the TLS branch as well (make_service_fn moves its captures).
        // Kopie auch fuer den TLS-Branch behalten (make_service_fn moved seine Captures).
        let rl_pr_tls = rl_pr.clone();
        let rl_pp_tls = rl_pp.clone();
        let rl_as_tls = rl_as.clone();
        let rl_fv_tls = rl_fv.clone();
        let rl_fvs_tls = rl_fvs.clone();
        let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
            let peer_ip = conn.remote_addr().ip();
            let mempool_dir = mempool_dir_http.clone();
            let store_dir = store_dir_http.clone();
            let do_fsync = do_fsync;
            let network_id = network_id_http;

            let auth_token = auth_token_http.clone();
            let node_rot_cfg = node_rot_cfg_http.clone();
            let node_da_cfg = node_da_cfg_http.clone();
            let unsafe_confirm = unsafe_confirm_http;
            let rl_pr = rl_pr.clone();
            let rl_pp = rl_pp.clone();
            let rl_as = rl_as.clone();
            let rl_fv = rl_fv.clone();
            let rl_fvs = rl_fvs.clone();
            async move {
                Ok::<_, anyhow::Error>(service_fn(move |req: Request<Body>| {
                    let mempool_dir = mempool_dir.clone();
                    let store_dir = store_dir.clone();
                    let do_fsync = do_fsync;
                    let network_id = network_id;
                    let peer_ip = peer_ip;

                    let auth_token = auth_token.clone();
                    let node_rot_cfg = node_rot_cfg.clone();
                    let node_da_cfg = node_da_cfg.clone();
                    let unsafe_confirm = unsafe_confirm;
                    let rl_pr = rl_pr.clone();
                    let rl_pp = rl_pp.clone();
                    let rl_as = rl_as.clone();
                    let rl_fv = rl_fv.clone();
                    let rl_fvs = rl_fvs.clone();
                    async move {
                        let fut = status_serve_handle_request_inner(peer_ip, false, req, mempool_dir, store_dir, do_fsync, network_id, require_auth, auth_token, node_rot_cfg, node_da_cfg, unsafe_confirm, consensus_tls_only, rl_pr, rl_pp, rl_as, rl_fv, rl_fvs);
                        match tokio::time::timeout(Duration::from_secs(2), fut).await {
                            Ok(r) => r,
                            Err(_) => {
                                let mut resp = Response::new(Body::from("Gateway Timeout"));
                                *resp.status_mut() = hyper::StatusCode::GATEWAY_TIMEOUT;
                                resp.headers_mut().insert(
                                    hyper::header::CONTENT_TYPE,
                                    hyper::header::HeaderValue::from_static("text/plain"),
                                );
                                Ok::<_, anyhow::Error>(resp)
                            }
                        }
                    }
                }))
            }
        });
        // TLS optional aktivieren
        if let (Some(cert_path), Some(key_path)) = (tls_cert.as_ref(), tls_key.as_ref()) {
            let tls_cfg = build_tls_config(cert_path, key_path, tls_client_ca.as_deref())?;
            let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
            let listener = TcpListener::bind(addr).await.map_err(|e| anyhow!("bind tls addr: {e}"))?;
            info!(addr = %addr, "status server listening (https)");
            loop {
                let (tcp, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => { warn!(error = %e, "tls accept error"); continue; }
                };
		                let peer_ip = peer.ip();
		                let acceptor = acceptor.clone();
		                let mempool_dir = mempool_dir.clone();
		                let store_dir = store_dir.clone();
		                let auth_token = auth_token.clone();
                        let node_rot_cfg = node_rot_cfg.clone();
                        let node_da_cfg = node_da_cfg.clone();
                        let rl_pr = rl_pr_tls.clone();
                        let rl_pp = rl_pp_tls.clone();
                        let rl_as = rl_as_tls.clone();
                        let rl_fv = rl_fv_tls.clone();
                        let rl_fvs = rl_fvs_tls.clone();

		                tokio::spawn(async move {
		                    match acceptor.accept(tcp).await {
		                        Ok(tls) => {
	                            let svc = service_fn(move |req: Request<Body>| {
	                                let mempool_dir = mempool_dir.clone();
	                                let store_dir = store_dir.clone();
	                                let auth_token = auth_token.clone();
                                    let node_rot_cfg = node_rot_cfg.clone();
                                    let node_da_cfg = node_da_cfg.clone();
                                    let rl_pr = rl_pr.clone();
                                    let rl_pp = rl_pp.clone();
                                    let rl_as = rl_as.clone();
                                    let rl_fv = rl_fv.clone();
                                    let rl_fvs = rl_fvs.clone();
	                                let do_fsync = do_fsync;
	                                let network_id = network_id;
	                                let unsafe_confirm = unsafe_confirm;
	                                let peer_ip = peer_ip;

	                                async move {
                                    let fut = status_serve_handle_request_inner(peer_ip, true, req, mempool_dir, store_dir, do_fsync, network_id, require_auth, auth_token, node_rot_cfg, node_da_cfg, unsafe_confirm, consensus_tls_only, rl_pr, rl_pp, rl_as, rl_fv, rl_fvs);
                                match tokio::time::timeout(Duration::from_secs(2), fut).await {
                                    Ok(r) => r,
                                    Err(_) => {
                                        let mut resp = Response::new(Body::from("Gateway Timeout"));
                                        *resp.status_mut() = hyper::StatusCode::GATEWAY_TIMEOUT;
                                        resp.headers_mut().insert(
                                            hyper::header::CONTENT_TYPE,
                                            hyper::header::HeaderValue::from_static("text/plain"),
                                        );
                                        Ok::<_, anyhow::Error>(resp)
                                    }
                                }
                            }
                        });
                            if let Err(e) = hyper::server::conn::Http::new().serve_connection(tls, svc).await {
                                warn!(error = %e, "serve tls conn error");
                            }
                        }
                        Err(e) => warn!(error = %e, "tls handshake error"),
                    }
                });
            }
        } else {
            info!(addr = %addr, "status server listening (http)");
            let server = Server::bind(&addr).serve(make_svc);
            if let Err(e) = server.await {
                warn!(error = %e, "status server error");
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn build_tls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = load_certs(cert_path)?;
    let key: PrivateKeyDer<'static> = load_key(key_path)?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("tls single_cert: {e}"))?;
    if let Some(ca) = client_ca_path {
        let roots = load_roots(ca)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| anyhow!("client verifier: {e}"))?;
        cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(load_certs(cert_path)?, load_key(key_path)?)
            .map_err(|e| anyhow!("tls single_cert client: {e}"))?;
    }
    Ok(cfg)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let bytes = std::fs::read(path).map_err(|e| anyhow!("read certs: {e}"))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("parse certs pem: {e}"))?;
    if certs.is_empty() {
        return Ok(vec![CertificateDer::from(bytes)]);
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::{Error as PemError, PemObject};
    let bytes = std::fs::read(path).map_err(|e| anyhow!("read key: {e}"))?;
    match PrivateKeyDer::from_pem_slice(&bytes) {
        Ok(k) => Ok(k),
        Err(PemError::NoItemsFound) => PrivateKeyDer::try_from(bytes.as_slice())
            .map(|k| k.clone_key())
            .map_err(|e| anyhow!("invalid key der: {e}")),
        Err(e) => Err(anyhow!("parse key pem: {e}")),
    }
}

fn load_roots(path: &str) -> Result<rustls::RootCertStore> {
    use rustls::pki_types::pem::PemObject;
    let bytes = std::fs::read(path).map_err(|e| anyhow!("read ca: {e}"))?;
    let mut store = rustls::RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("parse ca pem: {e}"))?;
    let certs = if certs.is_empty() {
        vec![CertificateDer::from(bytes)]
    } else {
        certs
    };
    let (added, _ignored) = store.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("no CA certs loaded from {}", path));
    }
    Ok(store)
}

#[derive(Debug, Clone, Args)]
pub(crate) struct StatusServeArgs {
    /// Path to a node configuration file (TOML). Takes precedence over CLI flags.
    /// Pfad zu einer Node-Konfigurationsdatei (TOML). Hat Vorrang vor CLI-Flags.
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    unsafe_confirm: bool,
    /// HTTP listen address, e.g. 127.0.0.1:8080.
    /// HTTP Listen-Adresse, z. B. 127.0.0.1:8080.
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: String,
    /// Mempool directory for incoming transactions.
    /// Mempool-Verzeichnis für eingehende Transaktionen.
    #[arg(long, default_value_t = crate::store_path::default_runtime_mempool_dir_string())]
    mempool_dir: String,
    /// Store directory (contains utxo/, headers/, payloads/, anchor_index, ...).
    /// Used for stateful validation (e.g. /tx/broadcast) and for reading the current anchor index.
    ///
    /// If not set, it is inferred from mempool_dir's parent directory.
    /// Store-Verzeichnis (enthaelt utxo/, headers/, payloads/, anchor_index, ...).
    /// Wird fuer stateful Validation (z. B. /tx/broadcast) und zum Lesen des Anchor-Index verwendet.
    ///
    /// Wenn nicht gesetzt, wird es aus dem Parent-Verzeichnis von mempool_dir abgeleitet.
    #[arg(long)]
    store_dir: Option<String>,
    #[arg(long)]
    genesis_note: Option<String>,
    /// Perform fsync() on files and directories.
    /// fsync() auf Dateien/Verzeichnisse.
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// Require bearer token for all non-public endpoints (default: true).
    /// Bearer-Token für alle nicht-öffentlichen Endpoints erzwingen (Default: true).
    #[arg(long, default_value_t = true)]
    require_auth: bool,
    /// Disable bearer token auth (unsafe; requires --unsafe-confirm).
    /// Bearer-Token Auth deaktivieren (unsicher; erfordert --unsafe-confirm).
    #[arg(long, default_value_t = false)]
    no_require_auth: bool,
    /// Expected bearer token (when --require-auth is set).
    /// Erwartetes Bearer-Token (wenn --require-auth).
    ///
    /// Hinweis: --auth-token ist UNSAFE (Token in Prozessliste). Bevorzuge --auth-token-file
    /// oder PHANTOM_STATUS_AUTH_TOKEN (Env).
    #[arg(long)]
    auth_token: Option<String>,
    /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
    /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
    #[arg(long)]
    auth_token_file: Option<String>,
    /// TLS: server certificate (PEM).
    /// TLS: Server-Zertifikat (PEM).
    #[arg(long)]
    tls_cert: Option<String>,
    /// TLS: server key (PEM, PKCS8 or RSA).
    /// TLS: Server-Schlüssel (PEM, PKCS8 oder RSA).
    #[arg(long)]
    tls_key: Option<String>,
    /// mTLS: client CA (PEM).
    /// mTLS: Client-CA (PEM).
    #[arg(long)]
    tls_client_ca: Option<String>,
    /// VRF: epoch length in anchors (override config).
    /// VRF: Epoch-Länge in Ankern (Override zu config).
    #[arg(long)]
    vrf_epoch_len: Option<u64>,
    /// VRF: cooldown in anchors (override config).
    /// VRF: Cooldown in Ankern (Override zu config).
    #[arg(long)]
    vrf_cooldown_anchors: Option<u64>,
    /// VRF: minimum attendance in percent (override config).
    /// VRF: Mindest-Attendance in Prozent (Override zu config).
    #[arg(long)]
    vrf_min_attendance_pct: Option<u8>,
}
