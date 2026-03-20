// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use lru::LruCache;
use once_cell::sync::OnceCell;
use pc_codec::{self, Encodable};
use pc_consensus::attestation::{
    attestation_message, attestor_aggregate_sigs, committee_precommit_message,
    committee_vote_message, slash_ticket_message,
};
use pc_consensus::finalized_queue::FinalizedQueue;
use pc_consensus::mint_censor_v1::{next_candidate_target_v1, MintCensorParamsV1, WindowStateV1};
use pc_consensus::role_policy::RolePolicy;
use pc_consensus::validator_control::ValidatorControl;
use pc_consensus::{
    compute_ack_distances_for_seats, compute_attestor_payout, compute_committee_payout,
    compute_committee_payout_from_headers, compute_total_payout_root, consts, mint_pow_seed_v1,
    pow_hash, pow_meets, validate_genesis_anchor, validate_mint_pow_bound_v1, AnchorGraphCache,
    ConsensusConfig, ConsensusEngine, FeeSplitParams,
};
use pc_crypto::blake3_32;
use pc_crypto::bls_fast_aggregate_verify;
use pc_crypto::bls_pk_from_bytes;
use pc_crypto::{merkle_build_proof, payout_leaf_hash};
use pc_p2p::async_svc::{
    inbound_subscribe, metrics_snapshot, outbox_deq_inc, OutboundSink, StoreDelegate,
};
use pc_p2p::messages::{
    P2pMessage, PeerInfo, ReqMsg, RespMsg, ROLE_FULLNODE, ROLE_MINER, ROLE_VALIDATOR,
};
use pc_p2p::peer_store::PeerStore;
use pc_p2p::quic_transport::{
    client_config_from_cert, connect, spawn_client_reader, start_server, QuicClientSink,
};
use pc_p2p::RateLimitConfig;
#[cfg(not(feature = "rocksdb"))]
use pc_state::InMemoryBackend;
use pc_state::SlashOpV1;
use pc_state::StateBackend;
use pc_state::UtxoState;
use pc_store::FileStore;
use pc_types::candidate_pow_hash_v1;
use pc_types::cmp_hash_be_u256;
use pc_types::digest_microtx;
use pc_types::genesis_payload_root;
use pc_types::mint_id_v1;
use pc_types::payload_merkle_root;
use pc_types::shard_for_tx;
use pc_types::validate_microtx_sanity;
use pc_types::validate_mint_sanity;
use pc_types::AnchorHeaderV2;
use pc_types::MAX_PAYLOAD_MICROTX;
use pc_types::{
    digest_genesis_note, AnchorPayloadV3, GenesisNote, GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
    GENESIS_FEATURE_MINT_CENSOR_PROOF_V1, GENESIS_FEATURE_MINT_FORCED_INCLUSION_V2,
    GENESIS_FEATURE_ROLE_POLICY_V1,
};
use pc_types::{
    AnchorHeader, AnchorId, AnchorIndex, AnchorPayload, ClaimEvent, EvidenceEvent, EvidenceKind,
    LockCommitment, MicroTx, MintCandidateEvent, MintEvent, MintPoWCertV1, OutPoint, PayoutEntry,
    PayoutSet, TxOut,
};
use phantom_config as pcfg;
use rand::Rng;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::DefaultHasher, BTreeSet, HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
// Metrics-only atomics:
// Relaxed ordering is acceptable for metrics because these counters are not used to make
// consensus/security decisions; they are observability-only.
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, System};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

mod mint_rpc;

fn observe_finality_ms(ms: u64) {
    let us = ms.saturating_mul(1_000);
    NODE_FINALITY_COUNT.fetch_add(1, Ordering::Relaxed);
    NODE_FINALITY_SUM_MICROS.fetch_add(us, Ordering::Relaxed);
    if us <= 50_000 {
        NODE_FINALITY_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 100_000 {
        NODE_FINALITY_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 500_000 {
        NODE_FINALITY_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 1_000_000 {
        NODE_FINALITY_BUCKET_LE_1S.fetch_add(1, Ordering::Relaxed);
    } else if us <= 2_000_000 {
        NODE_FINALITY_BUCKET_LE_2S.fetch_add(1, Ordering::Relaxed);
    } else if us <= 5_000_000 {
        NODE_FINALITY_BUCKET_LE_5S.fetch_add(1, Ordering::Relaxed);
    }
}

fn observe_finality_event_unknown_latency() {
    let submit_ms = NODE_POW_LAST_SUBMIT_MS.swap(0, Ordering::Relaxed);
    if submit_ms > 0 {
        let now_ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let latency = now_ms.saturating_sub(submit_ms);
        if latency > 0 {
            observe_finality_ms(latency);
            return;
        }
    }
    NODE_FINALITY_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn ensure_absolute_path(label: &str, path: &str, unsafe_confirm: bool) -> Result<()> {
    if unsafe_confirm {
        return Ok(());
    }
    if std::path::Path::new(path).is_absolute() {
        return Ok(());
    }
    Err(anyhow!("{} muss ein absoluter Pfad sein", label))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    // Avoid early-return on length mismatch to reduce observable timing signal.
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    let max_len = aa.len().max(bb.len());
    let mut diff: u8 = (aa.len() ^ bb.len()) as u8;
    for i in 0..max_len {
        let x = *aa.get(i).unwrap_or(&0);
        let y = *bb.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    diff == 0
}

fn bearer_auth_ok<B>(req: &Request<B>, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let got = req.headers().get(hyper::header::AUTHORIZATION);
    let Some(val) = got else {
        return false;
    };
    let Ok(s) = val.to_str() else {
        return false;
    };
    let Some(b) = s.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(b, expected)
}

fn is_public_status_endpoint(path: &str, method: &hyper::Method) -> bool {
    // Keep health/status/metrics public for local monitoring.
    if method == hyper::Method::GET
        && matches!(path, "/status" | "/healthz" | "/readyz" | "/metrics")
    {
        return true;
    }
    false
}

fn evidence_is_mint_censor_v1(ev: &EvidenceEvent) -> bool {
    matches!(
        ev.evidence,
        EvidenceKind::MintCandidateV1 { .. }
            | EvidenceKind::MintPoWCertV1 { .. }
            | EvidenceKind::MintCensorshipV1 { .. }
            | EvidenceKind::MintMissingImportV1 { .. }
    )
}

fn mint_censor_evidence_ingest_allowed_with_bits(
    ev: &EvidenceEvent,
    mint_censor_feature_enabled: bool,
    candidate_feature_bits: u64,
    forced_inclusion_v2_enabled: bool,
) -> Result<(), &'static str> {
    match &ev.evidence {
        EvidenceKind::MintCandidateV1 { candidate } => {
            if !mint_censor_feature_enabled {
                return Err("mint-censor candidate evidence while feature disabled");
            }
            pc_types::validate_mint_candidate_features_v1(candidate, candidate_feature_bits)
        }
        EvidenceKind::MintPoWCertV1 { .. } => {
            if !mint_censor_feature_enabled {
                return Err("mint-censor cert evidence while feature disabled");
            }
            if forced_inclusion_v2_enabled {
                Ok(())
            } else {
                Err("mint-censor forced-inclusion v2 evidence while feature disabled")
            }
        }
        EvidenceKind::MintCensorshipV1 { .. } => {
            if mint_censor_feature_enabled {
                Ok(())
            } else {
                Err("mint-censor evidence while feature disabled")
            }
        }
        EvidenceKind::MintMissingImportV1 { .. } => {
            if !mint_censor_feature_enabled {
                return Err("mint-censor missing-import evidence while feature disabled");
            }
            if forced_inclusion_v2_enabled {
                Ok(())
            } else {
                Err("mint-censor forced-inclusion v2 evidence while feature disabled")
            }
        }
        _ => Ok(()),
    }
}

fn mint_censor_evidence_ingest_allowed(
    ev: &EvidenceEvent,
    mint_censor_runtime: Option<&MintCensorRuntimeV1>,
) -> Result<(), &'static str> {
    let (enabled, bits, forced_v2) = match mint_censor_runtime {
        Some(rt) => (
            true,
            rt.params.candidate_feature_bits,
            rt.forced_inclusion_v2_enabled,
        ),
        None => (false, 0, false),
    };
    mint_censor_evidence_ingest_allowed_with_bits(ev, enabled, bits, forced_v2)
}

fn payload_contains_mint_censor_evidences_v1(payload: &AnchorPayloadV3) -> bool {
    payload.evidences.iter().any(evidence_is_mint_censor_v1)
}

fn content_type_is_json<B>(req: &Request<B>) -> bool {
    let Some(ct) = req.headers().get(hyper::header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(s) = ct.to_str() else {
        return false;
    };
    let base = s
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    base == "application/json" || base.ends_with("+json")
}

fn content_type_is_octet_stream<B>(req: &Request<B>) -> bool {
    let Some(ct) = req.headers().get(hyper::header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(s) = ct.to_str() else {
        return false;
    };
    let base = s.split(';').next().unwrap_or("").trim();
    base.eq_ignore_ascii_case("application/octet-stream")
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        let mut it = part.splitn(2, '=');
        let k = it.next().unwrap_or("");
        if k == key {
            return it.next();
        }
    }
    None
}

fn query_param_bool(query: &str, key: &str) -> bool {
    match query_param(query, key) {
        Some("1") => true,
        Some(v) if v.eq_ignore_ascii_case("true") => true,
        _ => false,
    }
}

fn query_param_u64(query: &str, key: &str) -> Option<u64> {
    query_param(query, key).and_then(|v| v.parse::<u64>().ok())
}

async fn readyz_check_mempool_dir(mempool_dir: &str) -> Result<(), String> {
    let path = mempool_dir.to_string();
    match tokio::task::spawn_blocking(move || std::fs::metadata(&path)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("mempool_dir: {}", e)),
        Err(e) => Err(format!("mempool_dir: spawn_blocking join: {}", e)),
    }
}

fn host_is_allowed<B>(req: &Request<B>) -> bool {
    if matches!(req.uri().path(), "/readyz" | "/healthz") {
        return true;
    }
    // Defense in depth: restrict non-health endpoints to loopback hosts.
    // Prefer `Host` header, fall back to URI authority (e.g. HTTP/2 :authority).
    let host = if let Some(hv) = req.headers().get(hyper::header::HOST) {
        let Ok(h) = hv.to_str() else {
            return false;
        };
        h.trim()
    } else if let Some(auth) = req.uri().authority() {
        auth.as_str().trim()
    } else {
        // No host information → reject (except health endpoints above).
        return false;
    };

    let host = if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            &rest[..end]
        } else {
            host
        }
    } else {
        host.split(':').next().unwrap_or(host)
    };

    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[derive(Debug)]
struct TokenBucket {
    cap: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(cap: f64, refill_per_sec: f64) -> Self {
        Self {
            cap,
            refill_per_sec,
            tokens: cap,
            last: Instant::now(),
        }
    }

    fn allow(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        if dt > 0.0 {
            self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.cap);
            self.last = now;
        }
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

async fn finality_verify_rate_allow() -> bool {
    // Global rate limit for expensive BLS finality verification. This caps CPU consumption under
    // malicious inbound header floods while still allowing fast sync bursts.
    const CAP: f64 = 200.0;
    const REFILL_PER_SEC: f64 = 100.0;
    static BUCKET: OnceCell<Mutex<TokenBucket>> = OnceCell::new();
    let b = BUCKET.get_or_init(|| Mutex::new(TokenBucket::new(CAP, REFILL_PER_SEC)));
    let mut g = b.lock().await;
    g.allow(1.0)
}

async fn handle_mint_request(
    req: Request<Body>,
    mempool_dir: &str,
    network_id: Option<[u8; 32]>,
    do_fsync: bool,
    require_auth: bool,
    auth_token: &Option<String>,
) -> Result<Response<Body>> {
    let path = req.uri().path();
    let method = req.method();

    let (longpoll, prev_mint_id_raw, timeout_ms) = match req.uri().query() {
        Some(q) => (
            query_param_bool(q, "longpoll"),
            query_param(q, "prev_mint_id").map(|v| v.to_string()),
            query_param_u64(q, "timeout_ms"),
        ),
        None => (false, None, None),
    };
    let prev_mint_id = prev_mint_id_raw
        .as_deref()
        .and_then(|v| parse_hex32(v).ok());

    if path == "/mint/template" && method == hyper::Method::GET {
        if longpoll {
            match prev_mint_id_raw.as_deref() {
                None => {
                    let mut resp = Response::new(Body::from(
                        "{\"error\":\"prev_mint_id required for longpoll\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok(resp);
                }
                Some(_) if prev_mint_id.is_none() => {
                    let mut resp = Response::new(Body::from(
                        "{\"error\":\"invalid prev_mint_id\"}".to_string(),
                    ));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok(resp);
                }
                _ => {}
            }
        }
        return Ok(mint_rpc::handle_mint_template(
            mempool_dir,
            network_id,
            longpoll,
            prev_mint_id,
            timeout_ms,
        )
        .await);
    }
    if path == "/mint/status" && method == hyper::Method::GET {
        return Ok(mint_rpc::handle_mint_status(mempool_dir).await);
    }
    if path == "/mint/submit" && method == hyper::Method::POST {
        if !content_type_is_json(&req) {
            let mut resp = Response::new(Body::from(
                "{\"ok\":false,\"error\":\"unsupported_media_type\"}".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return Ok(resp);
        }
        if require_auth {
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
                return Ok(resp);
            }
        }
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_MINT_SUBMIT_BODY_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(v) => hyper::body::Bytes::from(v),
            Err(ReadBodyError::Timeout) => {
                let mut resp = Response::new(Body::from(
                    "{\"ok\":false,\"error\":\"read timeout\"}".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return Ok(resp);
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
                return Ok(resp);
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
                return Ok(resp);
            }
        };
        let resp = mint_rpc::handle_mint_submit(mempool_dir, network_id, whole, do_fsync).await;
        return Ok(resp);
    }
    if path.starts_with("/mint/status/") && method == hyper::Method::GET {
        let id_hex = path.strip_prefix("/mint/status/").unwrap_or("");
        return Ok(mint_rpc::handle_mint_status_by_id(mempool_dir, id_hex));
    }

    let mut resp = Response::new(Body::from("Not Found"));
    *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain"),
    );
    Ok(resp)
}

// Max. erlaubte Größe für HTTP-Request-Bodies (1 MiB).
const MAX_HTTP_BODY_BYTES: usize = 1_048_576;
// Mint submit bodies are expected to be small; use a stricter cap.
const MAX_MINT_SUBMIT_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug)]
enum ReadBodyError {
    Timeout,
    TooLarge,
    Hyper(hyper::Error),
}

async fn read_body_limited(
    mut body: Body,
    limit: usize,
) -> std::result::Result<Vec<u8>, ReadBodyError> {
    use hyper::body::HttpBody;
    let mut out: Vec<u8> = Vec::new();
    while let Some(next) = body.data().await {
        let chunk = match next {
            Ok(c) => c,
            Err(e) => return Err(ReadBodyError::Hyper(e)),
        };
        if out.len().saturating_add(chunk.len()) > limit {
            return Err(ReadBodyError::TooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn read_body_limited_timeout(
    body: Body,
    limit: usize,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, ReadBodyError> {
    match tokio::time::timeout(timeout, read_body_limited(body, limit)).await {
        Ok(r) => r,
        Err(_) => Err(ReadBodyError::Timeout),
    }
}

#[cfg(feature = "rocksdb")]
use pc_state::RocksDbBackend;

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    #[cfg(feature = "console")]
    {
        let use_console = std::env::var("PHANTOM_CONSOLE")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false);
        if use_console {
            console_subscriber::init();
            return;
        }
    }
    let env_filter = EnvFilter::from_default_env();
    let fmt_env = std::env::var("PHANTOM_LOG_FORMAT").unwrap_or_else(|_| "compact".to_string());
    let targets = std::env::var("PHANTOM_LOG_TARGETS")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(true);
    let no_time = std::env::var("PHANTOM_LOG_TIME")
        .ok()
        .map(|v| v.eq_ignore_ascii_case("none"))
        .unwrap_or(false);

    match fmt_env.as_str() {
        "json" => {
            let b = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(targets)
                .json();
            if no_time {
                let _ = b.without_time().try_init();
            } else {
                let _ = b.try_init();
            }
        }
        "pretty" => {
            let b = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(targets)
                .pretty();
            if no_time {
                let _ = b.without_time().try_init();
            } else {
                let _ = b.try_init();
            }
        }
        _ => {
            let b = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(targets)
                .compact();
            if no_time {
                let _ = b.without_time().try_init();
            } else {
                let _ = b.try_init();
            }
        }
    }
}

// Globaler State-Helper (RocksDB oder InMemory), mit uhrfreiem minted_at-Index
#[cfg(feature = "rocksdb")]
fn open_rocksdb_primary_with_recovery(path: &str, label: &str) -> Result<RocksDbBackend> {
    match RocksDbBackend::open(path) {
        Ok(db) => Ok(db),
        Err(e) => {
            // Avoid panic-on-startup: attempt a best-effort repair, then retry open.
            warn!(db = %label, path = %path, err = %e, "rocksdb open failed; attempting repair");
            match RocksDbBackend::repair(path) {
                Ok(()) => {}
                Err(re) => {
                    return Err(anyhow!(
                        "rocksdb open failed for {label} at '{path}': {e}. repair failed: {re}. \
hint: run `phantom-node db repair --store-dir <dir>` or `phantom-node db reset --store-dir <dir>`"
                    ));
                }
            }
            RocksDbBackend::open(path).map_err(|e2| {
                anyhow!(
                    "rocksdb open failed for {label} at '{path}' after repair: {e2}. \
hint: run `phantom-node db repair --store-dir <dir>` or `phantom-node db reset --store-dir <dir>`"
                )
            })
        }
    }
}

#[cfg(feature = "rocksdb")]
fn open_rocksdb_secondary_with_recovery(
    primary: &str,
    secondary: &str,
    label: &str,
) -> Result<RocksDbBackend> {
    // First try directly.
    if let Ok(db) = RocksDbBackend::open_secondary(primary, secondary) {
        return Ok(db);
    }

    // Ensure the primary DB exists (create if missing). This may fail due to a live writer lock;
    // in that case we still try to open as secondary, since the DB does exist.
    let _ = RocksDbBackend::open(primary);
    if let Ok(db) = RocksDbBackend::open_secondary(primary, secondary) {
        return Ok(db);
    }

    // If secondary open still fails, try repairing the primary and retry.
    warn!(
        db = %label,
        primary = %primary,
        secondary = %secondary,
        "rocksdb secondary open failed; attempting primary repair"
    );
    if let Err(re) = RocksDbBackend::repair(primary) {
        return Err(anyhow!(
            "rocksdb secondary open failed for {label} (primary='{primary}', secondary='{secondary}'). primary repair failed: {re}. \
hint: run `phantom-node db repair --store-dir <dir>` or `phantom-node db reset --store-dir <dir>`"
        ));
    }

    // Wipe secondary dir (safe: it is a derived view) and retry one last time.
    let _ = std::fs::remove_dir_all(secondary);
    let _ = std::fs::create_dir_all(secondary);
    RocksDbBackend::open_secondary(primary, secondary).map_err(|e| {
        anyhow!(
            "rocksdb secondary open failed for {label} after repair (primary='{primary}', secondary='{secondary}'): {e}. \
hint: run `phantom-node db reset --store-dir <dir>`"
        )
    })
}

#[cfg(feature = "rocksdb")]
fn global_state(mempool_dir: &str) -> Result<&'static Mutex<UtxoState<RocksDbBackend>>> {
    static STATE: OnceCell<Mutex<UtxoState<RocksDbBackend>>> = OnceCell::new();
    STATE.get_or_try_init(|| {
        let path = std::path::Path::new(mempool_dir).join("state.rocks");
        let db = open_rocksdb_primary_with_recovery(&path.to_string_lossy(), "state.rocks")?;
        Ok(Mutex::new(UtxoState::new(db)))
    })
}

#[cfg(not(feature = "rocksdb"))]
fn global_state(_mempool_dir: &str) -> Result<&'static Mutex<UtxoState<InMemoryBackend>>> {
    static STATE: OnceCell<Mutex<UtxoState<InMemoryBackend>>> = OnceCell::new();
    Ok(STATE.get_or_init(|| Mutex::new(UtxoState::new(InMemoryBackend::new()))))
}

// Read-only view on the UTXO DB used by the node (store_dir/utxo).
// Read-only View auf die UTXO-DB des Nodes (store_dir/utxo).
//
// We open it as a RocksDB secondary so it can coexist with the primary writer handle.
// Wir öffnen als RocksDB-Secondary, damit sie parallel zum Primary-Writer laufen kann.
#[cfg(feature = "rocksdb")]
fn global_utxo_view(store_dir: &str) -> Result<&'static Mutex<UtxoState<RocksDbBackend>>> {
    static STATE: OnceCell<Mutex<UtxoState<RocksDbBackend>>> = OnceCell::new();
    STATE.get_or_try_init(|| {
        let primary = std::path::Path::new(store_dir).join("utxo");
        let secondary = std::path::Path::new(store_dir).join("utxo.secondary");
        let _ = std::fs::create_dir_all(&primary);
        let _ = std::fs::create_dir_all(&secondary);
        let primary_s = primary.to_string_lossy();
        let secondary_s = secondary.to_string_lossy();
        let backend = open_rocksdb_secondary_with_recovery(
            primary_s.as_ref(),
            secondary_s.as_ref(),
            "utxo.secondary",
        )?;
        Ok(Mutex::new(UtxoState::new(backend)))
    })
}

#[cfg(not(feature = "rocksdb"))]
fn global_utxo_view(_store_dir: &str) -> Result<&'static Mutex<UtxoState<InMemoryBackend>>> {
    static STATE: OnceCell<Mutex<UtxoState<InMemoryBackend>>> = OnceCell::new();
    Ok(STATE.get_or_init(|| Mutex::new(UtxoState::new(InMemoryBackend::new()))))
}

fn global_supply_state(mempool_dir: &str) -> &'static Mutex<pc_consensus::SupplyState> {
    static SUPPLY: OnceCell<Mutex<pc_consensus::SupplyState>> = OnceCell::new();
    SUPPLY.get_or_init(|| {
        let st = load_supply_state_snapshot(mempool_dir);
        Mutex::new(st)
    })
}

fn normalize_supply_state(mut st: pc_consensus::SupplyState) -> pc_consensus::SupplyState {
    // Backward-compat: older snapshots may predate `pow_bits_min`.
    if st.pow_bits_min == 0 && st.pow_bits != 0 {
        st.pow_bits_min = st.pow_bits;
    }
    if st.pow_bits < st.pow_bits_min {
        st.pow_bits = st.pow_bits_min;
    }
    st
}

fn load_supply_state_from_disk(mempool_dir: &str) -> Option<pc_consensus::SupplyState> {
    let path = std::path::Path::new(mempool_dir).join("supply_state.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<pc_consensus::SupplyState>(&raw).ok())
        .map(normalize_supply_state)
}

fn load_supply_state_snapshot(mempool_dir: &str) -> pc_consensus::SupplyState {
    load_supply_state_from_disk(mempool_dir).unwrap_or_default()
}

pub(crate) fn refresh_supply_state_from_disk(
    mempool_dir: &str,
    st: &mut pc_consensus::SupplyState,
) {
    if let Some(fresh) = load_supply_state_from_disk(mempool_dir) {
        *st = fresh;
    }
}

fn persist_supply_state_sync(mempool_dir: &str, st: &pc_consensus::SupplyState, do_fsync: bool) {
    let path = std::path::Path::new(mempool_dir).join("supply_state.json");
    let raw = match serde_json::to_vec(st) {
        Ok(v) => v,
        Err(e) => {
            warn!(err = %e, "serialize supply_state failed");
            return;
        }
    };
    if let Err(e) = atomic_write(&path, &raw, do_fsync) {
        warn!(path = %path.display(), err = %e, "persist supply_state failed");
    }
}

fn decode_genesis_note_exact(buf: &[u8]) -> Result<GenesisNote, pc_codec::CodecError> {
    pc_codec::decode_exact::<GenesisNote>(buf)
}

fn load_role_policy_from_mempool(mempool_dir: &str) -> Result<Option<RolePolicy>> {
    let mempool_path = std::path::Path::new(mempool_dir);
    let note_path = mempool_path.join("genesis_note.bin");
    if !note_path.exists() {
        return Ok(None);
    }
    let buf = std::fs::read(&note_path)
        .map_err(|e| anyhow!("read genesis_note.bin '{}': {e}", note_path.display()))?;
    let note = decode_genesis_note_exact(&buf)
        .map_err(|e| anyhow!("decode genesis_note.bin '{}': {e}", note_path.display()))?;
    let policy_path = mempool_path.join(pcfg::ROLE_POLICY_FILENAME);
    if (note.params.features & GENESIS_FEATURE_ROLE_POLICY_V1) == 0 {
        if policy_path.exists() {
            warn!(
                "role_policy.json present but GENESIS_FEATURE_ROLE_POLICY_V1 not set; policy ignored"
            );
        }
        return Ok(None);
    }
    if !policy_path.exists() {
        bail!(
            "role_policy.json required (GENESIS_FEATURE_ROLE_POLICY_V1 set) at {}",
            policy_path.display()
        );
    }
    let policy = pcfg::load_role_policy_from_file(&policy_path)
        .map_err(|e| anyhow!("role_policy load failed: {e}"))?;
    let got = policy.commitment();
    let want = note.seed;
    if got != want {
        bail!(
            "role_policy commitment mismatch: computed={}, genesis_note.seed={}",
            hex::encode(got),
            hex::encode(want)
        );
    }
    Ok(Some(policy))
}

pub(crate) fn global_role_policy(mempool_dir: &str) -> Result<Option<Arc<RolePolicy>>> {
    static ROLE_POLICY: OnceCell<Option<Arc<RolePolicy>>> = OnceCell::new();
    ROLE_POLICY
        .get_or_try_init(|| load_role_policy_from_mempool(mempool_dir).map(|p| p.map(Arc::new)))
        .cloned()
}

#[derive(Debug, Clone, Copy)]
struct ValidatorEligibility {
    eligible: bool,
    stake: u64,
    pop_ok: bool,
    policy_ok: bool,
}

fn resolve_validator_id(args: &P2pQuicListenArgs) -> Option<[u8; 32]> {
    if let Some(ref bls_hex) = args.bls_pk {
        if bls_hex.len() != 96 {
            return None;
        }
        let bytes = hex::decode(bls_hex).ok()?;
        if bytes.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        let pk = pc_crypto::bls_pk_from_bytes(&arr)?;
        return Some(pc_crypto::attestor_recipient_id_from_bls(&pk));
    }
    if let Some(ref vid_hex) = args.validator_id {
        return parse_hex32(vid_hex).ok();
    }
    None
}

fn validator_control_path(store_dir: &str) -> PathBuf {
    Path::new(store_dir).join(pcfg::VALIDATOR_CONTROL_FILENAME)
}

fn load_validator_control(path: &Path) -> ValidatorControl {
    match pcfg::load_validator_control_from_file(path) {
        Ok(v) => v,
        Err(e) => {
            warn!(path = %path.display(), err = %e, "validator_control load failed; using fail-closed defaults");
            pcfg::default_validator_control_fail_closed().unwrap_or_else(|e2| {
                warn!(err = %e2, "now_secs failed; using updated_at=0 for fail-closed defaults");
                ValidatorControl::default_fail_closed_at(0)
            })
        }
    }
}

fn bootstrap_validator_eligibility(
    store_dir: &str,
    validator_id: [u8; 32],
    role_policy: Option<&RolePolicy>,
) -> Option<ValidatorEligibility> {
    let mempool_dir = std::path::Path::new(store_dir).join("mempool");
    let mempool_dir_str = mempool_dir.to_string_lossy();
    let note = load_genesis_note_from_mempool(mempool_dir_str.as_ref())?;
    if note.version < 1 {
        return None;
    }
    if (note.params.features & GENESIS_FEATURE_GENESIS_VALIDATORS_V1) == 0 {
        return None;
    }
    for gv in note.genesis_validators.iter() {
        let pk = match bls_pk_from_bytes(&gv.bls_pk) {
            Some(v) => v,
            None => continue,
        };
        let rid = pc_crypto::attestor_recipient_id_from_bls(&pk);
        if rid != validator_id {
            continue;
        }
        let policy_ok = role_policy
            .map(|p| p.allows_validator_id(&rid))
            .unwrap_or(true);
        let pop_ok = pc_crypto::bls_pop_verify(&pk, &gv.bls_pop);
        return Some(ValidatorEligibility {
            eligible: pop_ok && policy_ok,
            stake: 0,
            pop_ok,
            policy_ok,
        });
    }
    None
}

async fn check_validator_eligibility(
    validator_id: Option<[u8; 32]>,
    role_policy: Option<&RolePolicy>,
    store_dir: &str,
) -> ValidatorEligibility {
    let mut policy_ok = true;
    if let Some(vid) = validator_id {
        if let Some(policy) = role_policy {
            policy_ok = policy.allows_validator_id(&vid);
        }
    }
    if validator_id.is_none() {
        return ValidatorEligibility {
            eligible: false,
            stake: 0,
            pop_ok: false,
            policy_ok,
        };
    }
    let vid = validator_id.unwrap_or([0u8; 32]);

    // On-chain source of truth: validator record + staked UTXOs in the state DB.
    // On-Chain Source of Truth: Validator-Record + gestakte UTXOs im State-DB.
    let st_mutex = match global_utxo_view(store_dir) {
        Ok(s) => s,
        Err(e) => {
            warn!(store_dir = %store_dir, err = %e, "utxo view unavailable; validator not eligible");
            if let Some(v) = bootstrap_validator_eligibility(store_dir, vid, role_policy) {
                return v;
            }
            return ValidatorEligibility {
                eligible: false,
                stake: 0,
                pop_ok: false,
                policy_ok,
            };
        }
    };
    let st = st_mutex.lock().await;
    #[cfg(feature = "rocksdb")]
    {
        let _ = st.backend().try_catch_up_with_primary();
    }

    let rec = match st.backend().get_validator_record(&vid) {
        Some(r) => r,
        None => {
            if let Some(v) = bootstrap_validator_eligibility(store_dir, vid, role_policy) {
                return v;
            }
            return ValidatorEligibility {
                eligible: false,
                stake: 0,
                pop_ok: false,
                policy_ok,
            };
        }
    };
    let stake = st.staked_amount_for_lock(&rec.stake_lock);
    let min_stake = consts::MIN_ATTESTOR_STAKE;
    let (pop_ok, rid_matches) = match bls_pk_from_bytes(&rec.bls_pk) {
        Some(pk) => {
            let derived = pc_crypto::attestor_recipient_id_from_bls(&pk);
            (pc_crypto::bls_pop_verify(&pk, &rec.bls_pop), derived == vid)
        }
        None => (false, false),
    };
    let eligible = stake >= min_stake && pop_ok && policy_ok && rid_matches;
    if !eligible {
        if let Some(v) = bootstrap_validator_eligibility(store_dir, vid, role_policy) {
            return v;
        }
    }
    ValidatorEligibility {
        eligible,
        stake,
        pop_ok,
        policy_ok,
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
struct NodeRotationCfg {
    #[serde(default)]
    epoch_len: Option<u64>,
    #[serde(default)]
    cooldown_anchors: Option<u64>,
    #[serde(default)]
    min_attendance_pct: Option<u8>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct NodeDaGatingCfg {
    #[serde(default)]
    payload_wait_timeout_secs: Option<u64>,
    #[serde(default)]
    retry_initial_delay_ms: Option<u64>,
    #[serde(default)]
    retry_max_delay_ms: Option<u64>,
    #[serde(default)]
    retry_max_retries: Option<u32>,
    #[serde(default)]
    retry_jitter_pct: Option<u8>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct NodeConsensusCfg {
    #[serde(default)]
    rotation: Option<NodeRotationCfg>,
    #[serde(default)]
    da_gating: Option<NodeDaGatingCfg>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct HttpRateRule {
    #[serde(default)]
    capacity: u64,
    #[serde(default)]
    refill_per_sec: u64,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
struct HttpRateCfg {
    #[serde(default)]
    select_committee: Option<HttpRateRule>,
    #[serde(default)]
    select_committee_persist: Option<HttpRateRule>,
    #[serde(default)]
    select_attestors: Option<HttpRateRule>,
    #[serde(default)]
    select_attestors_fair: Option<HttpRateRule>,
    #[serde(default)]
    attestor_payout_root: Option<HttpRateRule>,
    #[serde(default)]
    attestor_payout_proof: Option<HttpRateRule>,
    #[serde(default)]
    attestor_aggregate_sigs: Option<HttpRateRule>,
    #[serde(default)]
    attestor_fast_verify: Option<HttpRateRule>,
    #[serde(default)]
    attestor_fast_verify_seats: Option<HttpRateRule>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct StatusConfig {
    config_version: u32,
    addr: String,
    mempool_dir: String,
    #[serde(default)]
    store_dir: Option<String>,
    #[serde(default = "default_true")]
    fsync: bool,
    #[serde(default = "default_true")]
    require_auth: bool,
    #[serde(default)]
    auth_token: Option<String>,
    #[serde(default)]
    auth_token_file: Option<String>,
    #[serde(default)]
    tls_cert: Option<String>,
    #[serde(default)]
    tls_key: Option<String>,
    #[serde(default)]
    tls_client_ca: Option<String>,
    #[serde(default)]
    consensus: Option<NodeConsensusCfg>,
    #[serde(default)]
    http_rate: Option<HttpRateCfg>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug)]
struct CommitteeCache {
    epoch: u64,
    seed_anchor: [u8; 32],
    recipient_ids: Vec<[u8; 32]>,
    seats: Vec<pc_crypto::BlsPublicKey>,
    fee_eligible: Vec<bool>,
    bootstrap_mode: bool,
}

#[derive(Clone, Copy, Debug)]
struct FinalizedPayloadMeta {
    header_id: [u8; 32],
    root: [u8; 32],
    creator_index: u8,
    vote_epoch: u64,
    shard_id: u16,
    state_root: Option<[u8; 32]>,
}

const FINALIZED_PAYLOAD_INDEX_CAP: usize = 10_000;

#[derive(Default, Debug)]
struct FinalizedPayloadIndex {
    by_header_id: HashMap<[u8; 32], FinalizedPayloadMeta>,
    by_payload_root: HashMap<[u8; 32], BTreeSet<[u8; 32]>>,
    insert_order: VecDeque<[u8; 32]>,
}

fn finalized_headers_for_root(
    idx: &FinalizedPayloadIndex,
    root: [u8; 32],
) -> Vec<FinalizedPayloadMeta> {
    let header_ids = match idx.by_payload_root.get(&root) {
        Some(set) => set,
        None => return Vec::new(),
    };
    let mut out: Vec<FinalizedPayloadMeta> = header_ids
        .iter()
        .filter_map(|hid| idx.by_header_id.get(hid).cloned())
        .collect();
    out.sort_by_key(|m| m.header_id);
    out
}

fn cleanup_finalized_header_entry(
    idx: &mut FinalizedPayloadIndex,
    header_id: [u8; 32],
) -> Option<FinalizedPayloadMeta> {
    let meta = idx.by_header_id.remove(&header_id)?;
    if let Some(header_ids) = idx.by_payload_root.get_mut(&meta.root) {
        header_ids.remove(&header_id);
        if header_ids.is_empty() {
            idx.by_payload_root.remove(&meta.root);
        }
    }
    idx.insert_order.retain(|id| *id != header_id);
    Some(meta)
}

fn record_finalized_header(
    idx: &mut FinalizedPayloadIndex,
    h: &AnchorHeaderV2,
) -> Option<FinalizedPayloadMeta> {
    let header_id = h.id_digest();
    if idx.by_header_id.contains_key(&header_id) {
        return None;
    }
    let meta = FinalizedPayloadMeta {
        header_id,
        root: h.payload_hash,
        creator_index: h.creator_index,
        vote_epoch: h.vote_epoch,
        shard_id: h.shard_id,
        state_root: h.state_root,
    };
    idx.by_header_id.insert(header_id, meta);
    idx.by_payload_root
        .entry(h.payload_hash)
        .or_default()
        .insert(header_id);
    idx.insert_order.push_back(header_id);

    while idx.insert_order.len() > FINALIZED_PAYLOAD_INDEX_CAP {
        let Some(oldest) = idx.insert_order.pop_front() else {
            break;
        };
        let Some(old_meta) = idx.by_header_id.remove(&oldest) else {
            continue;
        };
        if let Some(header_ids) = idx.by_payload_root.get_mut(&old_meta.root) {
            header_ids.remove(&oldest);
            if header_ids.is_empty() {
                idx.by_payload_root.remove(&old_meta.root);
            }
        }
    }

    Some(meta)
}

fn queue_pending_payload_with_cap(
    pending: &mut HashMap<[u8; 32], (AnchorPayloadV3, Instant)>,
    order: &mut VecDeque<[u8; 32]>,
    root: [u8; 32],
    payload: AnchorPayloadV3,
    cap: usize,
) {
    if pending.contains_key(&root) {
        return;
    }
    if pending.len() >= cap {
        if let Some(old_key) = order.pop_front() {
            let _ = pending.remove(&old_key);
            warn!(root = %hex::encode(old_key), "evicted oldest pending payload due to cap");
        }
    }
    let _ = pending.insert(root, (payload, Instant::now()));
    order.push_back(root);
}

fn rewind_preaccounted_supply_for_mint(
    candidate: &mut pc_consensus::SupplyState,
    mint: &MintEvent,
) -> Result<()> {
    let mint_total: u64 = mint.outputs.iter().map(|o| o.amount).sum();
    if mint_total == 0 {
        return Ok(());
    }
    let expected_reward = pc_consensus::consts::compute_mint_reward(candidate.mint_height + 1);
    if mint_total > expected_reward {
        bail!(
            "mint output {} exceeds expected reward {}",
            mint_total,
            expected_reward
        );
    }
    let new_supply = candidate.total_supply.saturating_add(mint_total as u128);
    if new_supply > pc_consensus::consts::HARD_CAP_UNITS {
        bail!("mint would exceed hard cap");
    }
    Ok(())
}

async fn compute_payload_payout_root_strict<B: pc_state::StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    network_id: [u8; 32],
    k: u8,
    next_anchor_index: u64,
    _txs: &[MicroTx],
    role_policy: Option<&RolePolicy>,
    local_validator_id: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    let seed_anchor = committee_seed_anchor_from_mempool(mempool_dir)
        .or_else(|| {
            load_genesis_note_from_mempool(mempool_dir).map(|n| pc_types::genesis_payload_root(&n))
        })
        .ok_or_else(|| anyhow!("payout_root: seed_anchor unavailable"))?;

    let staked = compute_committee_from_utxo_state(
        st,
        next_anchor_index,
        seed_anchor,
        k,
        network_id,
        role_policy,
    );
    let bootstrap = compute_committee_from_genesis_note(
        mempool_dir,
        next_anchor_index,
        seed_anchor,
        k,
        network_id,
        role_policy,
    )
    .await;
    let cache = choose_effective_committee(k, staked, bootstrap)
        .ok_or_else(|| anyhow!("payout_root: no committee"))?;

    let creator_index = if let Some(vid) = local_validator_id {
        cache
            .recipient_ids
            .iter()
            .position(|r| *r == vid)
            .unwrap_or(0) as u8
    } else {
        0
    };

    if (creator_index as usize) >= cache.recipient_ids.len() {
        bail!(
            "payout_root: creator_index {} out of range (committee size {})",
            creator_index,
            cache.recipient_ids.len()
        );
    }

    let fees_total: u64 = 0;
    let params = FeeSplitParams::recommended();
    let ack_distances: Vec<Option<u8>> = vec![None; cache.recipient_ids.len()];
    let root = compute_total_payout_root(
        fees_total,
        &params,
        &cache.recipient_ids,
        creator_index as usize,
        &ack_distances,
        &[],
    )
    .map_err(|e| anyhow!("payout_root compute failed: {:?}", e))?;

    Ok(root)
}

async fn compute_payload_payout_root_strict_by_creator_index<B: pc_state::StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    network_id: [u8; 32],
    k: u8,
    next_anchor_index: u64,
    _txs: &[MicroTx],
    role_policy: Option<&RolePolicy>,
    creator_index: u8,
) -> Result<[u8; 32]> {
    let seed_anchor = committee_seed_anchor_from_mempool(mempool_dir)
        .or_else(|| {
            load_genesis_note_from_mempool(mempool_dir).map(|n| pc_types::genesis_payload_root(&n))
        })
        .ok_or_else(|| anyhow!("payout_root: seed_anchor unavailable"))?;

    let staked = compute_committee_from_utxo_state(
        st,
        next_anchor_index,
        seed_anchor,
        k,
        network_id,
        role_policy,
    );
    let bootstrap = compute_committee_from_genesis_note(
        mempool_dir,
        next_anchor_index,
        seed_anchor,
        k,
        network_id,
        role_policy,
    )
    .await;
    let cache = choose_effective_committee(k, staked, bootstrap)
        .ok_or_else(|| anyhow!("payout_root: no committee"))?;
    if (creator_index as usize) >= cache.recipient_ids.len() {
        bail!(
            "payout_root: creator_index {} out of range (committee size {})",
            creator_index,
            cache.recipient_ids.len()
        );
    }

    let fees_total: u64 = 0;
    let params = FeeSplitParams::recommended();
    let ack_distances: Vec<Option<u8>> = vec![None; cache.recipient_ids.len()];
    let root = compute_total_payout_root(
        fees_total,
        &params,
        &cache.recipient_ids,
        creator_index as usize,
        &ack_distances,
        &[],
    )
    .map_err(|e| anyhow!("payout_root compute failed: {:?}", e))?;

    Ok(root)
}

async fn verify_payload_payout_root_against_finalized_headers<B: pc_state::StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    network_id: [u8; 32],
    k: u8,
    next_anchor_index: u64,
    payload: &AnchorPayloadV3,
    role_policy: Option<&RolePolicy>,
    finalized_headers: &[FinalizedPayloadMeta],
) -> Result<FinalizedPayloadMeta> {
    let mut matched: Option<FinalizedPayloadMeta> = None;
    for fh in finalized_headers {
        let expected = compute_payload_payout_root_strict_by_creator_index(
            st,
            mempool_dir,
            network_id,
            k,
            next_anchor_index,
            &payload.micro_txs,
            role_policy,
            fh.creator_index,
        )
        .await;
        match expected {
            Ok(root) if root == payload.payout_root => {
                if let Some(prev) = matched {
                    bail!(
                        "payout_root {:?} matches multiple finalized header candidates: {} and {}",
                        hex::encode(payload.payout_root),
                        hex::encode(prev.header_id),
                        hex::encode(fh.header_id)
                    );
                }
                matched = Some(*fh);
            }
            _ => continue,
        }
    }
    if let Some(meta) = matched {
        return Ok(meta);
    }
    bail!(
        "payout_root {:?} does not match any finalized header candidate",
        hex::encode(payload.payout_root)
    )
}

fn choose_effective_committee(
    k_target: u8,
    staked: Option<CommitteeCache>,
    bootstrap: Option<CommitteeCache>,
) -> Option<CommitteeCache> {
    let target_len = k_target as usize;
    let staked_len = staked.as_ref().map_or(0usize, |c| c.seats.len());

    // Normal mode: only when the target committee is fully available from staked validators.
    if staked_len == target_len && staked_len > 0 {
        if let Some(mut c) = staked {
            c.bootstrap_mode = false;
            return Some(c);
        }
        return None;
    }

    // Emergency mode: keep bootstrap validators active while normal committee is not fully restored.
    if let Some(boot) = bootstrap {
        if !boot.seats.is_empty() {
            let mut c = boot;
            c.bootstrap_mode = true;
            return Some(c);
        }
    }

    // Last resort when no bootstrap set is configured.
    staked.filter(|c| !c.seats.is_empty()).map(|mut c| {
        c.bootstrap_mode = false;
        c
    })
}

fn publish_committee_metrics(cache: Option<&CommitteeCache>) {
    match cache {
        Some(c) => {
            let active = c.seats.len() as u64;
            let fee_eligible = c.fee_eligible.iter().filter(|v| **v).count() as u64;
            NODE_COMMITTEE_ACTIVE_SEATS.store(active, Ordering::Relaxed);
            NODE_COMMITTEE_FEE_ELIGIBLE_SEATS.store(fee_eligible, Ordering::Relaxed);
            NODE_COMMITTEE_BOOTSTRAP_MODE.store(u64::from(c.bootstrap_mode), Ordering::Relaxed);
        }
        None => {
            NODE_COMMITTEE_ACTIVE_SEATS.store(0, Ordering::Relaxed);
            NODE_COMMITTEE_FEE_ELIGIBLE_SEATS.store(0, Ordering::Relaxed);
            NODE_COMMITTEE_BOOTSTRAP_MODE.store(0, Ordering::Relaxed);
        }
    }
}

fn compute_committee_from_utxo_state<B: pc_state::StateBackend>(
    st: &pc_state::UtxoState<B>,
    epoch: u64,
    seed_anchor: [u8; 32],
    k: u8,
    network_id: [u8; 32],
    role_policy: Option<&RolePolicy>,
) -> Option<CommitteeCache> {
    use pc_consensus::committee_hash::{
        derive_committee_seed, select_committee_hash, CommitteeCandidate,
    };
    use pc_crypto::{attestor_recipient_id_from_bls, bls_pk_from_bytes};

    if k == 0 || k > 64 {
        return None;
    }

    // 1) Aggregate stake per lock commitment from on-chain (staked) UTXOs.
    let mut stake_by_lock: HashMap<[u8; 32], u64> = HashMap::new();
    for (_op, entry) in st.backend().iter_full() {
        if !entry.staked {
            continue;
        }
        let key = entry.lock.0;
        let cur = stake_by_lock.get(&key).copied().unwrap_or(0);
        let next = cur.saturating_add(entry.amount);
        let _ = stake_by_lock.insert(key, next);
    }

    // 2) Build committee candidates from the on-chain validator registry.
    let mut candidates: Vec<CommitteeCandidate> = Vec::new();
    for (validator_id, rec) in st.backend().iter_validator_records() {
        if let Some(policy) = role_policy {
            if !policy.allows_validator_id(&validator_id) {
                continue;
            }
        }
        let pk = match bls_pk_from_bytes(&rec.bls_pk) {
            Some(p) => p,
            None => continue,
        };
        // Safety check: ensure the record key matches the BLS-derived recipient id.
        let derived = attestor_recipient_id_from_bls(&pk);
        if derived != validator_id {
            continue;
        }
        let stake = stake_by_lock.get(&rec.stake_lock.0).copied().unwrap_or(0);
        candidates.push(CommitteeCandidate {
            recipient_id: validator_id,
            operator_id: rec.operator_id,
            bls_pk: pk,
            bls_pop: rec.bls_pop,
            stake,
        });
    }

    // 3) Deterministic selection.
    let seed = derive_committee_seed(network_id, seed_anchor, epoch);
    let selected = select_committee_hash(k, seed, &candidates);
    if selected.is_empty() {
        return None;
    }
    let mut recipient_ids: Vec<[u8; 32]> = Vec::with_capacity(selected.len());
    let mut seats: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(selected.len());
    for s in selected {
        recipient_ids.push(s.recipient_id);
        seats.push(s.bls_pk);
    }
    let fee_eligible = vec![true; seats.len()];

    Some(CommitteeCache {
        epoch,
        seed_anchor,
        recipient_ids,
        seats,
        fee_eligible,
        bootstrap_mode: false,
    })
}

async fn compute_committee_from_state(
    mempool_dir: &str,
    epoch: u64,
    seed_anchor: [u8; 32],
    k: u8,
    network_id: [u8; 32],
    role_policy: Option<&RolePolicy>,
) -> Option<CommitteeCache> {
    use pc_consensus::committee_hash::{
        derive_committee_seed, select_committee_hash, CommitteeCandidate,
    };
    use pc_crypto::{attestor_recipient_id_from_bls, bls_pk_from_bytes};

    if k == 0 || k > 64 {
        return None;
    }

    let store_dir = std::path::Path::new(mempool_dir)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());
    let st_mutex = match global_utxo_view(&store_dir) {
        Ok(s) => s,
        Err(e) => {
            warn!(store_dir = %store_dir, err = %e, "utxo view unavailable; committee selection skipped");
            return None;
        }
    };
    let st = st_mutex.lock().await;
    #[cfg(feature = "rocksdb")]
    {
        let _ = st.backend().try_catch_up_with_primary();
    }

    // 1) Aggregate stake per lock commitment from on-chain (staked) UTXOs.
    let mut stake_by_lock: HashMap<[u8; 32], u64> = HashMap::new();
    for (_op, entry) in st.backend().iter_full() {
        if !entry.staked {
            continue;
        }
        let key = entry.lock.0;
        let cur = stake_by_lock.get(&key).copied().unwrap_or(0);
        let next = cur.saturating_add(entry.amount);
        let _ = stake_by_lock.insert(key, next);
    }

    // 2) Build committee candidates from the on-chain validator registry.
    let mut candidates: Vec<CommitteeCandidate> = Vec::new();
    for (validator_id, rec) in st.backend().iter_validator_records() {
        if let Some(policy) = role_policy {
            if !policy.allows_validator_id(&validator_id) {
                continue;
            }
        }
        let pk = match bls_pk_from_bytes(&rec.bls_pk) {
            Some(p) => p,
            None => continue,
        };
        // Safety check: ensure the record key matches the BLS-derived recipient id.
        let derived = attestor_recipient_id_from_bls(&pk);
        if derived != validator_id {
            continue;
        }
        let stake = stake_by_lock.get(&rec.stake_lock.0).copied().unwrap_or(0);
        candidates.push(CommitteeCandidate {
            recipient_id: validator_id,
            operator_id: rec.operator_id,
            bls_pk: pk,
            bls_pop: rec.bls_pop,
            stake,
        });
    }

    // 3) Deterministic selection.
    let seed = derive_committee_seed(network_id, seed_anchor, epoch);
    let selected = select_committee_hash(k, seed, &candidates);
    if selected.is_empty() {
        return None;
    }
    let mut recipient_ids: Vec<[u8; 32]> = Vec::with_capacity(selected.len());
    let mut seats: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(selected.len());
    for s in selected {
        recipient_ids.push(s.recipient_id);
        seats.push(s.bls_pk);
    }
    let fee_eligible = vec![true; seats.len()];

    Some(CommitteeCache {
        epoch,
        seed_anchor,
        recipient_ids,
        seats,
        fee_eligible,
        bootstrap_mode: false,
    })
}

async fn compute_committee_from_genesis_note(
    mempool_dir: &str,
    epoch: u64,
    seed_anchor: [u8; 32],
    k: u8,
    network_id: [u8; 32],
    role_policy: Option<&RolePolicy>,
) -> Option<CommitteeCache> {
    use pc_consensus::committee_hash::{
        derive_committee_seed, select_committee_hash, CommitteeCandidate,
    };
    use pc_crypto::{attestor_recipient_id_from_bls, bls_pk_from_bytes};
    use pc_types::GENESIS_FEATURE_GENESIS_VALIDATORS_V1;

    if k == 0 || k > 64 {
        return None;
    }

    let p = std::path::Path::new(mempool_dir).join("genesis_note.bin");
    let buf = std::fs::read(&p).ok()?;
    let note = decode_genesis_note_exact(&buf).ok()?;
    if digest_genesis_note(&note) != network_id {
        return None;
    }
    if note.version < 1 {
        return None;
    }
    if (note.params.features & GENESIS_FEATURE_GENESIS_VALIDATORS_V1) == 0 {
        return None;
    }

    let mut candidates: Vec<CommitteeCandidate> = Vec::with_capacity(note.genesis_validators.len());
    for gv in note.genesis_validators.iter() {
        let pk = match bls_pk_from_bytes(&gv.bls_pk) {
            Some(p) => p,
            None => continue,
        };
        let rid = attestor_recipient_id_from_bls(&pk);
        if let Some(policy) = role_policy {
            if !policy.allows_validator_id(&rid) {
                continue;
            }
        }
        candidates.push(CommitteeCandidate {
            recipient_id: rid,
            operator_id: gv.operator_id,
            bls_pk: pk,
            bls_pop: gv.bls_pop,
            // Bootstrap: treat genesis validators as having at least minimum stake.
            // Bootstrap: behandle Genesis-Validatoren als >= Mindeststake.
            stake: consts::MIN_ATTESTOR_STAKE,
        });
    }

    let seed = derive_committee_seed(network_id, seed_anchor, epoch);
    let selected = select_committee_hash(k, seed, &candidates);
    if selected.is_empty() {
        return None;
    }
    let mut recipient_ids: Vec<[u8; 32]> = Vec::with_capacity(selected.len());
    let mut seats: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(selected.len());
    for s in selected {
        recipient_ids.push(s.recipient_id);
        seats.push(s.bls_pk);
    }
    // Bootstrap seats may finalize, but unstaked bootstrap validators are never fee-eligible.
    let fee_eligible = vec![false; seats.len()];

    Some(CommitteeCache {
        epoch,
        seed_anchor,
        recipient_ids,
        seats,
        fee_eligible,
        bootstrap_mode: true,
    })
}

fn load_network_id_from_mempool(mempool_dir: &str) -> Option<[u8; 32]> {
    let p = std::path::Path::new(mempool_dir).join("genesis_note.bin");
    let buf = std::fs::read(&p).ok()?;
    let note = decode_genesis_note_exact(&buf).ok()?;
    Some(digest_genesis_note(&note))
}

fn load_genesis_note_from_mempool(mempool_dir: &str) -> Option<GenesisNote> {
    let p = std::path::Path::new(mempool_dir).join("genesis_note.bin");
    let buf = std::fs::read(&p).ok()?;
    decode_genesis_note_exact(&buf).ok()
}

fn load_genesis_features_from_mempool(mempool_dir: &str) -> Option<u64> {
    load_genesis_note_from_mempool(mempool_dir).map(|n| n.params.features)
}

fn committee_seed_anchor_from_mempool(mempool_dir: &str) -> Option<[u8; 32]> {
    let mempool_path = std::path::Path::new(mempool_dir);
    let root_path = mempool_path
        .parent()
        .unwrap_or(mempool_path)
        .join("last_final_payload_root");
    let hex_str = std::fs::read_to_string(&root_path).ok()?;
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
const MINT_WINDOW_OPEN_DOMAIN_V1: &[u8] = b"PHANTOM:MINT:WINDOW:OPEN:v1";

fn mint_censor_feature_enabled(mempool_dir: &str) -> bool {
    load_genesis_note_from_mempool(mempool_dir)
        .map(|n| (n.params.features & GENESIS_FEATURE_MINT_CENSOR_PROOF_V1) != 0)
        .unwrap_or(false)
}

fn mint_forced_inclusion_v2_enabled(mempool_dir: &str) -> bool {
    load_genesis_note_from_mempool(mempool_dir)
        .map(|n| (n.params.features & GENESIS_FEATURE_MINT_FORCED_INCLUSION_V2) != 0)
        .unwrap_or(false)
}

fn pow_bits_to_target_be(bits: u8) -> [u8; 32] {
    if bits == 0 {
        return [0xFF; 32];
    }
    let mut out = [0xFFu8; 32];
    let full_zero_bytes: usize = usize::from(bits / 8);
    let rem_bits: u8 = bits % 8;

    for i in 0..full_zero_bytes {
        if let Some(slot) = out.get_mut(i) {
            *slot = 0;
        }
    }
    if rem_bits != 0 {
        if let Some(slot) = out.get_mut(full_zero_bytes) {
            let keep = 8u8.saturating_sub(rem_bits);
            *slot = (1u8 << keep).saturating_sub(1);
        }
    }
    out
}

fn clamp_target_be(target: [u8; 32], min_target: [u8; 32], max_target: [u8; 32]) -> [u8; 32] {
    if pc_types::cmp_hash_be_u256(&target, &min_target).is_lt() {
        return min_target;
    }
    if pc_types::cmp_hash_be_u256(&target, &max_target).is_gt() {
        return max_target;
    }
    target
}

#[cfg(test)]
fn derive_window_open_anchor_id_v1(
    network_id: &[u8; 32],
    prev_mint_id: &[u8; 32],
    window_id: u64,
    window_open_anchor: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(MINT_WINDOW_OPEN_DOMAIN_V1.len() + 32 + 32 + 8 + 8);
    buf.extend_from_slice(MINT_WINDOW_OPEN_DOMAIN_V1);
    buf.extend_from_slice(network_id);
    buf.extend_from_slice(prev_mint_id);
    buf.extend_from_slice(&window_id.to_le_bytes());
    buf.extend_from_slice(&window_open_anchor.to_le_bytes());
    blake3_32(&buf)
}

fn default_mint_censor_params_v1(
    network_id: [u8; 32],
    pow_bits_init: u8,
    genesis_features: u64,
) -> MintCensorParamsV1 {
    let min_target = pow_bits_to_target_be(consts::MINT_CENSOR_MIN_TARGET_BITS);
    let max_target = pow_bits_to_target_be(consts::MINT_CENSOR_MAX_TARGET_BITS);
    let initial_target =
        clamp_target_be(pow_bits_to_target_be(pow_bits_init), min_target, max_target);
    MintCensorParamsV1 {
        network_id,
        windows_start_anchor: consts::MINT_CENSOR_WINDOWS_START_ANCHOR,
        w: consts::MINT_CENSOR_WINDOW_W,
        k: consts::MINT_CENSOR_WINDOW_K,
        n: consts::MINT_CENSOR_TOP_N,
        e: consts::MINT_CENSOR_EXPECTED_CANDIDATES_E,
        min_target,
        max_target,
        initial_target,
        candidate_feature_bits: pc_types::mint_candidate_feature_bits_from_genesis_features(
            genesis_features,
        ),
    }
}

fn bootstrap_seed_finalized_anchor_ids(
    rt: &mut MintCensorRuntimeV1,
    anchor_index: u64,
    seed_root: [u8; 32],
) -> u64 {
    if seed_root == [0u8; 32] {
        return 0;
    }
    let mut seeded = 0u64;
    let start = rt.params.windows_start_anchor;
    let step = rt.params.w.max(1);
    if anchor_index >= start {
        let mut idx = start;
        while idx <= anchor_index {
            if let std::collections::hash_map::Entry::Vacant(entry) =
                rt.finalized_anchor_ids.entry(idx)
            {
                entry.insert(seed_root);
                seeded = seeded.saturating_add(1);
            }
            idx = idx.saturating_add(step);
        }
    }
    if let std::collections::hash_map::Entry::Vacant(entry) =
        rt.finalized_anchor_ids.entry(anchor_index)
    {
        entry.insert(seed_root);
        seeded = seeded.saturating_add(1);
    }
    seeded
}

fn mine_candidate_nonce_bounded(
    candidate: &MintCandidateEvent,
    target_be: [u8; 32],
    start_nonce: u64,
    max_iters: u64,
) -> (Option<u64>, u64) {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    let num_threads = rayon::current_num_threads().max(1);
    let chunk_size = max_iters / num_threads as u64;
    if chunk_size == 0 {
        let mut local = candidate.clone();
        for i in 0..max_iters {
            let n = start_nonce.wrapping_add(i);
            local.nonce = n;
            let h = candidate_pow_hash_v1(&local);
            if cmp_hash_be_u256(&h, &target_be).is_le() {
                return (Some(n), start_nonce.wrapping_add(max_iters));
            }
        }
        return (None, start_nonce.wrapping_add(max_iters));
    }

    let found = AtomicBool::new(false);
    let found_nonce = AtomicU64::new(0);

    (0..num_threads).into_par_iter().for_each(|tid| {
        let base = start_nonce.wrapping_add(tid as u64 * chunk_size);
        let iters = if tid == num_threads - 1 {
            max_iters.saturating_sub((num_threads as u64 - 1) * chunk_size)
        } else {
            chunk_size
        };
        let mut local = candidate.clone();
        for i in 0..iters {
            if i & 511 == 0 && found.load(Ordering::Relaxed) {
                return;
            }
            let n = base.wrapping_add(i);
            local.nonce = n;
            let h = candidate_pow_hash_v1(&local);
            if cmp_hash_be_u256(&h, &target_be).is_le() {
                found.store(true, Ordering::Relaxed);
                found_nonce.store(n, Ordering::Relaxed);
                return;
            }
        }
    });

    let end_nonce = start_nonce.wrapping_add(max_iters);
    if found.load(Ordering::Relaxed) {
        (Some(found_nonce.load(Ordering::Relaxed)), end_nonce)
    } else {
        (None, end_nonce)
    }
}

#[derive(Debug)]
struct MintCensorRuntimeV1 {
    params: MintCensorParamsV1,
    windows: HashMap<([u8; 32], u64), WindowStateV1>,
    finalized_anchor_ids: HashMap<u64, [u8; 32]>,
    forced_inclusion_v2_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposerMintDecisionV1 {
    None,
    Null,
    Mint([u8; 32]),
}

impl MintCensorRuntimeV1 {
    fn new(params: MintCensorParamsV1) -> Result<Self> {
        Self::new_with_forced_inclusion_v2(params, false)
    }

    fn new_with_forced_inclusion_v2(
        params: MintCensorParamsV1,
        forced_inclusion_v2_enabled: bool,
    ) -> Result<Self> {
        params
            .validate()
            .map_err(|e| anyhow!("mint-censor params invalid: {:?}", e))?;
        Ok(Self {
            params,
            windows: HashMap::new(),
            finalized_anchor_ids: HashMap::new(),
            forced_inclusion_v2_enabled,
        })
    }

    fn window_open_anchor_id_for(&self, window_open_anchor: u64) -> Option<[u8; 32]> {
        self.finalized_anchor_ids.get(&window_open_anchor).copied()
    }

    fn ensure_window_for_id(
        &mut self,
        state_last_mint_id: [u8; 32],
        window_id: u64,
    ) -> Option<([u8; 32], u64)> {
        if window_id > 0 {
            // Ensure predecessor exists so candidate_target(window_i) is always
            // derived from candidate_target(window_{i-1}) + obs_prev_window.
            self.ensure_window_for_id(state_last_mint_id, window_id.saturating_sub(1))?;
        }

        let window_open_anchor = self
            .params
            .windows_start_anchor
            .saturating_add(window_id.saturating_mul(self.params.w));
        let close_anchor = window_open_anchor.saturating_add(self.params.w.saturating_sub(1));
        let deadline_anchor = close_anchor.saturating_add(self.params.k);
        let bounds = pc_consensus::mint_censor_v1::WindowBoundsV1 {
            window_id,
            window_open_anchor,
            close_anchor,
            deadline_anchor,
        };

        let key = (state_last_mint_id, window_id);
        if bounds.window_id > 0 {
            let prev_key = (state_last_mint_id, bounds.window_id.saturating_sub(1));
            if let Some(prev_ws) = self.windows.get_mut(&prev_key) {
                prev_ws.maybe_freeze(bounds.window_open_anchor);
            }
        }

        if !self.windows.contains_key(&key) {
            let candidate_target = if bounds.window_id == 0 {
                self.params.initial_target
            } else {
                let prev_key = (state_last_mint_id, bounds.window_id.saturating_sub(1));
                let prev_ws = self.windows.get(&prev_key)?;
                next_candidate_target_v1(
                    prev_ws.candidate_target,
                    prev_ws.obs_prev_window,
                    self.params.e,
                    self.params.min_target,
                    self.params.max_target,
                )
            };

            let open_id = self.window_open_anchor_id_for(bounds.window_open_anchor)?;
            let ws = WindowStateV1::new(state_last_mint_id, open_id, bounds, candidate_target);
            let _ = self.windows.insert(key, ws);
        }
        Some(key)
    }

    fn ensure_window_for_anchor(
        &mut self,
        next_anchor_index: u64,
        state_last_mint_id: [u8; 32],
    ) -> Option<([u8; 32], u64)> {
        let bounds = self.params.window_bounds_for_anchor(next_anchor_index)?;
        self.ensure_window_for_id(state_last_mint_id, bounds.window_id)
    }

    fn validation_window_key_for_anchor(
        &mut self,
        next_anchor_index: u64,
        state_last_mint_id: [u8; 32],
    ) -> Option<([u8; 32], u64)> {
        let bounds = self.params.window_bounds_for_anchor(next_anchor_index)?;
        let current_key = self.ensure_window_for_anchor(next_anchor_index, state_last_mint_id);

        let mut validate_key = current_key;
        if bounds.window_id > 0 {
            let prev_key = (state_last_mint_id, bounds.window_id.saturating_sub(1));
            if let Some(prev_ws) = self.windows.get_mut(&prev_key) {
                prev_ws.maybe_freeze(next_anchor_index);
                if next_anchor_index <= prev_ws.deadline_anchor {
                    validate_key = Some(prev_key);
                }
            }
        }
        validate_key
    }

    fn candidate_context_for_anchor(
        &mut self,
        next_anchor_index: u64,
        state_last_mint_id: [u8; 32],
    ) -> Option<(u64, [u8; 32], [u8; 32])> {
        let bounds = self.params.window_bounds_for_anchor(next_anchor_index)?;
        if !self
            .finalized_anchor_ids
            .contains_key(&bounds.window_open_anchor)
        {
            return None;
        }
        let key = self.ensure_window_for_anchor(next_anchor_index, state_last_mint_id)?;
        let ws = self.windows.get(&key)?;
        Some((ws.window_id, ws.window_open_anchor_id, ws.candidate_target))
    }

    fn proposal_mint_decision(
        &mut self,
        next_anchor_index: u64,
        state_last_mint_id: [u8; 32],
    ) -> ProposerMintDecisionV1 {
        let Some(bounds) = self.params.window_bounds_for_anchor(next_anchor_index) else {
            tracing::debug!(next_anchor_index, "mint-decision: no bounds");
            return ProposerMintDecisionV1::None;
        };
        let Some(validate_key) =
            self.validation_window_key_for_anchor(next_anchor_index, state_last_mint_id)
        else {
            tracing::debug!(
                next_anchor_index,
                window_id = bounds.window_id,
                "mint-decision: validate_key=None"
            );
            return ProposerMintDecisionV1::None;
        };
        let Some(ws) = self.windows.get_mut(&validate_key) else {
            tracing::debug!(
                next_anchor_index,
                window_id = validate_key.1,
                "mint-decision: window not found"
            );
            return ProposerMintDecisionV1::None;
        };
        ws.maybe_freeze(next_anchor_index);
        if next_anchor_index < ws.deadline_anchor {
            return ProposerMintDecisionV1::None;
        }

        let decision = match ws.top_n_ref().first() {
            Some(w) => ProposerMintDecisionV1::Mint(w.mint_commitment),
            None => ProposerMintDecisionV1::Null,
        };
        tracing::info!(
            next_anchor_index,
            window_id = validate_key.1,
            deadline = ws.deadline_anchor,
            top_n_len = ws.top_n_ref().len(),
            frozen = ws.is_frozen(),
            obs = ws.obs_prev_window,
            decision = ?decision,
            "mint-decision: deadline reached"
        );
        decision
    }

    fn validate_final_payload(
        &mut self,
        payload: &AnchorPayloadV3,
        payload_root: [u8; 32],
        next_anchor_index: u64,
        state_last_mint_id: [u8; 32],
    ) -> Result<()> {
        let computed_root = pc_types::payload_merkle_root_v3(payload);
        if computed_root != payload_root {
            bail!("mint-censor payload-root mismatch");
        }
        // Transactional snapshot: failed validation must not mutate runtime state.
        let windows_before = self.windows.clone();
        let finalized_anchor_ids_before = self.finalized_anchor_ids.clone();
        let _ = self
            .finalized_anchor_ids
            .insert(next_anchor_index, payload_root);

        let validation = (|| -> Result<()> {
            let has_candidate_events = payload.evidences.iter().any(|e| {
                matches!(
                    e.evidence,
                    EvidenceKind::MintCandidateV1 { .. } | EvidenceKind::MintPoWCertV1 { .. }
                )
            });
            let has_forced_inclusion_v2 = payload.evidences.iter().any(|e| {
                matches!(
                    e.evidence,
                    EvidenceKind::MintPoWCertV1 { .. } | EvidenceKind::MintMissingImportV1 { .. }
                )
            });
            if has_forced_inclusion_v2 && !self.forced_inclusion_v2_enabled {
                bail!("mint-censor forced-inclusion v2 evidence while feature disabled");
            }
            let _bounds = self
                .params
                .window_bounds_for_anchor(next_anchor_index)
                .ok_or_else(|| {
                    if has_candidate_events {
                        anyhow!("mint-censor candidate event before windows_start_anchor")
                    } else {
                        anyhow!("mint-censor missing window bounds")
                    }
                })?;
            let Some(validate_key) =
                self.validation_window_key_for_anchor(next_anchor_index, state_last_mint_id)
            else {
                if has_candidate_events {
                    bail!("mint-censor candidate event without finalized window_open_anchor id");
                }
                bail!("mint-censor missing finalized window_open_anchor id for current window");
            };

            {
                #[derive(Clone)]
                struct CandidateApplyTransition {
                    anchor_index: u64,
                    candidate: MintCandidateEvent,
                }

                let mut transitions: Vec<CandidateApplyTransition> = payload
                    .evidences
                    .iter()
                    .filter_map(|ev| match &ev.evidence {
                        EvidenceKind::MintCandidateV1 { candidate } => {
                            Some(CandidateApplyTransition {
                                anchor_index: next_anchor_index,
                                candidate: candidate.clone(),
                            })
                        }
                        EvidenceKind::MintPoWCertV1 { cert } => {
                            let candidate = pc_types::mint_candidate_from_pow_cert_v1(cert);
                            Some(CandidateApplyTransition {
                                anchor_index: next_anchor_index,
                                candidate,
                            })
                        }
                        _ => None,
                    })
                    .collect();
                transitions.sort_unstable_by_key(|t| {
                    (
                        t.candidate.prev_mint_id,
                        t.candidate.window_id,
                        t.candidate.nonce,
                    )
                });
                let ws = self
                    .windows
                    .get_mut(&validate_key)
                    .ok_or_else(|| anyhow!("mint-censor window missing for transitions"))?;
                for t in transitions {
                    ws.apply_finalized_candidate(
                        t.anchor_index,
                        &t.candidate,
                        &state_last_mint_id,
                        &self.params,
                    )
                    .map_err(|e| anyhow!("mint-censor candidate rejected: {:?}", e))?;
                }
            }

            {
                let ws = self
                    .windows
                    .get_mut(&validate_key)
                    .ok_or_else(|| anyhow!("mint-censor window missing after insert"))?;
                ws.maybe_freeze(next_anchor_index);

                pc_types::validate_payload_sanity_v3(payload)
                    .map_err(|e| anyhow!("mint-censor payload-v3 sanity failed: {e}"))?;
                ws.validate_anchor_payload_v3(next_anchor_index, payload)
                    .map_err(|e| anyhow!("mint-censor payload-v3 validation failed: {:?}", e))?;
            }

            for ev in &payload.evidences {
                match &ev.evidence {
                    EvidenceKind::MintCensorshipV1 {
                        prev_mint_id,
                        window_id,
                        ..
                    } => {
                        let key = (*prev_mint_id, *window_id);
                        let ws = self.windows.get(&key).ok_or_else(|| {
                            anyhow!("mint-censor evidence references unknown window")
                        })?;
                        ws.verify_mint_censorship_evidence(
                            &ev.evidence,
                            AnchorId(payload_root),
                            next_anchor_index,
                            payload,
                        )
                        .map_err(|e| anyhow!("mint-censor evidence invalid: {:?}", e))?;
                    }
                    EvidenceKind::MintMissingImportV1 {
                        prev_mint_id,
                        window_id,
                        ..
                    } => {
                        let key = (*prev_mint_id, *window_id);
                        let ws = self.windows.get(&key).ok_or_else(|| {
                            anyhow!("mint-censor evidence references unknown window")
                        })?;
                        ws.verify_mint_missing_import_evidence(
                            &ev.evidence,
                            AnchorId(payload_root),
                            next_anchor_index,
                            payload,
                        )
                        .map_err(|e| anyhow!("mint-censor evidence invalid: {:?}", e))?;
                    }
                    _ => {}
                }
            }
            Ok(())
        })();

        match validation {
            Ok(_) => Ok(()),
            Err(e) => {
                self.windows = windows_before;
                self.finalized_anchor_ids = finalized_anchor_ids_before;
                warn!(err = %e, "mint-censor validation failed");
                Err(e)
            }
        }
    }
}

struct HeaderSignatureVerificationContext {
    root_hex: String,
    signer_pks: Vec<pc_crypto::BlsPublicKey>,
    pop: u8,
    committee_size: usize,
}

async fn resolve_header_signature_verification_context(
    h: &AnchorHeaderV2,
    k: u8,
    consensus_network_id: &mut Option<[u8; 32]>,
    mempool_dir: &str,
    committee_cache: &mut Option<CommitteeCache>,
    committee_recompute_last: &mut Option<Instant>,
    role_policy: Option<&RolePolicy>,
    reject_label: &'static str,
    count_vote_metrics: bool,
) -> Option<HeaderSignatureVerificationContext> {
    let root_hex = hex::encode(h.payload_hash);
    if consensus_network_id.is_none() {
        *consensus_network_id = load_network_id_from_mempool(mempool_dir);
    }
    let nid = match *consensus_network_id {
        Some(n) => n,
        None => {
            warn!(root = %root_hex, reason = "network_id_unavailable", "{reject_label} rejected");
            if count_vote_metrics {
                NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            return None;
        }
    };
    if h.network_id != nid {
        warn!(root = %root_hex, reason = "network_id_mismatch", expected = %hex::encode(nid), got = %hex::encode(h.network_id), "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    if !finality_verify_rate_allow().await {
        warn!(root = %root_hex, reason = "rate_limited", "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_RATE_LIMITED_TOTAL.fetch_add(1, Ordering::Relaxed);
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }

    let seed_anchor = match committee_seed_anchor_from_mempool(mempool_dir) {
        Some(v) => v,
        None => {
            warn!(root = %root_hex, reason = "seed_anchor_unavailable", "{reject_label} rejected");
            if count_vote_metrics {
                NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            return None;
        }
    };
    if committee_cache.as_ref().map(|c| (c.epoch, c.seed_anchor))
        != Some((h.vote_epoch, seed_anchor))
    {
        const MIN_RECOMPUTE_INTERVAL_MS: u64 = 500;
        if let Some(last) = committee_recompute_last.as_ref() {
            if last.elapsed() < Duration::from_millis(MIN_RECOMPUTE_INTERVAL_MS) {
                tracing::debug!(
                    root = %root_hex,
                    vote_epoch = h.vote_epoch,
                    seed_anchor = %hex::encode(seed_anchor),
                    reason = "committee_cache_miss_bypassing_recompute_throttle",
                    "{reject_label} recomputing committee despite throttle window"
                );
            }
        }
        *committee_recompute_last = Some(Instant::now());
        let staked = compute_committee_from_state(
            mempool_dir,
            h.vote_epoch,
            seed_anchor,
            k,
            nid,
            role_policy,
        )
        .await;
        let bootstrap = compute_committee_from_genesis_note(
            mempool_dir,
            h.vote_epoch,
            seed_anchor,
            k,
            nid,
            role_policy,
        )
        .await;
        *committee_cache = choose_effective_committee(k, staked, bootstrap);
        publish_committee_metrics(committee_cache.as_ref());
        info!(
            root = %root_hex,
            vote_epoch = h.vote_epoch,
            seed_anchor = %hex::encode(seed_anchor),
            committee_seats = committee_cache.as_ref().map_or(0, |c| c.seats.len()),
            bootstrap_mode = committee_cache.as_ref().is_some_and(|c| c.bootstrap_mode),
            "committee recomputed"
        );
    }
    let cache = match committee_cache.as_ref() {
        Some(c) if c.epoch == h.vote_epoch && c.seed_anchor == seed_anchor => c,
        _ => {
            warn!(root = %root_hex, reason = "committee_cache_miss", vote_epoch = h.vote_epoch, seed_anchor = %hex::encode(seed_anchor), "{reject_label} rejected");
            publish_committee_metrics(None);
            if count_vote_metrics {
                NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            return None;
        }
    };
    let k_usize = cache.seats.len();
    if k_usize == 0 || k_usize > 64 {
        warn!(root = %root_hex, reason = "committee_empty_or_too_large", k = k_usize, "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    if (h.creator_index as usize) >= k_usize {
        warn!(root = %root_hex, reason = "creator_index_out_of_range", creator_index = h.creator_index, k = k_usize, "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    if cache.recipient_ids.len() != k_usize || cache.fee_eligible.len() != k_usize {
        warn!(root = %root_hex, reason = "committee_metadata_inconsistent", recipients = cache.recipient_ids.len(), fee_eligible = cache.fee_eligible.len(), k = k_usize, "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    publish_committee_metrics(Some(cache));
    let allowed_mask = if k_usize == 64 {
        u64::MAX
    } else {
        (1u64 << k_usize) - 1
    };
    if (h.vote_mask & !allowed_mask) != 0 {
        warn!(root = %root_hex, reason = "vote_mask_out_of_range", vote_mask = h.vote_mask, allowed_mask = allowed_mask, "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    let pop = h.vote_mask.count_ones() as u8;
    let threshold = pc_consensus::finality_threshold(k_usize as u8);
    if pop < threshold {
        warn!(root = %root_hex, reason = "threshold_unmet", pop = pop, threshold = threshold, k = k_usize, "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    let mut signer_pks: Vec<pc_crypto::BlsPublicKey> = Vec::new();
    for i in 0..k_usize {
        if ((h.vote_mask >> i) & 1) == 1 {
            if let Some(pk) = cache.seats.get(i) {
                signer_pks.push(pk.clone());
            }
        }
    }
    if signer_pks.is_empty() {
        warn!(root = %root_hex, reason = "signer_set_empty", vote_mask = h.vote_mask, "{reject_label} rejected");
        if count_vote_metrics {
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    Some(HeaderSignatureVerificationContext {
        root_hex,
        signer_pks,
        pop,
        committee_size: k_usize,
    })
}

async fn verify_header_finality(
    h: &AnchorHeaderV2,
    k: u8,
    consensus_network_id: &mut Option<[u8; 32]>,
    mempool_dir: &str,
    committee_cache: &mut Option<CommitteeCache>,
    committee_recompute_last: &mut Option<Instant>,
    role_policy: Option<&RolePolicy>,
) -> bool {
    let root_hex = hex::encode(h.payload_hash);
    if consensus_network_id.is_none() {
        *consensus_network_id = load_network_id_from_mempool(mempool_dir);
    }
    let nid = match *consensus_network_id {
        Some(n) => n,
        None => {
            warn!(root = %root_hex, reason = "network_id_unavailable", "verify_header_finality rejected");
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    };
    let precheck = match finality_pipeline::precheck_finality_header(h, nid) {
        Ok(v) => v,
        Err(finality_pipeline::FinalityHeaderPrecheckError::HeaderVersionTooLow { version }) => {
            warn!(root = %root_hex, reason = "header_version_too_low", version = version, "verify_header_finality rejected");
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        Err(finality_pipeline::FinalityHeaderPrecheckError::AttestSigMissing) => {
            warn!(root = %root_hex, reason = "attest_sig_missing", "verify_header_finality rejected");
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        Err(finality_pipeline::FinalityHeaderPrecheckError::PostStateRootMissing) => {
            warn!(root = %root_hex, reason = "post_state_root_missing", "verify_header_finality rejected");
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        Err(finality_pipeline::FinalityHeaderPrecheckError::NetworkIdMismatch {
            header_network_id,
            local_network_id,
        }) => {
            warn!(root = %root_hex, reason = "network_id_mismatch", expected = %hex::encode(local_network_id), got = %hex::encode(header_network_id), "verify_header_finality rejected");
            NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    };
    let sig = precheck.attest_sig;
    let committed_state_root = precheck.committed_state_root;
    NODE_VOTE_SENT_TOTAL.fetch_add(1, Ordering::Relaxed);
    let Some(ctx) = resolve_header_signature_verification_context(
        h,
        k,
        consensus_network_id,
        mempool_dir,
        committee_cache,
        committee_recompute_last,
        role_policy,
        "verify_header_finality",
        true,
    )
    .await
    else {
        return false;
    };
    let msg = committee_precommit_message(
        &h.network_id,
        h.vote_epoch,
        &h.vote_target_hash(),
        &committed_state_root,
    );
    let t0 = Instant::now();
    let ok = bls_fast_aggregate_verify(&msg, &sig, &ctx.signer_pks);
    observe_verify(t0.elapsed());
    if ok {
        info!(root = %ctx.root_hex, vote_epoch = h.vote_epoch, pop = ctx.pop, "header finality verified");
        NODE_VOTE_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
    } else {
        warn!(root = %ctx.root_hex, reason = "bls_sig_invalid", vote_epoch = h.vote_epoch, pop = ctx.pop, k = ctx.committee_size, "verify_header_finality rejected");
        NODE_VOTE_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    ok
}

async fn verify_header_prevote(
    h: &AnchorHeaderV2,
    k: u8,
    consensus_network_id: &mut Option<[u8; 32]>,
    mempool_dir: &str,
    committee_cache: &mut Option<CommitteeCache>,
    committee_recompute_last: &mut Option<Instant>,
    role_policy: Option<&RolePolicy>,
) -> bool {
    let root_hex = hex::encode(h.payload_hash);
    if consensus_network_id.is_none() {
        *consensus_network_id = load_network_id_from_mempool(mempool_dir);
    }
    let nid = match *consensus_network_id {
        Some(n) => n,
        None => {
            warn!(root = %root_hex, reason = "network_id_unavailable", "verify_header_prevote rejected");
            return false;
        }
    };
    let precheck = match finality_pipeline::precheck_prevote_header(h, nid) {
        Ok(v) => v,
        Err(finality_pipeline::PrevoteHeaderPrecheckError::HeaderVersionTooLow { version }) => {
            warn!(root = %root_hex, reason = "header_version_too_low", version = version, "verify_header_prevote rejected");
            return false;
        }
        Err(finality_pipeline::PrevoteHeaderPrecheckError::AttestSigMissing) => {
            warn!(root = %root_hex, reason = "attest_sig_missing", "verify_header_prevote rejected");
            return false;
        }
        Err(finality_pipeline::PrevoteHeaderPrecheckError::PostStateRootPresent) => {
            warn!(root = %root_hex, reason = "post_state_root_present", "verify_header_prevote rejected");
            return false;
        }
        Err(finality_pipeline::PrevoteHeaderPrecheckError::NetworkIdMismatch {
            header_network_id,
            local_network_id,
        }) => {
            warn!(root = %root_hex, reason = "network_id_mismatch", expected = %hex::encode(local_network_id), got = %hex::encode(header_network_id), "verify_header_prevote rejected");
            return false;
        }
    };
    let Some(ctx) = resolve_header_signature_verification_context(
        h,
        k,
        consensus_network_id,
        mempool_dir,
        committee_cache,
        committee_recompute_last,
        role_policy,
        "verify_header_prevote",
        false,
    )
    .await
    else {
        return false;
    };
    let msg = committee_vote_message(&h.network_id, h.vote_epoch, &h.vote_target_hash());
    let t0 = Instant::now();
    let ok = bls_fast_aggregate_verify(&msg, &precheck.attest_sig, &ctx.signer_pks);
    observe_verify(t0.elapsed());
    if ok {
        info!(root = %ctx.root_hex, vote_epoch = h.vote_epoch, pop = ctx.pop, "header prevote verified");
    } else {
        warn!(root = %ctx.root_hex, reason = "bls_sig_invalid", vote_epoch = h.vote_epoch, pop = ctx.pop, k = ctx.committee_size, "verify_header_prevote rejected");
    }
    ok
}

async fn verify_and_extract_slash_ops<B: pc_state::StateBackend>(
    st: &pc_state::UtxoState<B>,
    mempool_dir: &str,
    network_id: [u8; 32],
    role_policy: Option<&RolePolicy>,
    committee_cache: &mut Option<CommitteeCache>,
    evidences: &[EvidenceEvent],
) -> Result<Vec<SlashOpV1>> {
    if evidences.is_empty() {
        return Ok(Vec::new());
    }
    let seed_anchor_now = committee_seed_anchor_from_mempool(mempool_dir)
        .ok_or_else(|| anyhow!("committee seed anchor unavailable"))?;

    // NOTE: This assumes the slash tickets are anchored to the current seed anchor
    // (the last finalized payload root persisted by the state task). We intentionally
    // do not support "old anchor" tickets, because the old committee would require
    // historical state to be derived/verifiable.

    let mut out: Vec<SlashOpV1> = Vec::new();
    for ev in evidences {
        match &ev.evidence {
            EvidenceKind::SlashTicketV1 {
                offender_id,
                category,
                slash_bp,
                vote_epoch,
                seed_anchor,
                slash_id,
                vote_mask,
                reporter_lock,
                agg_sig,
            } => {
                if *seed_anchor != seed_anchor_now {
                    bail!("slash ticket seed_anchor mismatch");
                }

                // Offender must exist on-chain (otherwise `pc-state` cannot apply the slash).
                if st.backend().get_validator_record(offender_id).is_none() {
                    bail!("slash ticket unknown offender");
                }

                // Basic parameter validation (consensus constants).
                let bp_ok = match *category {
                    1 => *slash_bp == consts::SLASH_EQUIVOCATION_BP,
                    2 => {
                        *slash_bp >= consts::SLASH_VOTE_INVALID_MIN_BP
                            && *slash_bp <= consts::SLASH_VOTE_INVALID_MAX_BP
                    }
                    3 => matches!(
                        *slash_bp,
                        consts::SLASH_DA_25_BP | consts::SLASH_DA_50_BP | consts::SLASH_DA_100_BP
                    ),
                    _ => false,
                };
                if !bp_ok {
                    bail!("slash ticket invalid category/bp");
                }

                // Idempotence: ignore already-applied tickets.
                if st.backend().is_slash_id_used(slash_id) {
                    continue;
                }

                // Ensure committee cache is for (epoch, seed_anchor_now).
                if committee_cache.as_ref().map(|c| (c.epoch, c.seed_anchor))
                    != Some((*vote_epoch, seed_anchor_now))
                {
                    let pool_size = st.backend().iter_validator_records().count();
                    let current_k = std::cmp::max(1, std::cmp::min(21, pool_size as u8));
                    let staked = compute_committee_from_utxo_state(
                        st,
                        *vote_epoch,
                        seed_anchor_now,
                        current_k,
                        network_id,
                        role_policy,
                    );
                    let bootstrap = compute_committee_from_genesis_note(
                        mempool_dir,
                        *vote_epoch,
                        seed_anchor_now,
                        current_k,
                        network_id,
                        role_policy,
                    )
                    .await;
                    *committee_cache = choose_effective_committee(current_k, staked, bootstrap);
                    publish_committee_metrics(committee_cache.as_ref());
                }
                let cache = match committee_cache.as_ref() {
                    Some(c) if c.epoch == *vote_epoch && c.seed_anchor == seed_anchor_now => c,
                    _ => bail!("slash ticket committee unavailable"),
                };
                let k_active = cache.seats.len();
                if k_active == 0 || k_active > 64 {
                    bail!("slash ticket committee size invalid");
                }
                let allowed_mask: u64 = if k_active == 64 {
                    u64::MAX
                } else {
                    (1u64 << (k_active as u64)) - 1
                };
                if (*vote_mask & !allowed_mask) != 0 {
                    bail!("slash ticket vote_mask has out-of-range bits");
                }
                let pop = vote_mask.count_ones() as u8;
                let threshold = pc_consensus::finality_threshold(k_active as u8);
                if pop < threshold {
                    bail!("slash ticket below threshold");
                }

                // Extract PKs according to vote_mask and verify aggregate signature.
                let mut pks: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(pop as usize);
                for i in 0..k_active {
                    if ((*vote_mask >> i) & 1) == 1 {
                        if let Some(pk) = cache.seats.get(i) {
                            pks.push(pk.clone());
                        }
                    }
                }
                if pks.is_empty() {
                    bail!("slash ticket empty signer set");
                }
                let msg = slash_ticket_message(
                    &network_id,
                    &seed_anchor_now,
                    *vote_epoch,
                    offender_id,
                    *category,
                    *slash_bp,
                    slash_id,
                    &reporter_lock.0,
                );
                if !bls_fast_aggregate_verify(&msg, agg_sig, &pks) {
                    bail!("slash ticket agg sig verify failed");
                }

                out.push(SlashOpV1 {
                    slash_id: *slash_id,
                    offender_id: *offender_id,
                    slash_bp: *slash_bp,
                    reporter_lock: *reporter_lock,
                    reporter_reward_bp: consts::SLASH_REPORTER_REWARD_BP,
                });
            }
            EvidenceKind::EquivocationBftV1 {
                offender_id,
                seed_anchor,
                a,
                b,
                reporter_lock,
                reporter_sig,
            } => {
                if *seed_anchor != seed_anchor_now {
                    bail!("equivocation seed_anchor mismatch");
                }

                // Offender must exist on-chain.
                if st.backend().get_validator_record(offender_id).is_none() {
                    bail!("equivocation unknown offender");
                }

                // Basic slot checks.
                if a.network_id != network_id || b.network_id != network_id {
                    bail!("equivocation network_id mismatch");
                }
                if a.vote_epoch != b.vote_epoch
                    || a.vote_round != b.vote_round
                    || a.shard_id != b.shard_id
                {
                    bail!("equivocation slot mismatch");
                }
                let target_a = a.vote_target_hash();
                let target_b = b.vote_target_hash();
                if target_a == target_b {
                    bail!("equivocation targets equal");
                }

                let vote_epoch = a.vote_epoch;

                // Ensure committee cache is for (epoch, seed_anchor_now).
                if committee_cache.as_ref().map(|c| (c.epoch, c.seed_anchor))
                    != Some((vote_epoch, seed_anchor_now))
                {
                    let pool_size = st.backend().iter_validator_records().count();
                    let current_k = std::cmp::max(1, std::cmp::min(21, pool_size as u8));
                    let staked = compute_committee_from_utxo_state(
                        st,
                        vote_epoch,
                        seed_anchor_now,
                        current_k,
                        network_id,
                        role_policy,
                    );
                    let bootstrap = compute_committee_from_genesis_note(
                        mempool_dir,
                        vote_epoch,
                        seed_anchor_now,
                        current_k,
                        network_id,
                        role_policy,
                    )
                    .await;
                    *committee_cache = choose_effective_committee(current_k, staked, bootstrap);
                    publish_committee_metrics(committee_cache.as_ref());
                }
                let cache = match committee_cache.as_ref() {
                    Some(c) if c.epoch == vote_epoch && c.seed_anchor == seed_anchor_now => c,
                    _ => bail!("equivocation committee unavailable"),
                };
                let k_active = cache.seats.len();
                if k_active == 0 || k_active > 64 {
                    bail!("equivocation committee size invalid");
                }
                if cache.recipient_ids.len() != k_active || cache.fee_eligible.len() != k_active {
                    bail!("equivocation committee metadata size mismatch");
                }
                let allowed_mask: u64 = if k_active == 64 {
                    u64::MAX
                } else {
                    (1u64 << (k_active as u64)) - 1
                };
                let threshold = pc_consensus::finality_threshold(k_active as u8);

                // Map offender_id -> seat index (0..k-1).
                let offender_idx = {
                    let mut idx: Option<usize> = None;
                    for (i, rid) in cache.recipient_ids.iter().enumerate() {
                        if rid == offender_id {
                            idx = Some(i);
                            break;
                        }
                    }
                    idx.ok_or_else(|| anyhow!("equivocation offender not in committee"))?
                };
                if offender_idx >= k_active || offender_idx >= 64 {
                    bail!("equivocation offender_idx out of range");
                }
                let bit = 1u64 << (offender_idx as u64);
                if (a.vote_mask & bit) == 0 || (b.vote_mask & bit) == 0 {
                    bail!("equivocation offender not in signer set");
                }

                // Each header must be final and have a verifiable aggregate signature for its signer set.
                let verify_header = |h: &AnchorHeaderV2| -> Result<()> {
                    if h.version < 5 {
                        bail!("equivocation header version too low");
                    }
                    if h.network_id != network_id {
                        bail!("equivocation header network_id mismatch");
                    }
                    if (h.vote_mask & !allowed_mask) != 0 {
                        bail!("equivocation header vote_mask out of range");
                    }
                    let pop = h.vote_mask.count_ones() as u8;
                    if pop < threshold {
                        bail!("equivocation header below finality threshold");
                    }
                    let sig = h
                        .attest_sig
                        .ok_or_else(|| anyhow!("equivocation header missing attest_sig"))?;
                    let committed_state_root = h
                        .state_root
                        .ok_or_else(|| anyhow!("equivocation header missing post_state_root"))?;
                    let mut pks: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(pop as usize);
                    for i in 0..k_active {
                        if ((h.vote_mask >> i) & 1) == 1 {
                            if let Some(pk) = cache.seats.get(i) {
                                pks.push(pk.clone());
                            }
                        }
                    }
                    if pks.is_empty() {
                        bail!("equivocation empty signer set");
                    }
                    let msg = committee_precommit_message(
                        &h.network_id,
                        h.vote_epoch,
                        &h.vote_target_hash(),
                        &committed_state_root,
                    );
                    if !bls_fast_aggregate_verify(&msg, &sig, &pks) {
                        bail!("equivocation agg sig verify failed");
                    }
                    Ok(())
                };
                verify_header(a)?;
                verify_header(b)?;

                let slash_id = pc_types::slash_id_equivocation_bft_v1(
                    &network_id,
                    &seed_anchor_now,
                    vote_epoch,
                    a.shard_id,
                    a.vote_round,
                    offender_id,
                    &target_a,
                    &target_b,
                );

                // Idempotence: ignore already-applied evidence.
                if st.backend().is_slash_id_used(&slash_id) {
                    continue;
                }

                // Reporter binding: Schnorr signature over deterministic message.
                let msg32 = pc_types::reporter_slash_claim_sighash_v1(&network_id, &slash_id);
                if !pc_crypto::schnorr_verify_xonly_bytes(&msg32, reporter_sig, &reporter_lock.0) {
                    bail!("equivocation reporter_sig invalid");
                }

                out.push(SlashOpV1 {
                    slash_id,
                    offender_id: *offender_id,
                    slash_bp: consts::SLASH_EQUIVOCATION_BP,
                    reporter_lock: *reporter_lock,
                    reporter_reward_bp: consts::SLASH_REPORTER_REWARD_BP,
                });
            }
            _ => continue,
        }
    }

    Ok(out)
}

mod committee_selection;
mod finality_pipeline;
mod http_api;
use http_api::{run_status_serve, StatusServeArgs};
mod quic_server;
use quic_server::run_p2p_quic_listen;
mod node_store;
use node_store::*;
mod cli;
mod store_path;
use cli::*;

#[cfg(test)]
mod tests;

fn rewrite_mempool_journal(
    journal_path: &std::path::Path,
    ids: &VecDeque<[u8; 32]>,
    do_fsync: bool,
) -> std::io::Result<()> {
    // Binary journal format:
    // - u32(le) payload_len
    // - payload bytes: op:u8 + id:[u8;32]
    // - u32(le) crc32(payload)
    //
    // Reader discards corrupted/partial tail records (crash-safety).
    journal_rewrite_binary_v1(journal_path, ids.iter().copied(), do_fsync)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WalletHistoryEventType {
    Mint,
    MicroTx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WalletHistoryDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletHistoryEventV1 {
    version: u8,
    anchor_index: u64,
    payload_root: [u8; 32],
    txid: [u8; 32],
    event_type: WalletHistoryEventType,
    direction: WalletHistoryDirection,
    amount: u64,
    lock: [u8; 32],
    outpoint_txid: [u8; 32],
    outpoint_vout: u32,
    staked: bool,
    #[serde(default)]
    timestamp_local: u64,
}

fn collect_wallet_history_events_for_payload<B: StateBackend>(
    st: &UtxoState<B>,
    payload: &AnchorPayloadV3,
    anchor_index: u64,
    payload_root: [u8; 32],
) -> Vec<WalletHistoryEventV1> {
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut events: Vec<WalletHistoryEventV1> = Vec::new();

    for mint in &payload.mints {
        let txid = pc_types::digest_mint(mint);
        for (vout, out) in mint.outputs.iter().enumerate() {
            events.push(WalletHistoryEventV1 {
                version: 1,
                anchor_index,
                payload_root,
                txid,
                event_type: WalletHistoryEventType::Mint,
                direction: WalletHistoryDirection::In,
                amount: out.amount,
                lock: out.lock.0,
                outpoint_txid: txid,
                outpoint_vout: vout as u32,
                staked: false,
                timestamp_local: now_ts,
            });
        }
    }

    for tx in &payload.micro_txs {
        let txid = digest_microtx(tx);
        for tin in &tx.inputs {
            if let Some((amt, lock)) = st.backend().get(&tin.prev_out) {
                let staked = st.backend().is_staked(&tin.prev_out);
                events.push(WalletHistoryEventV1 {
                    version: 1,
                    anchor_index,
                    payload_root,
                    txid,
                    event_type: WalletHistoryEventType::MicroTx,
                    direction: WalletHistoryDirection::Out,
                    amount: amt,
                    lock: lock.0,
                    outpoint_txid: tin.prev_out.txid,
                    outpoint_vout: tin.prev_out.vout,
                    staked,
                    timestamp_local: now_ts,
                });
            }
        }

        let out_staked = tx.version == pc_types::TX_VERSION_STAKE_BOND_V1;
        for (vout, out) in tx.outputs.iter().enumerate() {
            events.push(WalletHistoryEventV1 {
                version: 1,
                anchor_index,
                payload_root,
                txid,
                event_type: WalletHistoryEventType::MicroTx,
                direction: WalletHistoryDirection::In,
                amount: out.amount,
                lock: out.lock.0,
                outpoint_txid: txid,
                outpoint_vout: vout as u32,
                staked: out_staked,
                timestamp_local: now_ts,
            });
        }
    }

    events
}

fn append_wallet_history_events_sync(
    journal_path: &std::path::Path,
    do_fsync: bool,
    events: &[WalletHistoryEventV1],
) -> std::io::Result<()> {
    use std::io::Write as _;

    if events.is_empty() {
        return Ok(());
    }

    if let Some(dir) = journal_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)?;

    for ev in events {
        let line = serde_json::to_vec(ev)
            .map_err(|e| std::io::Error::other(format!("wallet_history encode: {e}")))?;
        f.write_all(&line)?;
        f.write_all(b"\n")?;
    }
    if do_fsync {
        let _ = f.sync_data();
    }
    Ok(())
}

async fn append_wallet_history_events_async(
    journal_path: &std::path::Path,
    do_fsync: bool,
    events: Vec<WalletHistoryEventV1>,
) -> std::io::Result<()> {
    let p = journal_path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || {
        append_wallet_history_events_sync(&p, do_fsync, &events)
    })
    .await
    .map_err(|e| std::io::Error::other(format!("join {e}")))?;
    res
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalFormat {
    BinaryV1,
    LegacyText,
}

const JOURNAL_REC_V1_PAYLOAD_LEN: u32 = 1 + 32;
const JOURNAL_REC_V1_MAX_PAYLOAD_LEN: u32 = 1024;

fn journal_write_record_binary_v1<W: std::io::Write>(
    w: &mut W,
    op: u8,
    id: &[u8; 32],
) -> std::io::Result<()> {
    let mut payload = [0u8; JOURNAL_REC_V1_PAYLOAD_LEN as usize];
    payload[0] = op;
    payload[1..].copy_from_slice(id);
    let crc = crc32fast::hash(&payload);

    w.write_all(&JOURNAL_REC_V1_PAYLOAD_LEN.to_le_bytes())?;
    w.write_all(&payload)?;
    w.write_all(&crc.to_le_bytes())?;
    Ok(())
}

fn journal_rewrite_binary_v1(
    journal_path: &std::path::Path,
    ids: impl IntoIterator<Item = [u8; 32]>,
    do_fsync: bool,
) -> std::io::Result<()> {
    let mut tmp = journal_path.to_path_buf();
    tmp.set_extension("journal.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        for id in ids {
            journal_write_record_binary_v1(&mut f, b'A', &id)?;
        }
        if do_fsync {
            let _ = f.sync_data();
        }
    }
    std::fs::rename(&tmp, journal_path)?;
    if do_fsync {
        if let Some(dir) = journal_path.parent() {
            if let Ok(dirf) = std::fs::File::open(dir) {
                let _ = dirf.sync_data();
            }
        }
    }
    Ok(())
}

fn journal_read_active_ids_legacy_text(bytes: &[u8]) -> std::collections::HashSet<[u8; 32]> {
    let s = String::from_utf8_lossy(bytes);
    let mut set: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for line in s.lines() {
        if line.len() < 65 {
            continue;
        }
        let (opch, hexid) = line.split_at(1);
        if let Ok(bytes) = hex::decode(hexid) {
            if bytes.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                match opch.as_bytes().first().copied() {
                    Some(b'A') => {
                        let _ = set.insert(id);
                    }
                    Some(b'D') => {
                        let _ = set.remove(&id);
                    }
                    _ => {}
                }
            }
        }
    }
    set
}

fn journal_read_active_ids_binary_v1(bytes: &[u8]) -> std::collections::HashSet<[u8; 32]> {
    use std::io::Read as _;

    let mut set: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut cur = std::io::Cursor::new(bytes);

    loop {
        let mut len_buf = [0u8; 4];
        if let Err(e) = cur.read_exact(&mut len_buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            break;
        }
        let len = u32::from_le_bytes(len_buf);
        if len == 0 || len > JOURNAL_REC_V1_MAX_PAYLOAD_LEN {
            // Corrupt tail (or unsupported future format) -> stop parsing.
            break;
        }

        let mut payload = vec![0u8; len as usize];
        if cur.read_exact(&mut payload).is_err() {
            break;
        }
        let mut crc_buf = [0u8; 4];
        if cur.read_exact(&mut crc_buf).is_err() {
            break;
        }
        let want = u32::from_le_bytes(crc_buf);
        let got = crc32fast::hash(&payload);
        if got != want {
            break;
        }

        // V1: op:u8 + id:[u8;32]
        if payload.len() != JOURNAL_REC_V1_PAYLOAD_LEN as usize {
            // Unknown/unsupported record size; ignore but keep parsing.
            continue;
        }
        let Some((&op, rest)) = payload.split_first() else {
            continue;
        };
        if op != b'A' && op != b'D' {
            continue;
        }
        let mut id = [0u8; 32];
        if rest.len() != 32 {
            continue;
        }
        id.copy_from_slice(rest);
        match op {
            b'A' => {
                let _ = set.insert(id);
            }
            b'D' => {
                let _ = set.remove(&id);
            }
            _ => {}
        }
    }
    set
}

fn journal_read_active_ids(
    journal_path: &std::path::Path,
) -> std::io::Result<Option<(std::collections::HashSet<[u8; 32]>, JournalFormat)>> {
    let bytes = match std::fs::read(journal_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if bytes.is_empty() {
        return Ok(Some((
            std::collections::HashSet::new(),
            JournalFormat::BinaryV1,
        )));
    }

    // Legacy format starts with ASCII 'A'/'D' (text lines).
    let fmt = match bytes.first().copied() {
        Some(b'A') | Some(b'D') => JournalFormat::LegacyText,
        _ => JournalFormat::BinaryV1,
    };
    let set = match fmt {
        JournalFormat::LegacyText => journal_read_active_ids_legacy_text(&bytes),
        JournalFormat::BinaryV1 => journal_read_active_ids_binary_v1(&bytes),
    };
    Ok(Some((set, fmt)))
}

fn journal_append(
    journal_path: &std::path::Path,
    do_fsync: bool,
    op: u8,
    id: &[u8; 32],
) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)?;
    journal_write_record_binary_v1(&mut f, op, id)?;
    if do_fsync {
        let _ = f.sync_data();
    }
    Ok(())
}

fn remove_with_dir_sync(path: &std::path::Path, do_fsync: bool) -> std::io::Result<()> {
    std::fs::remove_file(path)?;
    if do_fsync {
        if let Some(dir) = path.parent() {
            if let Ok(dirf) = std::fs::File::open(dir) {
                let _ = dirf.sync_data();
            }
        }
    }
    Ok(())
}

fn atomic_write(path: &std::path::Path, data: &[u8], do_fsync: bool) -> std::io::Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        use std::io::Write as _;
        f.write_all(data)?;
        if do_fsync {
            let _ = f.sync_data();
        }
    }
    std::fs::rename(&tmp, path)?;
    if do_fsync {
        if let Some(dir) = path.parent() {
            if let Ok(dirf) = std::fs::File::open(dir) {
                let _ = dirf.sync_data();
            }
        }
    }
    Ok(())
}

async fn atomic_write_async(
    path: &std::path::Path,
    data: Vec<u8>,
    do_fsync: bool,
) -> std::io::Result<()> {
    let p = path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || atomic_write(&p, &data, do_fsync))
        .await
        .map_err(|e| std::io::Error::other(format!("join {}", e)))?;
    res
}

#[derive(Debug, Clone, Args)]
struct CacheBenchArgs {
    /// Path to the store root (contains headers/ and payloads/).
    /// Pfad zum Store-Root (enthält headers/ und payloads/).
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    store_dir: String,
    /// Perform fsync() for file and directory operations (default: true).
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true).
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// Mode: "headers" or "payloads".
    /// Modus: headers | payloads.
    #[arg(long)]
    mode: String,
    /// Number of distinct elements loaded from the store (max).
    /// Anzahl eindeutiger Elemente aus dem Store (max.).
    #[arg(long, default_value_t = 100)]
    sample: usize,
    /// Iterations over the same sample set (>=1).
    /// Wiederholungen über dem gleichen Sample (>=1).
    #[arg(long, default_value_t = 3)]
    iterations: usize,
    /// Header cache capacity (0 = disabled).
    /// Header-Cache-Kapazität (0=aus).
    #[arg(long, default_value_t = 1000)]
    cache_hdr_cap: usize,
    /// Payload cache budget in MB (0 = disabled).
    /// Payload-Cache-Budget in MB (0=aus).
    #[arg(long, default_value_t = 200)]
    cache_pl_mb: usize,
}

// Node-wide metrics (not part of pc_p2p): persistence and observer lag.
// Node-weite Metriken (nicht Teil von pc_p2p): Persistenz und Observer-Lag.
//
// NOTE: These atomics are metrics-only. Using `Ordering::Relaxed` is intentional and
// sufficient because they are not used to make safety- or consensus-critical decisions.
static NODE_PERSIST_HEADERS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_HEADERS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_INBOUND_OBS_LAGGED_TOTAL: AtomicU64 = AtomicU64::new(0);
// Persist latency (Histogramm in Sekunden: 1ms,5ms,10ms,50ms,100ms,500ms,+Inf).
static NODE_PERSIST_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_1MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_5MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_10MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);
// Prozess-Metriken (best-effort, lokal).
static NODE_PROCESS_CPU_PCT_MICRO: AtomicU64 = AtomicU64::new(0);
static NODE_PROCESS_RSS_BYTES: AtomicU64 = AtomicU64::new(0);
// Cache metrics.
// Cache-Metriken.
static NODE_CACHE_HEADERS_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_HEADERS_MISSES_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_PAYLOADS_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_PAYLOADS_MISSES_TOTAL: AtomicU64 = AtomicU64::new(0);
// Mempool metrics.
// Mempool-Metriken.
static NODE_MEMPOOL_SIZE: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_DUPLICATE_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_CONFLICT_TOTAL: AtomicU64 = AtomicU64::new(0);
// Additional mempool metrics.
// Zusätzliche Mempool-Metriken.
static NODE_MEMPOOL_TTL_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_CAP_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_INVALIDATED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_SHARD_REJECT_TOTAL: AtomicU64 = AtomicU64::new(0);
// Proposer metrics.
// Proposer-Metriken.
static NODE_PROPOSER_BUILT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_LAST_SIZE: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_PENDING: AtomicU64 = AtomicU64::new(0);
// RPC broadcast metrics.
// RPC Broadcast Metriken.
static NODE_RPC_BROADCAST_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_RPC_BROADCAST_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_RPC_BROADCAST_DUP_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_RPC_BROADCAST_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);

// Consensus HTTP endpoints metrics.
// Consensus HTTP Endpoints Metriken.
static NODE_CONSENSUS_SELECT_COMMITTEE_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_SELECT_ATTESTORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_SELECT_ATTESTORS_FAIR_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_AGG_SIGS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_FAST_VERIFY_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_FAST_VERIFY_VALID_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_FAST_VERIFY_SEATS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_FAST_VERIFY_SEATS_VALID_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_PAYOUT_ROOT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_PAYOUT_PROOF_TOTAL: AtomicU64 = AtomicU64::new(0);

// Additional request counters
static NODE_CONSENSUS_SELECT_COMMITTEE_PERSIST_TOTAL: AtomicU64 = AtomicU64::new(0);

// Error counters per endpoint
static NODE_CONSENSUS_SELECT_COMMITTEE_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_SELECT_COMMITTEE_PERSIST_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_SELECT_ATTESTORS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_SELECT_ATTESTORS_FAIR_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_AGG_SIGS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_FAST_VERIFY_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_FAST_VERIFY_SEATS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_PAYOUT_ROOT_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CONSENSUS_PAYOUT_PROOF_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);

// Vote health metrics (finality attestation verification).
static NODE_VOTE_SENT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_VOTE_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_VOTE_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_VOTE_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_COMMITTEE_ACTIVE_SEATS: AtomicU64 = AtomicU64::new(0);
static NODE_COMMITTEE_FEE_ELIGIBLE_SEATS: AtomicU64 = AtomicU64::new(0);
static NODE_COMMITTEE_BOOTSTRAP_MODE: AtomicU64 = AtomicU64::new(0);

// Debug: State-Task apply-candidate pipeline step counters.
static NODE_DBG_APPLYCAND_RECV: AtomicU64 = AtomicU64::new(0);
static NODE_DBG_APPLYCAND_ALREADY_APPLIED: AtomicU64 = AtomicU64::new(0);
static NODE_DBG_APPLYCAND_HEADERS_EMPTY: AtomicU64 = AtomicU64::new(0);
static NODE_DBG_APPLYCAND_PAYLOAD_UNAVAIL: AtomicU64 = AtomicU64::new(0);
static NODE_DBG_APPLYCAND_SANITY_FAIL: AtomicU64 = AtomicU64::new(0);
static NODE_DBG_APPLYCAND_MINT_CENSOR_FAIL: AtomicU64 = AtomicU64::new(0);
static NODE_DBG_APPLYCAND_PAYOUT_FAIL: AtomicU64 = AtomicU64::new(0);
static NODE_DBG_APPLYCAND_APPLIED: AtomicU64 = AtomicU64::new(0);

// AnchorGraph cache metrics (from pc-consensus): bounded DAG + orphan pool.
static NODE_ANCHOR_GRAPH_HEADERS: AtomicU64 = AtomicU64::new(0);
static NODE_ANCHOR_GRAPH_ORPHANS: AtomicU64 = AtomicU64::new(0);
static NODE_ANCHOR_GRAPH_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_ANCHOR_GRAPH_ORPHAN_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

// Lokal: Rolle + Validator Eligibility/Control (keine Labels, low-cardinality).
static NODE_ROLE_FLAGS_GAUGE: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_ID_CONFIGURED: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_STAKE: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_MIN_STAKE: AtomicU64 = AtomicU64::new(consts::MIN_ATTESTOR_STAKE);
static NODE_VALIDATOR_POP_OK: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_POLICY_OK: AtomicU64 = AtomicU64::new(1);
static NODE_VALIDATOR_ELIGIBLE: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_CONDITIONS_OK: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_VOTING_ENABLED: AtomicU64 = AtomicU64::new(0);

static NODE_VALIDATOR_CONTROL_KILL_SWITCH: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_CONTROL_MAINTENANCE: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_CONTROL_MANUAL_DISABLE: AtomicU64 = AtomicU64::new(1);
static NODE_VALIDATOR_CONTROL_AUTO_REENABLE: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_CONTROL_COOLDOWN_UNTIL_EPOCH: AtomicU64 = AtomicU64::new(0);
static NODE_VALIDATOR_CONTROL_UPDATED_AT_EPOCH: AtomicU64 = AtomicU64::new(0);

// DA-gating config gauges (best-effort): exposed via /metrics for observability/debugging.
// Defaults match status-serve (/consensus/config) defaults.
static NODE_DA_GATING_CFG_PAYLOAD_WAIT_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(3);
static NODE_DA_GATING_CFG_RETRY_INITIAL_DELAY_MS: AtomicU64 = AtomicU64::new(100);
static NODE_DA_GATING_CFG_RETRY_MAX_DELAY_MS: AtomicU64 = AtomicU64::new(300);
static NODE_DA_GATING_CFG_RETRY_MAX_RETRIES: AtomicU64 = AtomicU64::new(2);
static NODE_DA_GATING_CFG_RETRY_JITTER_PCT: AtomicU64 = AtomicU64::new(12);

// Disk-Read Latenz (Header/Payload) als Histogramm (Buckets analog P2P: 1ms,5ms,10ms,50ms,100ms,500ms,+Inf)
static NODE_STORE_HDR_READ_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_READ_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_1MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_5MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_10MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);

static NODE_STORE_PL_READ_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_READ_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_1MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_5MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_10MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);

// Finalitäts-Histogramm (Sekunden-Buckets): 50ms, 100ms, 500ms, 1s, 2s, 5s, +Inf
static NODE_FINALITY_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_BUCKET_LE_1S: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_BUCKET_LE_2S: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_BUCKET_LE_5S: AtomicU64 = AtomicU64::new(0);
// (Buckets für Payload-Read bereits oberhalb bei PL Read Counters definiert)

// Verify-Histogramm (Sekunden-Buckets: 1ms,5ms,10ms,50ms,100ms,500ms, +Inf)
static NODE_VERIFY_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_VERIFY_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_VERIFY_BUCKET_LE_1MS: AtomicU64 = AtomicU64::new(0);
static NODE_VERIFY_BUCKET_LE_5MS: AtomicU64 = AtomicU64::new(0);
static NODE_VERIFY_BUCKET_LE_10MS: AtomicU64 = AtomicU64::new(0);
static NODE_VERIFY_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_VERIFY_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_VERIFY_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);

// Internal PoW-Miner metrics.
// Interne PoW-Miner-Metriken.
static NODE_POW_HASHES_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_POW_BLOCKS_FOUND_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_POW_SUBMIT_OK_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_POW_SUBMIT_STALE_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_POW_SUBMIT_ERR_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_POW_MINING_ACTIVE: AtomicU64 = AtomicU64::new(0);
static NODE_POW_LAST_SUBMIT_MS: AtomicU64 = AtomicU64::new(0);
static NODE_FINALIZED_TX_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_FINALITY_MINT_EVENTS: AtomicU64 = AtomicU64::new(0);
static NODE_ANCHOR_INDEX: AtomicU64 = AtomicU64::new(0);

fn observe_verify(d: std::time::Duration) {
    let us = d.as_micros() as u64;
    NODE_VERIFY_COUNT.fetch_add(1, Ordering::Relaxed);
    NODE_VERIFY_SUM_MICROS.fetch_add(us, Ordering::Relaxed);
    if us <= 1_000 {
        NODE_VERIFY_BUCKET_LE_1MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 5_000 {
        NODE_VERIFY_BUCKET_LE_5MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 10_000 {
        NODE_VERIFY_BUCKET_LE_10MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 50_000 {
        NODE_VERIFY_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 100_000 {
        NODE_VERIFY_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 500_000 {
        NODE_VERIFY_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    }
}

fn observe_hdr_read(d: std::time::Duration) {
    let us = d.as_micros() as u64;
    NODE_STORE_HDR_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    NODE_STORE_HDR_READ_SUM_MICROS.fetch_add(us, Ordering::Relaxed);
    if us <= 1_000 {
        NODE_STORE_HDR_BUCKET_LE_1MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 5_000 {
        NODE_STORE_HDR_BUCKET_LE_5MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 10_000 {
        NODE_STORE_HDR_BUCKET_LE_10MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 50_000 {
        NODE_STORE_HDR_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 100_000 {
        NODE_STORE_HDR_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 500_000 {
        NODE_STORE_HDR_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    }
    // +Inf implizit über count
}

fn observe_pl_read(d: std::time::Duration) {
    let us = d.as_micros() as u64;
    NODE_STORE_PL_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    NODE_STORE_PL_READ_SUM_MICROS.fetch_add(us, Ordering::Relaxed);
    if us <= 1_000 {
        NODE_STORE_PL_BUCKET_LE_1MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 5_000 {
        NODE_STORE_PL_BUCKET_LE_5MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 10_000 {
        NODE_STORE_PL_BUCKET_LE_10MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 50_000 {
        NODE_STORE_PL_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 100_000 {
        NODE_STORE_PL_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 500_000 {
        NODE_STORE_PL_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    }
}

fn observe_persist(d: std::time::Duration) {
    let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
    NODE_PERSIST_COUNT.fetch_add(1, Ordering::Relaxed);
    NODE_PERSIST_SUM_MICROS.fetch_add(us, Ordering::Relaxed);
    if us <= 1_000 {
        NODE_PERSIST_BUCKET_LE_1MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 5_000 {
        NODE_PERSIST_BUCKET_LE_5MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 10_000 {
        NODE_PERSIST_BUCKET_LE_10MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 50_000 {
        NODE_PERSIST_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 100_000 {
        NODE_PERSIST_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 500_000 {
        NODE_PERSIST_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    }
}

fn main() -> Result<()> {
    init_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rayon_threads = num_cpus::get().saturating_sub(1).max(1);
    rayon::ThreadPoolBuilder::new()
        .num_threads(rayon_threads)
        .build_global()
        .ok();
    info!(rayon_threads, "rayon global thread pool initialized");

    let opts = NodeOpts::parse();
    info!(?opts, "starting phantom-node");
    let cmd = opts.command.unwrap_or(Command::Run(NodeRunArgs::default()));
    match cmd {
        Command::Run(args) => run_node_run(&args),
        Command::PayoutRoot(args) => run_payout_root(&args),
        Command::CommitteePayoutFromHeaders(args) => run_committee_payout_from_headers(&args),
        Command::BuildPayload(args) => run_build_payload(&args),
        Command::GraphAck(args) => run_graph_ack(&args),
        Command::GraphInsertAndAck(args) => run_graph_insert_and_ack(&args),
        Command::P2pRun(args) => run_p2p_run(&args),
        Command::DaRun(args) => run_da_run(&args),
        Command::P2pQuicListen(args) => run_p2p_quic_listen(&args),
        Command::P2pQuicConnect(args) => run_p2p_quic_connect(&args),
        Command::P2pInjectHeaders(args) => run_p2p_inject_headers(&args),
        Command::P2pInjectPayloads(args) => run_p2p_inject_payloads(&args),
        Command::P2pMetrics => run_p2p_metrics(),
        Command::P2pMetricsServe(args) => run_p2p_metrics_serve(&args),
        Command::StatusServe(args) => run_status_serve(&args),
        Command::ConsensusAckDists(args) => run_consensus_ack_dists(&args),
        Command::ConsensusPayoutRoot(args) => run_consensus_payout_root(&args),
        Command::CacheBench(args) => run_cache_bench(&args),
        Command::Db(cmd) => match cmd {
            DbCmd::Repair(args) => run_db_repair(&args),
            DbCmd::Reset(args) => run_db_reset(&args),
        },
        Command::ValidatorControl(cmd) => match cmd {
            ValidatorControlCmd::Get(args) => run_validator_control_get(&args),
            ValidatorControlCmd::Status(args) => run_validator_control_status(&args),
            ValidatorControlCmd::Set(args) => run_validator_control_set(&args),
        },
    }
}
