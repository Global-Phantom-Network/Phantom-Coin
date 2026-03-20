// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use clap::Parser;
use hyper::body::HttpBody as _;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use pc_codec::Encodable;
use pc_consensus::{
    consts, current_emission_bucket, pow_hash, role_policy::RolePolicy, validate_mint_pow_bound_v1,
    SupplyState,
};
use pc_types::{
    cmp_hash_be_u256, digest_genesis_note, digest_mint, validate_mint_sanity, GenesisNote,
    GenesisParams, LockCommitment, MintEvent, MintRoundPhase, MintStatus, MintTemplate,
    SubmitMintRequest, SubmitMintResponse, TxOut, GENESIS_FEATURE_MINT_POW_BIND_V1,
    GENESIS_FEATURE_ROLE_POLICY_V1, MINT_VERSION_V2,
};
use phantom_config as pcfg;
#[path = "../store_path.rs"]
mod store_path;

#[derive(Debug, Parser)]
#[command(name = "phantom-mint-rpc", version, about = "Phantom Mint RPC Server")]
struct Cli {
    /// Bind address, e.g. 127.0.0.1:9090.
    /// Bind-Addr, z. B. 127.0.0.1:9090
    #[arg(long, default_value = "127.0.0.1:9090")]
    addr: String,
    /// Store-Verzeichnis (enthält mempool/). Wird für den Default von mempool_dir genutzt.
    /// Store directory (contains mempool/). Used as default for mempool_dir.
    #[arg(long, default_value_t = store_path::default_runtime_store_dir_string())]
    store_dir: String,
    /// Mempool directory for persistent mint state.
    /// Mempool-Verzeichnis für persistenten Mint-State.
    #[arg(long, default_value_t = store_path::default_runtime_mempool_dir_string())]
    mempool_dir: String,
    /// Allow a non-default mempool_dir.
    /// Required when --mempool-dir differs from <store_dir>/mempool.
    ///
    /// Erlaube ein nicht-Default mempool_dir.
    /// Pflicht, wenn --mempool-dir von <store_dir>/mempool abweicht.
    #[arg(long, default_value_t = false)]
    force_mempool_dir: bool,
    /// Perform fsync() on supply_state.json writes (default: true).
    /// Führe fsync() beim Schreiben von supply_state.json aus (Default: true).
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// PoW Target Bits (Difficulty)
    #[arg(long, default_value_t = consts::POW_DEFAULT_BITS)]
    pow_bits: u8,
    /// Pfad zur genesis_note Datei (binär). Optional für lokale Nutzung.
    #[arg(long)]
    genesis_note: Option<String>,
    /// Starte ohne TLS (nur lokal auf 127.0.0.1/::1 erlaubt).
    #[arg(long, default_value_t = false)]
    no_tls: bool,
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
    /// Max concurrent HTTP connections (default: 64).
    /// Max. gleichzeitige HTTP-Verbindungen (Default: 64).
    #[arg(long, default_value_t = 64)]
    max_connections: usize,
}

struct AppState {
    supply: Mutex<SupplyState>,
    round: Mutex<MintRoundState>,
    network_id: [u8; 32],
    emission_bootstrap_bucket: u64,
    mempool_dir: String,
    pow_bits_init: u8,
    do_fsync: bool,
    role_policy: Option<Arc<RolePolicy>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct MintRoundState {
    prev_mint_id: [u8; 32],
    next_mint_height: u64,
    round_id: [u8; 32],
    phase: MintRoundPhase,
    frozen_hit_bucket: Option<u64>,
    frozen_bits: Option<u8>,
    collection_deadline_bucket: Option<u64>,
    finalize_deadline_bucket: Option<u64>,
    best_candidate_id: Option<[u8; 32]>,
    best_pow_hash: Option<[u8; 32]>,
}

impl MintRoundState {
    fn searching(prev_mint_id: [u8; 32], next_mint_height: u64) -> Self {
        Self {
            prev_mint_id,
            next_mint_height,
            round_id: pc_consensus::mint_round_id_v1(&prev_mint_id, next_mint_height),
            phase: MintRoundPhase::Searching,
            frozen_hit_bucket: None,
            frozen_bits: None,
            collection_deadline_bucket: None,
            finalize_deadline_bucket: None,
            best_candidate_id: None,
            best_pow_hash: None,
        }
    }

    fn reset_from_supply(&mut self, supply: &SupplyState) {
        *self = Self::searching(supply.last_mint_id, supply.mint_height.saturating_add(1));
    }

    fn matches_supply(&self, supply: &SupplyState) -> bool {
        self.prev_mint_id == supply.last_mint_id
            && self.next_mint_height == supply.mint_height.saturating_add(1)
            && self.round_id
                == pc_consensus::mint_round_id_v1(&self.prev_mint_id, self.next_mint_height)
    }

    fn reconcile_with_supply(&mut self, supply: &SupplyState, now_bucket: u64) -> bool {
        let mut changed = false;
        if !self.matches_supply(supply) {
            self.reset_from_supply(supply);
            changed = true;
        }
        if matches!(self.phase, MintRoundPhase::Collecting)
            && (self.frozen_hit_bucket.is_none()
                || self.frozen_bits.is_none()
                || self.collection_deadline_bucket.is_none()
                || self.finalize_deadline_bucket.is_none()
                || self.collection_deadline_bucket > self.finalize_deadline_bucket)
        {
            self.reset_from_supply(supply);
            changed = true;
        }
        if matches!(self.phase, MintRoundPhase::Collecting)
            && self
                .finalize_deadline_bucket
                .is_some_and(|deadline| now_bucket > deadline)
        {
            self.reset_from_supply(supply);
            changed = true;
        }
        changed
    }
}

const MAX_MINT_SUBMIT_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug)]
enum ReadBodyError {
    TooLarge,
    Hyper(hyper::Error),
}

async fn read_body_limited(
    mut body: Body,
    limit: usize,
) -> std::result::Result<Vec<u8>, ReadBodyError> {
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

fn make_json_response(status: StatusCode, body: String) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn make_text_response(status: StatusCode, text: &str) -> Response<Body> {
    let mut resp = Response::new(Body::from(text.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    resp
}

fn content_type_is_json(req: &Request<Body>) -> bool {
    let Some(ct) = req.headers().get(CONTENT_TYPE) else {
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

fn parse_hex32(input: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn load_supply_state(
    mempool_dir: &str,
    pow_bits: u8,
    emission_bootstrap_bucket: u64,
) -> SupplyState {
    let path = Path::new(mempool_dir).join("supply_state.json");
    let mut st = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<SupplyState>(&raw).ok())
        .unwrap_or_default();
    if st.mint_height == 0
        && st.total_supply == 0
        && st.last_mint_id == [0u8; 32]
        && st.last_minted_at_index == 0
    {
        st.pow_bits = pow_bits;
        st.pow_bits_min = pow_bits;
        st.pow_asert_ref_bucket = emission_bootstrap_bucket;
    } else {
        // Backward-compat: supply_state.json may predate pow_bits_min.
        if st.pow_bits_min == 0 && pow_bits != 0 {
            st.pow_bits_min = pow_bits;
        }
        if st.pow_bits < st.pow_bits_min {
            st.pow_bits = st.pow_bits_min;
        }
        if st.pow_asert_ref_bucket == 0 {
            st.pow_asert_ref_bucket = if st.mint_height == 0 {
                emission_bootstrap_bucket
            } else {
                st.last_final_emission_bucket
            };
        }
    }
    st
}

fn mint_round_state_path(mempool_dir: &str) -> std::path::PathBuf {
    Path::new(mempool_dir).join("mint_round_state.json")
}

fn load_mint_round_state_from_disk(mempool_dir: &str) -> Option<MintRoundState> {
    let path = mint_round_state_path(mempool_dir);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<MintRoundState>(&raw).ok())
}

fn load_mint_round_state_snapshot(mempool_dir: &str, supply: &SupplyState) -> MintRoundState {
    let now_bucket = current_emission_bucket();
    let mut round = load_mint_round_state_from_disk(mempool_dir).unwrap_or_else(|| {
        MintRoundState::searching(supply.last_mint_id, supply.mint_height.saturating_add(1))
    });
    let _ = round.reconcile_with_supply(supply, now_bucket);
    round
}

fn refresh_mint_round_state_from_disk(
    mempool_dir: &str,
    supply: &SupplyState,
    st: &mut MintRoundState,
) {
    if let Some(mut fresh) = load_mint_round_state_from_disk(mempool_dir) {
        let now_bucket = current_emission_bucket();
        let _ = fresh.reconcile_with_supply(supply, now_bucket);
        *st = fresh;
    } else {
        *st = MintRoundState::searching(supply.last_mint_id, supply.mint_height.saturating_add(1));
    }
}

fn persist_mint_round_state_sync(mempool_dir: &str, st: &MintRoundState, do_fsync: bool) {
    let path = mint_round_state_path(mempool_dir);
    let raw = match serde_json::to_vec(st) {
        Ok(v) => v,
        Err(e) => {
            warn!(err = %e, "serialize mint_round_state failed");
            return;
        }
    };
    if let Err(e) = atomic_write(&path, &raw, do_fsync) {
        warn!(path = %path.display(), err = %e, "persist mint_round_state failed");
    }
}

fn active_target_bits(supply: &SupplyState, round: &MintRoundState, now_bucket: u64) -> u8 {
    match round.phase {
        MintRoundPhase::Searching => supply.expected_bits_for_bucket(now_bucket),
        MintRoundPhase::Collecting => round.frozen_bits.unwrap_or(supply.pow_bits),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MintTemplatePollKey {
    last_mint_id: [u8; 32],
    round_id: [u8; 32],
    phase: MintRoundPhase,
    hit_bucket: Option<u64>,
    bits_used: Option<u8>,
    collect_deadline_bucket: Option<u64>,
    finalize_deadline_bucket: Option<u64>,
    target_bits: u8,
}

fn mint_template_poll_key(
    supply: &SupplyState,
    round: &MintRoundState,
    now_bucket: u64,
) -> MintTemplatePollKey {
    MintTemplatePollKey {
        last_mint_id: supply.last_mint_id,
        round_id: round.round_id,
        phase: round.phase,
        hit_bucket: round.frozen_hit_bucket,
        bits_used: round.frozen_bits,
        collect_deadline_bucket: round.collection_deadline_bucket,
        finalize_deadline_bucket: round.finalize_deadline_bucket,
        target_bits: active_target_bits(supply, round, now_bucket),
    }
}

fn cleanup_seed_marker(seed_marker: std::path::PathBuf) {
    let _ = std::thread::spawn(move || {
        let _ = std::fs::remove_file(seed_marker);
    });
}

fn candidate_replaces_existing_best(
    candidate_pow_hash: &[u8; 32],
    candidate_id: &[u8; 32],
    previous_pow_hash: &[u8; 32],
    previous_candidate_id: &[u8; 32],
) -> bool {
    cmp_hash_be_u256(candidate_pow_hash, previous_pow_hash)
        .then_with(|| {
            candidate_id
                .as_slice()
                .cmp(previous_candidate_id.as_slice())
        })
        .is_lt()
}

fn atomic_write(path: &Path, data: &[u8], do_fsync: bool) -> std::io::Result<()> {
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

async fn handle(req: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        // GET /mint/template - Liefert Mining-Template
        // NOTE: Miner MUST compute pow_seed via mint_pow_seed_v2(network_id, mint_event)
        (&Method::GET, "/mint/template") => {
            let (longpoll, prev_mint_id_raw, timeout_ms) = match req.uri().query() {
                Some(q) => (
                    query_param_bool(q, "longpoll"),
                    query_param(q, "prev_mint_id").map(|v| v.to_string()),
                    query_param_u64(q, "timeout_ms"),
                ),
                None => (false, None, None),
            };
            let prev_mint_id = prev_mint_id_raw.as_deref().and_then(parse_hex32);

            if longpoll {
                match prev_mint_id_raw.as_deref() {
                    None => {
                        let body = serde_json::json!({
                            "error": "prev_mint_id required for longpoll"
                        })
                        .to_string();
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                    Some(_) if prev_mint_id.is_none() => {
                        let body = serde_json::json!({"error": "invalid prev_mint_id"}).to_string();
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                    _ => {}
                }
            }

            const LONGPOLL_TIMEOUT_DEFAULT_MS: u64 = 25_000;
            const LONGPOLL_TIMEOUT_MIN_MS: u64 = 1_000;
            const LONGPOLL_TIMEOUT_MAX_MS: u64 = 120_000;
            const LONGPOLL_POLL_INTERVAL_MS: u64 = 250;

            if longpoll {
                if let Some(prev) = prev_mint_id {
                    let timeout = timeout_ms
                        .unwrap_or(LONGPOLL_TIMEOUT_DEFAULT_MS)
                        .clamp(LONGPOLL_TIMEOUT_MIN_MS, LONGPOLL_TIMEOUT_MAX_MS);
                    let deadline = Instant::now() + Duration::from_millis(timeout);
                    let initial_key = {
                        let mut supply = state.supply.lock().await;
                        *supply = load_supply_state(
                            &state.mempool_dir,
                            state.pow_bits_init,
                            state.emission_bootstrap_bucket,
                        );
                        let now_bucket = current_emission_bucket();
                        let mut round = state.round.lock().await;
                        refresh_mint_round_state_from_disk(&state.mempool_dir, &supply, &mut round);
                        if round.reconcile_with_supply(&supply, now_bucket) {
                            persist_mint_round_state_sync(
                                &state.mempool_dir,
                                &round,
                                state.do_fsync,
                            );
                        }
                        mint_template_poll_key(&supply, &round, now_bucket)
                    };
                    loop {
                        let mut supply = state.supply.lock().await;
                        *supply = load_supply_state(
                            &state.mempool_dir,
                            state.pow_bits_init,
                            state.emission_bootstrap_bucket,
                        );
                        let now_bucket = current_emission_bucket();
                        let mut round = state.round.lock().await;
                        refresh_mint_round_state_from_disk(&state.mempool_dir, &supply, &mut round);
                        if round.reconcile_with_supply(&supply, now_bucket) {
                            persist_mint_round_state_sync(
                                &state.mempool_dir,
                                &round,
                                state.do_fsync,
                            );
                        }
                        let current_key = mint_template_poll_key(&supply, &round, now_bucket);
                        drop(round);
                        drop(supply);
                        if current_key.last_mint_id != prev || current_key != initial_key {
                            break;
                        }
                        if Instant::now() >= deadline {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(LONGPOLL_POLL_INTERVAL_MS)).await;
                    }
                }
            }

            let mut supply = state.supply.lock().await;
            *supply = load_supply_state(
                &state.mempool_dir,
                state.pow_bits_init,
                state.emission_bootstrap_bucket,
            );
            let now_bucket = current_emission_bucket();
            let mut round = state.round.lock().await;
            refresh_mint_round_state_from_disk(&state.mempool_dir, &supply, &mut round);
            if round.reconcile_with_supply(&supply, now_bucket) {
                persist_mint_round_state_sync(&state.mempool_dir, &round, state.do_fsync);
            }
            let template = MintTemplate {
                prev_mint_id: hex::encode(supply.last_mint_id),
                target_bits: active_target_bits(&supply, &round, now_bucket),
                reward: supply.next_reward(),
                mint_height: supply.mint_height,
                total_supply: supply.total_supply.to_string(),
                remaining_supply: supply.remaining_supply().to_string(),
                network_id: hex::encode(state.network_id),
                phase: round.phase,
                round_id: hex::encode(round.round_id),
                hit_bucket: round.frozen_hit_bucket,
                bits_used: round.frozen_bits,
                collect_deadline_bucket: round.collection_deadline_bucket,
                finalize_deadline_bucket: round.finalize_deadline_bucket,
            };
            match serde_json::to_string(&template) {
                Ok(body) => Ok(make_json_response(StatusCode::OK, body)),
                Err(_) => Ok(make_text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "serialization error",
                )),
            }
        }

        // GET /mint/status - Liefert aktuellen Mint-Status
        (&Method::GET, "/mint/status") => {
            let mut supply = state.supply.lock().await;
            *supply = load_supply_state(
                &state.mempool_dir,
                state.pow_bits_init,
                state.emission_bootstrap_bucket,
            );
            let now_bucket = current_emission_bucket();
            let mut round = state.round.lock().await;
            refresh_mint_round_state_from_disk(&state.mempool_dir, &supply, &mut round);
            if round.reconcile_with_supply(&supply, now_bucket) {
                persist_mint_round_state_sync(&state.mempool_dir, &round, state.do_fsync);
            }
            let status = MintStatus {
                last_mint_id: hex::encode(supply.last_mint_id),
                mint_height: supply.mint_height,
                total_supply: supply.total_supply.to_string(),
                remaining_supply: supply.remaining_supply().to_string(),
                hard_cap: consts::HARD_CAP_UNITS.to_string(),
                next_reward: supply.next_reward(),
                can_mint: supply.can_mint(),
                target_bits: active_target_bits(&supply, &round, now_bucket),
                phase: round.phase,
                round_id: hex::encode(round.round_id),
                last_final_emission_bucket: supply.last_final_emission_bucket,
                hit_bucket: round.frozen_hit_bucket,
                bits_used: round.frozen_bits,
                collect_deadline_bucket: round.collection_deadline_bucket,
                finalize_deadline_bucket: round.finalize_deadline_bucket,
            };
            match serde_json::to_string(&status) {
                Ok(body) => Ok(make_json_response(StatusCode::OK, body)),
                Err(_) => Ok(make_text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "serialization error",
                )),
            }
        }

        // POST /mint/submit - Nimmt Mint-Solution entgegen
        (&Method::POST, "/mint/submit") => {
            if !content_type_is_json(&req) {
                let resp = SubmitMintResponse {
                    ok: false,
                    mint_id: None,
                    error: Some("unsupported_media_type".to_string()),
                };
                let body = serde_json::to_string(&resp).unwrap_or_default();
                return Ok(make_json_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, body));
            }

            let body_bytes = match tokio::time::timeout(
                Duration::from_secs(5),
                read_body_limited(req.into_body(), MAX_MINT_SUBMIT_BODY_BYTES),
            )
            .await
            {
                Ok(Ok(b)) => b,
                Ok(Err(ReadBodyError::TooLarge)) => {
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some("body too large".to_string()),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::PAYLOAD_TOO_LARGE, body));
                }
                Ok(Err(ReadBodyError::Hyper(_e))) => {
                    return Ok(make_text_response(StatusCode::BAD_REQUEST, "invalid body"));
                }
                Err(_e) => {
                    return Ok(make_text_response(
                        StatusCode::REQUEST_TIMEOUT,
                        "read timeout",
                    ));
                }
            };

            let submit_req: SubmitMintRequest = match serde_json::from_slice(&body_bytes) {
                Ok(r) => r,
                Err(e) => {
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some(format!("invalid json: {}", e)),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                }
            };

            // Parse MintEventJson -> MintEvent
            let mint_json = submit_req.mint;
            let prev_mint_id = match hex::decode(&mint_json.prev_mint_id) {
                Ok(v) if v.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    arr
                }
                _ => {
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some("invalid prev_mint_id".into()),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                }
            };

            let pow_seed = match hex::decode(&mint_json.pow_seed) {
                Ok(v) if v.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    arr
                }
                _ => {
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some("invalid pow_seed".into()),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                }
            };

            let mut outputs = Vec::new();
            for out_json in &mint_json.outputs {
                let lock_bytes = match hex::decode(&out_json.lock) {
                    Ok(v) if v.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&v);
                        arr
                    }
                    _ => {
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("invalid output lock".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                };
                outputs.push(TxOut {
                    amount: out_json.amount,
                    lock: LockCommitment(lock_bytes),
                });
            }

            let mint = MintEvent {
                version: mint_json.version,
                prev_mint_id,
                outputs,
                pow_seed,
                pow_nonce: mint_json.pow_nonce,
                minted_at: 0,
                round_id: mint_json
                    .round_id
                    .as_deref()
                    .and_then(|v| hex::decode(v).ok())
                    .filter(|v| v.len() == 32)
                    .map(|v| {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&v);
                        arr
                    })
                    .unwrap_or([0u8; 32]),
                hit_bucket: mint_json.hit_bucket.unwrap_or(0),
                bits_used: mint_json.bits_used.unwrap_or(0),
            };

            let now_bucket = current_emission_bucket();
            let mut supply = state.supply.lock().await;
            *supply = load_supply_state(
                &state.mempool_dir,
                state.pow_bits_init,
                state.emission_bootstrap_bucket,
            );
            let expected_mint_height = supply.mint_height.saturating_add(1);
            let supply_snapshot = supply.clone();
            drop(supply);

            let mut round = state.round.lock().await;
            refresh_mint_round_state_from_disk(&state.mempool_dir, &supply_snapshot, &mut round);
            if round.reconcile_with_supply(&supply_snapshot, now_bucket) {
                persist_mint_round_state_sync(&state.mempool_dir, &round, state.do_fsync);
            }

            if mint.prev_mint_id != supply_snapshot.last_mint_id {
                let resp = SubmitMintResponse {
                    ok: false,
                    mint_id: None,
                    error: Some("prev_mint_id does not match chain tip - stale template".into()),
                };
                let body = serde_json::to_string(&resp).unwrap_or_default();
                return Ok(make_json_response(StatusCode::CONFLICT, body));
            }

            let (bits, round_phase) = match round.phase {
                MintRoundPhase::Searching => {
                    if mint.version < MINT_VERSION_V2 {
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("mint v2 required for emission rounds".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                    if mint.round_id != round.round_id {
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("round_id mismatch".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::CONFLICT, body));
                    }
                    if mint.hit_bucket
                        > now_bucket.saturating_add(consts::EMISSION_MAX_FUTURE_SKEW_BUCKETS)
                    {
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("hit_bucket too far in future".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                    let expected_bits = supply_snapshot.expected_bits_for_bucket(mint.hit_bucket);
                    if mint.bits_used != expected_bits {
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("bits_used mismatch".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                    (expected_bits, MintRoundPhase::Searching)
                }
                MintRoundPhase::Collecting => {
                    if mint.version < MINT_VERSION_V2 {
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("mint v2 required while round is collecting".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                    if mint.round_id != round.round_id
                        || Some(mint.hit_bucket) != round.frozen_hit_bucket
                        || Some(mint.bits_used) != round.frozen_bits
                    {
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("mint does not match frozen round".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::CONFLICT, body));
                    }
                    if round
                        .finalize_deadline_bucket
                        .is_some_and(|deadline| now_bucket > deadline)
                    {
                        round.reset_from_supply(&supply_snapshot);
                        persist_mint_round_state_sync(&state.mempool_dir, &round, state.do_fsync);
                        let resp = SubmitMintResponse {
                            ok: false,
                            mint_id: None,
                            error: Some("collecting round expired".into()),
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        return Ok(make_json_response(StatusCode::CONFLICT, body));
                    }
                    (
                        round.frozen_bits.unwrap_or(supply_snapshot.pow_bits),
                        MintRoundPhase::Collecting,
                    )
                }
            };

            if validate_mint_pow_bound_v1(&state.network_id, &mint, bits).is_err() {
                let resp = SubmitMintResponse {
                    ok: false,
                    mint_id: None,
                    error: Some("PoW validation failed".into()),
                };
                let body = serde_json::to_string(&resp).unwrap_or_default();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }

            if let Some(policy) = state.role_policy.as_ref() {
                if !policy.allows_mint(&mint) {
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some("mint rejected by role_policy".into()),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                }
            }

            // Reserve PoW seed (anti-replay) before persisting the mint.
            let seed_hex = hex::encode(mint.pow_seed);
            let seeds_dir = Path::new(&state.mempool_dir).join("mint_seeds");
            let seed_marker = seeds_dir.join(&seed_hex);
            let reserved = match tokio::task::spawn_blocking({
                let seeds_dir = seeds_dir.clone();
                let seed_marker = seed_marker.clone();
                move || -> std::io::Result<bool> {
                    std::fs::create_dir_all(&seeds_dir)?;
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&seed_marker)
                    {
                        Ok(mut f) => {
                            use std::io::Write as _;
                            let _ = f.write_all(b"1");
                            let _ = f.flush();
                            Ok(true)
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                        Err(e) => Err(e),
                    }
                }
            })
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some(format!("seed reservation failed: {}", e)),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
                Err(_) => {
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some("seed reservation failed".into()),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
            };
            if !reserved {
                let resp = SubmitMintResponse {
                    ok: false,
                    mint_id: None,
                    error: Some("seed already used".into()),
                };
                let body = serde_json::to_string(&resp).unwrap_or_default();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }

            if validate_mint_sanity(&mint).is_err() {
                cleanup_seed_marker(seed_marker.clone());
                let resp = SubmitMintResponse {
                    ok: false,
                    mint_id: None,
                    error: Some("mint sanity failed".into()),
                };
                let body = serde_json::to_string(&resp).unwrap_or_default();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }

            let mint_id = match supply_snapshot.validate_mint(&mint) {
                Ok(()) => digest_mint(&mint),
                Err(e) => {
                    cleanup_seed_marker(seed_marker.clone());
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some(format!("validation failed: {:?}", e)),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                }
            };

            // Persist mint into mempool_dir/mints/<id>.bin so the node can pick it up and gossip it.
            let mints_dir = Path::new(&state.mempool_dir).join("mints");
            let mints_dir_clone = mints_dir.clone();
            let _ = tokio::task::spawn_blocking(move || std::fs::create_dir_all(&mints_dir_clone))
                .await;
            let mpath = mints_dir.join(format!("{}.bin", hex::encode(mint_id)));
            let mut buf = Vec::new();
            if let Err(e) = mint.encode(&mut buf) {
                let _ = tokio::task::spawn_blocking({
                    let p = seed_marker.clone();
                    move || {
                        let _ = std::fs::remove_file(&p);
                    }
                })
                .await;
                let resp = SubmitMintResponse {
                    ok: false,
                    mint_id: None,
                    error: Some(format!("encode mint: {}", e)),
                };
                let body = serde_json::to_string(&resp).unwrap_or_default();
                return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
            }
            let do_fsync = state.do_fsync;
            let persist_res = tokio::task::spawn_blocking({
                let p = mpath.clone();
                let data = buf.clone();
                move || atomic_write(&p, &data, do_fsync)
            })
            .await;
            match persist_res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let _ = tokio::task::spawn_blocking({
                        let p = seed_marker.clone();
                        move || {
                            let _ = std::fs::remove_file(&p);
                        }
                    })
                    .await;
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some(format!("persist mint: {}", e)),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
                Err(_e) => {
                    let _ = tokio::task::spawn_blocking({
                        let p = seed_marker.clone();
                        move || {
                            let _ = std::fs::remove_file(&p);
                        }
                    })
                    .await;
                    let resp = SubmitMintResponse {
                        ok: false,
                        mint_id: None,
                        error: Some("persist mint: task failed".into()),
                    };
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
            }

            let pow = pow_hash(&mint.pow_seed, mint.pow_nonce);
            match round_phase {
                MintRoundPhase::Searching => {
                    round.phase = MintRoundPhase::Collecting;
                    round.frozen_hit_bucket = Some(mint.hit_bucket);
                    round.frozen_bits = Some(mint.bits_used);
                    round.collection_deadline_bucket =
                        Some(consts::emission_collect_deadline_bucket(mint.hit_bucket));
                    round.finalize_deadline_bucket =
                        Some(consts::emission_finalize_deadline_bucket(mint.hit_bucket));
                    round.best_candidate_id = Some(mint_id);
                    round.best_pow_hash = Some(pow);
                }
                MintRoundPhase::Collecting => {
                    let replace = match (round.best_pow_hash, round.best_candidate_id) {
                        (Some(prev_pow), Some(prev_id)) => {
                            candidate_replaces_existing_best(&pow, &mint_id, &prev_pow, &prev_id)
                        }
                        _ => true,
                    };
                    if replace {
                        round.best_candidate_id = Some(mint_id);
                        round.best_pow_hash = Some(pow);
                    }
                }
            }
            persist_mint_round_state_sync(&state.mempool_dir, &round, state.do_fsync);

            info!(mint_id = %hex::encode(mint_id), mint_height = expected_mint_height, "mint accepted (queued)");

            let resp = SubmitMintResponse {
                ok: true,
                mint_id: Some(hex::encode(mint_id)),
                error: None,
            };
            let body = serde_json::to_string(&resp).unwrap_or_default();
            Ok(make_json_response(StatusCode::OK, body))
        }

        _ => Ok(make_text_response(StatusCode::NOT_FOUND, "not found")),
    }
}

fn build_tls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = load_certs(cert_path)?;
    let key: PrivateKeyDer<'static> = load_key(key_path)?;
    let roots = load_roots(client_ca_path)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow!("client verifier: {e}"))?;
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("tls single_cert client: {e}"))
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

fn write_mint_rpc_marker(mempool_dir: &str, store_dir: &str, addr: &str) {
    let path = Path::new(mempool_dir).join("mint_rpc.marker.json");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let marker = serde_json::json!({
        "store_dir": store_dir,
        "mempool_dir": mempool_dir,
        "addr": addr,
        "ts": ts,
    });
    if let Err(e) = std::fs::write(&path, marker.to_string()) {
        warn!(file = %path.display(), err = %e, "mint_rpc marker write failed");
    }
}

fn enforce_mempool_dir_is_expected_or_forced(
    expected_mempool: &Path,
    mempool_dir: &Path,
    force: bool,
) -> Result<()> {
    if mempool_dir != expected_mempool && !force {
        anyhow::bail!(
            "mempool_dir '{}' weicht von store_dir/mempool '{}' ab. \
Setze --force-mempool-dir, um fortzufahren.",
            mempool_dir.display(),
            expected_mempool.display()
        );
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    let mempool_arg_set =
        std::env::args().any(|a| a == "--mempool-dir" || a.starts_with("--mempool-dir="));
    let store_dir_path = store_path::resolve_store_dir_value(&cli.store_dir, false)?;
    let store_dir = store_dir_path.to_string_lossy().to_string();
    let expected_mempool = store_dir_path.join("mempool");
    let mempool_dir = if mempool_arg_set {
        let mp_path =
            store_path::resolve_mempool_dir_value(&cli.mempool_dir, &store_dir_path, false)?;
        if mp_path != expected_mempool {
            enforce_mempool_dir_is_expected_or_forced(
                expected_mempool.as_path(),
                mp_path.as_path(),
                cli.force_mempool_dir,
            )?;
            warn!(
                mempool_dir = %mp_path.display(),
                expected = %expected_mempool.display(),
                "mempool_dir weicht von store_dir/mempool ab; Mint-Propagation zum Node kann fehlschlagen"
            );
        }
        mp_path.to_string_lossy().to_string()
    } else {
        let mp = expected_mempool.to_string_lossy().to_string();
        if cli.mempool_dir != mp {
            warn!(
                mempool_dir = %cli.mempool_dir,
                expected = %expected_mempool.display(),
                "mempool_dir default überschrieben durch store_dir/mempool"
            );
        }
        mp
    };
    std::fs::create_dir_all(&mempool_dir)
        .map_err(|e| anyhow!("create mempool_dir '{}': {e}", mempool_dir))?;
    write_mint_rpc_marker(&mempool_dir, &store_dir, &cli.addr);

    let note = if let Some(genesis_path) = cli.genesis_note.as_ref() {
        let note_buf = std::fs::read(genesis_path)
            .map_err(|e| anyhow!("read genesis_note '{}': {e}", genesis_path))?;
        let note = pc_codec::decode_exact::<GenesisNote>(&note_buf)
            .map_err(|e| anyhow!("decode genesis_note '{}': {e}", genesis_path))?;
        if (note.params.features & GENESIS_FEATURE_MINT_POW_BIND_V1) == 0 {
            warn!("genesis_note missing GENESIS_FEATURE_MINT_POW_BIND_V1; proceeding for backward compatibility");
        }
        note
    } else {
        // Prefer the node's mempool genesis_note.bin when running alongside phantom-node.
        // This keeps `network_id` stable and avoids wasting PoW on the wrong network_id.
        let mempool_note_path = Path::new(&mempool_dir).join("genesis_note.bin");
        if mempool_note_path.exists() {
            let note_buf = std::fs::read(&mempool_note_path)
                .map_err(|e| anyhow!("read genesis_note '{}': {e}", mempool_note_path.display()))?;
            let note = pc_codec::decode_exact::<GenesisNote>(&note_buf).map_err(|e| {
                anyhow!("decode genesis_note '{}': {e}", mempool_note_path.display())
            })?;
            if (note.params.features & GENESIS_FEATURE_MINT_POW_BIND_V1) == 0 {
                warn!(
                    file = %mempool_note_path.display(),
                    "genesis_note missing GENESIS_FEATURE_MINT_POW_BIND_V1; proceeding for backward compatibility"
                );
            }
            note
        } else {
            let mut seed_in = b"pc:mint_rpc:local:v1".to_vec();
            seed_in.extend_from_slice(cli.addr.as_bytes());
            let seed = pc_crypto::blake3_32(&seed_in);
            GenesisNote {
                version: 3,
                network_name: b"local".to_vec(),
                seed,
                params: GenesisParams {
                    shards_initial: 64,
                    committee_k: 21,
                    txs_per_payload: 256,
                    features: GENESIS_FEATURE_MINT_POW_BIND_V1,
                },
                genesis_validators: vec![],
                genesis_message: vec![],
                emission_bootstrap_bucket: current_emission_bucket(),
            }
        }
    };
    let role_policy = if (note.params.features & GENESIS_FEATURE_ROLE_POLICY_V1) != 0 {
        let policy_path = Path::new(&mempool_dir).join(pcfg::ROLE_POLICY_FILENAME);
        if !policy_path.exists() {
            anyhow::bail!(
                "role_policy.json required (GENESIS_FEATURE_ROLE_POLICY_V1 set) at {}",
                policy_path.display()
            );
        }
        let policy = pcfg::load_role_policy_from_file(&policy_path)
            .map_err(|e| anyhow!("role_policy load failed: {e}"))?;
        let got = policy.commitment();
        let want = note.seed;
        if got != want {
            anyhow::bail!(
                "role_policy commitment mismatch: computed={}, genesis_note.seed={}",
                hex::encode(got),
                hex::encode(want)
            );
        }
        Some(Arc::new(policy))
    } else {
        let policy_path = Path::new(&mempool_dir).join(pcfg::ROLE_POLICY_FILENAME);
        if policy_path.exists() {
            warn!("role_policy.json present but GENESIS_FEATURE_ROLE_POLICY_V1 not set; policy ignored");
        }
        None
    };
    let network_id = digest_genesis_note(&note);
    let addr: SocketAddr = cli
        .addr
        .parse()
        .map_err(|e| anyhow!("invalid addr '{}': {e}", &cli.addr))?;

    let tls_requested =
        cli.tls_cert.is_some() || cli.tls_key.is_some() || cli.tls_client_ca.is_some();
    if cli.no_tls && tls_requested {
        anyhow::bail!("no_tls ist gesetzt, aber TLS-Optionen wurden angegeben");
    }

    let use_tls = if cli.no_tls || !tls_requested {
        false
    } else {
        if cli
            .tls_cert
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
            || cli.tls_key.as_deref().unwrap_or_default().trim().is_empty()
            || cli
                .tls_client_ca
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
        {
            anyhow::bail!("TLS-Dateien sind unvollständig (tls_cert/tls_key/tls_client_ca)");
        }
        true
    };

    if !use_tls && !addr.ip().is_loopback() {
        anyhow::bail!("Ohne TLS darf mint_rpc nur auf 127.0.0.1/::1 laufen");
    }

    let acceptor = if use_tls {
        let tls_cfg = build_tls_config(
            cli.tls_cert.as_deref().unwrap_or_default(),
            cli.tls_key.as_deref().unwrap_or_default(),
            cli.tls_client_ca.as_deref().unwrap_or_default(),
        )?;
        Some(TlsAcceptor::from(Arc::new(tls_cfg)))
    } else {
        None
    };
    let supply_state =
        load_supply_state(&mempool_dir, cli.pow_bits, note.emission_bootstrap_bucket);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow!("bind addr: {e}"))?;
    info!(
        %addr,
        mempool_dir = %mempool_dir,
        pow_bits = cli.pow_bits,
        tls = use_tls,
        "starting mint rpc server"
    );

    let round_state = load_mint_round_state_snapshot(&mempool_dir, &supply_state);
    let state = Arc::new(AppState {
        supply: Mutex::new(supply_state),
        round: Mutex::new(round_state),
        network_id,
        emission_bootstrap_bucket: note.emission_bootstrap_bucket,
        mempool_dir,
        pow_bits_init: cli.pow_bits,
        do_fsync: cli.fsync,
        role_policy,
    });
    if cli.max_connections == 0 {
        anyhow::bail!("--max-connections muss >= 1 sein");
    }
    let sem = Arc::new(Semaphore::new(cli.max_connections));

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept error");
                continue;
            }
        };

        let state = state.clone();
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(%peer, "too many connections");
                continue;
            }
        };
        if let Some(acceptor) = acceptor.clone() {
            tokio::spawn(async move {
                let _permit = permit;
                match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => {
                        let svc = service_fn(move |req| {
                            let st = state.clone();
                            async move {
                                match tokio::time::timeout(Duration::from_secs(10), handle(req, st))
                                    .await
                                {
                                    Ok(r) => r,
                                    Err(_) => Ok::<Response<Body>, Infallible>(make_text_response(
                                        StatusCode::GATEWAY_TIMEOUT,
                                        "Gateway Timeout",
                                    )),
                                }
                            }
                        });
                        if let Err(e) = hyper::server::conn::Http::new()
                            .serve_connection(tls, svc)
                            .await
                        {
                            warn!(error = %e, "server error");
                        }
                    }
                    Ok(Err(e)) => warn!(error = %e, "tls handshake error"),
                    Err(_) => warn!("tls handshake timeout"),
                }
            });
        } else {
            tokio::spawn(async move {
                let _permit = permit;
                let svc = service_fn(move |req| {
                    let st = state.clone();
                    async move {
                        match tokio::time::timeout(Duration::from_secs(10), handle(req, st)).await {
                            Ok(r) => r,
                            Err(_) => Ok::<Response<Body>, Infallible>(make_text_response(
                                StatusCode::GATEWAY_TIMEOUT,
                                "Gateway Timeout",
                            )),
                        }
                    }
                });
                if let Err(e) = hyper::server::conn::Http::new()
                    .serve_connection(tcp, svc)
                    .await
                {
                    warn!(error = %e, "server error");
                }
            });
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f22_mempool_dir_mismatch_without_force_is_error() {
        let expected = store_path::default_runtime_store_dir_pathbuf().join("mempool");
        let actual = Path::new("other").join("mempool");
        let err =
            enforce_mempool_dir_is_expected_or_forced(expected.as_path(), actual.as_path(), false)
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mempool_dir"));
        assert!(msg.contains("--force-mempool-dir"));
    }

    #[test]
    fn f22_mempool_dir_mismatch_with_force_is_ok() {
        let expected = store_path::default_runtime_store_dir_pathbuf().join("mempool");
        let actual = Path::new("other").join("mempool");
        enforce_mempool_dir_is_expected_or_forced(expected.as_path(), actual.as_path(), true)
            .unwrap();
    }

    #[test]
    fn f22_mempool_dir_equal_without_force_is_ok() {
        let expected = store_path::default_runtime_store_dir_pathbuf().join("mempool");
        enforce_mempool_dir_is_expected_or_forced(expected.as_path(), expected.as_path(), false)
            .unwrap();
    }

    #[tokio::test]
    async fn f21_supply_state_is_refreshed_from_disk_per_request() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mempool_dir = dir.path().join("mempool");
        std::fs::create_dir_all(&mempool_dir)?;

        let mut st1 = SupplyState::default();
        st1.last_mint_id = [1u8; 32];
        st1.mint_height = 7;
        st1.total_supply = 123;
        st1.pow_bits = 20;
        st1.pow_bits_min = 20;

        let supply_path = mempool_dir.join("supply_state.json");
        std::fs::write(&supply_path, serde_json::to_string(&st1)?)?;

        let state = Arc::new(AppState {
            supply: Mutex::new(SupplyState::default()),
            round: Mutex::new(load_mint_round_state_snapshot(
                &mempool_dir.to_string_lossy(),
                &st1,
            )),
            network_id: [2u8; 32],
            emission_bootstrap_bucket: 0,
            mempool_dir: mempool_dir.to_string_lossy().to_string(),
            pow_bits_init: 20,
            do_fsync: false,
            role_policy: None,
        });

        let req1 = Request::builder()
            .method(Method::GET)
            .uri("/mint/status")
            .body(Body::empty())?;
        let resp1 = handle(req1, state.clone()).await?;
        let body1 = hyper::body::to_bytes(resp1.into_body()).await?;
        let v1: serde_json::Value = serde_json::from_slice(&body1)?;
        let want_id1 = hex::encode(st1.last_mint_id);
        assert_eq!(
            v1.get("last_mint_id").and_then(|v| v.as_str()),
            Some(want_id1.as_str())
        );
        assert_eq!(
            v1.get("mint_height").and_then(|v| v.as_u64()),
            Some(st1.mint_height)
        );

        // Update on-disk state and ensure the next request reflects it.
        let mut st2 = st1;
        st2.last_mint_id = [3u8; 32];
        st2.mint_height = 8;
        st2.total_supply = 999;
        std::fs::write(&supply_path, serde_json::to_string(&st2)?)?;

        let req2 = Request::builder()
            .method(Method::GET)
            .uri("/mint/status")
            .body(Body::empty())?;
        let resp2 = handle(req2, state.clone()).await?;
        let body2 = hyper::body::to_bytes(resp2.into_body()).await?;
        let v2: serde_json::Value = serde_json::from_slice(&body2)?;
        let want_id2 = hex::encode(st2.last_mint_id);
        assert_eq!(
            v2.get("last_mint_id").and_then(|v| v.as_str()),
            Some(want_id2.as_str())
        );
        assert_eq!(
            v2.get("mint_height").and_then(|v| v.as_u64()),
            Some(st2.mint_height)
        );
        Ok(())
    }

    #[test]
    fn f23_max_connections_is_configurable_with_cli_default() {
        let cli = Cli::parse_from(["phantom-mint-rpc"]);
        assert_eq!(cli.max_connections, 64);

        let cli2 = Cli::parse_from(["phantom-mint-rpc", "--max-connections", "10"]);
        assert_eq!(cli2.max_connections, 10);
    }
}
