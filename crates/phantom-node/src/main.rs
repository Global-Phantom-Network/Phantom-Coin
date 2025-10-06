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
use clap::{Args, Parser, Subcommand};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use lru::LruCache;
use pc_codec::{self, Decodable, Encodable};
use pc_consensus::{
    check_mint_pow, compute_ack_distances_for_seats, compute_committee_payout,
    compute_committee_payout_from_headers, compute_total_payout_root, compute_attestor_payout, consts, finality_threshold,
    is_final, popcount_u64, pow_hash, pow_meets, set_bit, AnchorGraphCache, ConsensusConfig,
    ConsensusEngine, FeeSplitParams, validate_genesis_anchor,
};
use pc_crypto::blake3_32;
use pc_crypto::{payout_leaf_hash, merkle_build_proof};
use pc_crypto::bls_pk_from_bytes;
use pc_crypto::bls_fast_aggregate_verify;
use pc_consensus::committee_vrf::{RotationParams as VrfRotationParams, VrfCandidate, SelectedSeat, committee_select_vrf, derive_epoch, derive_vrf_seed};
use pc_consensus::attestor_pool::{attestor_sample_vrf, attestor_sample_vrf_fair, attestor_aggregate_sigs, attestation_message};
use pc_p2p::async_svc::{
    inbound_subscribe, metrics_snapshot, outbox_deq_inc, OutboundSink, StoreDelegate,
};
use pc_p2p::messages::{P2pMessage, RespMsg};
use pc_p2p::quic_transport::{
    client_config_from_cert, connect, spawn_client_reader, start_server, QuicClientSink,
};
use pc_p2p::RateLimitConfig;
#[cfg(not(feature = "rocksdb"))]
use pc_state::InMemoryBackend;
use pc_state::UtxoState;
use pc_store::FileStore;
use pc_types::digest_microtx;
use pc_types::payload_merkle_root;
use pc_types::validate_microtx_sanity;
use pc_types::validate_mint_sanity;
use pc_types::MAX_PAYLOAD_MICROTX;
use pc_types::{
    AnchorHeader, AnchorId, AnchorIndex, AnchorPayload, ClaimEvent, EvidenceEvent, LockCommitment, MicroTx,
    MintEvent, OutPoint, ParentList, PayoutEntry, PayoutSet, TxOut,
};
use pc_types::{GenesisNote, digest_genesis_note};
use pc_types::{AnchorHeaderV2, AnchorPayloadV2};
use pc_types::genesis_payload_root;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use tracing::{info, warn};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use once_cell::sync::OnceCell;
// Max. erlaubte Größe für HTTP-Request-Bodies (1 MiB)
const MAX_HTTP_BODY_BYTES: usize = 1_048_576;

#[cfg(feature = "rocksdb")]
use pc_state::RocksDbBackend;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

// Globaler State-Helper (RocksDB oder InMemory), mit uhrfreiem minted_at-Index
#[cfg(feature = "rocksdb")]
fn global_state(mempool_dir: &str) -> &'static Mutex<UtxoState<RocksDbBackend>> {
    static STATE: OnceCell<Mutex<UtxoState<RocksDbBackend>>> = OnceCell::new();
    STATE.get_or_init(|| {
        let path = std::path::Path::new(mempool_dir).join("state.rocks");
        let db = RocksDbBackend::open(&path.to_string_lossy()).expect("open rocksdb state");
        Mutex::new(UtxoState::new_with_index(db))
    })
}

#[cfg(not(feature = "rocksdb"))]
fn global_state(_mempool_dir: &str) -> &'static Mutex<UtxoState<InMemoryBackend>> {
    static STATE: OnceCell<Mutex<UtxoState<InMemoryBackend>>> = OnceCell::new();
    STATE.get_or_init(|| Mutex::new(UtxoState::new_with_index(InMemoryBackend::new())))
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
struct NodeConsensusCfg {
    #[serde(default)]
    rotation: Option<NodeRotationCfg>,
}

#[derive(Debug, Deserialize)]
struct StatusConfig {
    addr: String,
    mempool_dir: String,
    #[serde(default = "default_true")]
    fsync: bool,
    #[serde(default)]
    require_auth: bool,
    #[serde(default)]
    auth_token: Option<String>,
    #[serde(default)]
    tls_cert: Option<String>,
    #[serde(default)]
    tls_key: Option<String>,
    #[serde(default)]
    tls_client_ca: Option<String>,
    #[serde(default)]
    consensus: Option<NodeConsensusCfg>,
}

fn default_true() -> bool { true }

// Globaler In-Memory-Cache für das zuletzt persistierte VRF-Komitee (als JSON)
static VRF_COMMITTEE: once_cell::sync::OnceCell<tokio::sync::Mutex<Option<serde_json::Value>>> = once_cell::sync::OnceCell::new();


fn run_status_serve(args: &StatusServeArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        // Konfiguration laden (Datei hat Vorrang, CLI fallback)
        let (addr_str, mempool_dir, do_fsync, require_auth, auth_token, tls_cert, tls_key, tls_client_ca) = if let Some(cfgp) = args.config.as_ref() {
            let raw = std::fs::read_to_string(cfgp).map_err(|e| anyhow!("read config: {e}"))?;
            let cfg: StatusConfig = toml::from_str(&raw).map_err(|e| anyhow!("parse config: {e}"))?;
            (cfg.addr, cfg.mempool_dir, cfg.fsync, cfg.require_auth, cfg.auth_token, cfg.tls_cert, cfg.tls_key, cfg.tls_client_ca)
        } else {
            (args.addr.clone(), args.mempool_dir.clone(), args.fsync, args.require_auth, args.auth_token.clone(), args.tls_cert.clone(), args.tls_key.clone(), args.tls_client_ca.clone())
        };
        // VRF-Rotation-Config laden (optional)
        let mut node_rot_cfg: Option<NodeRotationCfg> = if let Some(cfgp) = args.config.as_ref() {
            if let Ok(raw) = std::fs::read_to_string(cfgp) {
                if let Ok(cfg) = toml::from_str::<StatusConfig>(&raw) {
                    cfg.consensus.and_then(|c| c.rotation)
                } else { None }
            } else { None }
        } else { None };
        // CLI-Overrides anwenden (falls gesetzt)
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
        // bootstrap_k1 wird nicht verwendet

        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &addr_str))?;
        let mempool_dir = mempool_dir;
        let do_fsync = do_fsync;
        let require_auth = require_auth;
        let auth_token = auth_token;
        // Auto‑Rotation: Hintergrundtask, der bei vorhandenem Kontext+Kandidaten die Auswahl pro Epoche persistiert
        {
            let mempool_dir_bg = mempool_dir.clone();
            let node_rot_cfg_bg = node_rot_cfg.clone();
            tokio::spawn(async move {
                let mut tick = interval(Duration::from_millis(1500));
                let mut last_epoch_written: Option<u64> = None;
                loop {
                    tick.tick().await;
                    // Lade Rotation-Kontext und Kandidaten von Disk
                    let ctx_path = std::path::Path::new(&mempool_dir_bg).join("vrf_rotation_ctx.json");
                    let cand_path = std::path::Path::new(&mempool_dir_bg).join("vrf_candidates.json");
                    let committee_path = std::path::Path::new(&mempool_dir_bg).join("vrf_committee.json");
                    let ctx_buf = match tokio::task::spawn_blocking({ let p = ctx_path.clone(); move || std::fs::read(&p) }).await { Ok(Ok(a)) => a, _ => { continue; } };
                    let cands_buf = match tokio::task::spawn_blocking({ let p = cand_path.clone(); move || std::fs::read(&p) }).await { Ok(Ok(b)) => b, _ => { continue; } };
                    #[derive(Deserialize)]
                    struct Ctx { k: u8, current_anchor_index: u64, epoch_len: u64, network_id: String, last_anchor_id: String }
                    #[derive(Deserialize)]
                    struct CandIn { recipient_id: String, operator_id: String, bls_pk: String, last_selected_at: u64, attendance_recent_pct: u8, vrf_proof: String }
                    let ctx: Ctx = match serde_json::from_slice(&ctx_buf) { Ok(v)=>v, Err(_)=> continue };
                    let cins: Vec<CandIn> = match serde_json::from_slice(&cands_buf) { Ok(v)=>v, Err(_)=> continue };
                    // Dekodieren
                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex48(s: &str) -> Option<[u8;48]> { let mut out=[0u8;48]; if s.len()!=96 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=48 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex96(s: &str) -> Option<[u8;96]> { let mut out=[0u8;96]; if s.len()!=192 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=96 { return None; } out.copy_from_slice(&raw); Some(out) }
                    let nid = match hex32(&ctx.network_id) { Some(v)=>v, None=> continue };
                    let last = match hex32(&ctx.last_anchor_id) { Some(v)=>v, None=> continue };
                    let epoch_len = if ctx.epoch_len != 0 { ctx.epoch_len } else { node_rot_cfg_bg.as_ref().and_then(|r| r.epoch_len).unwrap_or(10_000) };
                    let epoch = derive_epoch(ctx.current_anchor_index, epoch_len);
                    if last_epoch_written == Some(epoch) { continue; }
                    let seed = derive_vrf_seed(nid, pc_types::AnchorId(last));
                    let rot = if let Some(cfg) = node_rot_cfg_bg.as_ref() {
                        VrfRotationParams{
                            cooldown_anchors: cfg.cooldown_anchors.unwrap_or(10_000),
                            min_attendance_pct: cfg.min_attendance_pct.unwrap_or(50),
                        }
                    } else { VrfRotationParams{ cooldown_anchors: 10_000, min_attendance_pct: 50 } };
                    // Kandidaten bauen
                    let mut cands: Vec<VrfCandidate> = Vec::with_capacity(cins.len());
                    let mut ok_all = true;
                    for c in cins.iter() {
                        let rid = match hex32(&c.recipient_id) { Some(v)=>v, None=> { ok_all=false; break; } };
                        let oid = match hex32(&c.operator_id) { Some(v)=>v, None=> { ok_all=false; break; } };
                        let pkb = match hex48(&c.bls_pk) { Some(v)=>v, None=> { ok_all=false; break; } };
                        let proof = match hex96(&c.vrf_proof) { Some(v)=>v, None=> { ok_all=false; break; } };
                        let pk = match bls_pk_from_bytes(&pkb) { Some(p)=>p, None=> { ok_all=false; break; } };
                        cands.push(VrfCandidate{ recipient_id: rid, operator_id: oid, bls_pk: pk, last_selected_at: c.last_selected_at, attendance_recent_pct: c.attendance_recent_pct, vrf_proof: proof });
                    }
                    if !ok_all { continue; }
                    let selected: Vec<SelectedSeat> = committee_select_vrf(ctx.k, epoch, seed, ctx.current_anchor_index, &cands, &rot);
                    #[derive(Serialize, Deserialize, Clone, Debug)]
                    struct SeatOut { recipient_id: String, operator_id: String, bls_pk: String, score: String }
                    #[derive(Serialize, Deserialize, Clone, Debug)]
                    struct CommitteeDoc { ok: bool, epoch: u64, current_anchor_index: u64, seed: String, n_selected: usize, seats: Vec<SeatOut>, ts: u64 }
                    let seats: Vec<SeatOut> = selected.iter().map(|s| SeatOut{
                        recipient_id: hex::encode(s.recipient_id),
                        operator_id: hex::encode(s.operator_id),
                        bls_pk: hex::encode(s.bls_pk.to_bytes()),
                        score: hex::encode(s.score),
                    }).collect();
                    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let doc = CommitteeDoc{ ok:true, epoch, current_anchor_index: ctx.current_anchor_index, seed: hex::encode(seed), n_selected: seats.len(), seats, ts };
                    // Nur schreiben, wenn epoch neu ist
                    if last_epoch_written != Some(epoch) {
                        if let Ok(raw) = serde_json::to_vec(&doc) {
                            let _ = atomic_write_async(&committee_path, raw.clone(), true).await;
                            last_epoch_written = Some(epoch);
                        }
                    }
                }
            });
        }
        // Klone für HTTP-Server-Branch (Plain-HTTP)
        let mempool_dir_http = mempool_dir.clone();
        let auth_token_http = auth_token.clone();
        let node_rot_cfg_http = node_rot_cfg.clone();
        let make_svc = make_service_fn(move |_conn| {
            let mempool_dir = mempool_dir_http.clone();
            let do_fsync = do_fsync;
            let require_auth = require_auth;
            let auth_token = auth_token_http.clone();
            let node_rot_cfg = node_rot_cfg_http.clone();
            async move {
                Ok::<_, anyhow::Error>(service_fn(move |req: Request<Body>| {
                    let mempool_dir = mempool_dir.clone();
                    let do_fsync = do_fsync;
                    let require_auth = require_auth;
                    let auth_token = auth_token.clone();
                    let node_rot_cfg = node_rot_cfg.clone();
                    async move {
                        if req.uri().path() == "/status" && req.method() == hyper::Method::GET {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Versuche genesis_note aus mempool_dir/genesis_note.bin zu laden
                    let mut root = serde_json::Map::new();
                    root.insert("ok".into(), serde_json::Value::Bool(true));
                    root.insert("service".into(), serde_json::Value::String("phantom-node".to_string()));
                    root.insert("ts".into(), serde_json::Value::Number(ts.into()));

                    let gpath = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
                    let read_res = {
                        let p = gpath.clone();
                        tokio::task::spawn_blocking(move || std::fs::read(&p)).await
                    };
                    if let Ok(Ok(buf)) = read_res {
                        let mut s = &buf[..];
                        if let Ok(note) = GenesisNote::decode(&mut s) {
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
                                "version": note.version
                            });
                            root.insert("genesis".into(), genesis);
                        }
                    }

                    let body = serde_json::Value::Object(root).to_string();
                    let mut resp = Response::builder()
                        .status(200)
                        .body(Body::from(body))
                        .unwrap();
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/healthz" && req.method() == hyper::Method::GET {
                    let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/readyz" && req.method() == hyper::Method::GET {
                    // Readiness: mempool_dir muss erreichbar sein
                    match std::fs::metadata(&mempool_dir) {
                        Ok(_) => {
                            let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                        Err(e) => {
                            let mut resp = Response::builder().status(503).body(Body::from(format!("{{\"ok\":false,\"error\":\"mempool_dir: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                } else if req.uri().path() == "/metrics" && req.method() == hyper::Method::GET {
                    // Prometheus-Format (Text)
                    let mut out = String::new();
                    use std::fmt::Write as _;
                    let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_total RPC broadcast requests total");
                    let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_total counter");
                    let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_total {}", NODE_RPC_BROADCAST_TOTAL.load(Ordering::Relaxed));
                    let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_accepted_total RPC broadcast accepted total");
                    let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_accepted_total counter");
                    let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_accepted_total {}", NODE_RPC_BROADCAST_ACCEPTED_TOTAL.load(Ordering::Relaxed));
                    let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_duplicate_total RPC broadcast duplicates total");
                    let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_duplicate_total counter");
                    let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_duplicate_total {}", NODE_RPC_BROADCAST_DUP_TOTAL.load(Ordering::Relaxed));
                    let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_errors_total RPC broadcast errors total");
                    let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_errors_total counter");
                    let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_errors_total {}", NODE_RPC_BROADCAST_ERRORS_TOTAL.load(Ordering::Relaxed));

                    // Genesis-/Netzwerk-Metriken
                    // pc_network_id{network="<name>"} 1, pc_genesis_height 0 (falls Genesis vorhanden)
                    let p = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
                    let read_res = { let p2 = p.clone(); tokio::task::spawn_blocking(move || std::fs::read(&p2)).await };
                    if let Ok(Ok(buf)) = read_res {
                        let mut s = &buf[..];
                        if let Ok(note) = GenesisNote::decode(&mut s) {
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
                    let mut resp = Response::builder().status(200).body(Body::from(out)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/genesis/bootstrap" && req.method() == hyper::Method::POST {
                    // Bootstrap: Lade genesis_note.bin, baue V2-Payload/Header und validiere A0
                    let gpath = std::path::Path::new(&mempool_dir).join("genesis_note.bin");
                    let buf = match std::fs::read(&gpath) {
                        Ok(b) => b,
                        Err(e) => {
                            let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"read genesis_note: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    };
                    let mut s = &buf[..];
                    let note = match GenesisNote::decode(&mut s) {
                        Ok(n) => n,
                        Err(e) => {
                            let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"decode genesis_note: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    };
                    let payload = AnchorPayloadV2 {
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
                        ack_id: pc_types::AnchorId([0u8;32]),
                        network_id: digest_genesis_note(&note),
                    };
                    match validate_genesis_anchor(&header, &payload) {
                        Ok(nid) => {
                            let body = serde_json::json!({
                                "ok": true,
                                "network_id": hex::encode(nid),
                                "message": "genesis bootstrap validated"
                            }).to_string();
                            let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                        Err(_e) => {
                            let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"genesis validation failed\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                } else if req.uri().path() == "/state/apply_mint_with_index" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize)]
                    struct MOut { amount: u64, lock: String }
                    #[derive(serde::Deserialize)]
                    struct ApplyMintReq { prev_mint_id: Option<String>, outputs: Vec<MOut>, pow_seed: String, pow_nonce: u64, minted_at: u64 }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: ApplyMintReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let mut prev_id = [0u8;32]; if let Some(s)=reqv.prev_mint_id.as_ref(){ if let Ok(b)=hex::decode(s){ if b.len()==32 { prev_id.copy_from_slice(&b); } } }
                    let mut seed = [0u8;32]; if let Ok(b)=hex::decode(&reqv.pow_seed){ if b.len()==32 { seed.copy_from_slice(&b); } }
                    let mut outs: Vec<TxOut> = Vec::with_capacity(reqv.outputs.len());
                    for o in reqv.outputs.iter(){ let mut lock=[0u8;32]; if let Ok(b)=hex::decode(&o.lock){ if b.len()==32 { lock.copy_from_slice(&b);} } outs.push(TxOut{amount:o.amount, lock:LockCommitment(lock)}); }
                    let mint = MintEvent { version:1, prev_mint_id: prev_id, outputs: outs, pow_seed: seed, pow_nonce: reqv.pow_nonce };
                    if let Err(_e)=validate_mint_sanity(&mint){ let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"mint sanity failed\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    // globaler State
                    let st_mutex = global_state(&mempool_dir);
                    let mut st = st_mutex.lock().await;
                    st.apply_mint_with_index(&mint, reqv.minted_at);
                    let id = pc_types::digest_mint(&mint);
                    let body = serde_json::json!({"ok":true, "mint_id": hex::encode(id)}).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/stake/bond" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize)]
                    struct OpRef { txid: String, vout: u32 }
                    #[derive(serde::Deserialize)]
                    struct BondReq { ops: Vec<OpRef>, current: u64, threshold: u64, allow_unripe_bond: Option<bool> }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: BondReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let mut ops: Vec<OutPoint> = Vec::with_capacity(reqv.ops.len());
                    for r in reqv.ops.iter(){ let mut txid=[0u8;32]; if let Ok(b)=hex::decode(&r.txid){ if b.len()==32 { txid.copy_from_slice(&b);} } ops.push(OutPoint{ txid, vout: r.vout}); }
                    let st_mutex = global_state(&mempool_dir);
                    let mut st = st_mutex.lock().await;
                    let allow = reqv.allow_unripe_bond.unwrap_or(false);
                    match st.bond_outpoints(&ops, reqv.current, reqv.threshold, allow) {
                        Ok(()) => {
                            let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                        Err(e) => {
                            let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                } else if req.uri().path() == "/stake/unbond" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize)]
                    struct OpRef { txid: String, vout: u32 }
                    #[derive(serde::Deserialize)]
                    struct UnbondReq { ops: Vec<OpRef>, current: u64, threshold: u64 }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: UnbondReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let mut ops: Vec<OutPoint> = Vec::with_capacity(reqv.ops.len());
                    for r in reqv.ops.iter(){ let mut txid=[0u8;32]; if let Ok(b)=hex::decode(&r.txid){ if b.len()==32 { txid.copy_from_slice(&b);} } ops.push(OutPoint{ txid, vout: r.vout}); }
                    let st_mutex = global_state(&mempool_dir);
                    let mut st = st_mutex.lock().await;
                    match st.unbond_outpoints(&ops, reqv.current, reqv.threshold) {
                        Ok(()) => {
                            let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                        Err(e) => {
                            let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                } else if req.uri().path() == "/mint/template" && req.method() == hyper::Method::GET {
                    // Template erzeugen: seed, bits, prev_mint_id
                    use rand::RngCore as _;
                    let mut seed = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut seed);
                    let bits = consts::POW_DEFAULT_BITS;
                    let last_path = std::path::Path::new(&mempool_dir).join("last_mint_id");
                    let prev_mint_id = match tokio::task::spawn_blocking({ let p = last_path.clone(); move || std::fs::read_to_string(&p) }).await {
                        Ok(Ok(s)) => {
                            let h = s.trim();
                            let mut b = [0u8; 32];
                            if h.len() == 64 {
                                if let Ok(raw) = hex::decode(h) { if raw.len()==32 { b.copy_from_slice(&raw); } }
                            }
                            b
                        }
                        Ok(Err(_)) => [0u8; 32],
                        Err(_) => [0u8; 32],
                    };
                    let body = serde_json::json!({
                        "ok": true,
                        "seed": hex::encode(seed),
                        "bits": bits,
                        "prev_mint_id": hex::encode(prev_mint_id),
                    }).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/mint/submit" && req.method() == hyper::Method::POST {
                    #[derive(serde::Deserialize)]
                    struct MintSubmitReq { seed: String, nonce: u64, bits: Option<u8>, outputs: Vec<MOut> }
                    #[derive(serde::Deserialize)]
                    struct MOut { amount: u64, lock: String }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre {
                        Ok(b) => b,
                        Err(e) => {
                            let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: MintSubmitReq = match serde_json::from_slice(&whole) {
                        Ok(v) => v,
                        Err(e) => {
                            let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    };
                    let mut seed = [0u8; 32];
                    if let Ok(b) = hex::decode(&reqv.seed) { if b.len()==32 { seed.copy_from_slice(&b); } }
                    let bits = reqv.bits.unwrap_or(consts::POW_DEFAULT_BITS);
                    let meets = pow_meets(bits, &pow_hash(&seed, reqv.nonce));
                    if !meets {
                        let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"pow not sufficient\"}".to_string())).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    // prev_mint_id ermitteln
                    let last_path = std::path::Path::new(&mempool_dir).join("last_mint_id");
                    let prev_mint_id = match tokio::task::spawn_blocking({ let p = last_path.clone(); move || std::fs::read_to_string(&p) }).await {
                        Ok(Ok(s)) => { let h=s.trim(); let mut b=[0u8;32]; if h.len()==64 { if let Ok(raw)=hex::decode(h){ if raw.len()==32 { b.copy_from_slice(&raw); } } } b }
                        Ok(Err(_)) => [0u8; 32],
                        Err(_) => [0u8; 32],
                    };
                    // Outputs bauen
                    let mut outs: Vec<TxOut> = Vec::with_capacity(reqv.outputs.len());
                    for o in reqv.outputs.iter() {
                        let mut lock = [0u8; 32];
                        if let Ok(b) = hex::decode(&o.lock) { if b.len()==32 { lock.copy_from_slice(&b); } }
                        outs.push(TxOut { amount: o.amount, lock: LockCommitment(lock) });
                    }
                    let mint = MintEvent { version: 1, prev_mint_id, outputs: outs, pow_seed: seed, pow_nonce: reqv.nonce };
                    if let Err(_e) = validate_mint_sanity(&mint) {
                        let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"mint sanity failed\"}".to_string())).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    let id = pc_types::digest_mint(&mint);
                    // persistieren
                    let mdir = std::path::Path::new(&mempool_dir).join("mints");
                    let _ = tokio::task::spawn_blocking({ let d = mdir.clone(); move || std::fs::create_dir_all(&d) }).await;
                    let mpath = mdir.join(format!("{}.bin", hex::encode(id)));
                    let mut buf = Vec::new();
                    if let Err(e) = mint.encode(&mut buf) {
                        let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"encode mint: {}\"}}", e))).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    if let Err(e) = atomic_write_async(&mpath, buf.clone(), do_fsync).await {
                        let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"persist mint: {}\"}}", e))).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    {
                        let lp = last_path.clone();
                        let data = hex::encode(id);
                        let _ = tokio::task::spawn_blocking(move || std::fs::write(&lp, data)).await;
                    }
                    let body = serde_json::json!({"ok": true, "mint_id": hex::encode(id)}).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.method() == hyper::Method::GET && req.uri().path().starts_with("/mint/status/") {
                    let path = req.uri().path();
                    let id_hex = &path["/mint/status/".len()..];
                    let mpath = std::path::Path::new(&mempool_dir).join("mints").join(format!("{}.bin", id_hex));
                    let found = mpath.exists();
                    let body = serde_json::json!({"ok": true, "found": found}).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/config" && req.method() == hyper::Method::GET {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    // Effektive Rotation-Config zurückgeben (mit Defaults)
                    let epoch_len = node_rot_cfg.as_ref().and_then(|r| r.epoch_len).unwrap_or(10_000);
                    let cooldown_anchors = node_rot_cfg.as_ref().and_then(|r| r.cooldown_anchors).unwrap_or(10_000);
                    let min_attendance_pct = node_rot_cfg.as_ref().and_then(|r| r.min_attendance_pct).unwrap_or(50);
                    let body = serde_json::json!({
                        "ok": true,
                        "rotation": {
                            "epoch_len": epoch_len,
                            "cooldown_anchors": cooldown_anchors,
                            "min_attendance_pct": min_attendance_pct
                        }
                    }).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/set_rotation_context" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize, serde::Serialize)]
                    struct Ctx { k: u8, current_anchor_index: u64, epoch_len: u64, network_id: String, last_anchor_id: String }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let ctx: Ctx = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    // Leichtgewichtig validieren
                    let ok_fields = ctx.k>0 && !ctx.network_id.is_empty() && !ctx.last_anchor_id.is_empty();
                    if !ok_fields { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid fields\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    let path = std::path::Path::new(&mempool_dir).join("vrf_rotation_ctx.json");
                    let raw = serde_json::to_vec(&ctx).unwrap_or_else(|_| b"{}".to_vec());
                    if let Err(e) = atomic_write_async(&path, raw.clone(), do_fsync).await {
                        let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"persist: {}\"}}", e))).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/set_candidates" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize, serde::Serialize)]
                    struct CandIn { recipient_id: String, operator_id: String, bls_pk: String, last_selected_at: u64, attendance_recent_pct: u8, vrf_proof: String }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let v: Vec<CandIn> = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    // Grundvalidierung
                    if v.is_empty() { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"empty\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    for c in &v { if c.recipient_id.len()!=64 || c.operator_id.len()!=64 || c.bls_pk.len()!=96 || c.vrf_proof.len()!=192 { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad lengths\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } }
                    let path = std::path::Path::new(&mempool_dir).join("vrf_candidates.json");
                    let raw = serde_json::to_vec(&v).unwrap_or_else(|_| b"[]".to_vec());
                    if let Err(e) = atomic_write_async(&path, raw.clone(), do_fsync).await {
                        let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"persist: {}\"}}", e))).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/select_committee" && req.method() == hyper::Method::POST {
                    #[derive(serde::Deserialize)]
                    struct ReqRotationCfg { cooldown_anchors: u64, min_attendance_pct: u8 }
                    #[derive(serde::Deserialize)]
                    struct CandIn { recipient_id: String, operator_id: String, bls_pk: String, last_selected_at: u64, attendance_recent_pct: u8, vrf_proof: String }
                    #[derive(serde::Deserialize)]
                    struct SelectReq {
                        k: u8,
                        current_anchor_index: u64,
                        epoch_len: u64,
                        network_id: String,
                        last_anchor_id: String,
                        rotation: Option<ReqRotationCfg>,
                        candidates: Vec<CandIn>,
                    }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: SelectReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };

                    // Decode helpers
                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex48(s: &str) -> Option<[u8;48]> { let mut out=[0u8;48]; if s.len()!=96 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=48 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex96(s: &str) -> Option<[u8;96]> { let mut out=[0u8;96]; if s.len()!=192 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=96 { return None; } out.copy_from_slice(&raw); Some(out) }

                    let nid = match hex32(&reqv.network_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad network_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let last = match hex32(&reqv.last_anchor_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad last_anchor_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let epoch_len = if reqv.epoch_len != 0 { reqv.epoch_len } else { node_rot_cfg.as_ref().and_then(|r| r.epoch_len).unwrap_or(10_000) };
                    let epoch = derive_epoch(reqv.current_anchor_index, epoch_len);
                    let seed = derive_vrf_seed(nid, pc_types::AnchorId(last));
                    let rot = if let Some(r) = reqv.rotation {
                        VrfRotationParams{ cooldown_anchors: r.cooldown_anchors, min_attendance_pct: r.min_attendance_pct }
                    } else if let Some(cfg) = node_rot_cfg.as_ref() {
                        VrfRotationParams{
                            cooldown_anchors: cfg.cooldown_anchors.unwrap_or(10_000),
                            min_attendance_pct: cfg.min_attendance_pct.unwrap_or(50),
                        }
                    } else {
                        VrfRotationParams{ cooldown_anchors: 10_000, min_attendance_pct: 50 }
                    };

                    let mut cands: Vec<VrfCandidate> = Vec::with_capacity(reqv.candidates.len());
                    for c in reqv.candidates.iter() {
                        let rid = match hex32(&c.recipient_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let oid = match hex32(&c.operator_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad operator_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pkb = match hex48(&c.bls_pk) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let proof = match hex96(&c.vrf_proof) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad vrf_proof\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pk = match bls_pk_from_bytes(&pkb) { Some(p)=>p, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        cands.push(VrfCandidate{ recipient_id: rid, operator_id: oid, bls_pk: pk, last_selected_at: c.last_selected_at, attendance_recent_pct: c.attendance_recent_pct, vrf_proof: proof });
                    }

                    let selected: Vec<SelectedSeat> = committee_select_vrf(reqv.k, epoch, seed, reqv.current_anchor_index, &cands, &rot);
                    #[derive(serde::Serialize)]
                    struct SeatOut { recipient_id: String, operator_id: String, bls_pk: String, score: String }
                    #[derive(serde::Serialize)]
                    struct SelectResp { ok: bool, epoch: u64, seed: String, n_selected: usize, seats: Vec<SeatOut> }
                    let seats: Vec<SeatOut> = selected.iter().map(|s| SeatOut{
                        recipient_id: hex::encode(s.recipient_id),
                        operator_id: hex::encode(s.operator_id),
                        bls_pk: hex::encode(s.bls_pk.to_bytes()),
                        score: hex::encode(s.score),
                    }).collect();
                    let body = serde_json::to_string(&SelectResp{ ok:true, epoch, seed: hex::encode(seed), n_selected: seats.len(), seats }).unwrap_or_else(|_| "{\"ok\":false}".to_string());
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/select_attestors" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize)]
                    struct ReqRotationCfg { cooldown_anchors: u64, min_attendance_pct: u8 }
                    #[derive(serde::Deserialize)]
                    struct CandIn { recipient_id: String, operator_id: String, bls_pk: String, last_selected_at: u64, attendance_recent_pct: u8, vrf_proof: String }
                    #[derive(serde::Deserialize)]
                    struct SelectReq {
                        m: u16,
                        current_anchor_index: u64,
                        epoch_len: u64,
                        network_id: String,
                        last_anchor_id: String,
                        rotation: Option<ReqRotationCfg>,
                        candidates: Vec<CandIn>,
                    }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: SelectReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };

                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex48(s: &str) -> Option<[u8;48]> { let mut out=[0u8;48]; if s.len()!=96 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=48 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex96(s: &str) -> Option<[u8;96]> { let mut out=[0u8;96]; if s.len()!=192 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=96 { return None; } out.copy_from_slice(&raw); Some(out) }

                    let nid = match hex32(&reqv.network_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad network_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let last = match hex32(&reqv.last_anchor_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad last_anchor_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let epoch_len = if reqv.epoch_len != 0 { reqv.epoch_len } else { node_rot_cfg.as_ref().and_then(|r| r.epoch_len).unwrap_or(10_000) };
                    let epoch = derive_epoch(reqv.current_anchor_index, epoch_len);
                    let seed = derive_vrf_seed(nid, pc_types::AnchorId(last));
                    let rot = if let Some(r) = reqv.rotation {
                        VrfRotationParams{ cooldown_anchors: r.cooldown_anchors, min_attendance_pct: r.min_attendance_pct }
                    } else if let Some(cfg) = node_rot_cfg.as_ref() {
                        VrfRotationParams{ cooldown_anchors: cfg.cooldown_anchors.unwrap_or(10_000), min_attendance_pct: cfg.min_attendance_pct.unwrap_or(50) }
                    } else {
                        VrfRotationParams{ cooldown_anchors: 10_000, min_attendance_pct: 50 }
                    };

                    let mut cands: Vec<VrfCandidate> = Vec::with_capacity(reqv.candidates.len());
                    for c in reqv.candidates.iter() {
                        let rid = match hex32(&c.recipient_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let oid = match hex32(&c.operator_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad operator_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pkb = match hex48(&c.bls_pk) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let proof = match hex96(&c.vrf_proof) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad vrf_proof\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pk = match bls_pk_from_bytes(&pkb) { Some(p)=>p, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        cands.push(VrfCandidate{ recipient_id: rid, operator_id: oid, bls_pk: pk, last_selected_at: c.last_selected_at, attendance_recent_pct: c.attendance_recent_pct, vrf_proof: proof });
                    }

                    let selected: Vec<SelectedSeat> = attestor_sample_vrf(reqv.m, reqv.current_anchor_index, epoch_len, nid, pc_types::AnchorId(last), &cands, &rot);
                    #[derive(serde::Serialize)]
                    struct SeatOut { recipient_id: String, operator_id: String, bls_pk: String, score: String }
                    #[derive(serde::Serialize)]
                    struct SelectResp { ok: bool, epoch: u64, seed: String, n_selected: usize, seats: Vec<SeatOut> }
                    let seats: Vec<SeatOut> = selected.iter().map(|s| SeatOut{
                        recipient_id: hex::encode(s.recipient_id),
                        operator_id: hex::encode(s.operator_id),
                        bls_pk: hex::encode(s.bls_pk.to_bytes()),
                        score: hex::encode(s.score),
                    }).collect();
                    let body = serde_json::to_string(&SelectResp{ ok:true, epoch, seed: hex::encode(seed), n_selected: seats.len(), seats }).unwrap_or_else(|_| "{\"ok\":false}".to_string());
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/select_attestors_fair" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize)]
                    struct ReqRotationCfg { cooldown_anchors: u64, min_attendance_pct: u8 }
                    #[derive(serde::Deserialize)]
                    struct CandIn { recipient_id: String, operator_id: String, bls_pk: String, last_selected_at: u64, attendance_recent_pct: u8, vrf_proof: String }
                    #[derive(serde::Deserialize)]
                    struct CountIn { operator_id: String, count: u32 }
                    #[derive(serde::Deserialize)]
                    struct PerfIn { operator_id: String, score: u32 }
                    #[derive(serde::Deserialize)]
                    struct FairReq {
                        m: u16,
                        current_anchor_index: u64,
                        epoch_len: u64,
                        network_id: String,
                        last_anchor_id: String,
                        rotation: Option<ReqRotationCfg>,
                        cap_limit_per_op: u32,
                        recent_op_selection_count: Vec<CountIn>,
                        perf_index: Vec<PerfIn>,
                        candidates: Vec<CandIn>,
                    }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: FairReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };

                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex48(s: &str) -> Option<[u8;48]> { let mut out=[0u8;48]; if s.len()!=96 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=48 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex96(s: &str) -> Option<[u8;96]> { let mut out=[0u8;96]; if s.len()!=192 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=96 { return None; } out.copy_from_slice(&raw); Some(out) }

                    let nid = match hex32(&reqv.network_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad network_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let last = match hex32(&reqv.last_anchor_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad last_anchor_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let epoch_len = if reqv.epoch_len != 0 { reqv.epoch_len } else { node_rot_cfg.as_ref().and_then(|r| r.epoch_len).unwrap_or(10_000) };
                    let epoch = derive_epoch(reqv.current_anchor_index, epoch_len);
                    let seed = derive_vrf_seed(nid, pc_types::AnchorId(last));
                    let rot = if let Some(r) = reqv.rotation {
                        VrfRotationParams{ cooldown_anchors: r.cooldown_anchors, min_attendance_pct: r.min_attendance_pct }
                    } else if let Some(cfg) = node_rot_cfg.as_ref() {
                        VrfRotationParams{ cooldown_anchors: cfg.cooldown_anchors.unwrap_or(10_000), min_attendance_pct: cfg.min_attendance_pct.unwrap_or(50) }
                    } else {
                        VrfRotationParams{ cooldown_anchors: 10_000, min_attendance_pct: 50 }
                    };

                    let mut cands: Vec<VrfCandidate> = Vec::with_capacity(reqv.candidates.len());
                    for c in reqv.candidates.iter() {
                        let rid = match hex32(&c.recipient_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let oid = match hex32(&c.operator_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad operator_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pkb = match hex48(&c.bls_pk) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let proof = match hex96(&c.vrf_proof) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad vrf_proof\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pk = match bls_pk_from_bytes(&pkb) { Some(p)=>p, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        cands.push(VrfCandidate{ recipient_id: rid, operator_id: oid, bls_pk: pk, last_selected_at: c.last_selected_at, attendance_recent_pct: c.attendance_recent_pct, vrf_proof: proof });
                    }

                    let mut recent_map: HashMap<[u8;32], u32> = HashMap::new();
                    for it in reqv.recent_op_selection_count.iter() {
                        if let Some(oid) = hex32(&it.operator_id) { recent_map.insert(oid, it.count); }
                    }
                    let mut perf_map: HashMap<[u8;32], u32> = HashMap::new();
                    for it in reqv.perf_index.iter() {
                        if let Some(oid) = hex32(&it.operator_id) { perf_map.insert(oid, it.score); }
                    }

                    let selected: Vec<SelectedSeat> = attestor_sample_vrf_fair(
                        reqv.m,
                        reqv.current_anchor_index,
                        epoch_len,
                        nid,
                        pc_types::AnchorId(last),
                        &cands,
                        &rot,
                        &recent_map,
                        reqv.cap_limit_per_op,
                        &perf_map,
                    );
                    #[derive(serde::Serialize)]
                    struct SeatOut { recipient_id: String, operator_id: String, bls_pk: String, score: String }
                    #[derive(serde::Serialize)]
                    struct SelectResp { ok: bool, epoch: u64, seed: String, n_selected: usize, seats: Vec<SeatOut> }
                    let seats: Vec<SeatOut> = selected.iter().map(|s| SeatOut{
                        recipient_id: hex::encode(s.recipient_id),
                        operator_id: hex::encode(s.operator_id),
                        bls_pk: hex::encode(s.bls_pk.to_bytes()),
                        score: hex::encode(s.score),
                    }).collect();
                    let body = serde_json::to_string(&SelectResp{ ok:true, epoch, seed: hex::encode(seed), n_selected: seats.len(), seats }).unwrap_or_else(|_| "{\"ok\":false}".to_string());
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/attestor_payout_root" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok { let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    }
                    #[derive(serde::Deserialize)]
                    struct FeeParamsIn { p_base_bp: u16, p_prop_bp: u16, p_perf_bp: u16, p_att_bp: u16, d_max: u8, perf_weights: Vec<u32> }
                    #[derive(serde::Deserialize)]
                    struct SeatIn { recipient_id: String }
                    #[derive(serde::Deserialize)]
                    struct RootReq { fees_total: u64, fee_params: Option<FeeParamsIn>, seats: Vec<SeatIn> }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: RootReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };

                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    let params = if let Some(p)=reqv.fee_params { pc_consensus::FeeSplitParams{ p_base_bp:p.p_base_bp, p_prop_bp:p.p_prop_bp, p_perf_bp:p.p_perf_bp, p_att_bp:p.p_att_bp, d_max:p.d_max, perf_weights:p.perf_weights } } else { pc_consensus::FeeSplitParams::recommended() };
                    if let Err(_)=params.validate(){ let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid fee params\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    if reqv.seats.is_empty(){ let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"empty seats\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    let mut ids: Vec<[u8;32]> = Vec::with_capacity(reqv.seats.len());
                    for s in reqv.seats.iter(){ if let Some(id)=hex32(&s.recipient_id){ ids.push(id); } else { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } }
                    let set = match compute_attestor_payout(reqv.fees_total, &params, &ids) { Ok(s)=>s, Err(_)=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"payout failed\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } };
                    let root = set.payout_root();
                    let body = serde_json::json!({"ok":true, "payout_root": hex::encode(root), "n_seats": ids.len() }).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/attestor_payout_proof" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok { let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    }
                    #[derive(serde::Deserialize)]
                    struct FeeParamsIn { p_base_bp: u16, p_prop_bp: u16, p_perf_bp: u16, p_att_bp: u16, d_max: u8, perf_weights: Vec<u32> }
                    #[derive(serde::Deserialize)]
                    struct SeatIn { recipient_id: String }
                    #[derive(serde::Deserialize)]
                    struct ProofReq { fees_total: u64, fee_params: Option<FeeParamsIn>, seats: Vec<SeatIn>, recipient_id: String }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: ProofReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };

                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    let params = if let Some(p)=reqv.fee_params { pc_consensus::FeeSplitParams{ p_base_bp:p.p_base_bp, p_prop_bp:p.p_prop_bp, p_perf_bp:p.p_perf_bp, p_att_bp:p.p_att_bp, d_max:p.d_max, perf_weights:p.perf_weights } } else { pc_consensus::FeeSplitParams::recommended() };
                    if let Err(_)=params.validate(){ let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid fee params\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    if reqv.seats.is_empty(){ let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"empty seats\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    let mut ids: Vec<[u8;32]> = Vec::with_capacity(reqv.seats.len());
                    for s in reqv.seats.iter(){ if let Some(id)=hex32(&s.recipient_id){ ids.push(id); } else { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } }
                    let set = match compute_attestor_payout(reqv.fees_total, &params, &ids) { Ok(s)=>s, Err(_)=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"payout failed\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } };
                    let target = match hex32(&reqv.recipient_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } };
                    let mut leaves: Vec<[u8;32]> = Vec::with_capacity(set.entries.len());
                    let mut idx: Option<usize> = None;
                    for (i, e) in set.entries.iter().enumerate() {
                        leaves.push(payout_leaf_hash(&e.recipient_id, e.amount));
                        if e.recipient_id == target { idx = Some(i); }
                    }
                    let index = if let Some(i) = idx { i } else { let mut resp=Response::builder().status(404).body(Body::from("{\"ok\":false,\"error\":\"recipient not found\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); };
                    let leaf = leaves[index];
                    let proof = merkle_build_proof(&leaves, index);
                    let root = set.payout_root();
                    #[derive(serde::Serialize)]
                    struct StepOut { hash: String, right: bool }
                    let steps: Vec<StepOut> = proof.into_iter().map(|s| StepOut{ hash: hex::encode(s.hash), right: s.right }).collect();
                    let body = serde_json::json!({
                        "ok": true,
                        "index": index,
                        "leaf": hex::encode(leaf),
                        "payout_root": hex::encode(root),
                        "proof": steps
                    }).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/attestor_aggregate_sigs" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok { let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    }
                    #[derive(serde::Deserialize)]
                    struct AggReq { parts: Vec<String> }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: AggReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let mut sigs: Vec<[u8;96]> = Vec::with_capacity(reqv.parts.len());
                    for s in reqv.parts.iter() {
                        if s.len() != 192 { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad sig length\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                        let mut arr = [0u8;96];
                        match hex::decode(s) { Ok(b) if b.len()==96 => { arr.copy_from_slice(&b); sigs.push(arr); }, _ => { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad sig hex\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } }
                    }
                    match attestor_aggregate_sigs(&sigs) {
                        Some(agg) => {
                            let body = serde_json::json!({"ok":true, "agg_sig": hex::encode(agg)}).to_string();
                            let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                        None => {
                            let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"aggregate failed\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                } else if req.uri().path() == "/consensus/attestor_fast_verify" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok { let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    }
                    #[derive(serde::Deserialize)]
                    struct VerifyReq { network_id: String, epoch: u64, topic: String, bls_pks: Vec<String>, agg_sig: String }
                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex48(s: &str) -> Option<[u8;48]> { let mut out=[0u8;48]; if s.len()!=96 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=48 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex96(s: &str) -> Option<[u8;96]> { let mut out=[0u8;96]; if s.len()!=192 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=96 { return None; } out.copy_from_slice(&raw); Some(out) }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: VerifyReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let nid = match hex32(&reqv.network_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad network_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } };
                    let topic_bytes = match hex::decode(&reqv.topic) { Ok(v)=>v, Err(_)=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad topic hex\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let msg = attestation_message(&nid, reqv.epoch, &topic_bytes);
                    let mut pks: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(reqv.bls_pks.len());
                    for s in reqv.bls_pks.iter() {
                        let kb = match hex48(s) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pk = match bls_pk_from_bytes(&kb) { Some(p)=>p, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        pks.push(pk);
                    }
                    let agg = match hex96(&reqv.agg_sig) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad agg_sig\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let ok = bls_fast_aggregate_verify(&msg, &agg, &pks);
                    let body = serde_json::json!({"ok": true, "valid": ok}).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/attestor_fast_verify_seats" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got { if let Ok(s) = val.to_str() { if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false } } else { false } } else { false };
                        if !ok { let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                    }
                    #[derive(serde::Deserialize)]
                    struct SeatIn { bls_pk: String }
                    #[derive(serde::Deserialize)]
                    struct VerifySeatsReq { network_id: String, epoch: u64, topic: String, seats: Vec<SeatIn>, agg_sig: String }
                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex48(s: &str) -> Option<[u8;48]> { let mut out=[0u8;48]; if s.len()!=96 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=48 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex96(s: &str) -> Option<[u8;96]> { let mut out=[0u8;96]; if s.len()!=192 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=96 { return None; } out.copy_from_slice(&raw); Some(out) }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: VerifySeatsReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let nid = match hex32(&reqv.network_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad network_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); } };
                    let topic_bytes = match hex::decode(&reqv.topic) { Ok(v)=>v, Err(_)=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad topic hex\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let msg = attestation_message(&nid, reqv.epoch, &topic_bytes);
                    let mut pks: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(reqv.seats.len());
                    for s in reqv.seats.iter() {
                        let kb = match hex48(&s.bls_pk) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pk = match bls_pk_from_bytes(&kb) { Some(p)=>p, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        pks.push(pk);
                    }
                    let agg = match hex96(&reqv.agg_sig) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad agg_sig\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let ok = bls_fast_aggregate_verify(&msg, &agg, &pks);
                    let body = serde_json::json!({"ok": true, "valid": ok}).to_string();
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/select_committee_persist" && req.method() == hyper::Method::POST {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    #[derive(serde::Deserialize)]
                    struct ReqRotationCfg { cooldown_anchors: u64, min_attendance_pct: u8 }
                    #[derive(serde::Deserialize)]
                    struct CandIn { recipient_id: String, operator_id: String, bls_pk: String, last_selected_at: u64, attendance_recent_pct: u8, vrf_proof: String }
                    #[derive(serde::Deserialize)]
                    struct SelectReq {
                        k: u8,
                        current_anchor_index: u64,
                        epoch_len: u64,
                        network_id: String,
                        last_anchor_id: String,
                        rotation: Option<ReqRotationCfg>,
                        candidates: Vec<CandIn>,
                    }
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    let reqv: SelectReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };

                    // Decode helpers
                    fn hex32(s: &str) -> Option<[u8;32]> { let mut out=[0u8;32]; if s.len()!=64 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=32 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex48(s: &str) -> Option<[u8;48]> { let mut out=[0u8;48]; if s.len()!=96 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=48 { return None; } out.copy_from_slice(&raw); Some(out) }
                    fn hex96(s: &str) -> Option<[u8;96]> { let mut out=[0u8;96]; if s.len()!=192 { return None; } let raw=hex::decode(s).ok()?; if raw.len()!=96 { return None; } out.copy_from_slice(&raw); Some(out) }

                    let nid = match hex32(&reqv.network_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad network_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let last = match hex32(&reqv.last_anchor_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad last_anchor_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                    let epoch_len = if reqv.epoch_len != 0 { reqv.epoch_len } else { node_rot_cfg.as_ref().and_then(|r| r.epoch_len).unwrap_or(10_000) };
                    let epoch = derive_epoch(reqv.current_anchor_index, epoch_len);
                    let seed = derive_vrf_seed(nid, pc_types::AnchorId(last));
                    let rot = if let Some(r) = reqv.rotation {
                        VrfRotationParams{ cooldown_anchors: r.cooldown_anchors, min_attendance_pct: r.min_attendance_pct }
                    } else if let Some(cfg) = node_rot_cfg.as_ref() {
                        VrfRotationParams{
                            cooldown_anchors: cfg.cooldown_anchors.unwrap_or(10_000),
                            min_attendance_pct: cfg.min_attendance_pct.unwrap_or(50),
                        }
                    } else {
                        VrfRotationParams{ cooldown_anchors: 10_000, min_attendance_pct: 50 }
                    };

                    let mut cands: Vec<VrfCandidate> = Vec::with_capacity(reqv.candidates.len());
                    for c in reqv.candidates.iter() {
                        let rid = match hex32(&c.recipient_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad recipient_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let oid = match hex32(&c.operator_id) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad operator_id\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pkb = match hex48(&c.bls_pk) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let proof = match hex96(&c.vrf_proof) { Some(v)=>v, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"bad vrf_proof\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        let pk = match bls_pk_from_bytes(&pkb) { Some(p)=>p, None=> { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid bls_pk\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                        cands.push(VrfCandidate{ recipient_id: rid, operator_id: oid, bls_pk: pk, last_selected_at: c.last_selected_at, attendance_recent_pct: c.attendance_recent_pct, vrf_proof: proof });
                    }

                    let selected: Vec<SelectedSeat> = committee_select_vrf(reqv.k, epoch, seed, reqv.current_anchor_index, &cands, &rot);
                    #[derive(Serialize, Deserialize, Clone, Debug)]
                    struct SeatOut { recipient_id: String, operator_id: String, bls_pk: String, score: String }
                    #[derive(Serialize, Deserialize, Clone, Debug)]
                    struct CommitteeDoc { ok: bool, epoch: u64, current_anchor_index: u64, seed: String, n_selected: usize, seats: Vec<SeatOut>, ts: u64 }
                    let seats: Vec<SeatOut> = selected.iter().map(|s| SeatOut{
                        recipient_id: hex::encode(s.recipient_id),
                        operator_id: hex::encode(s.operator_id),
                        bls_pk: hex::encode(s.bls_pk.to_bytes()),
                        score: hex::encode(s.score),
                    }).collect();
                    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let doc = CommitteeDoc{ ok:true, epoch, current_anchor_index: reqv.current_anchor_index, seed: hex::encode(seed), n_selected: seats.len(), seats, ts };
                    // persistieren
                    let path = std::path::Path::new(&mempool_dir).join("vrf_committee.json");
                    let raw = serde_json::to_vec(&doc).unwrap_or_else(|_| b"{}".to_vec());
                    if let Err(e) = atomic_write_async(&path, raw.clone(), do_fsync).await {
                        let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"persist: {}\"}}", e))).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    // In-Memory-State aktualisieren
                    {
                        let m = VRF_COMMITTEE.get_or_init(|| tokio::sync::Mutex::new(None));
                        let mut g = m.lock().await;
                        if let Ok(v) = serde_json::to_value(&doc) { *g = Some(v); }
                    }
                    let body = serde_json::to_string(&doc).unwrap_or_else(|_| "{\"ok\":true}".to_string());
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                    return Ok::<_, anyhow::Error>(resp);
                } else if req.uri().path() == "/consensus/current_committee" && req.method() == hyper::Method::GET {
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    // Zuerst aus In-Memory-State, sonst von Disk versuchen
                    #[derive(Serialize, Deserialize, Clone, Debug)]
                    struct CommitteeDoc { ok: bool, epoch: u64, current_anchor_index: u64, seed: String, n_selected: usize, seats: Vec<serde_json::Value>, ts: u64 }
                    let mut have = None;
                    {
                        let m = VRF_COMMITTEE.get_or_init(|| tokio::sync::Mutex::new(None));
                        let g = m.lock().await; if let Some(v) = g.as_ref() { have = Some(v.clone()); }
                    }
                    if have.is_none() {
                        let path = std::path::Path::new(&mempool_dir).join("vrf_committee.json");
                        if let Ok(Ok(buf)) = tokio::task::spawn_blocking({ let p = path.clone(); move || std::fs::read(&p) }).await {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&buf) { have = Some(v); }
                        }
                    }
                    if let Some(v) = have {
                        let body = serde_json::to_string(&v).unwrap_or_else(|_| "{\"ok\":true}".to_string());
                        let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    } else {
                        let mut resp = Response::builder().status(404).body(Body::from("{\"ok\":false,\"error\":\"not found\"}".to_string())).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                } else if req.uri().path() == "/tx/broadcast" && req.method() == hyper::Method::POST {
                    NODE_RPC_BROADCAST_TOTAL.fetch_add(1, Ordering::Relaxed);
                    if require_auth {
                        let expected = auth_token.as_deref().unwrap_or("");
                        let got = req.headers().get(hyper::header::AUTHORIZATION);
                        let ok = if let Some(val) = got {
                            if let Ok(s) = val.to_str() {
                                if let Some(b) = s.strip_prefix("Bearer ") {
                                    !expected.is_empty() && b == expected
                                } else { false }
                            } else { false }
                        } else { false };
                        if !ok {
                            let mut resp = Response::builder()
                                .status(401)
                                .body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string()))
                                .unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    }
                    // Begrenze Request-Body (Schutz gegen zu große Bodies)
                    let max = 1_000_000usize; // 1 MB Limit
                    let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre {
                        Ok(b) => b,
                        Err(e) => {
                            let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                    if whole.len() > max {
                        let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"payload too large\"}".to_string())).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    // Decode MicroTx
                    let mut s = &whole[..];
                    let tx = match MicroTx::decode(&mut s) {
                        Ok(t) => t,
                        Err(_e) => {
                            let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid tx\"}".to_string())).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                    };
                    if let Err(_e) = validate_microtx_sanity(&tx) {
                        let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"tx sanity failed\"}".to_string())).unwrap();
                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                    }
                    let id = digest_microtx(&tx);
                    // Persistenz in Mempool: Datei + Journal (id.hex.bin)
                    let _ = tokio::task::spawn_blocking({ let d = mempool_dir.clone(); move || std::fs::create_dir_all(&d) }).await;
                    let fname = format!("{}.bin", hex::encode(id));
                    let path = std::path::Path::new(&mempool_dir).join(&fname);
                    let status = if path.exists() {
                        NODE_RPC_BROADCAST_DUP_TOTAL.fetch_add(1, Ordering::Relaxed);
                        "duplicate"
                    } else {
                        let mut buf = Vec::new();
                        if let Err(e) = tx.encode(&mut buf) {
                            let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"encode: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                        if let Err(e) = atomic_write_async(&path, buf.clone(), do_fsync).await {
                            let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"persist: {}\"}}", e))).unwrap();
                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                            return Ok::<_, anyhow::Error>(resp);
                        }
                        let journal = std::path::Path::new(&mempool_dir).join("mempool.journal");
                        let _ = journal_append(&journal, do_fsync, b'A', &id);
                        NODE_RPC_BROADCAST_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                        "accepted"
                    };
                    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let body = format!("{{\"ok\":true,\"txid\":\"{}\",\"status\":\"{}\",\"ts\":{}}}", hex::encode(id), status, ts);
                    let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                        return Ok::<_, anyhow::Error>(resp);
                        }
                        // Fallback 404
                        let mut resp = Response::builder()
                            .status(404)
                            .body(Body::from("Not Found"))
                            .unwrap();
                        resp.headers_mut().insert(
                            hyper::header::CONTENT_TYPE,
                            hyper::header::HeaderValue::from_static("text/plain"),
                        );
                        Ok::<_, anyhow::Error>(resp)
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
                let (tcp, _peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => { warn!(error = %e, "tls accept error"); continue; }
                };
                let acceptor = acceptor.clone();
                let mempool_dir = mempool_dir.clone();
                let auth_token = auth_token.clone();
                let require_auth = require_auth;
                tokio::spawn(async move {
                    match acceptor.accept(tcp).await {
                        Ok(tls) => {
                            let svc = service_fn(move |req: Request<Body>| {
                                let mempool_dir = mempool_dir.clone();
                                let auth_token = auth_token.clone();
                                let require_auth = require_auth;
                                async move {
                                    if req.uri().path() == "/status" && req.method() == hyper::Method::GET {
                                        let ts = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        let body = format!(
                                            "{{\"ok\":true,\"service\":\"phantom-node\",\"ts\":{}}}",
                                            ts
                                        );
                                        let mut resp = Response::builder()
                                            .status(200)
                                            .body(Body::from(body))
                                            .unwrap();
                                        resp.headers_mut().insert(
                                            hyper::header::CONTENT_TYPE,
                                            hyper::header::HeaderValue::from_static("application/json"),
                                        );
                                        return Ok::<_, anyhow::Error>(resp);
                                    } else if req.uri().path() == "/healthz" && req.method() == hyper::Method::GET {
                                        let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                        return Ok::<_, anyhow::Error>(resp);
                                    } else if req.uri().path() == "/readyz" && req.method() == hyper::Method::GET {
                                        match std::fs::metadata(&mempool_dir) {
                                            Ok(_) => {
                                                let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap();
                                                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                                return Ok::<_, anyhow::Error>(resp);
                                            }
                                            Err(e) => {
                                                let mut resp = Response::builder().status(503).body(Body::from(format!("{{\"ok\":false,\"error\":\"mempool_dir: {}\"}}", e))).unwrap();
                                                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                                return Ok::<_, anyhow::Error>(resp);
                                            }
                                        }
                                    } else if req.uri().path() == "/metrics" && req.method() == hyper::Method::GET {
                                        let mut out = String::new();
                                        use std::fmt::Write as _;
                                        let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_total RPC broadcast requests total");
                                        let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_total counter");
                                        let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_total {}", NODE_RPC_BROADCAST_TOTAL.load(Ordering::Relaxed));
                                        let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_accepted_total RPC broadcast accepted total");
                                        let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_accepted_total counter");
                                        let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_accepted_total {}", NODE_RPC_BROADCAST_ACCEPTED_TOTAL.load(Ordering::Relaxed));
                                        let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_duplicate_total RPC broadcast duplicates total");
                                        let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_duplicate_total counter");
                                        let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_duplicate_total {}", NODE_RPC_BROADCAST_DUP_TOTAL.load(Ordering::Relaxed));
                                        let _ = writeln!(&mut out, "# HELP phantom_node_rpc_broadcast_errors_total RPC broadcast errors total");
                                        let _ = writeln!(&mut out, "# TYPE phantom_node_rpc_broadcast_errors_total counter");
                                        let _ = writeln!(&mut out, "phantom_node_rpc_broadcast_errors_total {}", NODE_RPC_BROADCAST_ERRORS_TOTAL.load(Ordering::Relaxed));
                                        let mut resp = Response::builder().status(200).body(Body::from(out)).unwrap();
                                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"));
                                        return Ok::<_, anyhow::Error>(resp);
                                    } else if req.uri().path() == "/state/apply_mint_with_index" && req.method() == hyper::Method::POST {
                                        #[derive(serde::Deserialize)]
                                        struct MOut { amount: u64, lock: String }
                                        #[derive(serde::Deserialize)]
                                        struct ApplyMintReq { prev_mint_id: Option<String>, outputs: Vec<MOut>, pow_seed: String, pow_nonce: u64, minted_at: u64 }
                                        let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                                        let reqv: ApplyMintReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                                        let mut prev_id = [0u8;32]; if let Some(s)=reqv.prev_mint_id.as_ref(){ if let Ok(b)=hex::decode(s){ if b.len()==32 { prev_id.copy_from_slice(&b); } } }
                                        let mut seed = [0u8;32]; if let Ok(b)=hex::decode(&reqv.pow_seed){ if b.len()==32 { seed.copy_from_slice(&b); } }
                                        let mut outs: Vec<TxOut> = Vec::with_capacity(reqv.outputs.len());
                                        for o in reqv.outputs.iter(){ let mut lock=[0u8;32]; if let Ok(b)=hex::decode(&o.lock){ if b.len()==32 { lock.copy_from_slice(&b);} } outs.push(TxOut{amount:o.amount, lock:LockCommitment(lock)}); }
                                        let mint = MintEvent { version:1, prev_mint_id: prev_id, outputs: outs, pow_seed: seed, pow_nonce: reqv.pow_nonce };
                                        if let Err(_e)=validate_mint_sanity(&mint){ let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"mint sanity failed\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                                        let st_mutex = global_state(&mempool_dir);
                                        let mut st = st_mutex.lock().await;
                                        st.apply_mint_with_index(&mint, reqv.minted_at);
                                        let id = pc_types::digest_mint(&mint);
                                        let body = serde_json::json!({"ok":true, "mint_id": hex::encode(id)}).to_string();
                                        let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                        return Ok::<_, anyhow::Error>(resp);
                                    } else if req.uri().path() == "/stake/bond" && req.method() == hyper::Method::POST {
                                        #[derive(serde::Deserialize)]
                                        struct OpRef { txid: String, vout: u32 }
                                        #[derive(serde::Deserialize)]
                                        struct BondReq { ops: Vec<OpRef>, current: u64, threshold: u64, allow_unripe_bond: Option<bool> }
                                        let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                                        let reqv: BondReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                                        let mut ops: Vec<OutPoint> = Vec::with_capacity(reqv.ops.len());
                                        for r in reqv.ops.iter(){ let mut txid=[0u8;32]; if let Ok(b)=hex::decode(&r.txid){ if b.len()==32 { txid.copy_from_slice(&b);} } ops.push(OutPoint{ txid, vout: r.vout}); }
                                        let st_mutex = global_state(&mempool_dir);
                                        let mut st = st_mutex.lock().await;
                                        let allow = reqv.allow_unripe_bond.unwrap_or(false);
                                        match st.bond_outpoints(&ops, reqv.current, reqv.threshold, allow) {
                                            Ok(()) => { let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                                            Err(e) => { let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                                        }
                                    } else if req.uri().path() == "/stake/unbond" && req.method() == hyper::Method::POST {
                                        #[derive(serde::Deserialize)]
                                        struct OpRef { txid: String, vout: u32 }
                                        #[derive(serde::Deserialize)]
                                        struct UnbondReq { ops: Vec<OpRef>, current: u64, threshold: u64 }
                                        let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                                        let reqv: UnbondReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                                        let mut ops: Vec<OutPoint> = Vec::with_capacity(reqv.ops.len());
                                        for r in reqv.ops.iter(){ let mut txid=[0u8;32]; if let Ok(b)=hex::decode(&r.txid){ if b.len()==32 { txid.copy_from_slice(&b);} } ops.push(OutPoint{ txid, vout: r.vout}); }
                                        let st_mutex = global_state(&mempool_dir);
                                        let mut st = st_mutex.lock().await;
                                        match st.unbond_outpoints(&ops, reqv.current, reqv.threshold) {
                                            Ok(()) => { let mut resp = Response::builder().status(200).body(Body::from("{\"ok\":true}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                                            Err(e) => { let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"{}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                                        }
                                    } else if req.uri().path() == "/mint/template" && req.method() == hyper::Method::GET {
                                        use rand::RngCore as _;
                                        let mut seed = [0u8; 32]; rand::thread_rng().fill_bytes(&mut seed);
                                        let bits = consts::POW_DEFAULT_BITS;
                                        let last_path = std::path::Path::new(&mempool_dir).join("last_mint_id");
                                        let prev_mint_id = match std::fs::read_to_string(&last_path) {
                                            Ok(s) => { let h=s.trim(); let mut b=[0u8;32]; if h.len()==64 { if let Ok(raw)=hex::decode(h){ if raw.len()==32 { b.copy_from_slice(&raw); } } } b }
                                            Err(_) => [0u8; 32],
                                        };
                                        let body = serde_json::json!({"ok":true, "seed":hex::encode(seed), "bits":bits, "prev_mint_id":hex::encode(prev_mint_id)}).to_string();
                                        let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                        return Ok::<_, anyhow::Error>(resp);
                                    } else if req.uri().path() == "/mint/submit" && req.method() == hyper::Method::POST {
                                        #[derive(serde::Deserialize)]
                                        struct MintSubmitReq { seed: String, nonce: u64, bits: Option<u8>, outputs: Vec<MOut> }
                                        #[derive(serde::Deserialize)]
                                        struct MOut { amount: u64, lock: String }
                                        let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre { Ok(b)=>b, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                                        let reqv: MintSubmitReq = match serde_json::from_slice(&whole) { Ok(v)=>v, Err(e)=> { let mut resp=Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} };
                                        let mut seed=[0u8;32]; if let Ok(b)=hex::decode(&reqv.seed){ if b.len()==32 { seed.copy_from_slice(&b);} }
                                        let bits=reqv.bits.unwrap_or(consts::POW_DEFAULT_BITS);
                                        if !pow_meets(bits, &pow_hash(&seed, reqv.nonce)) { let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"pow not sufficient\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                                        let last_path = std::path::Path::new(&mempool_dir).join("last_mint_id");
                                        let prev_mint_id = match tokio::task::spawn_blocking({ let p = last_path.clone(); move || std::fs::read_to_string(&p) }).await { Ok(Ok(s))=>{ let h=s.trim(); let mut b=[0u8;32]; if h.len()==64 { if let Ok(raw)=hex::decode(h){ if raw.len()==32 { b.copy_from_slice(&raw); } } } b }, Ok(Err(_))=>[0u8;32], Err(_)=>[0u8;32] };
                                        let mut outs: Vec<TxOut> = Vec::with_capacity(reqv.outputs.len());
                                        for o in reqv.outputs.iter(){ let mut lock=[0u8;32]; if let Ok(b)=hex::decode(&o.lock){ if b.len()==32 { lock.copy_from_slice(&b);} } outs.push(TxOut{amount:o.amount, lock:LockCommitment(lock)}); }
                                        let mint = MintEvent { version:1, prev_mint_id, outputs: outs, pow_seed: seed, pow_nonce: reqv.nonce };
                                        if let Err(_e)=validate_mint_sanity(&mint){ let mut resp=Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"mint sanity failed\"}".to_string())).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp); }
                                        let id = pc_types::digest_mint(&mint);
                                        let mdir=std::path::Path::new(&mempool_dir).join("mints"); let _ = tokio::task::spawn_blocking({ let d = mdir.clone(); move || std::fs::create_dir_all(&d) }).await;
                                        let mpath=mdir.join(format!("{}.bin", hex::encode(id)));
                                        let mut buf=Vec::new(); if let Err(e)=mint.encode(&mut buf){ let mut resp=Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"encode mint: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} 
                                        if let Err(e)=atomic_write_async(&mpath, buf.clone(), false).await{ let mut resp=Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"persist mint: {}\"}}", e))).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);} 
                                        {
                                            let lp = last_path.clone();
                                            let data = hex::encode(id);
                                            let _ = tokio::task::spawn_blocking(move || std::fs::write(&lp, data)).await;
                                        }
                                        let body=serde_json::json!({"ok":true, "mint_id":hex::encode(id)}).to_string();
                                        let mut resp=Response::builder().status(200).body(Body::from(body)).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);
                                    } else if req.method()==hyper::Method::GET && req.uri().path().starts_with("/mint/status/") {
                                        let path=req.uri().path(); let id_hex=&path["/mint/status/".len()..];
                                        let mpath=std::path::Path::new(&mempool_dir).join("mints").join(format!("{}.bin", id_hex));
                                        let found=mpath.exists();
                                        let body=serde_json::json!({"ok":true, "found":found}).to_string();
                                        let mut resp=Response::builder().status(200).body(Body::from(body)).unwrap(); resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json")); return Ok::<_, anyhow::Error>(resp);
                                    } else if req.uri().path() == "/tx/broadcast" && req.method() == hyper::Method::POST {
                                        NODE_RPC_BROADCAST_TOTAL.fetch_add(1, Ordering::Relaxed);
                                        if require_auth {
                                            let expected = auth_token.as_deref().unwrap_or("");
                                            let got = req.headers().get(hyper::header::AUTHORIZATION);
                                            let ok = if let Some(val) = got {
                                                if let Ok(s) = val.to_str() {
                                                    if let Some(b) = s.strip_prefix("Bearer ") { !expected.is_empty() && b == expected } else { false }
                                                } else { false }
                                            } else { false };
                                            if !ok {
                                                let mut resp = Response::builder().status(401).body(Body::from("{\"ok\":false,\"error\":\"unauthorized\"}".to_string())).unwrap();
                                                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                                NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                return Ok::<_, anyhow::Error>(resp);
                                            }
                                        }
                                        let max = 1_000_000usize;
                                        let whole_pre = match tokio::time::timeout(std::time::Duration::from_secs(5), hyper::body::to_bytes(req.into_body())).await {
    Ok(v) => v,
    Err(_e) => {
        let mut resp = Response::builder().status(408).body(Body::from("{\"ok\":false,\"error\":\"read timeout\"}".to_string())).unwrap();
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
        return Ok::<_, anyhow::Error>(resp);
    }
};
let whole = match whole_pre {
                                            Ok(b) => b,
                                            Err(e) => {
                                                let mut resp = Response::builder().status(400).body(Body::from(format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e))).unwrap();
                                                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                                NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                return Ok::<_, anyhow::Error>(resp);
                                            }
                                        };
if whole.len() > MAX_HTTP_BODY_BYTES {
    let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"body too large\"}".to_string())).unwrap();
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    return Ok::<_, anyhow::Error>(resp);
}
                                        if whole.len() > max {
                                            let mut resp = Response::builder().status(413).body(Body::from("{\"ok\":false,\"error\":\"payload too large\"}".to_string())).unwrap();
                                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                            NODE_RPC_BROADCAST_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            return Ok::<_, anyhow::Error>(resp);
                                        }
                                        let mut s = &whole[..];
                                        let tx = match MicroTx::decode(&mut s) {
                                            Ok(t) => t,
                                            Err(_e) => {
                                                let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"invalid tx\"}".to_string())).unwrap();
                                                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                                return Ok::<_, anyhow::Error>(resp);
                                            }
                                        };
                                        if let Err(_e) = validate_microtx_sanity(&tx) {
                                            let mut resp = Response::builder().status(400).body(Body::from("{\"ok\":false,\"error\":\"tx sanity failed\"}".to_string())).unwrap();
                                            resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                            return Ok::<_, anyhow::Error>(resp);
                                        }
                                        let id = digest_microtx(&tx);
                                        let _ = tokio::task::spawn_blocking({ let d = mempool_dir.clone(); move || std::fs::create_dir_all(&d) }).await;
                                        let fname = format!("{}.bin", hex::encode(id));
                                        let path = std::path::Path::new(&mempool_dir).join(&fname);
                                        let status = if path.exists() {
                                            NODE_RPC_BROADCAST_DUP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            "duplicate"
                                        } else {
                                            let mut buf = Vec::new();
                                            if let Err(e) = tx.encode(&mut buf) {
                                                let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"encode: {}\"}}", e))).unwrap();
                                                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                                return Ok::<_, anyhow::Error>(resp);
                                            }
                                            if let Err(e) = atomic_write_async(&path, buf.clone(), false).await {
                                                let mut resp = Response::builder().status(500).body(Body::from(format!("{{\"ok\":false,\"error\":\"persist: {}\"}}", e))).unwrap();
                                                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                                return Ok::<_, anyhow::Error>(resp);
                                            }
                                            let journal = std::path::Path::new(&mempool_dir).join("mempool.journal");
                                            let _ = journal_append(&journal, false, b'A', &id);
                                            NODE_RPC_BROADCAST_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            "accepted"
                                        };
                                        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                        let body = format!("{{\"ok\":true,\"txid\":\"{}\",\"status\":\"{}\",\"ts\":{}}}", hex::encode(id), status, ts);
                                        let mut resp = Response::builder().status(200).body(Body::from(body)).unwrap();
                                        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
                                        return Ok::<_, anyhow::Error>(resp);
                                    }
                                    let mut resp = Response::builder()
                                        .status(404)
                                        .body(Body::from("Not Found"))
                                        .unwrap();
                                    resp.headers_mut().insert(
                                        hyper::header::CONTENT_TYPE,
                                        hyper::header::HeaderValue::from_static("text/plain"),
                                    );
                                    Ok::<_, anyhow::Error>(resp)
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

fn build_tls_config(cert_path: &str, key_path: &str, client_ca_path: Option<&str>) -> Result<rustls::ServerConfig> {
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
    let mut rd = std::io::BufReader::new(std::fs::File::open(path).map_err(|e| anyhow!("open certs: {e}"))?);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let mut rd = std::io::BufReader::new(std::fs::File::open(path).map_err(|e| anyhow!("open key: {e}"))?);
    let keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut rd)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(Into::into)
        .collect();
    if let Some(k) = keys.into_iter().next() { return Ok(k); }
    let mut rd = std::io::BufReader::new(std::fs::File::open(path).map_err(|e| anyhow!("open key2: {e}"))?);
    let keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::rsa_private_keys(&mut rd)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(Into::into)
        .collect();
    if let Some(k) = keys.into_iter().next() { return Ok(k); }
    Err(anyhow!("no private key found in {}", path))
}

fn load_roots(path: &str) -> Result<rustls::RootCertStore> {
    let mut rd = std::io::BufReader::new(std::fs::File::open(path).map_err(|e| anyhow!("open ca: {e}"))?);
    let mut store = rustls::RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd).collect::<Result<Vec<_>, _>>()?;
    let (added, _ignored) = store.add_parsable_certificates(certs);
    if added == 0 { return Err(anyhow!("no CA certs loaded from {}", path)); }
    Ok(store)
}

#[derive(Debug, Clone, Args)]
struct StatusServeArgs {
    /// Pfad zu einer Node-Konfigurationsdatei (TOML). Hat Vorrang vor CLI-Flags
    #[arg(long)]
    config: Option<PathBuf>,
    /// HTTP Listen-Adresse, z. B. 127.0.0.1:8080
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: String,
    /// Mempool-Verzeichnis für eingehende Transaktionen
    #[arg(long, default_value = "pc-data/mempool")]
    mempool_dir: String,
    /// fsync() auf Dateien/Verzeichnisse
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// Fordere Bearer-Token für /tx/broadcast
    #[arg(long, default_value_t = false)]
    require_auth: bool,
    /// Erwartetes Bearer-Token (wenn --require-auth)
    #[arg(long)]
    auth_token: Option<String>,
    /// TLS: Server-Zertifikat (PEM)
    #[arg(long)]
    tls_cert: Option<String>,
    /// TLS: Server-Schlüssel (PEM, PKCS8 oder RSA)
    #[arg(long)]
    tls_key: Option<String>,
    /// mTLS: Client-CA (PEM)
    #[arg(long)]
    tls_client_ca: Option<String>,
    /// VRF: Epoch-Länge in Ankern (Override zu config)
    #[arg(long)]
    vrf_epoch_len: Option<u64>,
    /// VRF: Cooldown in Ankern (Override zu config)
    #[arg(long)]
    vrf_cooldown_anchors: Option<u64>,
    /// VRF: Mindest-Attendance in Prozent (Override zu config)
    #[arg(long)]
    vrf_min_attendance_pct: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::io::Write as _;

    fn unique_tmp(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pc_journal_test_{}_{}", prefix, nanos))
    }

    #[tokio::test]
    async fn journal_recovery_roundtrip() {
        let base = unique_tmp("recovery");
        let mempool_dir = base.join("mempool");
        std::fs::create_dir_all(&mempool_dir).unwrap();
        let journal_path = mempool_dir.join("mempool.journal");

        // Baue minimalen MicroTx (leer), schreibe Datei + Journal
        let tx = MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
        };
        let id = digest_microtx(&tx);
        let fname = format!("{}.bin", hex::encode(id));
        let path = mempool_dir.join(fname);
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        atomic_write_async(&path, buf.clone(), false).await.unwrap();
        journal_append(&journal_path, false, b'A', &id).unwrap();

        // Recovery nach Journal: aktive IDs
        let contents = std::fs::read_to_string(&journal_path).unwrap();
        let mut active: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for line in contents.lines() {
            let (op, hexid) = line.split_at(1);
            let bytes = hex::decode(hexid).unwrap();
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            match op.as_bytes()[0] {
                b'A' => {
                    active.insert(id);
                }
                b'D' => {
                    active.remove(&id);
                }
                _ => {}
            }
        }
        assert!(active.contains(&id));

        // Datei laden und decodieren
        let mut fb = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut fb)
            .unwrap();
        let got = MicroTx::decode(&mut &fb[..]).unwrap();
        assert_eq!(tx, got);
    }

    #[test]
    fn ttl_eviction_removes_expired_file() {
        let base = unique_tmp("ttl");
        let mempool_dir = base.join("mempool");
        std::fs::create_dir_all(&mempool_dir).unwrap();

        // Eine Datei erzeugen und dann entfernen
        let path = mempool_dir.join("dead.bin");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"x").unwrap();
        remove_with_dir_sync(&path, false).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn deterministic_sort_matches_payload_root() {
        // Drei Txs, unsortiert
        let mk = |n: u8| MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                amount: n as u64,
                lock: LockCommitment([n; 32]),
            }],
        };
        let txs = vec![mk(3), mk(1), mk(2)];
        let sorted = {
            let mut v = txs.clone();
            v.sort_unstable_by(|a, b| digest_microtx(a).cmp(&digest_microtx(b)));
            v
        };
        let p_unsorted = AnchorPayload {
            version: 1,
            micro_txs: txs,
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
        };
        let p_sorted = AnchorPayload {
            version: 1,
            micro_txs: sorted,
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
        };
        assert_eq!(
            payload_merkle_root(&p_unsorted),
            payload_merkle_root(&p_sorted)
        );
    }

    #[tokio::test]
    async fn pending_finalization_invalidation() {
        // Setup: zwei Txs im Mempool (Dateien + Journal), Payload enthält eine davon
        let base = unique_tmp("finalize");
        let mempool_dir = base.join("mempool");
        std::fs::create_dir_all(&mempool_dir).unwrap();
        let journal_path = mempool_dir.join("mempool.journal");

        let mk = |n: u8| MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                amount: n as u64,
                lock: LockCommitment([n; 32]),
            }],
        };
        let tx_keep = mk(7);
        let tx_inval = mk(9);
        let id_keep = digest_microtx(&tx_keep);
        let id_inval = digest_microtx(&tx_inval);

        // Schreibe beide Txs in Dateien + Journal
        for (tx, id) in [(&tx_keep, &id_keep), (&tx_inval, &id_inval)] {
            let fname = format!("{}.bin", hex::encode(id));
            let path = mempool_dir.join(fname);
            let mut buf = Vec::new();
            tx.encode(&mut buf).unwrap();
            atomic_write_async(&path, buf.clone(), false).await.unwrap();
            journal_append(&journal_path, false, b'A', id).unwrap();
        }

        // RAM‑Mempool und Order füllen
        let mut mempool: HashMap<[u8; 32], (MicroTx, Instant)> = HashMap::new();
        let mut order: VecDeque<[u8; 32]> = VecDeque::new();
        let _ = mempool.insert(id_keep, (tx_keep.clone(), Instant::now()));
        let _ = mempool.insert(id_inval, (tx_inval.clone(), Instant::now()));
        order.push_back(id_keep);
        order.push_back(id_inval);

        // Payload mit tx_inval
        let payload = AnchorPayload {
            version: 1,
            micro_txs: vec![tx_inval.clone()],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
        };

        // Invalidation simulieren (inline wie im State‑Task)
        let mut invalidated: u64 = 0;
        for tx in &payload.micro_txs {
            let id = digest_microtx(tx);
            if mempool.remove(&id).is_some() {
                invalidated += 1;
                if let Some(pos) = order.iter().position(|k| *k == id) {
                    let _ = order.remove(pos);
                }
                let fname = format!("{}.bin", hex::encode(id));
                let path = mempool_dir.join(fname);
                journal_append(&journal_path, false, b'D', &id).unwrap();
                remove_with_dir_sync(&path, false).unwrap();
            }
        }

        // Prüfen: eine Tx invalidiert, Datei entfernt, die andere existiert
        assert_eq!(invalidated, 1);
        assert!(mempool.get(&id_inval).is_none());
        assert!(mempool.get(&id_keep).is_some());
        let keep_path = mempool_dir.join(format!("{}.bin", hex::encode(id_keep)));
        assert!(keep_path.exists());
        let inval_path = mempool_dir.join(format!("{}.bin", hex::encode(id_inval)));
        assert!(!inval_path.exists());
        // Order enthält nur id_keep
        assert_eq!(order.len(), 1);
        assert_eq!(order.front().copied(), Some(id_keep));
    }
}
fn rewrite_mempool_journal(
    journal_path: &std::path::Path,
    ids: &VecDeque<[u8; 32]>,
    do_fsync: bool,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = journal_path.to_path_buf();
    tmp.set_extension("journal.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        for id in ids.iter() {
            f.write_all(b"A")?;
            f.write_all(hex::encode(id).as_bytes())?;
            f.write_all(b"\n")?;
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

fn journal_append(
    journal_path: &std::path::Path,
    do_fsync: bool,
    op: u8,
    id: &[u8; 32],
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)?;
    // Zeile: 'A' oder 'D' + hex + '\n'
    let mut line = Vec::with_capacity(1 + 64 + 1);
    line.push(op);
    line.extend_from_slice(hex::encode(id).as_bytes());
    line.push(b'\n');
    f.write_all(&line)?;
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

async fn atomic_write_async(path: &std::path::Path, data: Vec<u8>, do_fsync: bool) -> std::io::Result<()> {
    let p = path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || atomic_write(&p, &data, do_fsync))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("join {}", e)))?;
    res
}


#[derive(Debug, Clone, Args)]
struct CacheBenchArgs {
    /// Pfad zum Store-Root (enthält headers/ und payloads/)
    #[arg(long, default_value = "pc-data")]
    store_dir: String,
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true)
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// Modus: headers | payloads
    #[arg(long)]
    mode: String,
    /// Anzahl eindeutiger Elemente aus dem Store (max.)
    #[arg(long, default_value_t = 100)]
    sample: usize,
    /// Wiederholungen über dem gleichen Sample (>=1)
    #[arg(long, default_value_t = 3)]
    iterations: usize,
    /// Header-Cache-Kapazität (0=aus)
    #[arg(long, default_value_t = 1000)]
    cache_hdr_cap: usize,
    /// Payload-Cache-Kapazität (0=aus)
    #[arg(long, default_value_t = 1000)]
    cache_pl_cap: usize,
}

// Node-weite Metriken (nicht Teil von pc_p2p): Persistenz und Observer-Lag
static NODE_PERSIST_HEADERS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_HEADERS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_INBOUND_OBS_LAGGED_TOTAL: AtomicU64 = AtomicU64::new(0);
// Cache-Metriken
static NODE_CACHE_HEADERS_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_HEADERS_MISSES_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_PAYLOADS_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_PAYLOADS_MISSES_TOTAL: AtomicU64 = AtomicU64::new(0);
// Mempool-Metriken
static NODE_MEMPOOL_SIZE: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_DUPLICATE_TOTAL: AtomicU64 = AtomicU64::new(0);
// Zusätzliche Mempool-Metriken
static NODE_MEMPOOL_TTL_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_CAP_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_INVALIDATED_TOTAL: AtomicU64 = AtomicU64::new(0);
// Proposer-Metriken
static NODE_PROPOSER_BUILT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_LAST_SIZE: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_PENDING: AtomicU64 = AtomicU64::new(0);
// RPC Broadcast Metriken
static NODE_RPC_BROADCAST_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_RPC_BROADCAST_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_RPC_BROADCAST_DUP_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_RPC_BROADCAST_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);

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

// Sharded-LRU zur Reduktion von Mutex-Contention
struct ShardedLru<K, V> {
    shards: Vec<Mutex<LruCache<K, V>>>,
}

impl<K: Hash + Eq + Clone, V: Clone> ShardedLru<K, V> {
    fn new(n_shards: usize, total_cap: usize) -> Self {
        let n = std::cmp::max(1, n_shards);
        let per = std::cmp::max(1, total_cap / n);
        let mut shards = Vec::with_capacity(n);
        for _ in 0..n {
            shards.push(Mutex::new(LruCache::new(NonZeroUsize::new(per).unwrap())));
        }
        Self { shards }
    }
    fn index(&self, key: &K) -> usize {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        (h.finish() as usize) % self.shards.len()
    }
    async fn get_clone(&self, key: &K) -> Option<V> {
        let idx = self.index(key);
        let mut g = self.shards[idx].lock().await;
        g.get(key).cloned()
    }
    async fn put(&self, key: K, val: V) {
        let idx = self.index(&key);
        let mut g = self.shards[idx].lock().await;
        g.put(key, val);
    }
    async fn touch_present(&self, key: &K) -> bool {
        let idx = self.index(key);
        let mut g = self.shards[idx].lock().await;
        g.get(key).is_some()
    }
}

// StoreDelegate-Wrapper: persistiert Header/Payloads auf Disk via FileStore, mit optionalem LRU-Cache (sharded)
#[derive(Clone)]
struct NodeDiskStore {
    inner: Arc<FileStore>,
    hdr_cache: Option<Arc<ShardedLru<AnchorId, pc_types::AnchorHeaderV2>>>,
    pl_cache: Option<Arc<ShardedLru<[u8; 32], pc_types::AnchorPayloadV2>>>,
    txs: Arc<tokio::sync::Mutex<HashMap<[u8; 32], MicroTx>>>,
}

impl NodeDiskStore {
    fn new(store: FileStore, hdr_cap: usize, pl_cap: usize) -> Self {
        let shards = std::cmp::max(1, num_cpus::get());
        let hdr_cache = if hdr_cap > 0 {
            Some(Arc::new(ShardedLru::new(shards, hdr_cap)))
        } else {
            None
        };
        let pl_cache = if pl_cap > 0 {
            Some(Arc::new(ShardedLru::new(shards, pl_cap)))
        } else {
            None
        };
        Self {
            inner: Arc::new(store),
            hdr_cache,
            pl_cache,
            txs: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl pc_p2p::async_svc::StoreDelegate for NodeDiskStore {
    async fn insert_header(&self, h: pc_types::AnchorHeaderV2) {
        let store = self.inner.clone();
        let h_clone_for_cache = h.clone();
        match tokio::task::spawn_blocking(move || store.put_header_v2(&h)).await {
            Ok(Ok(_)) => {
                NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
                if let Some(c) = &self.hdr_cache {
                    let id = AnchorId(h_clone_for_cache.id_digest());
                    c.put(id, h_clone_for_cache).await;
                }
            }
            _ => {
                NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!("store.put_header failed");
            }
        }
    }
    async fn insert_payload(&self, p: pc_types::AnchorPayloadV2) {
        let store = self.inner.clone();
        let p_clone_for_cache = p.clone();
        match tokio::task::spawn_blocking(move || store.put_payload_v2(&p)).await {
            Ok(Ok(_)) => {
                NODE_PERSIST_PAYLOADS_TOTAL.fetch_add(1, Ordering::Relaxed);
                if let Some(c) = &self.pl_cache {
                    let root = pc_types::payload_merkle_root_v2(&p_clone_for_cache);
                    c.put(root, p_clone_for_cache).await;
                }
            }
            _ => {
                NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!("store.put_payload failed");
            }
        }
    }
    async fn has_payload(&self, root: &[u8; 32]) -> bool {
        let r = *root;
        if let Some(c) = &self.pl_cache {
            if c.touch_present(&r).await {
                NODE_CACHE_PAYLOADS_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return true;
            } else {
                NODE_CACHE_PAYLOADS_MISSES_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        }
        let store = self.inner.clone();
        match tokio::task::spawn_blocking(move || store.has_payload(&r)).await {
            Ok(v) => v,
            Err(_) => false,
        }
    }
    async fn get_headers(&self, ids: &[AnchorId]) -> (Vec<pc_types::AnchorHeaderV2>, Vec<[u8; 32]>) {
        let mut found: Vec<pc_types::AnchorHeaderV2> = Vec::new();
        let mut to_fetch: Vec<AnchorId> = Vec::new();
        if let Some(c) = &self.hdr_cache {
            for id in ids.iter().cloned() {
                if let Some(h) = c.get_clone(&id).await {
                    NODE_CACHE_HEADERS_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    found.push(h);
                } else {
                    NODE_CACHE_HEADERS_MISSES_TOTAL.fetch_add(1, Ordering::Relaxed);
                    to_fetch.push(id);
                }
            }
        } else {
            to_fetch.extend_from_slice(ids);
        }
        // Disk-Fetch in einem Blocking-Block
        let store = self.inner.clone();
        let fetched: Vec<pc_types::AnchorHeaderV2> = match tokio::task::spawn_blocking(move || {
            let mut v = Vec::new();
            for id in to_fetch.iter() {
                let t0 = std::time::Instant::now();
                let res = store.get_header_v2(&id.0);
                let dt = t0.elapsed();
                observe_hdr_read(dt);
                match res {
                    Ok(Some(h)) => v.push(h),
                    _ => {}
                }
            }
            v
        })
        .await
        {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        // Cache auffüllen
        if let Some(c) = &self.hdr_cache {
            for h in &fetched {
                let id = AnchorId(h.id_digest());
                c.put(id, h.clone()).await;
            }
        }
        // Missing ermitteln
        let mut missing: Vec<[u8; 32]> = Vec::new();
        let mut seen_ids: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for h in &found {
            seen_ids.insert(h.id_digest());
        }
        for h in &fetched {
            seen_ids.insert(h.id_digest());
        }
        for id in ids.iter() {
            if !seen_ids.contains(&id.0) {
                missing.push(id.0);
            }
        }
        // Zusammenführen
        let mut all_found = found;
        all_found.extend(fetched.into_iter());
        (all_found, missing)
    }
    async fn get_payloads(&self, roots: &[[u8; 32]]) -> (Vec<pc_types::AnchorPayloadV2>, Vec<[u8; 32]>) {
        let mut found: Vec<pc_types::AnchorPayloadV2> = Vec::new();
        let mut to_fetch: Vec<[u8; 32]> = Vec::new();
        if let Some(c) = &self.pl_cache {
            for r in roots.iter().cloned() {
                if let Some(p) = c.get_clone(&r).await {
                    NODE_CACHE_PAYLOADS_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    found.push(p);
                } else {
                    NODE_CACHE_PAYLOADS_MISSES_TOTAL.fetch_add(1, Ordering::Relaxed);
                    to_fetch.push(r);
                }
            }
        } else {
            to_fetch.extend_from_slice(roots);
        }
        // Disk-Fetch in einem Blocking-Block
        let store = self.inner.clone();
        let fetched: Vec<(pc_types::AnchorPayloadV2, [u8; 32])> = match tokio::task::spawn_blocking(move || {
            let mut v = Vec::new();
            for r in to_fetch.iter() {
                let t0 = std::time::Instant::now();
                let res = store.get_payload_v2(r);
                let dt = t0.elapsed();
                observe_pl_read(dt);
                match res {
                    Ok(Some(p)) => v.push((p, *r)),
                    _ => {}
                }
            }
            v
        })
        .await
        {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        // Cache auffüllen
        if let Some(c) = &self.pl_cache {
            for (p, r) in &fetched {
                c.put(*r, p.clone()).await;
            }
        }
        // Missing ermitteln
        let mut missing: Vec<[u8; 32]> = Vec::new();
        let mut seen_roots: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for p in &found {
            seen_roots.insert(pc_types::payload_merkle_root_v2(p));
        }
        for (_p, r) in &fetched {
            seen_roots.insert(*r);
        }
        for r in roots.iter() {
            if !seen_roots.contains(r) {
                missing.push(*r);
            }
        }
        // Zusammenführen
        let mut all_found = found;
        all_found.extend(fetched.into_iter().map(|(p, _r)| p));
        (all_found, missing)
    }

    async fn insert_tx(&self, tx: MicroTx) {
        let id = digest_microtx(&tx);
        let mut g = self.txs.lock().await;
        let _ = g.insert(id, tx);
    }
    async fn has_tx(&self, id: &[u8; 32]) -> bool {
        let g = self.txs.lock().await;
        g.contains_key(id)
    }
    async fn get_txs(&self, ids: &[[u8; 32]]) -> (Vec<MicroTx>, Vec<[u8; 32]>) {
        let g = self.txs.lock().await;
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for id in ids {
            if let Some(tx) = g.get(id) {
                found.push(tx.clone());
            } else {
                missing.push(*id);
            }
        }
        (found, missing)
    }
}

fn run_consensus_ack_dists(args: &ConsensusAckDistsArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let headers: Vec<AnchorHeader> = load_vec_decodable(&args.headers_file)?;
    // k aus Genesis (falls vorhanden) oder CLI ableiten; Genesis hat Vorrang
    let k_eff = if let Some(ref gpath) = args.genesis {
        let g = load_genesis(gpath)?;
        let k = g.consensus.k;
        if k == 0 || k > 64 {
            bail!("invalid k in genesis: {} (must be 1..=64)", k);
        }
        println!(
            "{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}",
            k, g.commitment
        );
        k
    } else {
        if args.k == 0 || args.k > 64 {
            bail!("invalid k: {} (must be 1..=64)", args.k);
        }
        println!(
            "{{\"type\":\"k_selected\",\"k\":{},\"source\":\"cli\"}}",
            args.k
        );
        args.k
    };
    let mut cfg = ConsensusConfig::recommended(k_eff);
    if let Some(dm) = args.d_max {
        cfg.fee_params.d_max = dm;
    }
    let dmax_out = cfg.fee_params.d_max;
    let mut eng = ConsensusEngine::new(cfg);
    for h in headers {
        let _ = eng.insert_header(h);
    }
    let dists = eng.ack_distances(AnchorId(ack));
    // Baue JSON deterministisch ohne Format-String-Brace-Escapes
    let mut out = String::new();
    out.push_str("{\"k\":");
    out.push_str(&args.k.to_string());
    out.push_str(",\"d_max\":");
    out.push_str(&dmax_out.to_string());
    out.push_str(",\"distances\":[");
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match d {
            Some(v) => out.push_str(&v.to_string()),
            None => out.push_str("null"),
        }
    }
    out.push_str("]}");
    println!("{}", out);
    Ok(())
}

fn run_consensus_payout_root(args: &ConsensusPayoutRootArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let headers: Vec<AnchorHeader> = load_vec_decodable(&args.headers_file)?;
    let recipients = parse_hex32_list(&args.recipients)?;
    // k aus Genesis (falls vorhanden) oder CLI ableiten; Genesis hat Vorrang
    let k_eff = if let Some(ref gpath) = args.genesis {
        let g = load_genesis(gpath)?;
        let k = g.consensus.k;
        if k == 0 || k > 64 {
            bail!("invalid k in genesis: {} (must be 1..=64)", k);
        }
        println!(
            "{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}",
            k, g.commitment
        );
        k
    } else {
        if args.k == 0 || args.k > 64 {
            bail!("invalid k: {} (must be 1..=64)", args.k);
        }
        println!(
            "{{\"type\":\"k_selected\",\"k\":{},\"source\":\"cli\"}}",
            args.k
        );
        args.k
    };
    if recipients.len() != k_eff as usize {
        bail!(
            "recipients length ({}) must equal k ({})",
            recipients.len(),
            k_eff
        );
    }
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let mut cfg = ConsensusConfig::recommended(k_eff);
    if let Some(dm) = args.d_max {
        cfg.fee_params.d_max = dm;
    }
    let mut eng = ConsensusEngine::new(cfg);
    for h in headers {
        let _ = eng.insert_header(h);
    }
    let root = eng.committee_payout_root_for_ack(
        args.fees,
        &recipients,
        args.proposer_index,
        AnchorId(ack),
    )?;
    println!("{}", hex::encode(root));
    Ok(())
}

#[derive(Debug, Clone, Args)]
struct ConsensusAckDistsArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    genesis: Option<String>,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
}

#[derive(Debug, Clone, Args)]
struct ConsensusPayoutRootArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert) – muss Länge k haben
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: usize,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    genesis: Option<String>,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
}

#[derive(Debug, Clone, Args, Default)]
struct RateArgs {
    /// HeaderAnnounce Bucket-Kapazität
    #[arg(long)]
    hdr_capacity: Option<u32>,
    /// HeaderAnnounce Tokens pro Sekunde
    #[arg(long)]
    hdr_refill_per_sec: Option<u32>,
    /// PayloadInv Bucket-Kapazität
    #[arg(long)]
    inv_capacity: Option<u32>,
    /// PayloadInv Tokens pro Sekunde
    #[arg(long)]
    inv_refill_per_sec: Option<u32>,
    /// Req Bucket-Kapazität
    #[arg(long)]
    req_capacity: Option<u32>,
    /// Req Tokens pro Sekunde
    #[arg(long)]
    req_refill_per_sec: Option<u32>,
    /// Resp Bucket-Kapazität
    #[arg(long)]
    resp_capacity: Option<u32>,
    /// Resp Tokens pro Sekunde
    #[arg(long)]
    resp_refill_per_sec: Option<u32>,
    /// Per-Peer-Limits aktivieren (true/false)
    #[arg(long)]
    per_peer: Option<bool>,
    /// TTL für per-Peer Rate-Limiter in Sekunden (Cleanup), 0 = Default
    #[arg(long)]
    peer_ttl_secs: Option<u64>,
}

fn rate_cfg_opt(r: &RateArgs) -> Option<RateLimitConfig> {
    let any = r.hdr_capacity.is_some()
        || r.hdr_refill_per_sec.is_some()
        || r.inv_capacity.is_some()
        || r.inv_refill_per_sec.is_some()
        || r.req_capacity.is_some()
        || r.req_refill_per_sec.is_some()
        || r.resp_capacity.is_some()
        || r.resp_refill_per_sec.is_some()
        || r.per_peer.is_some()
        || r.peer_ttl_secs.is_some();
    if !any {
        return None;
    }
    Some(RateLimitConfig {
        hdr_capacity: r.hdr_capacity.unwrap_or(0),
        hdr_refill_per_sec: r.hdr_refill_per_sec.unwrap_or(0),
        inv_capacity: r.inv_capacity.unwrap_or(0),
        inv_refill_per_sec: r.inv_refill_per_sec.unwrap_or(0),
        req_capacity: r.req_capacity.unwrap_or(0),
        req_refill_per_sec: r.req_refill_per_sec.unwrap_or(0),
        resp_capacity: r.resp_capacity.unwrap_or(0),
        resp_refill_per_sec: r.resp_refill_per_sec.unwrap_or(0),
        per_peer: r.per_peer.unwrap_or(true),
        peer_ttl_secs: r.peer_ttl_secs.unwrap_or(0),
    })
}

#[derive(Debug, Clone, Args)]
struct P2pInjectHeadersArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    cert_file: String,
    /// Datei mit Vec<AnchorHeader> (pc-codec)
    #[arg(long)]
    headers_file: String,
}

#[derive(Debug, Clone, Args)]
struct P2pInjectPayloadsArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    cert_file: String,
    /// Datei mit Vec<AnchorPayload> (pc-codec)
    #[arg(long)]
    payloads_file: String,
    /// Zusätzlich zur Inventory die Payloads direkt mitsenden (RespMsg::Payloads)
    #[arg(long, default_value_t = false)]
    with_payloads: bool,
}

#[derive(Debug, Clone, Args)]
struct P2pQuicListenArgs {
    /// QUIC Listen-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Optional: schreibe Zertifikat (DER) in Datei
    #[arg(long)]
    cert_out: Option<String>,
    /// Pfad zu einer TOML-Konfigurationsdatei (optional)
    #[arg(long)]
    config: Option<String>,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    genesis: Option<String>,
    /// Persistenz-Verzeichnis für Headers/Payloads (wird angelegt)
    #[arg(long, default_value = "pc-data")]
    store_dir: String,
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true)
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// Committee-Größe k (1..=64) für ConsensusEngine
    #[arg(long, default_value_t = 21)]
    k: u8,
    /// Header-Cache-Kapazität (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    cache_hdr_cap: Option<usize>,
    /// Payload-Cache-Kapazität (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    cache_pl_cap: Option<usize>,
    /// Rate-Limits (optional)
    #[command(flatten)]
    rate: RateArgs,
    /// Aktiviere einfachen PoW-Miner für Mint-Emission (Dev)
    #[arg(long, default_value_t = false)]
    pow_miner: bool,
    /// Mint-Amount (in kleinster Einheit)
    #[arg(long)]
    mint_amount: Option<u64>,
    /// Payout-Lock (32-Byte Hex Commitment)
    #[arg(long)]
    mint_lock: Option<String>,
    /// Aktiviere Tx-Proposer: baut periodisch Payloads aus Mempool-TXs und announced sie
    #[arg(long, default_value_t = false)]
    tx_proposer: bool,
    /// Intervall für Tx-Proposer in Millisekunden
    #[arg(long, default_value_t = 5000)]
    tx_proposer_interval_ms: u64,
    /// Max. Anzahl MicroTxs pro Payload (Default: MAX_PAYLOAD_MICROTX)
    #[arg(long)]
    txs_per_payload: Option<usize>,
    /// Optionales Payload-Größenbudget (Bytes, encoded_len Summe); übersteigt Auswahl nicht diesen Wert
    #[arg(long)]
    payload_budget_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    consensus: Option<ConsensusCfg>,
    node: Option<NodeSection>,
}

#[derive(Debug, Deserialize)]
struct ConsensusCfg {
    k: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct NodeSection {
    cache: Option<CacheCfg>,
}

#[derive(Debug, Deserialize)]
struct CacheCfg {
    header_cap: Option<usize>,
    payload_cap: Option<usize>,
}

fn load_node_config(path: &str) -> Result<NodeConfig> {
    let s = std::fs::read_to_string(path).map_err(|e| anyhow!("read config '{}': {}", path, e))?;
    let cfg: NodeConfig =
        toml::from_str(&s).map_err(|e| anyhow!("parse toml '{}': {}", path, e))?;
    Ok(cfg)
}

#[derive(Debug, Deserialize)]
struct Genesis {
    consensus: GenesisConsensus,
    genesis_note: String,
    commitment: String,
}

#[derive(Debug, Deserialize)]
struct GenesisConsensus {
    k: u8,
    // Optional: PoW-Difficulty in führenden Nullbits für Mint-PoW
    pow_bits: Option<u8>,
}

fn load_genesis(path: &str) -> Result<Genesis> {
    let s = std::fs::read_to_string(path).map_err(|e| anyhow!("read genesis '{}': {}", path, e))?;
    let g: Genesis = toml::from_str(&s).map_err(|e| anyhow!("parse toml '{}': {}", path, e))?;
    // Validierung: commitment == blake3_32(genesis_note)
    let note = parse_hex32(&g.genesis_note)?;
    let got = blake3_32(&note);
    let want = parse_hex32(&g.commitment)?;
    if got != want {
        bail!(
            "genesis commitment mismatch: computed={}, expected={}",
            hex::encode(got),
            g.commitment
        );
    }
    Ok(g)
}

#[derive(Debug, Clone, Args)]
struct P2pQuicConnectArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    cert_file: String,
    /// Rate-Limits (optional)
    #[command(flatten)]
    rate: RateArgs,
}

fn run_p2p_run(args: &P2pRunArgs) -> Result<()> {
    // Runtime erstellen
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::P2pConfig;
        let cfg = P2pConfig {
            max_peers: args.max_peers,
            rate: rate_cfg_opt(&args.rate),
        };
        // Libp2p-Swarm + interner Service starten
        let lp2p_cfg = pc_p2p::Libp2pConfig::default();
        let (svc, svc_handle, swarm_handle) = pc_p2p::spawn_with_libp2p(cfg, lp2p_cfg)
            .map_err(|e| anyhow!("spawn_with_libp2p failed: {e:?}"))?;

        // Inbound-Observer für Ausgabe nutzen
        let mut rx_in = inbound_subscribe();
        let print_task = tokio::spawn(async move {
            loop {
                match rx_in.recv().await {
                    Ok(msg) => {
                        print_p2p_json(&msg);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        // Warte auf Ctrl-C und stoppe dann
        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = print_task.await;
        let res = svc_handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))?;
        let _ = swarm_handle.await;
        Ok(())
    })
}

fn read_hex32_files_in(dir: &std::path::Path, max_n: usize) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if let Some(name) = p.file_stem().and_then(|s| s.to_str()) {
            if name.len() == 64 {
                // 32 bytes hex
                if let Ok(bytes) = hex::decode(name) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        out.push(arr);
                        if out.len() >= max_n {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

fn run_cache_bench(args: &CacheBenchArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = FileStore::open(&args.store_dir, args.fsync)?;
        let delegate = NodeDiskStore::new(store, args.cache_hdr_cap, args.cache_pl_cap);
        let start_hits_hdr = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
        let start_miss_hdr = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
        let start_hits_pl = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
        let start_miss_pl = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
        let t0 = Instant::now();
        match args.mode.as_str() {
            "headers" => {
                let ids = read_hex32_files_in(&std::path::Path::new(&args.store_dir).join("headers"), args.sample)?
                    .into_iter().map(AnchorId).collect::<Vec<_>>();
                if ids.is_empty() { bail!("no headers found in store_dir"); }
                for _ in 0..args.iterations {
                    let _ = delegate.get_headers(&ids).await;
                }
            }
            "payloads" => {
                let roots = read_hex32_files_in(&std::path::Path::new(&args.store_dir).join("payloads"), args.sample)?;
                if roots.is_empty() { bail!("no payloads found in store_dir"); }
                for _ in 0..args.iterations {
                    let _ = delegate.get_payloads(&roots).await;
                }
            }
            other => { bail!("invalid mode: {} (use 'headers' or 'payloads')", other); }
        }
        let elapsed = t0.elapsed();
        let end_hits_hdr = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
        let end_miss_hdr = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
        let end_hits_pl = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
        let end_miss_pl = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
        let dh_hdr = end_hits_hdr.saturating_sub(start_hits_hdr);
        let dm_hdr = end_miss_hdr.saturating_sub(start_miss_hdr);
        let dh_pl = end_hits_pl.saturating_sub(start_hits_pl);
        let dm_pl = end_miss_pl.saturating_sub(start_miss_pl);
        println!(
            "{{\"type\":\"cache_bench\",\"mode\":\"{}\",\"sample\":{},\"iterations\":{},\"hdr_hits\":{},\"hdr_misses\":{},\"pl_hits\":{},\"pl_misses\":{},\"elapsed_ms\":{}}}",
            args.mode, args.sample, args.iterations, dh_hdr, dm_hdr, dh_pl, dm_pl, elapsed.as_millis()
        );
        Ok::<(), anyhow::Error>(())
    })
}

fn run_p2p_metrics() -> Result<()> {
    let m = metrics_snapshot();
    let n_hdr = NODE_PERSIST_HEADERS_TOTAL.load(Ordering::Relaxed);
    let n_hdr_err = NODE_PERSIST_HEADERS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_pl = NODE_PERSIST_PAYLOADS_TOTAL.load(Ordering::Relaxed);
    let n_pl_err = NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_lag = NODE_INBOUND_OBS_LAGGED_TOTAL.load(Ordering::Relaxed);
    println!(
        "{{\"inbound_total\":{},\"inbound_dropped_rate\":{},\"outbound_total\":{},\"peer_rl_purged_total\":{},\"in_hdr_total\":{},\"in_inv_total\":{},\"in_req_total\":{},\"in_resp_total\":{},\"out_hdr_total\":{},\"out_inv_total\":{},\"out_req_total\":{},\"out_resp_total\":{},\"out_errors_total\":{},\"outbox_enq_total\":{},\"outbox_deq_total\":{},\"in_handle_count\":{},\"in_handle_sum_micros\":{},\"in_bucket_le_1ms\":{},\"in_bucket_le_5ms\":{},\"in_bucket_le_10ms\":{},\"in_bucket_le_50ms\":{},\"in_bucket_le_100ms\":{},\"in_bucket_le_500ms\":{},\"node_persist_headers_total\":{},\"node_persist_headers_errors_total\":{},\"node_persist_payloads_total\":{},\"node_persist_payloads_errors_total\":{},\"node_inbound_obs_lagged_total\":{}}}",
        m.inbound_total,
        m.inbound_dropped_rate,
        m.outbound_total,
        m.peer_rl_purged_total,
        m.in_hdr_total,
        m.in_inv_total,
        m.in_req_total,
        m.in_resp_total,
        m.out_hdr_total,
        m.out_inv_total,
        m.out_req_total,
        m.out_resp_total,
        m.out_errors_total,
        m.outbox_enq_total,
        m.outbox_deq_total,
        m.in_handle_count,
        m.in_handle_sum_micros,
        m.in_bucket_le_1ms,
        m.in_bucket_le_5ms,
        m.in_bucket_le_10ms,
        m.in_bucket_le_50ms,
        m.in_bucket_le_100ms,
        m.in_bucket_le_500ms,
        n_hdr,
        n_hdr_err,
        n_pl,
        n_pl_err,
        n_lag
    );
    Ok(())
}

fn run_p2p_metrics_serve(args: &MetricsServeArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = args.addr.parse().map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let make_svc = make_service_fn(|_conn| async move {
            Ok::<_, anyhow::Error>(service_fn(|req: Request<Body>| async move {
                if req.uri().path() != "/metrics" {
                    let mut resp = Response::builder()
                        .status(404)
                        .body(Body::from("Not Found"))
                        .unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain"));
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
                let n_hdr = NODE_PERSIST_HEADERS_TOTAL.load(Ordering::Relaxed);
                let n_hdr_err = NODE_PERSIST_HEADERS_ERRORS_TOTAL.load(Ordering::Relaxed);
                let n_pl = NODE_PERSIST_PAYLOADS_TOTAL.load(Ordering::Relaxed);
                let n_pl_err = NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.load(Ordering::Relaxed);
                let n_lag = NODE_INBOUND_OBS_LAGGED_TOTAL.load(Ordering::Relaxed);
                // Node-Store Read Latenzen
                let hdr_cnt = NODE_STORE_HDR_READ_COUNT.load(Ordering::Relaxed);
                let hdr_sum_sec = (NODE_STORE_HDR_READ_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
                let h1 = NODE_STORE_HDR_BUCKET_LE_1MS.load(Ordering::Relaxed);
                let h5 = h1 + NODE_STORE_HDR_BUCKET_LE_5MS.load(Ordering::Relaxed);
                let h10 = h5 + NODE_STORE_HDR_BUCKET_LE_10MS.load(Ordering::Relaxed);
                let h50 = h10 + NODE_STORE_HDR_BUCKET_LE_50MS.load(Ordering::Relaxed);
                let h100 = h50 + NODE_STORE_HDR_BUCKET_LE_100MS.load(Ordering::Relaxed);
                let h500 = h100 + NODE_STORE_HDR_BUCKET_LE_500MS.load(Ordering::Relaxed);

                let pl_cnt = NODE_STORE_PL_READ_COUNT.load(Ordering::Relaxed);
                let pl_sum_sec = (NODE_STORE_PL_READ_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
                let p1 = NODE_STORE_PL_BUCKET_LE_1MS.load(Ordering::Relaxed);
                let p5 = p1 + NODE_STORE_PL_BUCKET_LE_5MS.load(Ordering::Relaxed);
                let p10 = p5 + NODE_STORE_PL_BUCKET_LE_10MS.load(Ordering::Relaxed);
                let p50 = p10 + NODE_STORE_PL_BUCKET_LE_50MS.load(Ordering::Relaxed);
                let p100 = p50 + NODE_STORE_PL_BUCKET_LE_100MS.load(Ordering::Relaxed);
                let p500 = p100 + NODE_STORE_PL_BUCKET_LE_500MS.load(Ordering::Relaxed);
                let cache_hdr_hit = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
                let cache_hdr_miss = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
                let cache_pl_hit = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
                let cache_pl_miss = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
                // Mempool-Kennzahlen
                let mp_size = NODE_MEMPOOL_SIZE.load(Ordering::Relaxed);
                let mp_acc = NODE_MEMPOOL_ACCEPTED_TOTAL.load(Ordering::Relaxed);
                let mp_rej = NODE_MEMPOOL_REJECTED_TOTAL.load(Ordering::Relaxed);
                let mp_dup = NODE_MEMPOOL_DUPLICATE_TOTAL.load(Ordering::Relaxed);
                let mp_ttl = NODE_MEMPOOL_TTL_EVICT_TOTAL.load(Ordering::Relaxed);
                let mp_cap = NODE_MEMPOOL_CAP_EVICT_TOTAL.load(Ordering::Relaxed);
                let mp_invld = NODE_MEMPOOL_INVALIDATED_TOTAL.load(Ordering::Relaxed);
                let prop_built = NODE_PROPOSER_BUILT_TOTAL.load(Ordering::Relaxed);
                let prop_last = NODE_PROPOSER_LAST_SIZE.load(Ordering::Relaxed);
                let prop_err = NODE_PROPOSER_ERRORS_TOTAL.load(Ordering::Relaxed);
                let prop_pending = NODE_PROPOSER_PENDING.load(Ordering::Relaxed);
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
                // Node-Metriken (Persistenz/Observer-Lag/Cache) anhängen
                let node_metrics = format!(
                    "# HELP pc_node_persist_headers_total Total persisted headers\n# TYPE pc_node_persist_headers_total counter\npc_node_persist_headers_total {}\n\
# HELP pc_node_persist_headers_errors_total Total errors persisting headers\n# TYPE pc_node_persist_headers_errors_total counter\npc_node_persist_headers_errors_total {}\n\
# HELP pc_node_persist_payloads_total Total persisted payloads\n# TYPE pc_node_persist_payloads_total counter\npc_node_persist_payloads_total {}\n\
# HELP pc_node_persist_payloads_errors_total Total errors persisting payloads\n# TYPE pc_node_persist_payloads_errors_total counter\npc_node_persist_payloads_errors_total {}\n\
# HELP pc_node_inbound_obs_lagged_total Total dropped messages in node inbound observer due to lag\n# TYPE pc_node_inbound_obs_lagged_total counter\npc_node_inbound_obs_lagged_total {}\n\
# HELP pc_node_cache_headers_hits_total Cache hits for headers\n# TYPE pc_node_cache_headers_hits_total counter\npc_node_cache_headers_hits_total {}\n\
# HELP pc_node_cache_headers_misses_total Cache misses for headers\n# TYPE pc_node_cache_headers_misses_total counter\npc_node_cache_headers_misses_total {}\n\
# HELP pc_node_cache_payloads_hits_total Cache hits for payloads\n# TYPE pc_node_cache_payloads_hits_total counter\npc_node_cache_payloads_hits_total {}\n\
# HELP pc_node_cache_payloads_misses_total Cache misses for payloads\n# TYPE pc_node_cache_payloads_misses_total counter\npc_node_cache_payloads_misses_total {}\n\
# HELP pc_node_store_header_read_seconds Node store header read latency\n# TYPE pc_node_store_header_read_seconds histogram\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_store_header_read_seconds_sum {}\n\
pc_node_store_header_read_seconds_count {}\n\
# HELP pc_node_store_payload_read_seconds Node store payload read latency\n# TYPE pc_node_store_payload_read_seconds histogram\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_store_payload_read_seconds_sum {}\n\
pc_node_store_payload_read_seconds_count {}\n\
# HELP pc_node_mempool_size Current mempool size\n# TYPE pc_node_mempool_size gauge\npc_node_mempool_size {}\n\
# HELP pc_node_mempool_accepted_total Total accepted txs into mempool\n# TYPE pc_node_mempool_accepted_total counter\npc_node_mempool_accepted_total {}\n\
# HELP pc_node_mempool_rejected_total Total rejected txs (stateless invalid)\n# TYPE pc_node_mempool_rejected_total counter\npc_node_mempool_rejected_total {}\n\
# HELP pc_node_mempool_duplicate_total Total duplicate txs ignored\n# TYPE pc_node_mempool_duplicate_total counter\npc_node_mempool_duplicate_total {}\n\
# HELP pc_node_mempool_ttl_evict_total Total mempool evictions due to TTL\n# TYPE pc_node_mempool_ttl_evict_total counter\npc_node_mempool_ttl_evict_total {}\n\
# HELP pc_node_mempool_cap_evict_total Total mempool evictions due to cap limit\n# TYPE pc_node_mempool_cap_evict_total counter\npc_node_mempool_cap_evict_total {}\n\
# HELP pc_node_mempool_invalidated_total Total mempool txs invalidated by finalized state\n# TYPE pc_node_mempool_invalidated_total counter\npc_node_mempool_invalidated_total {}\n\
# HELP pc_node_proposer_built_total Total payloads built by proposer\n# TYPE pc_node_proposer_built_total counter\npc_node_proposer_built_total {}\n\
# HELP pc_node_proposer_last_size Last built payload micro_txs count\n# TYPE pc_node_proposer_last_size gauge\npc_node_proposer_last_size {}\n\
# HELP pc_node_proposer_errors_total Total proposer errors\n# TYPE pc_node_proposer_errors_total counter\npc_node_proposer_errors_total {}\n\
# HELP pc_node_proposer_pending Current pending payloads awaiting finalization\n# TYPE pc_node_proposer_pending gauge\npc_node_proposer_pending {}\n",
                    n_hdr, n_hdr_err, n_pl, n_pl_err, n_lag,
                    cache_hdr_hit, cache_hdr_miss, cache_pl_hit, cache_pl_miss,
                    h1, h5, h10, h50, h100, h500, hdr_cnt, hdr_sum_sec, hdr_cnt,
                    p1, p5, p10, p50, p100, p500, pl_cnt, pl_sum_sec, pl_cnt,
                    mp_size, mp_acc, mp_rej, mp_dup,
                    mp_ttl, mp_cap, mp_invld, prop_built, prop_last, prop_err, prop_pending
                );
                let body = format!("{}{}", body, node_metrics);
                let mut resp = Response::new(Body::from(body));
                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"));
                Ok::<_, anyhow::Error>(resp)
            }))
        });
        let server = Server::bind(&addr).serve(make_svc);
        println!("{{\"type\":\"metrics_serve\",\"addr\":\"{}\"}}", addr);
        let graceful = server.with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        graceful.await.map_err(|e| anyhow!("metrics server error: {e}"))
    })
}

fn run_da_run(args: &DaRunArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_da::async_svc as da_async;
        use pc_da::DaConfig;
        let cfg = DaConfig {
            max_chunks: args.max_chunks,
        };
        let (svc, handle) = da_async::spawn(cfg);
        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let res = handle
            .await
            .map_err(|e| anyhow!("da task join error: {e}"))?;
        res.map_err(|e| anyhow!("da loop error: {e}"))
    })
}

fn run_graph_insert_and_ack(args: &GraphInsertAndAckArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    // Datei laden
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let mut slice = &buf[..];
    let headers: Vec<AnchorHeader> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;

    let d_max = args
        .d_max
        .unwrap_or_else(|| FeeSplitParams::recommended().d_max);

    let mut cache = AnchorGraphCache::new();
    for h in headers {
        let _ = cache.insert(h);
    }
    let dists = cache.compute_ack_distances(AnchorId(ack), args.k, d_max);

    // Optional Committee-Payout-Root
    let mut payout_root_hex: Option<String> = None;
    if let (Some(fees), Some(prop_idx)) = (args.fees, args.proposer_index) {
        if !args.recipients.is_empty() {
            let recipients = parse_hex32_list(&args.recipients)?;
            if recipients.len() != args.k as usize {
                bail!(
                    "recipients length ({}) must equal k ({})",
                    recipients.len(),
                    args.k
                );
            }
            if prop_idx >= recipients.len() {
                bail!(
                    "proposer_index {} out of range (k={})",
                    prop_idx,
                    recipients.len()
                );
            }
            let params = FeeSplitParams::recommended();
            let set = compute_committee_payout(fees, &params, &recipients, prop_idx, &dists)
                .map_err(|e| anyhow!("committee payout failed: {e}"))?;
            payout_root_hex = Some(hex::encode(set.payout_root()));
        }
    }

    // JSON-Ausgabe
    print!("{{\"k\":{},\"d_max\":{},\"distances\":[", args.k, d_max);
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        match d {
            Some(v) => print!("{}", v),
            None => print!("null"),
        }
    }
    if let Some(root) = payout_root_hex {
        println!("],\"committee_payout_root\":\"{}\"}}", root);
    } else {
        println!("]}}");
    }
    Ok(())
}

#[derive(Debug, Clone, Args)]
struct GraphInsertAndAckArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
    /// Optional: Gesamt-Gebühren (wenn gesetzt, wird Committee-Payout-Root berechnet)
    #[arg(long)]
    fees: Option<u64>,
    /// Optional: Recipients (32-Byte Hex, komma-separiert) – muss Länge k haben
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Optional: Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: Option<usize>,
}

#[derive(Debug, Clone, Args)]
struct GraphAckArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
}

#[derive(Debug, Clone, Args)]
struct P2pRunArgs {
    /// Maximale Anzahl Peers
    #[arg(long, default_value_t = 128)]
    max_peers: u16,
    /// Rate-Limits (optional)
    #[command(flatten)]
    rate: RateArgs,
}

#[derive(Debug, Clone, Args)]
struct DaRunArgs {
    /// Maximale Anzahl Chunks im DA-Service
    #[arg(long, default_value_t = 4096)]
    max_chunks: u32,
}

fn load_vec_decodable<T: pc_codec::Decodable>(path: &str) -> Result<Vec<T>> {
    let mut f =
        std::fs::File::open(path).map_err(|e| anyhow!("cannot open file '{}': {e}", path))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read file '{}': {e}", path))?;
    let mut slice = &buf[..];
    let v: Vec<T> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec: {e}"))?;
    Ok(v)
}

fn run_build_payload(args: &BuildPayloadArgs) -> Result<()> {
    // Events ggf. laden
    let mut micro_txs: Vec<MicroTx> = if let Some(p) = &args.microtx_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    // Optional: Mempool lesen und anhängen (deterministisch sortieren, deduplizieren, cap)
    if args.from_mempool {
        let base = args
            .store_dir
            .clone()
            .unwrap_or_else(|| "pc-data".to_string());
        let mp_dir = std::path::Path::new(&base).join("mempool");
        if let Ok(rd) = std::fs::read_dir(&mp_dir) {
            for ent in rd.flatten() {
                if let Ok(meta) = ent.metadata() {
                    if !meta.is_file() {
                        continue;
                    }
                }
                if let Ok(mut f) = std::fs::File::open(ent.path()) {
                    let mut buf = Vec::new();
                    use std::io::Read as _;
                    if f.read_to_end(&mut buf).is_ok() {
                        let mut s = &buf[..];
                        if let Ok(tx) = MicroTx::decode(&mut s) {
                            if validate_microtx_sanity(&tx).is_ok() {
                                micro_txs.push(tx);
                            }
                        }
                    }
                }
            }
        }
        // Dedupe + Sort + Cap
        use std::collections::HashSet;
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut uniq: Vec<MicroTx> = Vec::with_capacity(micro_txs.len());
        for tx in micro_txs.into_iter() {
            let id = digest_microtx(&tx);
            if seen.insert(id) {
                uniq.push(tx);
            }
        }
        uniq.sort_unstable_by(|a, b| digest_microtx(a).cmp(&digest_microtx(b)));
        if uniq.len() > MAX_PAYLOAD_MICROTX {
            uniq.truncate(MAX_PAYLOAD_MICROTX);
        }
        micro_txs = uniq;
    }
    let mints: Vec<MintEvent> = if let Some(p) = &args.mints_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    let claims: Vec<ClaimEvent> = if let Some(p) = &args.claims_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    let evidences: Vec<EvidenceEvent> = if let Some(p) = &args.evidences_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };

    // Payout-Root bestimmen
    let payout_root = if let Some(payout_path) = &args.payout_file {
        let entries: Vec<PayoutEntry> = load_vec_decodable(payout_path)?;
        let set = PayoutSet { entries };
        set.payout_root()
    } else {
        // via Fees/Recipients/Acks/Attestors
        let fees = args
            .fees
            .ok_or_else(|| anyhow!("missing --fees when --payout_file is not provided"))?;
        let proposer_index = args.proposer_index.ok_or_else(|| {
            anyhow!("missing --proposer-index when --payout_file is not provided")
        })?;
        let recipients = parse_hex32_list(&args.recipients)?;
        let acks = parse_acks(&args.acks)?;
        let attestors = parse_hex32_list(&args.attestors)?;
        if recipients.len() != acks.len() {
            bail!(
                "recipients ({}) and acks ({}) length mismatch",
                recipients.len(),
                acks.len()
            );
        }
        if proposer_index >= recipients.len() {
            bail!(
                "proposer_index {} out of range (k={})",
                proposer_index,
                recipients.len()
            );
        }
        let params = FeeSplitParams::recommended();
        compute_total_payout_root(
            fees,
            &params,
            &recipients,
            proposer_index,
            &acks,
            &attestors,
        )?
    };

    let payload = AnchorPayload {
        version: 1,
        micro_txs,
        mints,
        claims,
        evidences,
        payout_root,
    };
    let root = compute_payload_hash(&payload);
    println!("{}", hex::encode(root));
    if let Some(out) = &args.out_file {
        let mut buf = Vec::with_capacity(payload.encoded_len());
        payload
            .encode(&mut buf)
            .map_err(|e| anyhow!("encode payload failed: {e}"))?;
        std::fs::write(out, &buf).map_err(|e| anyhow!("write out_file failed: {e}"))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Args)]
struct BuildPayloadArgs {
    /// Datei mit Vec<MicroTx> (pc-codec)
    #[arg(long)]
    microtx_file: Option<String>,
    /// Optional: auch aus dem Mempool lesen (store_dir/mempool)
    #[arg(long, default_value_t = false)]
    from_mempool: bool,
    /// Basisverzeichnis für Mempool/UTXO/Store
    #[arg(long)]
    store_dir: Option<String>,
    /// Datei mit Vec<MintEvent> (pc-codec)
    #[arg(long)]
    mints_file: Option<String>,
    /// Datei mit Vec<ClaimEvent> (pc-codec)
    #[arg(long)]
    claims_file: Option<String>,
    /// Datei mit Vec<EvidenceEvent> (pc-codec)
    #[arg(long)]
    evidences_file: Option<String>,
    /// Datei mit Vec<PayoutEntry> (pc-codec); alternativ fees/recipients/acks/attestors verwenden
    #[arg(long)]
    payout_file: Option<String>,

    /// Falls keine payout_file: Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: Option<u64>,
    /// Falls keine payout_file: Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Falls keine payout_file: Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: Option<usize>,
    /// Falls keine payout_file: Ack-Distanzen (z. B. "1,2,none,4"; gleiche Länge wie recipients)
    #[arg(long, value_delimiter = ',')]
    acks: Vec<String>,
    /// Falls keine payout_file: Attestors (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    attestors: Vec<String>,

    /// Optional: schreibe AnchorPayload (pc-codec) in Datei
    #[arg(long)]
    out_file: Option<String>,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "phantom-node",
    version,
    about = "PhantomCoin Fullnode/Validator/Miner",
    disable_help_subcommand = true
)]
struct NodeOpts {
    /// Aktiviere Fullnode-Rolle
    #[arg(long, default_value_t = true)]
    fullnode: bool,
    /// Aktiviere Validator-Rolle (benötigt später Seat-Key/HSM)
    #[arg(long, default_value_t = false)]
    validator: bool,
    /// Aktiviere Miner-Worker (PoW nur für Emission)
    #[arg(long, default_value_t = false)]
    miner: bool,
    /// Dienstprogramme
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Berechne die finale Payout-Merkle-Root (Committee + Attestors)
    PayoutRoot(PayoutArgs),
    /// Berechne die Committee-Payout-Root aus Header-Datei und ack_id
    CommitteePayoutFromHeaders(CommitteePayoutHeadersArgs),
    /// Baue einen AnchorPayload aus Event-Dateien oder Parametern
    BuildPayload(BuildPayloadArgs),
    /// Berechne Ack-Distanzen aus einer Header-Datei für eine gegebene ack_id
    GraphAck(GraphAckArgs),
    /// Füge Header in einen In-Memory DAG (AnchorGraphCache) ein und berechne Ack-Distanzen; optional Committee-Payout-Root
    GraphInsertAndAck(GraphInsertAndAckArgs),
    /// Starte den P2P-Service (Tokio-basiert); beendet mit Ctrl-C
    P2pRun(P2pRunArgs),
    /// Starte den DA-Service (Tokio-basiert); beendet mit Ctrl-C
    DaRun(DaRunArgs),
    /// Starte QUIC-Listener, gibt cert_der (Hex) aus und broadcastet P2P-Messages an Clients; beendet mit Ctrl-C
    P2pQuicListen(P2pQuicListenArgs),
    /// Verbinde zu QUIC-Server, forwarde lokale P2P-Outbox an Remote und verarbeite eingehende Nachrichten; beendet mit Ctrl-C
    P2pQuicConnect(P2pQuicConnectArgs),
    /// Injiziere Header-Announce-Messages über QUIC in einen Remote-Knoten
    P2pInjectHeaders(P2pInjectHeadersArgs),
    /// Injiziere Payload-Inventory (und optional Payloads) über QUIC in einen Remote-Knoten
    P2pInjectPayloads(P2pInjectPayloadsArgs),
    /// Gib aktuelle P2P-Metriken als JSON auf stdout aus
    P2pMetrics,
    /// Starte einen HTTP-Server, der Prometheus-kompatible Metriken liefert (Default: 127.0.0.1:9100)
    P2pMetricsServe(MetricsServeArgs),
    /// Starte einen einfachen Status-HTTP-Server (GET /status)
    StatusServe(StatusServeArgs),
    /// Konsens: Ack-Distanzen via ConsensusEngine aus Header-Datei berechnen
    ConsensusAckDists(ConsensusAckDistsArgs),
    /// Konsens: Committee-Payout-Root via ConsensusEngine berechnen
    ConsensusPayoutRoot(ConsensusPayoutRootArgs),
    /// Cache-Benchmark: misst Cache-Hits/Misses und Laufzeit gegen FileStore
    CacheBench(CacheBenchArgs),
}

#[derive(Debug, Clone, Args)]
struct MetricsServeArgs {
    /// HTTP Listen-Adresse, z. B. 127.0.0.1:9100
    #[arg(long, default_value = "127.0.0.1:9100")]
    addr: String,
}

#[derive(Debug, Clone, Args)]
struct PayoutArgs {
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: usize,
    /// Ack-Distanzen (z. B. "1,2,none,4"; muss gleiche Länge wie recipients haben)
    #[arg(long, value_delimiter = ',')]
    acks: Vec<String>,
    /// Attestors (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    attestors: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct CommitteePayoutHeadersArgs {
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: usize,
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
}

fn compute_payload_hash(payload: &AnchorPayload) -> pc_crypto::Hash32 {
    payload_merkle_root(payload)
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex for 32-byte id: {e}"))?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex32_list(v: &[String]) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::with_capacity(v.len());
    for s in v {
        out.push(parse_hex32(s)?);
    }
    Ok(out)
}

fn parse_acks(v: &[String]) -> Result<Vec<Option<u8>>> {
    let mut out = Vec::with_capacity(v.len());
    for s in v {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("none") || t == "-" {
            out.push(None);
        } else {
            out.push(Some(
                t.parse::<u8>()
                    .map_err(|e| anyhow!("invalid ack distance '{t}': {e}"))?,
            ));
        }
    }
    Ok(out)
}

fn run_payout_root(args: &PayoutArgs) -> Result<()> {
    let recipients = parse_hex32_list(&args.recipients)?;
    let acks = parse_acks(&args.acks)?;
    let attestors = parse_hex32_list(&args.attestors)?;
    if recipients.len() != acks.len() {
        bail!(
            "recipients ({}) and acks ({}) length mismatch",
            recipients.len(),
            acks.len()
        );
    }
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let params = FeeSplitParams::recommended();
    let root = compute_total_payout_root(
        args.fees,
        &params,
        &recipients,
        args.proposer_index,
        &acks,
        &attestors,
    )?;
    println!("{}", hex::encode(root));
    Ok(())
}

fn run_committee_payout_from_headers(args: &CommitteePayoutHeadersArgs) -> Result<()> {
    let recipients = parse_hex32_list(&args.recipients)?;
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let ack = parse_hex32(&args.ack_id)?;
    // Datei laden
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let mut slice = &buf[..];
    let headers: Vec<AnchorHeader> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;
    let params = FeeSplitParams::recommended();
    let set = compute_committee_payout_from_headers(
        args.fees,
        &params,
        &recipients,
        args.proposer_index,
        AnchorId(ack),
        &headers,
        recipients.len() as u8,
    )?;
    println!("{}", hex::encode(set.payout_root()));
    Ok(())
}

fn run_graph_ack(args: &GraphAckArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let mut slice = &buf[..];
    let headers: Vec<AnchorHeader> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;
    let d_max = args
        .d_max
        .unwrap_or_else(|| FeeSplitParams::recommended().d_max);
    let dists = compute_ack_distances_for_seats(AnchorId(ack), &headers, args.k, d_max);
    // JSON Ausgabe minimal, ohne externe Abhängigkeit
    print!("{{\"k\":{},\"d_max\":{},\"distances\":[", args.k, d_max);
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        match d {
            Some(v) => print!("{}", v),
            None => print!("null"),
        }
    }
    println!("]}}");
    Ok(())
}

fn print_p2p_json(msg: &P2pMessage) {
    match msg {
        P2pMessage::HeaderAnnounce(h) => {
            println!(
                "{{\"type\":\"header_announce\",\"creator\":{},\"id\":\"{}\"}}",
                h.creator_index,
                hex::encode(h.id_digest())
            );
        }
        P2pMessage::HeadersInv { ids } => {
            let mut out = String::from("{\"type\":\"headers_inv\",\"ids\":[");
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(id.0));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::PayloadInv { roots } => {
            let mut out = String::from("{\"type\":\"payload_inv\",\"roots\":[");
            for (i, r) in roots.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(r));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::TxInv { ids } => {
            let mut out = String::from("{\"type\":\"tx_inv\",\"ids\":[");
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(id));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::Req(_) => {
            println!("{{\"type\":\"req\"}}");
        }
        P2pMessage::Resp(_) => {
            println!("{{\"type\":\"resp\"}}");
        }
    }
}

fn run_p2p_quic_listen(args: &P2pQuicListenArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::P2pConfig;
        use pc_p2p::async_svc as p2p_async;
        let cfg = P2pConfig { max_peers: 256, rate: rate_cfg_opt(&args.rate) };
        let store = FileStore::open(&args.store_dir, args.fsync)?;
        println!("{{\"type\":\"store_opened\",\"dir\":\"{}\",\"fsync\":{}}}", &args.store_dir, args.fsync);
        // Cache-Kapazitäten: CLI > Config > 0
        let (cfg_hdr_cap, cfg_pl_cap) = if let Some(ref path) = args.config {
            let nc = load_node_config(path)?;
            let h = nc.node.as_ref().and_then(|n| n.cache.as_ref()).and_then(|c| c.header_cap).unwrap_or(0);
            let p = nc.node.as_ref().and_then(|n| n.cache.as_ref()).and_then(|c| c.payload_cap).unwrap_or(0);
            (h, p)
        } else { (0usize, 0usize) };
        let hdr_cap_eff = args.cache_hdr_cap.unwrap_or(cfg_hdr_cap);
        let pl_cap_eff = args.cache_pl_cap.unwrap_or(cfg_pl_cap);
        let delegate = NodeDiskStore::new(store, hdr_cap_eff, pl_cap_eff);
        let (svc, mut out_rx, handle) = p2p_async::spawn_with_store(cfg, Arc::new(delegate));
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let (_endpoint, cert_der, server_task, tx_broadcast) = start_server(addr, svc.clone())
            .await
            .map_err(|e| anyhow!("quic start_server failed: {e}"))?;
        println!(
            "{{\"type\":\"quic_listen\",\"addr\":\"{}\",\"cert_der\":\"{}\"}}",
            addr,
            hex::encode(&cert_der)
        );
        if let Some(path) = &args.cert_out {
            std::fs::write(path, &cert_der).map_err(|e| anyhow!("write cert_out failed: {e}"))?;
            println!("{{\"type\":\"cert_written\",\"path\":\"{}\"}}", path);
        }

        let tx_b = tx_broadcast.clone();
        let forward_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                outbox_deq_inc();
                print_p2p_json(&msg);
                let _ = tx_b.send(msg).await;
            }
            Ok::<(), anyhow::Error>(())
        });

        // pow_bits aus Genesis (falls vorhanden), sonst Default
        let pow_bits_eff: u8 = if let Some(ref gpath) = args.genesis {
            let g = load_genesis(gpath)?;
            let b = g.consensus.pow_bits.unwrap_or(consts::POW_DEFAULT_BITS);
            if (b as u16) > 256 { return Err(anyhow!("invalid pow_bits in genesis: {} (must be 0..=256)", b)); }
            println!("{{\"type\":\"pow_bits\",\"bits\":{}}}", b);
            b
        } else { consts::POW_DEFAULT_BITS };

        // Optional: Dev-PoW-Miner für Mint-Emission (nur im Listen-Server sinnvoll)
        if args.pow_miner {
            let svc_miner = svc.clone();
            let tx_inv = tx_broadcast.clone();
            let amount = args.mint_amount.ok_or_else(|| anyhow!("--pow_miner requires --mint_amount"))?;
            let lock = if let Some(l) = &args.mint_lock { LockCommitment(parse_hex32(l)?) } else { return Err(anyhow!("--pow_miner requires --mint_lock")); };
            let bits = pow_bits_eff;
            tokio::spawn(async move {
                let mut prev_mint_id = [0u8;32];
                let mut seed_ctr: u64 = 0;
                loop {
                    let mut buf = Vec::with_capacity(32 + 8);
                    buf.extend_from_slice(&prev_mint_id);
                    buf.extend_from_slice(&seed_ctr.to_be_bytes());
                    let seed = blake3_32(&buf);
                    seed_ctr = seed_ctr.wrapping_add(1);
                    let mut nonce: u64 = 0;
                    loop {
                        let h = pow_hash(&seed, nonce);
                        if pow_meets(bits, &h) {
                            let txout = TxOut { amount, lock };
                            let mint = MintEvent { version:1, prev_mint_id, outputs: vec![txout], pow_seed: seed, pow_nonce: nonce };
                            let payload = pc_types::AnchorPayloadV2 { version:2, micro_txs: vec![], mints: vec![mint], claims: vec![], evidences: vec![], payout_root: [0u8;32], genesis_note: None };
                            let root = pc_types::payload_merkle_root_v2(&payload);
                            let _ = svc_miner.put_payload(payload).await;
                            let _ = tx_inv.send(P2pMessage::PayloadInv { roots: vec![root] }).await;
                            prev_mint_id = h;
                            break;
                        }
                        nonce = nonce.wrapping_add(1);
                        if (nonce & 0xFFFF) == 0 { tokio::task::yield_now().await; }
                    }
                }
            });
        }

        // k aus Genesis (falls vorhanden) oder Konfig/CLI ableiten; Genesis hat Vorrang
        let k_eff = if let Some(ref gpath) = args.genesis {
            let g = load_genesis(gpath)?;
            let k = g.consensus.k;
            if k == 0 || k > 64 { return Err(anyhow!("invalid k in genesis: {} (must be 1..=64)", k)); }
            println!("{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}", k, g.commitment);
            k
        } else {
            let cfg_k = if let Some(ref path) = args.config { Some(load_node_config(path)?.consensus.and_then(|c| c.k).unwrap_or(args.k)) } else { None };
            let k = cfg_k.unwrap_or(args.k);
            if k == 0 || k > 64 { return Err(anyhow!("invalid k: {} (must be 1..=64)", k)); }
            println!("{{\"type\":\"k_selected\",\"k\":{},\"source\":\"{}\"}}", k, if args.config.is_some() { "config" } else { "cli" });
            k
        };

        

        // Konsens-Task: beobachtet Header, pflegt Graph und markiert finale Payload-Roots
        let mut rx_in = inbound_subscribe();
        let k = k_eff; // in Task bewegen
        let final_roots: Arc<tokio::sync::Mutex<HashSet<[u8;32]>>> = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let finals_for_cons = final_roots.clone();
        // Notify-Kanal für Finalisierungen an den State-Task
        let (tx_final, mut rx_final) = mpsc::unbounded_channel::<[u8;32]>();
        let tx_final_cons = tx_final.clone();
        let consensus_task = tokio::spawn(async move {
            let cfg = ConsensusConfig::recommended(k);
            let mut eng = ConsensusEngine::new(cfg);
            let finals = finals_for_cons;
            loop {
                match rx_in.recv().await {
                    Ok(P2pMessage::HeaderAnnounce(h)) => {
                        // Finalität prüfen und finalen Payload-Root merken
                        if eng.is_final_mask(h.vote_mask) {
                            let mut g = finals.lock().await;
                            let _ = g.insert(h.payload_hash);
                            let _ = tx_final_cons.send(h.payload_hash);
                        }
                        // Adapter V2->V1 für Konsens
                        let hv1 = pc_types::AnchorHeader { version:1, shard_id: h.shard_id, parents: h.parents.clone(), payload_hash: h.payload_hash, creator_index: h.creator_index, vote_mask: h.vote_mask, ack_present: h.ack_present, ack_id: h.ack_id };
                        let _ = eng.insert_header(hv1);
                    }
                    Ok(P2pMessage::Resp(RespMsg::Headers { headers })) => {
                        for h in headers {
                            if eng.is_final_mask(h.vote_mask) {
                                let mut g = finals.lock().await;
                                let _ = g.insert(h.payload_hash);
                                let _ = tx_final_cons.send(h.payload_hash);
                            }
                            let hv1 = pc_types::AnchorHeader { version:1, shard_id: h.shard_id, parents: h.parents.clone(), payload_hash: h.payload_hash, creator_index: h.creator_index, vote_mask: h.vote_mask, ack_present: h.ack_present, ack_id: h.ack_id };
                            let _ = eng.insert_header(hv1);
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => { NODE_INBOUND_OBS_LAGGED_TOTAL.fetch_add(n as u64, Ordering::Relaxed); continue; }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => { break; }
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        // State-Task: beobachtet Payload-/Tx-Responses und aktualisiert den UTXO-State deterministisch
        let mut rx_state = inbound_subscribe();
        let finals_for_state = final_roots.clone();
        // mpsc Receiver für Finalisierungen
        let _utxo_path = std::path::Path::new(&args.store_dir).join("utxo").to_string_lossy().to_string();
        let mempool_path = std::path::Path::new(&args.store_dir).join("mempool").to_string_lossy().to_string();
        let anchor_index_path = std::path::Path::new(&args.store_dir).join("anchor_index").to_string_lossy().to_string();
        // Tx-Proposer Parameter aus CLI
        let proposer_enabled = args.tx_proposer;
        let proposer_interval_ms = args.tx_proposer_interval_ms;
        let proposer_cap = args.txs_per_payload.unwrap_or(MAX_PAYLOAD_MICROTX);
        let svc_prop = svc.clone();
        let tx_b_prop = tx_broadcast.clone();
        let fsync_flag = args.fsync;
        let payload_budget = args.payload_budget_bytes;
        let state_task = tokio::spawn(async move {
            #[cfg(feature = "rocksdb")]
            let mut st = {
                let _ = std::fs::create_dir_all(&_utxo_path);
                let backend = pc_state::RocksDbBackend::open(&_utxo_path).expect("open rocksdb utxo");
                UtxoState::new_with_index(backend)
            };
            #[cfg(not(feature = "rocksdb"))]
            let mut st = UtxoState::new_with_index(InMemoryBackend::new());
            // globaler Anchor-Index für Maturity (uhrfrei, zählt final angewandte Payloads)
            let mut anchor_index: AnchorIndex = match std::fs::read_to_string(&anchor_index_path) {
                Ok(s) => s.trim().parse::<u64>().unwrap_or(0),
                Err(_) => 0,
            };
            let mut mempool: HashMap<[u8;32], (MicroTx, Instant)> = HashMap::new();
            let mut mempool_order: VecDeque<[u8;32]> = VecDeque::new();
            const MEMPOOL_MAX: usize = 65536;
            const MEMPOOL_TTL_SECS: u64 = 3600; // 1h
            let _ = std::fs::create_dir_all(&mempool_path);
            let journal_path = std::path::Path::new(&mempool_path).join("mempool.journal");
            // Bootstrap: Recovery via Journal (falls vorhanden), sonst Verzeichnis lesen
            let mut active_ids: Option<std::collections::HashSet<[u8;32]>> = None;
            if let Ok(contents) = std::fs::read_to_string(&journal_path) {
                let mut set: std::collections::HashSet<[u8;32]> = std::collections::HashSet::new();
                for line in contents.lines() {
                    if line.len() < 65 { continue; }
                    let (opch, hexid) = line.split_at(1);
                    if let Ok(bytes) = hex::decode(hexid) {
                        if bytes.len() == 32 {
                            let mut id = [0u8;32];
                            id.copy_from_slice(&bytes);
                            match opch.as_bytes()[0] {
                                b'A' => { set.insert(id); }
                                b'D' => { set.remove(&id); }
                                _ => {}
                            }
                        }
                    }
                }
                active_ids = Some(set);
            }
            if let Some(ids) = active_ids {
                // Lade nur IDs aus Journal
                for id in ids.iter() {
                    let fname = format!("{}.bin", hex::encode(id));
                    let p = std::path::Path::new(&mempool_path).join(fname);
                    if let Ok(mut f) = std::fs::File::open(&p) {
                        let mut buf = Vec::new();
                        use std::io::Read as _;
                        if f.read_to_end(&mut buf).is_ok() {
                            let mut s = &buf[..];
                            if let Ok(tx) = MicroTx::decode(&mut s) {
                                if validate_microtx_sanity(&tx).is_ok() && st.can_apply_micro_tx(&tx).is_ok() {
                                    let _ = mempool.insert(*id, (tx, Instant::now()));
                                    mempool_order.push_back(*id);
                                }
                            }
                        }
                    }
                }
                NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
            } else if let Ok(rd) = std::fs::read_dir(&mempool_path) {
                // Fallback: Verzeichnis
                let mut files: Vec<std::path::PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
                files.sort();
                for p in files {
                    if let Ok(mut f) = std::fs::File::open(&p) {
                        let mut buf = Vec::new();
                        use std::io::Read as _;
                        if f.read_to_end(&mut buf).is_ok() {
                            let mut s = &buf[..];
                            if let Ok(tx) = MicroTx::decode(&mut s) {
                                if validate_microtx_sanity(&tx).is_ok() && st.can_apply_micro_tx(&tx).is_ok() {
                                    let id = digest_microtx(&tx);
                                    let _ = mempool.insert(id, (tx, Instant::now()));
                                    mempool_order.push_back(id);
                                }
                            }
                        }
                    }
                }
                NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
            }
            // Pending-Queue Limits
            const PENDING_MAX: usize = 8192; // Obergrenze für gepufferte Payloads
            const PENDING_TTL_SECS: u64 = 600; // 10 Minuten TTL
            let mut pending: HashMap<[u8;32], (pc_types::AnchorPayloadV2, Instant)> = HashMap::new();
            let mut order: VecDeque<[u8;32]> = VecDeque::new();
            let mut tick = interval(Duration::from_secs(30));
            let mut prop_tick = interval(Duration::from_millis(proposer_interval_ms));
            loop {
                tokio::select! {
                    // Finalisierungsmeldung: versuche pending Payload anzuwenden
                    Some(root) = rx_final.recv() => {
                        if let Some((p, _ts)) = pending.remove(&root) {
                            // aus Order entfernen
                            if let Some(pos) = order.iter().position(|k| *k == root) { let _ = order.remove(pos); }
                            if let Err(e) = pc_types::validate_payload_sanity_v2(&p) { warn!(root = %hex::encode(root), err = %e, "drop pending payload: invalid"); continue; }
                            // Mint-PoW-Validierung
                            let mut mint_ok = true;
                            for m in &p.mints {
                                if validate_mint_sanity(m).is_err() || !check_mint_pow(m, pow_bits_eff) { mint_ok = false; break; }
                            }
                            if !mint_ok { warn!(root = %hex::encode(root), bits = pow_bits_eff, "drop pending payload: mint pow invalid"); continue; }
                            // final angewandt → AnchorIndex erhöhen
                            anchor_index = anchor_index.saturating_add(1);
                            // persistieren
                            { let data = anchor_index.to_string().into_bytes(); let p = std::path::Path::new(&anchor_index_path); let _ = atomic_write_async(p, data, fsync_flag).await; }
                            // Mints mit minted_at indexieren
                            for m in &p.mints { st.apply_mint_with_index(m, anchor_index); }
                            // MicroTxs mit Maturity-Schwelle L1 anwenden
                            for tx in &p.micro_txs {
                                if let Err(e) = st.apply_micro_tx_with_maturity_indexed(tx, anchor_index, consts::MATURITY_L1) {
                                    warn!(%e, "utxo apply_micro_tx_with_maturity_indexed failed (pending)");
                                }
                            }
                            // Entferne bestätigte MicroTxs aus dem Mempool (inkl. Dateien) und zähle Invalidationen
                            let mut invalidated: u64 = 0;
                            for tx in &p.micro_txs {
                                let id = digest_microtx(tx);
                                if mempool.remove(&id).is_some() {
                                    invalidated = invalidated.saturating_add(1);
                                    if let Some(pos) = mempool_order.iter().position(|k| *k == id) { let _ = mempool_order.remove(pos); }
                                    let fname = format!("{}.bin", hex::encode(id));
                                    let path = std::path::Path::new(&mempool_path).join(fname);
                                    let _ = journal_append(&journal_path, fsync_flag, b'D', &id);
                                    let _ = remove_with_dir_sync(&path, fsync_flag);
                                }
                            }
                            if invalidated > 0 { NODE_MEMPOOL_INVALIDATED_TOTAL.fetch_add(invalidated, Ordering::Relaxed); }
                            NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
                            NODE_PROPOSER_PENDING.store(pending.len() as u64, Ordering::Relaxed);
                            let r = st.root();
                            info!(root = %hex::encode(root), state_root = %hex::encode(r), "applied pending payload after finalization");
                        }
                    }
                    // Periodischer TTL-Cleanup
                    _ = tick.tick() => {
                        let now = Instant::now();
                        // Entferne abgelaufene Einträge von vorne
                        loop {
                            if let Some(front) = order.front().copied() {
                                if let Some((_, ts)) = pending.get(&front) {
                                    if now.duration_since(*ts) > Duration::from_secs(PENDING_TTL_SECS) {
                                        let _ = order.pop_front();
                                        let _ = pending.remove(&front);
                                        warn!(root = %hex::encode(front), "dropped pending payload due to TTL");
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                        NODE_PROPOSER_PENDING.store(pending.len() as u64, Ordering::Relaxed);
                        // Mempool TTL-Cleanup
                        loop {
                            if let Some(front) = mempool_order.front().copied() {
                                if let Some((_, ts)) = mempool.get(&front) {
                                    if now.duration_since(*ts) > Duration::from_secs(MEMPOOL_TTL_SECS) {
                                        let _ = mempool_order.pop_front();
                                        let _ = mempool.remove(&front);
                                        // Datei löschen
                                        let fname = format!("{}.bin", hex::encode(front));
                                        let path = std::path::Path::new(&mempool_path).join(fname);
                                        let _ = journal_append(&journal_path, fsync_flag, b'D', &front);
                                        let _ = remove_with_dir_sync(&path, fsync_flag);
                                        NODE_MEMPOOL_TTL_EVICT_TOTAL.fetch_add(1, Ordering::Relaxed);
                                        NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                        // Journal-Komprimierung bei zu großer Datei
                        if let Ok(meta) = std::fs::metadata(&journal_path) {
                            if meta.len() > 5_000_000 { // ~5 MB Schwellwert
                                let _ = rewrite_mempool_journal(&journal_path, &mempool_order, fsync_flag);
                            }
                        }
                    }
                    // Periodischer Tx-Proposer
                    _ = prop_tick.tick(), if proposer_enabled => {
                        // Proposer-Policy: bevorzugt kleine Txs, dann älter (Index aus mempool_order), ohne Konflikte/Reservierungen
                        let mut txs: Vec<MicroTx> = Vec::new();
                        let mut used: HashSet<OutPoint> = HashSet::new();
                        // Reservierte TX-IDs aus pending nicht erneut vorschlagen
                        let mut reserved_ids: HashSet<[u8;32]> = HashSet::new();
                        for (pl, _) in pending.values() { for tx in &pl.micro_txs { reserved_ids.insert(digest_microtx(tx)); } }
                        // Kandidaten sammeln mit Größe und Alter (Index) und Group-Key (LockCommitment der ersten Output)
                        let mut cands: Vec<(MicroTx, [u8;32], usize, usize, [u8;32])> = Vec::new();
                        for (idx, id) in mempool_order.iter().enumerate() {
                            if let Some((tx, _ts)) = mempool.get(id) {
                                let tx_id = digest_microtx(tx);
                                if reserved_ids.contains(&tx_id) { continue; }
                                let size = tx.encoded_len();
                                let group_key = tx.outputs.get(0).map(|o| o.lock.0).unwrap_or([0u8;32]);
                                cands.push((tx.clone(), *id, size, idx, group_key));
                            }
                        }
                        // Sortiere Kandidaten nach Größe, dann Alter
                        cands.sort_by(|a, b| a.2.cmp(&b.2).then(a.3.cmp(&b.3)));
                        // Round-Robin über Gruppen: deterministische Gruppenreihenfolge
                        use std::collections::BTreeMap;
                        let mut groups: BTreeMap<[u8;32], Vec<(MicroTx, usize)>> = BTreeMap::new();
                        for (tx, _id, size, _idx, gk) in cands.into_iter() {
                            groups.entry(gk).or_default().push((tx, size));
                        }
                        // Budget-Logik
                        let mut budget_used: usize = 0;
                        'outer: loop {
                            let mut progressed = false;
                            for (_gk, vecq) in groups.iter_mut() {
                                // Nimm nächste Tx der Gruppe, die konfliktfrei ist und ins Budget passt
                                while let Some((tx, sz)) = vecq.first().cloned() {
                                    let mut conflict = false;
                                    for tin in &tx.inputs { if used.contains(&tin.prev_out) { conflict = true; break; } }
                                    if conflict { let _ = vecq.remove(0); continue; }
                                    if let Some(b) = payload_budget { if budget_used + sz > b { break; } }
                                    // accept
                                    for tin in &tx.inputs { let _ = used.insert(tin.prev_out); }
                                    txs.push(tx);
                                    budget_used += sz;
                                    let _ = vecq.remove(0);
                                    progressed = true;
                                    if txs.len() >= proposer_cap { break 'outer; }
                                    break;
                                }
                            }
                            if !progressed { break; }
                        }
                        if !txs.is_empty() {
                            // deterministische Ordnung: nach digest_microtx sortieren
                            txs.sort_unstable_by(|a, b| digest_microtx(a).cmp(&digest_microtx(b)));
                            let txs_len = txs.len();
                            let payload = pc_types::AnchorPayloadV2 { version:2, micro_txs: txs, mints: vec![], claims: vec![], evidences: vec![], payout_root: [0u8;32], genesis_note: None };
                            let root = pc_types::payload_merkle_root_v2(&payload);
                            let payload_clone = payload.clone();
                            match svc_prop.put_payload(payload).await {
                                Ok(()) => {
                                    NODE_PROPOSER_BUILT_TOTAL.fetch_add(1, Ordering::Relaxed);
                                    NODE_PROPOSER_LAST_SIZE.store(txs_len as u64, Ordering::Relaxed);
                                    // Für spätere State-Anwendung zwischenspeichern (Pending), falls nicht vorhanden
                                    if !pending.contains_key(&root) {
                                        pending.insert(root, (payload_clone, Instant::now()));
                                        order.push_back(root);
                                    }
                                }
                                Err(_e) => {
                                    NODE_PROPOSER_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if tx_b_prop.send(P2pMessage::PayloadInv { roots: vec![root] }).await.is_err() {
                                NODE_PROPOSER_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                            info!(proposer = true, root = %hex::encode(root), "proposed payload from mempool");
                        }
                    }
                    res = rx_state.recv() => {
                        match res {
                            Ok(P2pMessage::Resp(RespMsg::Payloads { payloads })) => {
                                for p in payloads.into_iter() {
                                    let root = pc_types::payload_merkle_root_v2(&p);
                                    let apply = { let g = finals_for_state.lock().await; g.contains(&root) };
                                    if apply {
                                        if let Err(e) = pc_types::validate_payload_sanity_v2(&p) { warn!(root = %hex::encode(root), err = %e, "drop payload: invalid"); continue; }
                                        // Mint-PoW-Validierung
                                        let mut mint_ok = true;
                                        for m in &p.mints {
                                            if validate_mint_sanity(m).is_err() || !check_mint_pow(m, pow_bits_eff) { mint_ok = false; break; }
                                        }
                                        if !mint_ok { warn!(root = %hex::encode(root), bits = pow_bits_eff, "drop payload: mint pow invalid"); continue; }
                                        // final angewandt → AnchorIndex erhöhen
                                        anchor_index = anchor_index.saturating_add(1);
                                        // persistieren
                                        { let data = anchor_index.to_string().into_bytes(); let p = std::path::Path::new(&anchor_index_path); let _ = atomic_write_async(p, data, fsync_flag).await; }
                                        // Mints mit minted_at indexieren
                                        for m in &p.mints { st.apply_mint_with_index(m, anchor_index); }
                                        // MicroTxs mit Maturity-Schwelle L1 anwenden
                                        for tx in &p.micro_txs {
                                            if let Err(e) = st.apply_micro_tx_with_maturity_indexed(tx, anchor_index, consts::MATURITY_L1) {
                                                warn!(%e, "utxo apply_micro_tx_with_maturity_indexed failed");
                                            }
                                        }
                                        let r = st.root();
                                        info!(root = %hex::encode(root), state_root = %hex::encode(r), "applied payload (final)");
                                    } else {
                                        // Nur einmal penden (Duplikate ignorieren)
                                        if !pending.contains_key(&root) {
                                            // Evict bei Überlauf
                                            if pending.len() >= PENDING_MAX {
                                                if let Some(old_key) = order.pop_front() {
                                                    let _ = pending.remove(&old_key);
                                                    warn!(root = %hex::encode(old_key), "evicted oldest pending payload due to cap");
                                                }
                                            }
                                            // Nur valide Payloads penden
                                            if let Err(e) = pc_types::validate_payload_sanity_v2(&p) {
                                                warn!(root = %hex::encode(root), err = %e, "drop payload: invalid (not queued)");
                                            } else {
                                                // Mint-PoW-Validierung vor dem Queuen
                                                let mut mint_ok = true;
                                                for m in &p.mints {
                                                    if validate_mint_sanity(m).is_err() || !check_mint_pow(m, pow_bits_eff) { mint_ok = false; break; }
                                                }
                                                if !mint_ok {
                                                    warn!(root = %hex::encode(root), bits = pow_bits_eff, "drop payload: mint pow invalid (not queued)");
                                                    continue;
                                                }
                                                pending.insert(root, (p, Instant::now()));
                                                order.push_back(root);
                                                warn!(root = %hex::encode(root), "queued payload: header not final yet");
                                            }
                                        } else {
                                            warn!(root = %hex::encode(root), "duplicate payload ignored (pending exists)");
                                        }
                                    }
                                }
                            }
                            Ok(P2pMessage::Resp(RespMsg::Txs { txs })) => {
                                for tx in txs.into_iter() {
                                    match validate_microtx_sanity(&tx) {
                                        Ok(()) => {
                                            let id = digest_microtx(&tx);
                                            if mempool.contains_key(&id) {
                                                NODE_MEMPOOL_DUPLICATE_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                            // Stateful-Check gegen aktuellen UTXO-State
                                            if let Err(_e) = st.can_apply_micro_tx(&tx) {
                                                NODE_MEMPOOL_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                            // Cap-Eviction: älteste entfernen, falls voll
                                            if mempool.len() >= MEMPOOL_MAX {
                                                if let Some(old_id) = mempool_order.pop_front() {
                                                    let _ = mempool.remove(&old_id);
                                                    let old_fname = format!("{}.bin", hex::encode(old_id));
                                                    let old_path = std::path::Path::new(&mempool_path).join(old_fname);
                                                    let _ = journal_append(&journal_path, fsync_flag, b'D', &old_id);
                                                    let _ = remove_with_dir_sync(&old_path, fsync_flag);
                                                    NODE_MEMPOOL_CAP_EVICT_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            let _ = mempool.insert(id, (tx.clone(), Instant::now()));
                                            mempool_order.push_back(id);
                                            // Persistiere in store_dir/mempool/<hexid>.bin
                                            let fname = format!("{}.bin", hex::encode(id));
                                            let path = std::path::Path::new(&mempool_path).join(fname);
                                            let mut buf = Vec::with_capacity(tx.encoded_len());
                                            if tx.encode(&mut buf).is_ok() {
                                                if atomic_write_async(&path, buf.clone(), fsync_flag).await.is_ok() {
                                                    let _ = journal_append(&journal_path, fsync_flag, b'A', &id);
                                                }
                                            }
                                            NODE_MEMPOOL_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
                                        }
                                        Err(e) => {
                                            warn!(err = %e, "drop microtx: invalid");
                                            NODE_MEMPOOL_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => { NODE_INBOUND_OBS_LAGGED_TOTAL.fetch_add(n as u64, Ordering::Relaxed); }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => { break; }
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = forward_task.await;
        let _ = server_task.await;
        let _ = consensus_task.await;
        let _ = state_task.await;
        let res = handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))
    })
}

fn run_p2p_quic_connect(args: &P2pQuicConnectArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::async_svc as p2p_async;
        use pc_p2p::P2pConfig;
        let cfg = P2pConfig {
            max_peers: 256,
            rate: None,
        };
        let (svc, mut out_rx, handle) = p2p_async::spawn(cfg);
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let _reader = spawn_client_reader(conn.clone(), svc.clone());
        let sink = QuicClientSink::new(conn);

        let forward_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                outbox_deq_inc();
                print_p2p_json(&msg);
                let _ = sink.deliver(msg).await;
            }
            Ok::<(), anyhow::Error>(())
        });

        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = forward_task.await;
        let res = handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))
    })
}

fn run_p2p_inject_headers(args: &P2pInjectHeadersArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let sink = QuicClientSink::new(conn);
        let headers: Vec<pc_types::AnchorHeaderV2> = load_vec_decodable(&args.headers_file)?;
        let mut sent = 0usize;
        for h in headers.into_iter() {
            sink.deliver(P2pMessage::HeaderAnnounce(h))
                .await
                .map_err(|e| anyhow!("deliver header_announce failed: {e}"))?;
            sent += 1;
        }
        println!(
            "{{\"type\":\"inject\",\"kind\":\"headers\",\"count\":{}}}",
            sent
        );
        Ok(())
    })
}

fn run_p2p_inject_payloads(args: &P2pInjectPayloadsArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let sink = QuicClientSink::new(conn);
        let payloads: Vec<pc_types::AnchorPayloadV2> = load_vec_decodable(&args.payloads_file)?;
        let mut roots = Vec::with_capacity(payloads.len());
        for p in &payloads {
            roots.push(pc_types::payload_merkle_root_v2(p));
        }
        sink.deliver(P2pMessage::PayloadInv {
            roots: roots.clone(),
        })
        .await
        .map_err(|e| anyhow!("deliver payload_inv failed: {e}"))?;
        if args.with_payloads {
            sink.deliver(P2pMessage::Resp(RespMsg::Payloads { payloads }))
                .await
                .map_err(|e| anyhow!("deliver payloads failed: {e}"))?;
        }
        println!(
            "{{\"type\":\"inject\",\"kind\":\"payloads\",\"roots\":{}}}",
            roots.len()
        );
        Ok(())
    })
}

fn self_check() -> Result<()> {
    // Build a minimal header and compute its id
    let mut parents = ParentList::default();
    parents.push(AnchorId([0u8; 32]))?;
    let header = AnchorHeader {
        version: 1,
        shard_id: 0,
        parents,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
    };
    let id = header.id_digest();
    info!(hash = %hex::encode(id), "anchor header digest computed");

    // Payload-Hash (leer) deterministisch berechnen
    let empty_payout = PayoutSet { entries: vec![] };
    let payload = AnchorPayload {
        version: 1,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: empty_payout.payout_root(),
    };
    let ph = compute_payload_hash(&payload);
    info!(payload_root = %hex::encode(ph), "payload merkle root computed");

    // Consensus threshold check for k=21
    let k = 21u8;
    let t = finality_threshold(k);
    let mask = set_bit(0, 0)?;
    let pc = popcount_u64(mask);
    warn!(
        k,
        threshold = t,
        popcount = pc,
        "consensus threshold sample"
    );
    let f = is_final(pc, k);
    info!(finalized = f, "finality check (expected false)");
    Ok(())
}

fn main() -> Result<()> {
    init_tracing();
    let opts = NodeOpts::parse();
    info!(?opts, "starting phantom-node roles");
    if let Some(cmd) = &opts.command {
        match cmd {
            Command::PayoutRoot(args) => {
                run_payout_root(args)?;
                return Ok(());
            }
            Command::CommitteePayoutFromHeaders(args) => {
                run_committee_payout_from_headers(args)?;
                return Ok(());
            }
            Command::BuildPayload(args) => {
                run_build_payload(args)?;
                return Ok(());
            }
            Command::GraphAck(args) => {
                run_graph_ack(args)?;
                return Ok(());
            }
            Command::GraphInsertAndAck(args) => {
                run_graph_insert_and_ack(args)?;
                return Ok(());
            }
            Command::P2pRun(args) => {
                run_p2p_run(args)?;
                return Ok(());
            }
            Command::DaRun(args) => {
                run_da_run(args)?;
                return Ok(());
            }
            Command::P2pQuicListen(args) => {
                run_p2p_quic_listen(args)?;
                return Ok(());
            }
            Command::P2pQuicConnect(args) => {
                run_p2p_quic_connect(args)?;
                return Ok(());
            }
            Command::P2pInjectHeaders(args) => {
                run_p2p_inject_headers(args)?;
                return Ok(());
            }
            Command::P2pInjectPayloads(args) => {
                run_p2p_inject_payloads(args)?;
                return Ok(());
            }
            Command::P2pMetrics => {
                run_p2p_metrics()?;
                return Ok(());
            }
            Command::P2pMetricsServe(args) => {
                run_p2p_metrics_serve(args)?;
                return Ok(());
            }
            Command::StatusServe(args) => {
                run_status_serve(args)?;
                return Ok(());
            }
            Command::ConsensusAckDists(args) => {
                run_consensus_ack_dists(args)?;
                return Ok(());
            }
            Command::ConsensusPayoutRoot(args) => {
                run_consensus_payout_root(args)?;
                return Ok(());
            }
            Command::CacheBench(args) => {
                run_cache_bench(args)?;
                return Ok(());
            }
        }
    }
    self_check()?;
    Ok(())
}
