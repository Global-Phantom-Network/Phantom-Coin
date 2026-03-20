// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use pc_codec::{Decodable, Encodable};
#[cfg(not(feature = "rocksdb"))]
use pc_state::InMemoryBackend;
#[cfg(feature = "rocksdb")]
use pc_state::RocksDbBackend;
use pc_state::StateBackend;
use pc_state::UtxoState;
use pc_types::{
    digest_evidence, digest_genesis_note, digest_microtx, validate_evidence_sanity,
    validate_microtx_sanity, EvidenceEvent, EvidenceKind, GenesisNote, LockCommitment, MicroTx,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[path = "../committee_selection.rs"]
mod committee_selection;
#[path = "../store_path.rs"]
mod store_path;

#[derive(Debug, Parser)]
#[command(
    name = "phantom-node-status",
    version,
    about = "Phantom Node Status HTTPS"
)]
struct Cli {
    /// Bind address, e.g. 127.0.0.1:8443.
    /// Bind-Addr, z. B. 127.0.0.1:8443
    #[arg(long, default_value = "127.0.0.1:8443")]
    addr: String,
    /// Store-Verzeichnis
    #[arg(long, default_value_os_t = store_path::default_runtime_store_dir_pathbuf())]
    store_dir: PathBuf,
    /// TLS: Server certificate (PEM). Auto-generated if not provided.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// TLS: Server private key (PEM). Auto-generated if not provided.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// mTLS: Client-CA (PEM). Wenn gesetzt, sind Client-Zertifikate Pflicht.
    #[arg(long)]
    tls_client_ca: Option<PathBuf>,
    /// Optional: Bearer-Token, falls du den Zugriff schützen willst.
    #[arg(long)]
    auth_token: Option<String>,
    /// Optional: Bearer-Token Datei (eine Zeile). Vermeidet Token-Leaks via Prozessliste.
    /// Optional: Bearer token file (single line). Avoids leaking tokens via process list.
    #[arg(long)]
    auth_token_file: Option<PathBuf>,
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

// Max. erlaubte Größe für HTTP-Request-Bodies (Status-HTTP, 1 MB).
const MAX_STATUS_HTTP_BODY_BYTES: usize = 1_000_000;

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

fn constant_time_eq(a: &str, b: &str) -> bool {
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    let max_len = aa.len().max(bb.len());
    let mut out = (aa.len() ^ bb.len()) as u8;
    for i in 0..max_len {
        let x = *aa.get(i).unwrap_or(&0);
        let y = *bb.get(i).unwrap_or(&0);
        out |= x ^ y;
    }
    out == 0
}

fn content_type_is_octet_stream(req: &Request<Body>) -> bool {
    let Some(ct) = req.headers().get(CONTENT_TYPE) else {
        return false;
    };
    let Ok(s) = ct.to_str() else {
        return false;
    };
    let base = s.split(';').next().unwrap_or("").trim();
    base.eq_ignore_ascii_case("application/octet-stream")
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        let mut it = part.splitn(2, '=');
        let k = it.next().unwrap_or("");
        if k != key {
            continue;
        }
        return Some(it.next().unwrap_or(""));
    }
    None
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        let _ = f.sync_data();
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(dirf) = std::fs::File::open(dir) {
            let _ = dirf.sync_data();
        }
    }
    Ok(())
}

fn journal_append(journal_path: &std::path::Path, op: u8, id: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)?;
    let mut line = Vec::with_capacity(1 + 64 + 1);
    line.push(op);
    line.extend_from_slice(hex::encode(id).as_bytes());
    line.push(b'\n');
    f.write_all(&line)?;
    let _ = f.sync_data();
    Ok(())
}

fn load_genesis_note(store_dir: &Path) -> Result<Option<GenesisNote>> {
    let p = store_dir.join("mempool").join("genesis_note.bin");
    let buf = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(anyhow!("read genesis_note.bin: {}", e));
        }
    };
    let note = pc_codec::decode_exact::<GenesisNote>(&buf)
        .map_err(|e| anyhow!("decode genesis_note.bin: {e}"))?;
    Ok(Some(note))
}

fn seed_anchor_default_from_store(store_dir: &Path, genesis_root: [u8; 32]) -> [u8; 32] {
    let p = store_dir.join("last_final_payload_root");
    match fs::read_to_string(&p) {
        Ok(s) => parse_hex32(s.trim()).unwrap_or(genesis_root),
        Err(_) => genesis_root,
    }
}

fn aggregate_stake_by_lock<B: StateBackend>(backend: &B) -> HashMap<[u8; 32], (u64, u64)> {
    // (sum, count)
    let mut stake_by_lock: HashMap<[u8; 32], (u64, u64)> = HashMap::new();
    for (_op, entry) in backend.iter_full() {
        if !entry.staked {
            continue;
        }
        let key = entry.lock.0;
        let (cur_sum, cur_cnt) = stake_by_lock.get(&key).copied().unwrap_or((0, 0));
        let next_sum = cur_sum.saturating_add(entry.amount);
        let next_cnt = cur_cnt.saturating_add(1);
        let _ = stake_by_lock.insert(key, (next_sum, next_cnt));
    }
    stake_by_lock
}

#[derive(Clone, Default)]
struct StakeCache {
    computed_at_unix: u64,
    stake_by_lock: HashMap<[u8; 32], (u64, u64)>,
}

fn stake_sum_map(stake_by_lock: &HashMap<[u8; 32], (u64, u64)>) -> HashMap<[u8; 32], u64> {
    stake_by_lock
        .iter()
        .map(|(lock, (sum, _count))| (*lock, *sum))
        .collect()
}

fn validate_evidence_against_state<B: StateBackend>(
    evid: &EvidenceEvent,
    backend: &B,
    note: &GenesisNote,
    network_id: [u8; 32],
    seed_anchor_now: [u8; 32],
    role_policy: Option<&pc_consensus::role_policy::RolePolicy>,
) -> Result<()> {
    use pc_consensus::attestation::{committee_precommit_message, slash_ticket_message};

    let stake_by_lock = committee_selection::aggregate_stake_by_lock(backend);

    match &evid.evidence {
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
                anyhow::bail!("slash ticket seed_anchor mismatch");
            }
            if backend.get_validator_record(offender_id).is_none() {
                anyhow::bail!("slash ticket unknown offender");
            }
            if backend.is_slash_id_used(slash_id) {
                anyhow::bail!("slash ticket already applied");
            }

            let committee = committee_selection::select_effective_committee_from_backend(
                backend,
                note,
                &stake_by_lock,
                note.params.committee_k,
                *vote_epoch,
                seed_anchor_now,
                network_id,
                role_policy,
            );
            let seats = committee.seats;
            let k_active = seats.len();
            if k_active == 0 || k_active > 64 {
                anyhow::bail!("slash ticket committee unavailable");
            }
            let threshold: u8 = pc_consensus::finality_threshold(k_active as u8);
            let allowed_mask: u64 = if k_active == 64 {
                u64::MAX
            } else {
                (1u64 << k_active) - 1
            };
            if (*vote_mask & !allowed_mask) != 0 {
                anyhow::bail!("slash ticket vote_mask out of range");
            }
            let pop = vote_mask.count_ones() as u8;
            if pop < threshold {
                anyhow::bail!("slash ticket below finality threshold");
            }

            // Extract PKs according to vote_mask and verify aggregate signature.
            let mut pks: Vec<pc_crypto::BlsPublicKey> = Vec::with_capacity(pop as usize);
            for i in 0..k_active {
                if ((*vote_mask >> i) & 1) == 1 {
                    if let Some(seat) = seats.get(i) {
                        pks.push(seat.bls_pk.clone());
                    }
                }
            }
            if pks.is_empty() {
                anyhow::bail!("slash ticket empty signer set");
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
            if !pc_crypto::bls_fast_aggregate_verify(&msg, agg_sig, &pks) {
                anyhow::bail!("slash ticket agg sig verify failed");
            }
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
                anyhow::bail!("equivocation seed_anchor mismatch");
            }
            if backend.get_validator_record(offender_id).is_none() {
                anyhow::bail!("equivocation unknown offender");
            }

            // Basic slot checks.
            if a.network_id != network_id || b.network_id != network_id {
                anyhow::bail!("equivocation network_id mismatch");
            }
            if a.vote_epoch != b.vote_epoch
                || a.vote_round != b.vote_round
                || a.shard_id != b.shard_id
            {
                anyhow::bail!("equivocation slot mismatch");
            }
            let target_a = a.vote_target_hash();
            let target_b = b.vote_target_hash();
            if target_a == target_b {
                anyhow::bail!("equivocation targets equal");
            }

            let committee = committee_selection::select_effective_committee_from_backend(
                backend,
                note,
                &stake_by_lock,
                note.params.committee_k,
                a.vote_epoch,
                seed_anchor_now,
                network_id,
                role_policy,
            );
            let seats = committee.seats;
            let k_active = seats.len();
            if k_active == 0 || k_active > 64 {
                anyhow::bail!("equivocation committee unavailable");
            }
            let threshold: u8 = pc_consensus::finality_threshold(k_active as u8);
            let allowed_mask: u64 = if k_active == 64 {
                u64::MAX
            } else {
                (1u64 << k_active) - 1
            };

            // Map offender_id -> seat index (0..k-1).
            let offender_idx = {
                let mut idx: Option<usize> = None;
                for (i, seat) in seats.iter().enumerate() {
                    if &seat.recipient_id == offender_id {
                        idx = Some(i);
                        break;
                    }
                }
                idx.ok_or_else(|| anyhow!("equivocation offender not in committee"))?
            };
            if offender_idx >= k_active || offender_idx >= 64 {
                anyhow::bail!("equivocation offender_idx out of range");
            }
            let bit = 1u64 << (offender_idx as u64);
            if (a.vote_mask & bit) == 0 || (b.vote_mask & bit) == 0 {
                anyhow::bail!("equivocation offender not in signer set");
            }

            // Each header must be final and have a verifiable aggregate signature for its signer set.
            let verify_header = |h: &pc_types::AnchorHeaderV2| -> Result<()> {
                if h.version < 5 {
                    anyhow::bail!("equivocation header version too low");
                }
                if h.network_id != network_id {
                    anyhow::bail!("equivocation header network_id mismatch");
                }
                if (h.vote_mask & !allowed_mask) != 0 {
                    anyhow::bail!("equivocation header vote_mask out of range");
                }
                let pop = h.vote_mask.count_ones() as u8;
                if pop < threshold {
                    anyhow::bail!("equivocation header below finality threshold");
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
                        if let Some(seat) = seats.get(i) {
                            pks.push(seat.bls_pk.clone());
                        }
                    }
                }
                if pks.is_empty() {
                    anyhow::bail!("equivocation empty signer set");
                }
                let msg = committee_precommit_message(
                    &network_id,
                    h.vote_epoch,
                    &h.vote_target_hash(),
                    &committed_state_root,
                );
                if !pc_crypto::bls_fast_aggregate_verify(&msg, &sig, &pks) {
                    anyhow::bail!("equivocation agg sig verify failed");
                }
                Ok(())
            };
            verify_header(a)?;
            verify_header(b)?;

            let slash_id = pc_types::slash_id_equivocation_bft_v1(
                &network_id,
                &seed_anchor_now,
                a.vote_epoch,
                a.shard_id,
                a.vote_round,
                offender_id,
                &target_a,
                &target_b,
            );
            if backend.is_slash_id_used(&slash_id) {
                anyhow::bail!("equivocation already applied");
            }

            // Reporter binding: Schnorr signature over deterministic message.
            let msg32 = pc_types::reporter_slash_claim_sighash_v1(&network_id, &slash_id);
            if !pc_crypto::schnorr_verify_xonly_bytes(&msg32, reporter_sig, &reporter_lock.0) {
                anyhow::bail!("equivocation reporter_sig invalid");
            }
        }
        EvidenceKind::Equivocation { seat_id, .. }
        | EvidenceKind::VoteInvalid { seat_id, .. }
        | EvidenceKind::ConflictingDAAttest { seat_id, .. } => {
            if backend.get_validator_record(seat_id).is_none() {
                anyhow::bail!("unknown seat_id");
            }
        }
        EvidenceKind::MintCandidateV1 { candidate } => {
            if candidate.network_id != network_id {
                anyhow::bail!("mint candidate network_id mismatch");
            }
        }
        EvidenceKind::MintPoWCertV1 { cert } => {
            if cert.network_id != network_id {
                anyhow::bail!("mint pow cert network_id mismatch");
            }
        }
        EvidenceKind::MintCandidateV2 { candidate } => {
            if candidate.network_id != network_id {
                anyhow::bail!("mint candidate network_id mismatch");
            }
        }
        EvidenceKind::MintPoWCertV2 { cert } => {
            if cert.network_id != network_id {
                anyhow::bail!("mint pow cert network_id mismatch");
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(feature = "rocksdb")]
type Backend = RocksDbBackend;

#[cfg(not(feature = "rocksdb"))]
type Backend = InMemoryBackend;

#[cfg(feature = "rocksdb")]
fn open_utxo_backend_read_only(store_dir: &Path) -> Result<RocksDbBackend> {
    let utxo_path = store_dir.join("utxo");
    let utxo_path_str = utxo_path.to_string_lossy().to_string();
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    let secondary_dir = store_dir.join("utxo_secondary");
    let secondary_dir_str = secondary_dir.to_string_lossy().to_string();
    let _ = std::fs::create_dir_all(&secondary_dir);
    for _ in 0..20 {
        match RocksDbBackend::open_secondary(&utxo_path_str, &secondary_dir_str) {
            Ok(b) => {
                eprintln!(
                    "[STATUS] RocksDB Secondary geöffnet bei {}",
                    secondary_dir_str
                );
                return Ok(b);
            }
            Err(e) => {
                last_err = Some(e);
                if let Ok(b) = RocksDbBackend::open_read_only(&utxo_path_str) {
                    eprintln!(
                        "[STATUS] RocksDB Secondary fehlgeschlagen, nutze read-only (kein Live-Update)"
                    );
                    return Ok(b);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(anyhow!(
        "failed to open RocksDB secondary/read-only at {}: {}",
        utxo_path_str,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

#[cfg(feature = "rocksdb")]
fn open_utxo_backend_read_only_with_secondary_dir(
    store_dir: &Path,
    secondary_dir: &Path,
) -> Result<RocksDbBackend> {
    let utxo_path = store_dir.join("utxo");
    let utxo_path_str = utxo_path.to_string_lossy().to_string();
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    let secondary_dir_str = secondary_dir.to_string_lossy().to_string();
    let _ = std::fs::create_dir_all(secondary_dir);
    for _ in 0..20 {
        match RocksDbBackend::open_secondary(&utxo_path_str, &secondary_dir_str) {
            Ok(b) => {
                eprintln!(
                    "[STATUS] RocksDB Secondary (stake) geöffnet bei {}",
                    secondary_dir_str
                );
                return Ok(b);
            }
            Err(e) => {
                last_err = Some(e);
                if let Ok(b) = RocksDbBackend::open_read_only(&utxo_path_str) {
                    eprintln!(
                        "[STATUS] RocksDB Secondary fehlgeschlagen, nutze read-only (kein Live-Update)"
                    );
                    return Ok(b);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(anyhow!(
        "failed to open RocksDB secondary/read-only at {}: {}",
        utxo_path_str,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum WalletHistoryEventType {
    Mint,
    MicroTx,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum WalletHistoryDirection {
    In,
    Out,
}

#[derive(Debug, Clone, serde::Deserialize)]
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

fn load_wallet_history_for_lock(store_dir: &Path, lock: [u8; 32]) -> Vec<serde_json::Value> {
    let journal = store_dir.join("mempool").join("wallet_history.v1.jsonl");
    let raw = match fs::read(&journal) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let mut rows: Vec<(u64, serde_json::Value)> = Vec::new();
    let mut seen: HashSet<(u64, [u8; 32], [u8; 32], [u8; 32], u32, u8, u8, u64)> = HashSet::new();

    for line in raw.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let ev: WalletHistoryEventV1 = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if ev.version != 1 || ev.lock != lock {
            continue;
        }
        let ev_type_u8 = match ev.event_type {
            WalletHistoryEventType::Mint => 0u8,
            WalletHistoryEventType::MicroTx => 1u8,
        };
        let dir_u8 = match ev.direction {
            WalletHistoryDirection::In => 0u8,
            WalletHistoryDirection::Out => 1u8,
        };
        let key = (
            ev.anchor_index,
            ev.payload_root,
            ev.txid,
            ev.outpoint_txid,
            ev.outpoint_vout,
            ev_type_u8,
            dir_u8,
            ev.amount,
        );
        if !seen.insert(key) {
            continue;
        }
        let event_type = if ev_type_u8 == 0 { "mint" } else { "micro_tx" };
        let direction = if dir_u8 == 0 { "in" } else { "out" };
        rows.push((
            ev.anchor_index,
            serde_json::json!({
                "anchor_index": ev.anchor_index,
                "payload_root": hex::encode(ev.payload_root),
                "txid": hex::encode(ev.txid),
                "event_type": event_type,
                "direction": direction,
                "amount": ev.amount,
                "lock": hex::encode(ev.lock),
                "outpoint_txid": hex::encode(ev.outpoint_txid),
                "outpoint_vout": ev.outpoint_vout,
                "outpoint": format!("{}:{}", hex::encode(ev.outpoint_txid), ev.outpoint_vout),
                "staked": ev.staked,
                "timestamp_local": ev.timestamp_local,
            }),
        ));
    }

    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.into_iter().map(|(_, v)| v).collect()
}

async fn handle(
    req: Request<Body>,
    store_dir: Arc<PathBuf>,
    state: Arc<Mutex<UtxoState<Backend>>>,
    stake_cache: Arc<RwLock<StakeCache>>,
    auth_token: Option<&str>,
) -> Result<Response<Body>, Infallible> {
    if let Some(expected) = auth_token {
        if !expected.is_empty() {
            let got = req.headers().get(AUTHORIZATION);
            let ok = if let Some(val) = got {
                if let Ok(s) = val.to_str() {
                    if let Some(b) = s.strip_prefix("Bearer ") {
                        constant_time_eq(b, expected)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            if !ok {
                return Ok(make_text_response(StatusCode::UNAUTHORIZED, "unauthorized"));
            }
        }
    }

    let path = req.uri().path().to_string();
    if req.method() == Method::GET && path == "/status" {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut root = serde_json::Map::new();
        root.insert("ok".into(), serde_json::Value::Bool(true));
        root.insert(
            "service".into(),
            serde_json::Value::String("phantom-node".to_string()),
        );
        root.insert("ts".into(), serde_json::Value::Number(ts.into()));

        if let Ok(Some(note)) = load_genesis_note(&store_dir) {
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

        let body = serde_json::Value::Object(root).to_string();
        return Ok(make_json_response(StatusCode::OK, body));
    }

    if req.method() == Method::GET && path.starts_with("/wallet/utxos_by_lock/") {
        let lock_hex = path.strip_prefix("/wallet/utxos_by_lock/").unwrap_or("");
        let lock_bytes = match parse_hex32(lock_hex) {
            Ok(b) => b,
            Err(e) => {
                let body = format!("{{\"ok\":false,\"error\":\"bad lock: {}\"}}", e);
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };

        let st = state.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }
        let lock = LockCommitment(lock_bytes);
        let utxos = st.utxos_for_lock_detailed(&lock);

        let mut utxo_json = Vec::with_capacity(utxos.len());
        let mut balance: u64 = 0;
        let mut staked_balance: u64 = 0;

        for (op, amt, minted_at, staked) in utxos.into_iter() {
            balance = balance.saturating_add(amt);
            if staked {
                staked_balance = staked_balance.saturating_add(amt);
            }
            utxo_json.push(serde_json::json!({
                "txid": hex::encode(op.txid),
                "vout": op.vout,
                "amount": amt,
                "minted_at": minted_at,
                "staked": staked,
            }));
        }

        let body = serde_json::json!({
            "ok": true,
            "lock": lock_hex,
            "balance": balance,
            "staked_balance": staked_balance,
            "n_utxos": utxo_json.len(),
            "utxos": utxo_json,
        })
        .to_string();

        return Ok(make_json_response(StatusCode::OK, body));
    }

    if req.method() == Method::GET && path.starts_with("/wallet/history/") {
        let lock_hex = path.strip_prefix("/wallet/history/").unwrap_or("");
        let lock_bytes = match parse_hex32(lock_hex) {
            Ok(b) => b,
            Err(e) => {
                let body = format!("{{\"ok\":false,\"error\":\"bad lock: {}\"}}", e);
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };

        let (utxo_json, balance, staked_balance) = {
            let st = state.lock().await;
            #[cfg(feature = "rocksdb")]
            {
                let _ = st.backend().try_catch_up_with_primary();
            }
            let lock = LockCommitment(lock_bytes);
            let utxos = st.utxos_for_lock_detailed(&lock);
            let mut utxo_json = Vec::with_capacity(utxos.len());
            let mut balance: u64 = 0;
            let mut staked_balance: u64 = 0;

            for (op, amt, minted_at, staked) in utxos.into_iter() {
                balance = balance.saturating_add(amt);
                if staked {
                    staked_balance = staked_balance.saturating_add(amt);
                }
                utxo_json.push(serde_json::json!({
                    "txid": hex::encode(op.txid),
                    "vout": op.vout,
                    "amount": amt,
                    "minted_at": minted_at,
                    "staked": staked,
                }));
            }
            (utxo_json, balance, staked_balance)
        };

        let history = load_wallet_history_for_lock(&store_dir, lock_bytes);
        let body = serde_json::json!({
            "ok": true,
            "lock": lock_hex,
            "balance": balance,
            "staked_balance": staked_balance,
            "n_utxos": utxo_json.len(),
            "utxos": utxo_json,
            "n_history": history.len(),
            "history": history,
        })
        .to_string();
        return Ok(make_json_response(StatusCode::OK, body));
    }

    if req.method() == Method::GET && path == "/consensus/validators" {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stake_snapshot = stake_cache.read().await;

        let st = state.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }

        // Aggregate stake per lock from on-chain (staked) UTXOs.
        let stake_by_lock = &stake_snapshot.stake_by_lock;

        let min_stake = pc_consensus::consts::MIN_ATTESTOR_STAKE;

        let mut validators: Vec<serde_json::Value> = Vec::new();
        for (validator_id, rec) in st.backend().iter_validator_records() {
            let (stake, utxo_count) = stake_by_lock
                .get(&rec.stake_lock.0)
                .copied()
                .unwrap_or((0, 0));
            let bls_pop_valid = pc_crypto::bls_pk_from_bytes(&rec.bls_pk)
                .map(|pk| pc_crypto::bls_pop_verify(&pk, &rec.bls_pop))
                .unwrap_or(false);
            let meets_min_stake = stake >= min_stake;
            validators.push(serde_json::json!({
                "validator_id": hex::encode(validator_id),
                "stake_lock": hex::encode(rec.stake_lock.0),
                "sequence": rec.sequence,
                "operator_id": hex::encode(rec.operator_id),
                "bls_pk": hex::encode(rec.bls_pk),
                "bls_pop_valid": bls_pop_valid,
                "stake": stake,
                "utxo_count": utxo_count,
                "min_stake": min_stake,
                "meets_min_stake": meets_min_stake,
            }));
        }

        let body = serde_json::json!({
            "ok": true,
            "n": validators.len(),
            "validators": validators,
            "stake_ts": stake_snapshot.computed_at_unix,
            "ts": ts,
        })
        .to_string();
        return Ok(make_json_response(StatusCode::OK, body));
    }

    if req.method() == Method::GET && path == "/consensus/committee" {
        use pc_consensus::committee_hash::derive_committee_seed;

        let query = req.uri().query().unwrap_or("");
        let epoch: u64 = match query_param(query, "epoch").and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                let body = "{\"ok\":false,\"error\":\"missing epoch\"}".to_string();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };
        let note = match load_genesis_note(&store_dir) {
            Ok(Some(n)) => n,
            Ok(None) => {
                let body = "{\"ok\":false,\"error\":\"genesis_note.bin not found\"}".to_string();
                return Ok(make_json_response(StatusCode::NOT_FOUND, body));
            }
            Err(e) => {
                let body = format!("{{\"ok\":false,\"error\":\"load genesis: {}\"}}", e);
                return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
            }
        };

        let network_id = digest_genesis_note(&note);
        let genesis_root = pc_types::genesis_payload_root(&note);

        // seed_anchor default: last finalized payload root (persisted by the node runtime).
        // seed_anchor Default: letzte final angewandte Payload-Root (vom Node Runtime persistiert).
        let seed_anchor: [u8; 32] = if let Some(v) = query_param(query, "seed_anchor") {
            let t = v.trim();
            if t.is_empty() {
                genesis_root
            } else {
                match parse_hex32(t) {
                    Ok(id) => id,
                    Err(e) => {
                        let body = format!("{{\"ok\":false,\"error\":\"bad seed_anchor: {}\"}}", e);
                        return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
                    }
                }
            }
        } else {
            let p = store_dir.join("last_final_payload_root");
            match fs::read_to_string(&p) {
                Ok(s) => parse_hex32(s.trim()).unwrap_or(genesis_root),
                Err(_) => genesis_root,
            }
        };

        let k_default = note.params.committee_k;
        let k: u8 = query_param(query, "k")
            .and_then(|s| s.parse().ok())
            .unwrap_or(k_default);
        if k == 0 || k > 64 {
            let body = "{\"ok\":false,\"error\":\"bad k\"}".to_string();
            return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
        }

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stake_snapshot = stake_cache.read().await;
        let stake_by_lock = stake_sum_map(&stake_snapshot.stake_by_lock);

        let st = state.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }

        let seed = derive_committee_seed(network_id, seed_anchor, epoch);
        let role_policy = match committee_selection::load_role_policy_from_mempool_dir(
            &store_dir.join("mempool"),
            &note,
        ) {
            Ok(p) => p,
            Err(e) => {
                let body = format!(
                    "{{\"ok\":false,\"error\":\"role policy load failed: {}\"}}",
                    e
                );
                return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
            }
        };
        let committee = committee_selection::select_effective_committee_from_backend(
            st.backend(),
            &note,
            &stake_by_lock,
            k,
            epoch,
            seed_anchor,
            network_id,
            role_policy.as_ref(),
        );
        let k_active = committee.seats.len();
        let n_fee_eligible = committee.fee_eligible.iter().filter(|v| **v).count();
        let mut stake_by_recipient: HashMap<[u8; 32], u64> = HashMap::new();
        for (validator_id, rec) in st.backend().iter_validator_records() {
            let stake = stake_by_lock.get(&rec.stake_lock.0).copied().unwrap_or(0);
            let _ = stake_by_recipient.insert(validator_id, stake);
        }
        let seats: Vec<serde_json::Value> = committee
            .seats
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let stake = stake_by_recipient
                    .get(&s.recipient_id)
                    .copied()
                    .unwrap_or(0);
                serde_json::json!({
                    "recipient_id": hex::encode(s.recipient_id),
                    "operator_id": hex::encode(s.operator_id),
                    "bls_pk": hex::encode(s.bls_pk.to_bytes()),
                    "score": hex::encode(s.score),
                    "stake": stake,
                    "fee_eligible": committee.fee_eligible.get(i).copied().unwrap_or(false),
                })
            })
            .collect();

        let body = serde_json::json!({
            "ok": true,
            "network_id": hex::encode(network_id),
            "epoch": epoch,
            "seed_anchor": hex::encode(seed_anchor),
            "k": k,
            "k_active": k_active,
            "min_stake": pc_consensus::consts::MIN_ATTESTOR_STAKE,
            "bootstrap_mode": committee.bootstrap_mode,
            "n_fee_eligible": n_fee_eligible,
            "seed": hex::encode(seed),
            "stake_ts": stake_snapshot.computed_at_unix,
            "n_selected": seats.len(),
            "seats": seats,
            "ts": ts,
        })
        .to_string();

        return Ok(make_json_response(StatusCode::OK, body));
    }

    if req.method() == Method::GET && path.starts_with("/consensus/validator/") {
        let id_hex = path.strip_prefix("/consensus/validator/").unwrap_or("");
        let id = match parse_hex32(id_hex) {
            Ok(v) => v,
            Err(e) => {
                let body = format!("{{\"ok\":false,\"error\":\"bad validator_id: {}\"}}", e);
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stake_snapshot = stake_cache.read().await;

        let st = state.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }

        let rec = match st.backend().get_validator_record(&id) {
            Some(r) => r,
            None => {
                let body = "{\"ok\":false,\"error\":\"not found\"}".to_string();
                return Ok(make_json_response(StatusCode::NOT_FOUND, body));
            }
        };
        let stake = stake_snapshot
            .stake_by_lock
            .get(&rec.stake_lock.0)
            .copied()
            .map(|(sum, _cnt)| sum)
            .unwrap_or(0);
        let min_stake = pc_consensus::consts::MIN_ATTESTOR_STAKE;
        let bls_pop_valid = pc_crypto::bls_pk_from_bytes(&rec.bls_pk)
            .map(|pk| pc_crypto::bls_pop_verify(&pk, &rec.bls_pop))
            .unwrap_or(false);
        let body = serde_json::json!({
            "ok": true,
            "validator_id": hex::encode(id),
            "stake_lock": hex::encode(rec.stake_lock.0),
            "sequence": rec.sequence,
            "operator_id": hex::encode(rec.operator_id),
            "bls_pk": hex::encode(rec.bls_pk),
            "bls_pop_valid": bls_pop_valid,
            "stake": stake,
            "min_stake": min_stake,
            "meets_min_stake": stake >= min_stake,
            "stake_ts": stake_snapshot.computed_at_unix,
            "ts": ts,
        })
        .to_string();
        return Ok(make_json_response(StatusCode::OK, body));
    }

    if req.method() == Method::POST && path == "/tx/broadcast" {
        // Do not allow local write endpoints unless the operator explicitly enables auth.
        // Keine lokalen Write-Endpunkte ohne explizit gesetztes Auth-Token zulassen.
        if auth_token.unwrap_or("").is_empty() {
            let body = serde_json::json!({
                "ok": false,
                "error": "broadcast disabled: start status_http with --auth-token-file and send Authorization: Bearer <TOKEN>"
            })
            .to_string();
            return Ok(make_json_response(StatusCode::FORBIDDEN, body));
        }
        if !content_type_is_octet_stream(&req) {
            let body = "{\"ok\":false,\"error\":\"unsupported_media_type\"}".to_string();
            return Ok(make_json_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, body));
        }

        // Decode tx
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_STATUS_HTTP_BODY_BYTES,
            Duration::from_secs(5),
        )
        .await
        {
            Ok(b) => b,
            Err(ReadBodyError::Timeout) => {
                let body = "{\"ok\":false,\"error\":\"read timeout\"}".to_string();
                return Ok(make_json_response(StatusCode::REQUEST_TIMEOUT, body));
            }
            Err(ReadBodyError::TooLarge) => {
                let body = "{\"ok\":false,\"error\":\"payload too large\"}".to_string();
                return Ok(make_json_response(StatusCode::PAYLOAD_TOO_LARGE, body));
            }
            Err(ReadBodyError::Hyper(e)) => {
                let body = format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e);
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };

        let mut s = &whole[..];
        let tx = match MicroTx::decode(&mut s) {
            Ok(t) => t,
            Err(_e) => {
                let body = "{\"ok\":false,\"error\":\"invalid tx\"}".to_string();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };
        if validate_microtx_sanity(&tx).is_err() {
            let body = "{\"ok\":false,\"error\":\"tx sanity failed\"}".to_string();
            return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
        }

        // Load network_id (required for signature verification).
        let nid = match load_genesis_note(&store_dir) {
            Ok(Some(note)) => digest_genesis_note(&note),
            _ => {
                let body =
                    "{\"ok\":false,\"error\":\"genesis_note.bin missing or invalid\"}".to_string();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };

        // Best-effort: catch up read-only backend and validate stateful.
        let st = state.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }
        if let Err(e) = st.can_apply_micro_tx(&tx, &nid) {
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
            return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
        }
        drop(st);

        let id = digest_microtx(&tx);
        let mempool_dir = store_dir.join("mempool");
        let _ = std::fs::create_dir_all(&mempool_dir);
        let path = mempool_dir.join(format!("{}.bin", hex::encode(id)));
        let status = if path.exists() {
            "duplicate"
        } else {
            let mut buf: Vec<u8> = Vec::with_capacity(tx.encoded_len());
            if tx.encode(&mut buf).is_err() {
                let body = "{\"ok\":false,\"error\":\"encode failed\"}".to_string();
                return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
            }
            let persist_res = tokio::task::spawn_blocking({
                let path = path.clone();
                let buf = buf.clone();
                move || atomic_write(&path, &buf)
            })
            .await;
            match persist_res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let body = format!("{{\"ok\":false,\"error\":\"persist: {}\"}}", e);
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
                Err(e) => {
                    let body = format!("{{\"ok\":false,\"error\":\"persist task: {}\"}}", e);
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
            }
            let journal = mempool_dir.join("mempool.journal");
            let _ = tokio::task::spawn_blocking(move || journal_append(&journal, b'A', &id)).await;
            "accepted"
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let body = serde_json::json!({
            "ok": true,
            "txid": hex::encode(id),
            "status": status,
            "ts": ts
        })
        .to_string();
        return Ok(make_json_response(StatusCode::OK, body));
    }

    if req.method() == Method::POST && path == "/evidence/broadcast" {
        // Do not allow local write endpoints unless the operator explicitly enables auth.
        // Keine lokalen Write-Endpunkte ohne explizit gesetztes Auth-Token zulassen.
        if auth_token.unwrap_or("").is_empty() {
            let body = serde_json::json!({
                "ok": false,
                "error": "broadcast disabled: start status_http with --auth-token-file and send Authorization: Bearer <TOKEN>"
            })
            .to_string();
            return Ok(make_json_response(StatusCode::FORBIDDEN, body));
        }
        if !content_type_is_octet_stream(&req) {
            let body = "{\"ok\":false,\"error\":\"unsupported_media_type\"}".to_string();
            return Ok(make_json_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, body));
        }

        // Decode evidence
        let whole = match read_body_limited_timeout(
            req.into_body(),
            MAX_STATUS_HTTP_BODY_BYTES,
            Duration::from_secs(5),
        )
        .await
        {
            Ok(b) => b,
            Err(ReadBodyError::Timeout) => {
                let body = "{\"ok\":false,\"error\":\"read timeout\"}".to_string();
                return Ok(make_json_response(StatusCode::REQUEST_TIMEOUT, body));
            }
            Err(ReadBodyError::TooLarge) => {
                let body = "{\"ok\":false,\"error\":\"payload too large\"}".to_string();
                return Ok(make_json_response(StatusCode::PAYLOAD_TOO_LARGE, body));
            }
            Err(ReadBodyError::Hyper(e)) => {
                let body = format!("{{\"ok\":false,\"error\":\"read body: {}\"}}", e);
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };

        let evid = match pc_codec::decode_exact::<EvidenceEvent>(&whole) {
            Ok(e) => e,
            Err(_e) => {
                let body = "{\"ok\":false,\"error\":\"invalid evidence\"}".to_string();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };
        if validate_evidence_sanity(&evid).is_err() {
            let body = "{\"ok\":false,\"error\":\"evidence sanity failed\"}".to_string();
            return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
        }

        // Load network_id (required for evidence signature verification).
        let note = match load_genesis_note(&store_dir) {
            Ok(Some(n)) => n,
            _ => {
                let body =
                    "{\"ok\":false,\"error\":\"genesis_note.bin missing or invalid\"}".to_string();
                return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
            }
        };
        let nid = digest_genesis_note(&note);
        let genesis_root = pc_types::genesis_payload_root(&note);
        let seed_anchor_now = seed_anchor_default_from_store(&store_dir, genesis_root);
        let role_policy = match committee_selection::load_role_policy_from_mempool_dir(
            &store_dir.join("mempool"),
            &note,
        ) {
            Ok(p) => p,
            Err(e) => {
                let body = serde_json::json!({
                    "ok": false,
                    "error": "role policy load failed",
                    "reason": e.to_string(),
                })
                .to_string();
                return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
            }
        };

        // Stateful evidence validation (validator existence, signatures, replay/dupes).
        let stake_snapshot = stake_cache.read().await;
        let st = state.lock().await;
        #[cfg(feature = "rocksdb")]
        {
            let _ = st.backend().try_catch_up_with_primary();
        }
        if let Err(e) = validate_evidence_against_state(
            &evid,
            st.backend(),
            &note,
            nid,
            seed_anchor_now,
            role_policy.as_ref(),
        ) {
            let body = serde_json::json!({
                "ok": false,
                "error": "evidence rejected by state",
                "reason": e.to_string(),
            })
            .to_string();
            return Ok(make_json_response(StatusCode::BAD_REQUEST, body));
        }
        drop(st);
        drop(stake_snapshot);

        let id = digest_evidence(&evid);
        let mempool_dir = store_dir.join("mempool");
        let evid_dir = mempool_dir.join("evidences");
        let _ = std::fs::create_dir_all(&evid_dir);
        let path = evid_dir.join(format!("{}.bin", hex::encode(id)));
        let status = if path.exists() {
            "duplicate"
        } else {
            let mut buf: Vec<u8> = Vec::with_capacity(evid.encoded_len());
            if evid.encode(&mut buf).is_err() {
                let body = "{\"ok\":false,\"error\":\"encode failed\"}".to_string();
                return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
            }
            let persist_res = tokio::task::spawn_blocking({
                let path = path.clone();
                let buf = buf.clone();
                move || atomic_write(&path, &buf)
            })
            .await;
            match persist_res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let body = format!("{{\"ok\":false,\"error\":\"persist: {}\"}}", e);
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
                Err(e) => {
                    let body = format!("{{\"ok\":false,\"error\":\"persist task: {}\"}}", e);
                    return Ok(make_json_response(StatusCode::INTERNAL_SERVER_ERROR, body));
                }
            }
            let journal = mempool_dir.join("evidences.journal");
            let _ = tokio::task::spawn_blocking(move || journal_append(&journal, b'A', &id)).await;
            "accepted"
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let body = serde_json::json!({
            "ok": true,
            "evidence_id": hex::encode(id),
            "status": status,
            "ts": ts
        })
        .to_string();
        return Ok(make_json_response(StatusCode::OK, body));
    }

    Ok(make_text_response(StatusCode::NOT_FOUND, "not found"))
}

fn generate_self_signed_cert(store_dir: &PathBuf) -> Result<(PathBuf, PathBuf)> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let cert_path = store_dir.join("server.crt");
    let key_path = store_dir.join("server.key");
    if cert_path.exists() && key_path.exists() {
        // Best-effort hardening: ensure private key isn't world-readable.
        // Best-Effort Härtung: Private-Key nicht world-readable lassen.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(md) = fs::metadata(&key_path) {
                let mode = md.permissions().mode() & 0o777;
                if (mode & 0o077) != 0 {
                    let mut perms = md.permissions();
                    perms.set_mode(0o600);
                    let _ = fs::set_permissions(&key_path, perms);
                }
            }
        }
        return Ok((cert_path, key_path));
    }

    let store_existed = store_dir.exists();
    fs::create_dir_all(store_dir)
        .with_context(|| format!("create store_dir {}", store_dir.display()))?;
    // Best-effort hardening: if we created the directory, keep it private.
    // Best-Effort Härtung: Wenn wir das Verzeichnis angelegt haben, privat halten.
    #[cfg(unix)]
    if !store_existed {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(md) = fs::metadata(store_dir) {
            let mode = md.permissions().mode() & 0o777;
            if mode != 0o700 {
                let mut perms = md.permissions();
                perms.set_mode(0o700);
                let _ = fs::set_permissions(store_dir, perms);
            }
        }
    }

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(subject_alt_names).context("generate tls cert")?;

    fs::write(&cert_path, cert.pem()).with_context(|| format!("write {}", cert_path.display()))?;
    let key_pem = key_pair.serialize_pem();
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .with_context(|| format!("open {}", key_path.display()))?;
        f.write_all(key_pem.as_bytes())
            .with_context(|| format!("write {}", key_path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&key_path, key_pem).with_context(|| format!("write {}", key_path.display()))?;
    }

    Ok((cert_path, key_path))
}

fn load_roots(path: &PathBuf) -> Result<RootCertStore> {
    use rustls::pki_types::pem::PemObject;
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse ca certs")?;
    let certs = if certs.is_empty() {
        vec![CertificateDer::from(bytes)]
    } else {
        certs
    };
    let mut roots = RootCertStore::empty();
    for c in certs {
        roots
            .add(c)
            .map_err(|_| anyhow!("invalid ca cert in {}", path.display()))?;
    }
    Ok(roots)
}

fn load_tls_config(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    client_ca: Option<&PathBuf>,
) -> Result<rustls::ServerConfig> {
    use rustls::pki_types::pem::{Error as PemError, PemObject};
    let cert_bytes =
        fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certs")?;
    let certs = if certs.is_empty() {
        vec![CertificateDer::from(cert_bytes)]
    } else {
        certs
    };

    let key_bytes = fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
    let key = match PrivateKeyDer::from_pem_slice(&key_bytes) {
        Ok(k) => k,
        Err(PemError::NoItemsFound) => PrivateKeyDer::try_from(key_bytes.as_slice())
            .map(|k| k.clone_key())
            .map_err(|e| anyhow!("invalid key der: {e}"))?,
        Err(e) => return Err(anyhow!("parse key pem: {e}")),
    };

    if let Some(ca_path) = client_ca {
        let roots = load_roots(ca_path)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("build client verifier")?;
        let cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("build tls config (mtls)")?;
        Ok(cfg)
    } else {
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("build tls config")?;
        Ok(cfg)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // `install_default` can fail if another crate already installed a provider; that is not fatal
    // for this binary. Avoid panicking on startup.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    let store_dir = store_path::resolve_store_dir_value(&cli.store_dir.to_string_lossy(), false)?;
    let addr: SocketAddr = cli
        .addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid addr '{}': {e}", &cli.addr))?;
    if !addr.ip().is_loopback() {
        anyhow::bail!("status_http darf nur auf 127.0.0.1/::1 laufen: {}", addr);
    }

    let (cert_path, key_path) = match (&cli.tls_cert, &cli.tls_key) {
        (Some(cert), Some(key)) => (cert.clone(), key.clone()),
        (None, None) => generate_self_signed_cert(&store_dir)?,
        _ => anyhow::bail!("tls_cert und tls_key müssen zusammen gesetzt sein (oder gar nicht)"),
    };

    let tls_cfg = load_tls_config(&cert_path, &key_path, cli.tls_client_ca.as_ref())?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    #[cfg(feature = "rocksdb")]
    let backend = { open_utxo_backend_read_only(&store_dir)? };

    #[cfg(not(feature = "rocksdb"))]
    let backend = InMemoryBackend::new();

    let state = Arc::new(Mutex::new(UtxoState::new(backend)));

    #[cfg(feature = "rocksdb")]
    let stake_backend: Backend = {
        let secondary = store_dir.join("utxo_secondary_status_stake");
        open_utxo_backend_read_only_with_secondary_dir(&store_dir, &secondary)?
    };
    #[cfg(not(feature = "rocksdb"))]
    let stake_backend: Backend = InMemoryBackend::new();
    let stake_backend = Arc::new(stake_backend);
    let stake_cache: Arc<RwLock<StakeCache>> = Arc::new(RwLock::new(StakeCache::default()));
    {
        // Compute initial snapshot once to avoid serving empty stake values.
        let stake_backend = stake_backend.clone();
        let initial = tokio::task::spawn_blocking(move || {
            #[cfg(feature = "rocksdb")]
            {
                let _ = stake_backend.try_catch_up_with_primary();
            }
            let stake_by_lock = aggregate_stake_by_lock(stake_backend.as_ref());
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            StakeCache {
                computed_at_unix: ts,
                stake_by_lock,
            }
        })
        .await
        .map_err(|e| anyhow!("stake cache init task failed: {e}"))?;
        *stake_cache.write().await = initial;
    }

    {
        // Periodically refresh the stake snapshot in the background to keep handlers fast.
        let stake_backend = stake_backend.clone();
        let stake_cache = stake_cache.clone();
        tokio::spawn(async move {
            loop {
                let stake_backend = stake_backend.clone();
                let snap_res = tokio::task::spawn_blocking(move || {
                    #[cfg(feature = "rocksdb")]
                    {
                        let _ = stake_backend.try_catch_up_with_primary();
                    }
                    let stake_by_lock = aggregate_stake_by_lock(stake_backend.as_ref());
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    StakeCache {
                        computed_at_unix: ts,
                        stake_by_lock,
                    }
                })
                .await;
                if let Ok(snap) = snap_res {
                    *stake_cache.write().await = snap;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    info!(%addr, store_dir = %store_dir.display(), "starting status_http");
    let listener = TcpListener::bind(&addr).await?;
    let sem = Arc::new(Semaphore::new(32));
    if cli.auth_token.is_some() && cli.auth_token_file.is_some() {
        anyhow::bail!("auth_token und auth_token_file koennen nicht gleichzeitig gesetzt sein");
    }
    if !cfg!(debug_assertions) && cli.auth_token.is_some() && cli.auth_token_file.is_none() {
        anyhow::bail!(
            "--auth-token ist in Release-Builds deaktiviert (Token-Leak via Prozessliste). Nutze --auth-token-file."
        );
    }
    let auth_token = if let Some(path) = cli.auth_token_file.as_ref() {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read auth_token_file {}", path.display()))?;
        let t = raw.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    } else {
        cli.auth_token
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let store_dir = Arc::new(store_dir);

    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(%peer, "too many connections");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        let stake_cache = stake_cache.clone();
        let auth_token = auth_token.clone();
        let store_dir = store_dir.clone();

        tokio::spawn(async move {
            let _permit = permit;

            let tls_stream =
                match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!(%peer, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        warn!(%peer, "TLS handshake timeout");
                        return;
                    }
                };

            let svc = service_fn(move |req: Request<Body>| {
                let state = state.clone();
                let stake_cache = stake_cache.clone();
                let auth = auth_token.clone();
                let store_dir = store_dir.clone();
                async move {
                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        handle(req, store_dir, state, stake_cache, auth.as_deref()),
                    )
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

            if let Err(e) = Http::new().serve_connection(tls_stream, svc).await {
                warn!(%peer, error = %e, "serve_connection failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_http_src() -> &'static str {
        include_str!("status_http.rs")
    }

    #[test]
    fn f100_constant_time_eq_does_not_early_return_on_len_mismatch() {
        let src = status_http_src();
        let start = src
            .find("fn constant_time_eq")
            .expect("constant_time_eq missing");
        let end = src[start..]
            .find("fn content_type_is_octet_stream")
            .map(|rel| start + rel)
            .unwrap_or(src.len());
        let body = &src[start..end];
        assert!(
            body.contains("max_len = aa.len().max(bb.len())"),
            "expected constant_time_eq to iterate up to max_len"
        );
        assert!(
            body.contains("for i in 0..max_len") && body.contains("unwrap_or(&0)"),
            "expected constant_time_eq to avoid indexing panics and length early-returns"
        );
        assert!(
            !body.contains("len() != ") || !body.contains("return false"),
            "expected no length-mismatch early return in constant_time_eq"
        );
    }

    #[test]
    fn f101_consensus_validators_uses_stake_cache_snapshot() {
        let src = status_http_src();
        assert!(
            src.contains("if req.method() == Method::GET && path == \"/consensus/validators\""),
            "expected /consensus/validators endpoint to exist"
        );
        assert!(
            src.contains("let stake_snapshot = stake_cache.read().await"),
            "expected /consensus/validators to use stake_cache snapshot (avoid full UTXO iteration under state mutex)"
        );
        assert!(
            src.contains("stake_snapshot.stake_by_lock"),
            "expected stake values to be read from stake_snapshot.stake_by_lock"
        );
    }

    #[test]
    fn f102_broadcast_endpoints_use_spawn_blocking_for_disk_io() {
        let src = status_http_src();
        // /tx/broadcast: atomic_write + journal_append must be bridged out of async context.
        assert!(
            src.contains("path == \"/tx/broadcast\"")
                && src.contains("tokio::task::spawn_blocking")
                && src.contains("move || atomic_write"),
            "expected /tx/broadcast persistence to use spawn_blocking(atomic_write)"
        );
        assert!(
            src.contains("path == \"/evidence/broadcast\"")
                && src.contains("tokio::task::spawn_blocking")
                && src.contains("move || journal_append"),
            "expected /evidence/broadcast journaling to use spawn_blocking(journal_append)"
        );
    }

    #[test]
    fn f104_aggregate_stake_by_lock_sums_and_counts_only_staked_utxos() {
        use pc_state::StateBackend as _;

        let mut b = pc_state::InMemoryBackend::new();
        let lock1 = LockCommitment([1u8; 32]);
        let lock2 = LockCommitment([2u8; 32]);

        let op1 = pc_types::OutPoint {
            txid: [3u8; 32],
            vout: 0,
        };
        b.put(op1, (10, lock1));
        b.set_staked(op1);

        let op2 = pc_types::OutPoint {
            txid: [3u8; 32],
            vout: 1,
        };
        b.put(op2, (5, lock1));
        // not staked

        let op3 = pc_types::OutPoint {
            txid: [4u8; 32],
            vout: 0,
        };
        b.put(op3, (7, lock2));
        b.set_staked(op3);

        let out = aggregate_stake_by_lock(&b);
        assert_eq!(out.get(&lock1.0).copied(), Some((10, 1)));
        assert_eq!(out.get(&lock2.0).copied(), Some((7, 1)));
    }

    #[test]
    fn f103_evidence_broadcast_rejects_unknown_offender() {
        let note = pc_types::GenesisNote {
            version: 0,
            network_name: b"test".to_vec(),
            seed: [1u8; 32],
            params: pc_types::GenesisParams {
                shards_initial: 1,
                committee_k: 1,
                txs_per_payload: 1,
                features: 0,
            },
            genesis_validators: Vec::new(),
            genesis_message: Vec::new(),
            emission_bootstrap_bucket: 0,
        };
        let nid = pc_types::digest_genesis_note(&note);
        let seed_anchor_now = [9u8; 32];

        let backend = pc_state::InMemoryBackend::new();

        let evid = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::SlashTicketV1 {
                offender_id: [7u8; 32],
                category: 1,
                slash_bp: 2500,
                vote_epoch: 1,
                seed_anchor: seed_anchor_now,
                slash_id: [6u8; 32],
                vote_mask: 1,
                reporter_lock: LockCommitment([8u8; 32]),
                agg_sig: [0u8; 96],
            },
        };

        let err =
            validate_evidence_against_state(&evid, &backend, &note, nid, seed_anchor_now, None)
                .unwrap_err();
        assert!(err.to_string().contains("unknown offender"));
    }

    #[test]
    fn f103_evidence_broadcast_rejects_bad_slash_ticket_signature() -> Result<()> {
        use pc_state::StateBackend as _;

        let note = pc_types::GenesisNote {
            version: 0,
            network_name: b"test".to_vec(),
            seed: [2u8; 32],
            params: pc_types::GenesisParams {
                shards_initial: 1,
                committee_k: 1,
                txs_per_payload: 1,
                features: 0,
            },
            genesis_validators: Vec::new(),
            genesis_message: Vec::new(),
            emission_bootstrap_bucket: 0,
        };
        let nid = pc_types::digest_genesis_note(&note);
        let seed_anchor_now = [9u8; 32];

        // Build a single eligible validator so committee selection is well-defined.
        let ikm = [3u8; 32];
        let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen"))?;
        let pop = pc_crypto::bls_pop_prove(&kp.sk);
        let validator_id = pc_crypto::attestor_recipient_id_from_bls(&kp.pk);
        let stake_lock = LockCommitment([4u8; 32]);
        let rec = pc_types::ValidatorRecordV1 {
            version: 1,
            stake_lock,
            sequence: 0,
            operator_id: [5u8; 32],
            bls_pk: kp.pk.to_bytes(),
            bls_pop: pop,
        };

        let mut backend = pc_state::InMemoryBackend::new();
        backend.put_validator_record(validator_id, rec);
        let staked_op = pc_types::OutPoint {
            txid: [7u8; 32],
            vout: 0,
        };
        backend.put(
            staked_op,
            (pc_consensus::consts::MIN_ATTESTOR_STAKE, stake_lock),
        );
        backend.set_staked(staked_op);

        let evid = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::SlashTicketV1 {
                offender_id: validator_id,
                category: 1,
                slash_bp: 2500,
                vote_epoch: 1,
                seed_anchor: seed_anchor_now,
                slash_id: [6u8; 32],
                vote_mask: 1,
                reporter_lock: LockCommitment([8u8; 32]),
                // Invalid on purpose.
                agg_sig: [0u8; 96],
            },
        };

        let err =
            validate_evidence_against_state(&evid, &backend, &note, nid, seed_anchor_now, None)
                .unwrap_err();
        assert!(err.to_string().contains("agg sig"));
        Ok(())
    }
}
