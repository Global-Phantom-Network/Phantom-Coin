use hyper::{Body, Response};
use pc_codec::Encodable;
use pc_consensus::{consts, current_emission_bucket, pow_hash, validate_mint_pow_bound_v1};
use pc_types::{
    validate_mint_sanity, LockCommitment, MintEvent, MintRoundPhase, MintStatus, MintTemplate,
    SubmitMintRequest, SubmitMintResponse, TxOut, MINT_VERSION_V2,
};
use std::time::{Duration, Instant};
use tracing::info;

fn active_target_bits(
    supply: &pc_consensus::SupplyState,
    round: &crate::MintRoundState,
    now_bucket: u64,
) -> u8 {
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
    supply: &pc_consensus::SupplyState,
    round: &crate::MintRoundState,
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

async fn load_mint_template_snapshot(
    mempool_dir: &str,
) -> (
    pc_consensus::SupplyState,
    crate::MintRoundState,
    u64,
    MintTemplatePollKey,
) {
    let supply_mutex = crate::global_supply_state(mempool_dir);
    let mut supply = supply_mutex.lock().await;
    crate::refresh_supply_state_from_disk(mempool_dir, &mut supply);
    let supply_snapshot = supply.clone();
    drop(supply);

    let now_bucket = current_emission_bucket();
    let round_mutex = crate::global_mint_round_state(mempool_dir);
    let mut round = round_mutex.lock().await;
    crate::refresh_mint_round_state_from_disk(mempool_dir, &supply_snapshot, &mut round);
    if round.reconcile_with_supply(&supply_snapshot, now_bucket) {
        crate::persist_mint_round_state_sync(mempool_dir, &round, false);
    }
    let round_snapshot = round.clone();
    drop(round);

    let poll_key = mint_template_poll_key(&supply_snapshot, &round_snapshot, now_bucket);
    (supply_snapshot, round_snapshot, now_bucket, poll_key)
}

fn cleanup_seed_marker(seed_marker: std::path::PathBuf) {
    let _ = std::thread::spawn(move || {
        let _ = std::fs::remove_file(seed_marker);
    });
}

pub(crate) async fn handle_mint_status(mempool_dir: &str) -> Response<Body> {
    let supply_mutex = crate::global_supply_state(mempool_dir);
    let mut supply = supply_mutex.lock().await;
    crate::refresh_supply_state_from_disk(mempool_dir, &mut supply);
    let now_bucket = current_emission_bucket();
    let round_mutex = crate::global_mint_round_state(mempool_dir);
    let mut round = round_mutex.lock().await;
    crate::refresh_mint_round_state_from_disk(mempool_dir, &supply, &mut round);
    if round.reconcile_with_supply(&supply, now_bucket) {
        crate::persist_mint_round_state_sync(mempool_dir, &round, false);
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
    let body = match serde_json::to_string(&status) {
        Ok(b) => b,
        Err(_) => {
            let mut resp = Response::new(Body::from("{\"error\":\"serialization error\"}"));
            *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return resp;
        }
    };
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = hyper::StatusCode::OK;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

pub(crate) async fn handle_mint_template(
    mempool_dir: &str,
    network_id: Option<[u8; 32]>,
    longpoll: bool,
    prev_mint_id: Option<[u8; 32]>,
    timeout_ms: Option<u64>,
) -> Response<Body> {
    let nid = match network_id {
        Some(n) => n,
        None => {
            let resp_body =
                serde_json::json!({"error": "network_id not configured (genesis_note missing)"})
                    .to_string();
            let mut resp = Response::new(Body::from(resp_body));
            *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return resp;
        }
    };
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
            let (_, _, _, initial_key) = load_mint_template_snapshot(mempool_dir).await;
            loop {
                let (_, _, _, current_key) = load_mint_template_snapshot(mempool_dir).await;
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
    let (supply, round, now_bucket, _) = load_mint_template_snapshot(mempool_dir).await;
    let template = MintTemplate {
        prev_mint_id: hex::encode(supply.last_mint_id),
        target_bits: active_target_bits(&supply, &round, now_bucket),
        reward: supply.next_reward(),
        mint_height: supply.mint_height,
        total_supply: supply.total_supply.to_string(),
        remaining_supply: supply.remaining_supply().to_string(),
        network_id: hex::encode(nid),
        phase: round.phase,
        round_id: hex::encode(round.round_id),
        hit_bucket: round.frozen_hit_bucket,
        bits_used: round.frozen_bits,
        collect_deadline_bucket: round.collection_deadline_bucket,
        finalize_deadline_bucket: round.finalize_deadline_bucket,
    };
    let body = match serde_json::to_string(&template) {
        Ok(b) => b,
        Err(_) => {
            let mut resp = Response::new(Body::from("{\"error\":\"serialization error\"}"));
            *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            return resp;
        }
    };
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = hyper::StatusCode::OK;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

pub(crate) async fn handle_mint_submit(
    mempool_dir: &str,
    network_id: Option<[u8; 32]>,
    body_bytes: hyper::body::Bytes,
    do_fsync: bool,
) -> Response<Body> {
    fn mint_error(status: hyper::StatusCode, msg: &str) -> Response<Body> {
        let resp_body = SubmitMintResponse {
            ok: false,
            mint_id: None,
            error: Some(msg.to_string()),
        };
        let body = serde_json::to_string(&resp_body).unwrap_or_default();
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        resp
    }

    if body_bytes.len() > crate::MAX_HTTP_BODY_BYTES {
        return mint_error(hyper::StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    }

    let submit_req: SubmitMintRequest = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return mint_error(
                hyper::StatusCode::BAD_REQUEST,
                &format!("invalid json: {}", e),
            );
        }
    };
    let mint_json = submit_req.mint;

    let prev_mint_id: [u8; 32] = match hex::decode(&mint_json.prev_mint_id) {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => return mint_error(hyper::StatusCode::BAD_REQUEST, "invalid prev_mint_id"),
    };

    let pow_seed: [u8; 32] = match hex::decode(&mint_json.pow_seed) {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => return mint_error(hyper::StatusCode::BAD_REQUEST, "invalid pow_seed"),
    };
    let round_id = match &mint_json.round_id {
        Some(v) => match hex::decode(v) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return mint_error(hyper::StatusCode::BAD_REQUEST, "invalid round_id"),
        },
        None => [0u8; 32],
    };

    let mut outputs: Vec<TxOut> = Vec::with_capacity(mint_json.outputs.len());
    for out_json in &mint_json.outputs {
        let lock_bytes: [u8; 32] = match hex::decode(&out_json.lock) {
            Ok(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                arr
            }
            _ => return mint_error(hyper::StatusCode::BAD_REQUEST, "invalid output lock"),
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
        round_id,
        hit_bucket: mint_json.hit_bucket.unwrap_or(0),
        bits_used: mint_json.bits_used.unwrap_or(0),
    };

    let nid = match network_id {
        Some(n) => n,
        None => {
            return mint_error(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "network_id not configured",
            );
        }
    };

    // Hold the supply lock only while taking a consistent snapshot; do not block
    // the state task (finalization) on filesystem operations.
    let now_bucket = current_emission_bucket();
    let supply_mutex = crate::global_supply_state(mempool_dir);
    let mut supply_guard = supply_mutex.lock().await;
    crate::refresh_supply_state_from_disk(mempool_dir, &mut supply_guard);
    let expected_mint_height = supply_guard.mint_height.saturating_add(1);
    let supply_snapshot = supply_guard.clone();
    drop(supply_guard);
    let round_mutex = crate::global_mint_round_state(mempool_dir);
    let mut round_guard = round_mutex.lock().await;
    crate::refresh_mint_round_state_from_disk(mempool_dir, &supply_snapshot, &mut round_guard);
    if round_guard.reconcile_with_supply(&supply_snapshot, now_bucket) {
        crate::persist_mint_round_state_sync(mempool_dir, &round_guard, do_fsync);
    }
    if mint.prev_mint_id != supply_snapshot.last_mint_id {
        return mint_error(
            hyper::StatusCode::CONFLICT,
            "prev_mint_id does not match chain tip - stale template",
        );
    }

    let (bits, round_phase) = match round_guard.phase {
        MintRoundPhase::Searching => {
            if mint.version < MINT_VERSION_V2 {
                return mint_error(
                    hyper::StatusCode::BAD_REQUEST,
                    "mint v2 required for emission rounds",
                );
            }
            if mint.round_id != round_guard.round_id {
                return mint_error(hyper::StatusCode::CONFLICT, "round_id mismatch");
            }
            if mint.hit_bucket > now_bucket.saturating_add(consts::EMISSION_MAX_FUTURE_SKEW_BUCKETS)
            {
                return mint_error(
                    hyper::StatusCode::BAD_REQUEST,
                    "hit_bucket too far in future",
                );
            }
            let expected_bits = supply_snapshot.expected_bits_for_bucket(mint.hit_bucket);
            if mint.bits_used != expected_bits {
                return mint_error(hyper::StatusCode::BAD_REQUEST, "bits_used mismatch");
            }
            (expected_bits, MintRoundPhase::Searching)
        }
        MintRoundPhase::Collecting => {
            if mint.version < MINT_VERSION_V2 {
                return mint_error(
                    hyper::StatusCode::BAD_REQUEST,
                    "mint v2 required while round is collecting",
                );
            }
            if mint.round_id != round_guard.round_id
                || Some(mint.hit_bucket) != round_guard.frozen_hit_bucket
                || Some(mint.bits_used) != round_guard.frozen_bits
            {
                return mint_error(
                    hyper::StatusCode::CONFLICT,
                    "mint does not match frozen round",
                );
            }
            if round_guard
                .finalize_deadline_bucket
                .is_some_and(|deadline| now_bucket > deadline)
            {
                round_guard.reset_from_supply(&supply_snapshot);
                crate::persist_mint_round_state_sync(mempool_dir, &round_guard, do_fsync);
                return mint_error(hyper::StatusCode::CONFLICT, "collecting round expired");
            }
            (
                round_guard.frozen_bits.unwrap_or(supply_snapshot.pow_bits),
                MintRoundPhase::Collecting,
            )
        }
    };

    if validate_mint_pow_bound_v1(&nid, &mint, bits).is_err() {
        return mint_error(
            hyper::StatusCode::BAD_REQUEST,
            "pow validation failed: seed not bound or difficulty not met",
        );
    }

    let role_policy = match crate::global_role_policy(mempool_dir) {
        Ok(p) => p,
        Err(e) => {
            return mint_error(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &format!("role_policy error: {e}"),
            );
        }
    };
    if let Some(policy) = role_policy.as_ref() {
        if !policy.allows_mint(&mint) {
            return mint_error(
                hyper::StatusCode::BAD_REQUEST,
                "mint rejected by role_policy",
            );
        }
    }

    let seed_hex = hex::encode(pow_seed);
    let seeds_dir = std::path::Path::new(mempool_dir).join("mint_seeds");
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
            return mint_error(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &format!("seed reservation failed: {}", e),
            );
        }
        Err(_) => {
            return mint_error(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                "seed reservation failed",
            );
        }
    };
    if !reserved {
        return mint_error(hyper::StatusCode::BAD_REQUEST, "seed already used");
    }

    if validate_mint_sanity(&mint).is_err() {
        cleanup_seed_marker(seed_marker.clone());
        return mint_error(hyper::StatusCode::BAD_REQUEST, "mint sanity failed");
    }

    if let Err(e) = supply_snapshot.validate_mint(&mint) {
        cleanup_seed_marker(seed_marker.clone());
        return mint_error(
            hyper::StatusCode::BAD_REQUEST,
            &format!("mint validation failed: {:?}", e),
        );
    }

    let id = pc_types::digest_mint(&mint);
    info!(
        mint_id = %hex::encode(id),
        mint_height = expected_mint_height,
        "mint_submitted"
    );
    let mdir = std::path::Path::new(mempool_dir).join("mints");
    let _ = tokio::task::spawn_blocking({
        let d = mdir.clone();
        move || std::fs::create_dir_all(&d)
    })
    .await;
    let mpath = mdir.join(format!("{}.bin", hex::encode(id)));
    let mut buf = Vec::new();
    if let Err(e) = mint.encode(&mut buf) {
        cleanup_seed_marker(seed_marker.clone());
        return mint_error(
            hyper::StatusCode::INTERNAL_SERVER_ERROR,
            &format!("encode mint: {}", e),
        );
    }
    if let Err(e) = crate::atomic_write_async(&mpath, buf.clone(), do_fsync).await {
        cleanup_seed_marker(seed_marker.clone());
        return mint_error(
            hyper::StatusCode::INTERNAL_SERVER_ERROR,
            &format!("persist mint: {}", e),
        );
    }

    let pow = pow_hash(&mint.pow_seed, mint.pow_nonce);
    match round_phase {
        MintRoundPhase::Searching => {
            round_guard.phase = MintRoundPhase::Collecting;
            round_guard.frozen_hit_bucket = Some(mint.hit_bucket);
            round_guard.frozen_bits = Some(mint.bits_used);
            round_guard.collection_deadline_bucket =
                Some(consts::emission_collect_deadline_bucket(mint.hit_bucket));
            round_guard.finalize_deadline_bucket =
                Some(consts::emission_finalize_deadline_bucket(mint.hit_bucket));
            round_guard.best_candidate_id = Some(id);
            round_guard.best_pow_hash = Some(pow);
        }
        MintRoundPhase::Collecting => {
            let replace = match (round_guard.best_pow_hash, round_guard.best_candidate_id) {
                (Some(prev_pow), Some(prev_id)) => {
                    crate::mint_candidate_runtime::candidate_replaces_existing_best(
                        &pow, &id, &id, &prev_pow, &prev_id, &prev_id,
                    )
                }
                _ => true,
            };
            if replace {
                round_guard.best_candidate_id = Some(id);
                round_guard.best_pow_hash = Some(pow);
            }
        }
    }
    crate::persist_mint_round_state_sync(mempool_dir, &round_guard, do_fsync);

    let resp_body = SubmitMintResponse {
        ok: true,
        mint_id: Some(hex::encode(id)),
        error: None,
    };
    let body = serde_json::to_string(&resp_body).unwrap_or_default();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = hyper::StatusCode::OK;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

pub(crate) fn handle_mint_status_by_id(mempool_dir: &str, id_hex: &str) -> Response<Body> {
    let mpath = std::path::Path::new(mempool_dir)
        .join("mints")
        .join(format!("{}.bin", id_hex));
    let found = mpath.exists();
    let body = serde_json::json!({"ok": true, "found": found}).to_string();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = hyper::StatusCode::OK;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}
