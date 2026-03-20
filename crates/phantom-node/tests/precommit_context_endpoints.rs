#![forbid(unsafe_code)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use pc_codec::Encodable;
use pc_consensus::{compute_total_payout_root, FeeSplitParams};
use pc_crypto::{attestor_recipient_id_from_bls, bls_keygen_from_ikm, bls_pop_prove};
use pc_state::{InMemoryBackend, UtxoState};
use pc_types::{
    digest_genesis_note, genesis_payload_root, AnchorId, AnchorPayloadV3, EvidenceEvent,
    EvidenceKind, GenesisNote, GenesisParams, GenesisValidatorV1, LockCommitment, MicroTx,
    MintCandidateEvent, OutPoint, TxIn, TxOut, GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
    TX_VERSION_TRANSFER_V1,
};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use tempfile::TempDir;

static PRECOMMIT_CONTEXT_ENDPOINTS_SERIAL: Lazy<Arc<tokio::sync::Mutex<()>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(())));

#[derive(Debug, Deserialize)]
struct LocalPrevoteContextResp {
    ok: bool,
    network_id: String,
    payload_root: String,
    next_anchor_index: u64,
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
}

#[derive(Debug, Deserialize)]
struct LocalPrecommitContextResp {
    ok: bool,
    network_id: String,
    payload_root: String,
    next_anchor_index: u64,
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
    post_state_root: String,
}

#[derive(Debug, Deserialize)]
struct PrecommitStateRootResp {
    ok: bool,
    payload_root: String,
    creator_index: u8,
    post_state_root: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResp {
    ok: bool,
    error: String,
    detail: Option<String>,
}

struct LivePrecommitServer {
    _temp_dir: TempDir,
    _serial_guard: tokio::sync::OwnedMutexGuard<()>,
    child: Child,
    addr: String,
    token: String,
    network_id: [u8; 32],
    payload_root: [u8; 32],
    bls_pk_hex: String,
    expected_state_root: [u8; 32],
}

#[derive(Clone, Copy)]
enum GenesisNoteMode {
    Present,
    InvalidCommitteeK,
}

#[derive(Clone, Copy)]
enum PayloadMode {
    Bootstrap,
    InvalidMicroTx,
    MintCandidateEvidence,
}

impl Drop for LivePrecommitServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| anyhow!("reqwest client build failed: {e}"))
}

async fn wait_ready(client: &Client, addr: &str, child: &mut Child, secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(anyhow!("status-serve exited early: {status}"));
        }
        if Instant::now() > deadline {
            return Err(anyhow!("status-serve not ready in time"));
        }
        match client.get(format!("http://{addr}/readyz")).send().await {
            Ok(resp) if resp.status() == StatusCode::OK => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

fn bootstrap_genesis(kp: &pc_crypto::BlsKeypair) -> GenesisNote {
    GenesisNote {
        version: 1,
        network_name: b"pc-precommit-e2e".to_vec(),
        seed: [0x44; 32],
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![GenesisValidatorV1 {
            operator_id: [0x55; 32],
            bls_pk: kp.pk.to_bytes(),
            bls_pop: bls_pop_prove(&kp.sk),
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    }
}

fn persist_bootstrap_genesis(mempool_dir: &Path, note: &GenesisNote) -> Result<()> {
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::create_dir_all(mempool_dir)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;
    let store_dir = mempool_dir
        .parent()
        .ok_or_else(|| anyhow!("mempool_dir must have parent"))?;
    std::fs::write(
        store_dir.join("last_final_payload_root"),
        hex::encode(genesis_payload_root(&note)),
    )?;
    Ok(())
}

fn expected_bootstrap_payout_root(kp: &pc_crypto::BlsKeypair) -> Result<[u8; 32]> {
    let params = FeeSplitParams::recommended();
    let recipients = [attestor_recipient_id_from_bls(&kp.pk)];
    let ack_distances = [None];
    compute_total_payout_root(0, &params, &recipients, 0, &ack_distances, &[])
        .map_err(|e| anyhow!("payout root compute failed: {e:?}"))
}

fn write_legacy_payload_v3(store_dir: &Path, payload: &AnchorPayloadV3) -> Result<[u8; 32]> {
    let payload_root = pc_types::payload_merkle_root_v3(payload);
    let payloads_dir = store_dir.join("payloads");
    std::fs::create_dir_all(&payloads_dir)?;
    let mut buf = Vec::new();
    payload.encode(&mut buf)?;
    std::fs::write(
        payloads_dir.join(format!("{}.bin", hex::encode(payload_root))),
        buf,
    )?;
    Ok(payload_root)
}

fn payload_for_mode(
    note: GenesisNote,
    kp: &pc_crypto::BlsKeypair,
    payload_mode: PayloadMode,
) -> Result<AnchorPayloadV3> {
    match payload_mode {
        PayloadMode::Bootstrap => Ok(AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: expected_bootstrap_payout_root(kp)?,
            genesis_note: Some(note),
            null_mint: false,
        }),
        PayloadMode::InvalidMicroTx => Ok(AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![MicroTx {
                version: TX_VERSION_TRANSFER_V1,
                inputs: vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0x71; 32],
                        vout: 0,
                    },
                    witness: vec![0x11; 32],
                }],
                outputs: vec![TxOut {
                    amount: 1,
                    lock: LockCommitment([0x22; 32]),
                }],
            }],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: expected_bootstrap_payout_root(kp)?,
            genesis_note: Some(note),
            null_mint: false,
        }),
        PayloadMode::MintCandidateEvidence => Ok(AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![EvidenceEvent {
                version: 1,
                evidence: EvidenceKind::MintCandidateV1 {
                    candidate: MintCandidateEvent {
                        version: 1,
                        network_id: digest_genesis_note(&note),
                        prev_mint_id: genesis_payload_root(&note),
                        window_id: 0,
                        window_open_anchor_id: AnchorId(genesis_payload_root(&note)).0,
                        mint_commitment: [0x44; 32],
                        nonce: 7,
                        work_id: None,
                        miner_pubkey: None,
                        recipient_lock: None,
                    },
                },
            }],
            payout_root: expected_bootstrap_payout_root(kp)?,
            genesis_note: Some(note),
            null_mint: false,
        }),
    }
}

async fn spawn_live_precommit_server_with_modes(
    genesis_note_mode: GenesisNoteMode,
    payload_mode: PayloadMode,
) -> Result<LivePrecommitServer> {
    let serial_guard = PRECOMMIT_CONTEXT_ENDPOINTS_SERIAL
        .clone()
        .lock_owned()
        .await;
    let temp_dir = TempDir::new()?;
    let store_dir = temp_dir.path().to_path_buf();
    let mempool_dir = store_dir.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;
    std::fs::write(store_dir.join("anchor_index"), b"0")?;

    let ikm = [0x91u8; 32];
    let kp = bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let mut note = bootstrap_genesis(&kp);
    if matches!(genesis_note_mode, GenesisNoteMode::InvalidCommitteeK) {
        note.params.committee_k = 0;
    }
    persist_bootstrap_genesis(&mempool_dir, &note)?;
    let network_id = digest_genesis_note(&note);
    let payload = payload_for_mode(note, &kp, payload_mode)?;
    let payload_root = write_legacy_payload_v3(&store_dir, &payload)?;
    let expected_state_root = UtxoState::new(InMemoryBackend::new()).root();
    let token = "precommit-secret".to_string();
    let token_file = store_dir.join("status.token");
    std::fs::write(&token_file, format!("{token}\n"))?;

    let addr = format!("127.0.0.1:{}", free_port()?);
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("phantom-node"))
        .arg("status-serve")
        .arg("--addr")
        .arg(&addr)
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .arg("--store-dir")
        .arg(store_dir.to_string_lossy().to_string())
        .arg("--auth-token-file")
        .arg(token_file.to_string_lossy().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let client = http_client()?;
    wait_ready(&client, &addr, &mut child, 20).await?;

    Ok(LivePrecommitServer {
        _temp_dir: temp_dir,
        _serial_guard: serial_guard,
        child,
        addr,
        token,
        network_id,
        payload_root,
        bls_pk_hex: hex::encode(kp.pk.to_bytes()),
        expected_state_root,
    })
}

async fn spawn_live_precommit_server() -> Result<LivePrecommitServer> {
    spawn_live_precommit_server_with_modes(GenesisNoteMode::Present, PayloadMode::Bootstrap).await
}

async fn get_text(
    client: &Client,
    addr: &str,
    path: &str,
    token: Option<&str>,
) -> Result<(StatusCode, String)> {
    let url = format!("http://{addr}{path}");
    let mut req = client.get(url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow!("request failed: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow!("read response body failed: {e}"))?;
    Ok((status, body))
}

#[tokio::test]
async fn local_prevote_context_live_returns_authoritative_context() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/local_prevote_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        server.bls_pk_hex
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::OK);
    let resp: LocalPrevoteContextResp = serde_json::from_str(&body)?;
    assert!(resp.ok);
    assert_eq!(resp.network_id, hex::encode(server.network_id));
    assert_eq!(resp.payload_root, hex::encode(server.payload_root));
    assert_eq!(resp.next_anchor_index, 1);
    assert_eq!(resp.vote_epoch, 0);
    assert_eq!(resp.creator_index, 0);
    assert_eq!(resp.vote_mask, 1);
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_live_returns_authoritative_context() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        server.bls_pk_hex
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::OK);
    let resp: LocalPrecommitContextResp = serde_json::from_str(&body)?;
    assert!(resp.ok);
    assert_eq!(resp.network_id, hex::encode(server.network_id));
    assert_eq!(resp.payload_root, hex::encode(server.payload_root));
    assert_eq!(resp.next_anchor_index, 1);
    assert_eq!(resp.vote_epoch, 0);
    assert_eq!(resp.creator_index, 0);
    assert_eq!(resp.vote_mask, 1);
    assert_eq!(
        resp.post_state_root,
        hex::encode(server.expected_state_root)
    );
    Ok(())
}

#[tokio::test]
async fn local_prevote_context_allows_mint_censor_evidence_payloads() -> Result<()> {
    let server = spawn_live_precommit_server_with_modes(
        GenesisNoteMode::Present,
        PayloadMode::MintCandidateEvidence,
    )
    .await?;
    let client = http_client()?;
    let prevote_path = format!(
        "/consensus/local_prevote_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        server.bls_pk_hex
    );
    let (prevote_status, prevote_body) =
        get_text(&client, &server.addr, &prevote_path, Some(&server.token)).await?;

    assert_eq!(prevote_status, StatusCode::OK);
    let prevote_resp: LocalPrevoteContextResp = serde_json::from_str(&prevote_body)?;
    assert!(prevote_resp.ok);
    assert_eq!(prevote_resp.payload_root, hex::encode(server.payload_root));

    let precommit_path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        server.bls_pk_hex
    );
    let (precommit_status, precommit_body) =
        get_text(&client, &server.addr, &precommit_path, Some(&server.token)).await?;

    assert_eq!(precommit_status, StatusCode::OK);
    let precommit_resp: LocalPrecommitContextResp = serde_json::from_str(&precommit_body)?;
    assert!(precommit_resp.ok);
    assert_eq!(
        precommit_resp.payload_root,
        hex::encode(server.payload_root)
    );
    assert_eq!(
        precommit_resp.post_state_root,
        hex::encode(server.expected_state_root)
    );
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_allows_mint_censor_evidence_payloads() -> Result<()> {
    let server = spawn_live_precommit_server_with_modes(
        GenesisNoteMode::Present,
        PayloadMode::MintCandidateEvidence,
    )
    .await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=0",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::OK);
    let resp: PrecommitStateRootResp = serde_json::from_str(&body)?;
    assert!(resp.ok);
    assert_eq!(resp.payload_root, hex::encode(server.payload_root));
    assert_eq!(resp.creator_index, 0);
    assert_eq!(
        resp.post_state_root,
        hex::encode(server.expected_state_root)
    );
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_live_returns_authoritative_state_root() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=0",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::OK);
    let resp: PrecommitStateRootResp = serde_json::from_str(&body)?;
    assert!(resp.ok);
    assert_eq!(resp.payload_root, hex::encode(server.payload_root));
    assert_eq!(resp.creator_index, 0);
    assert_eq!(
        resp.post_state_root,
        hex::encode(server.expected_state_root)
    );
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_requires_auth() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        server.bls_pk_hex
    );
    let (status, body) = get_text(&client, &server.addr, &path, None).await?;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "unauthorized");
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_rejects_invalid_payload_root() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/local_precommit_context?payload_root=abcd&bls_pk={}",
        server.bls_pk_hex
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "payload_root_invalid");
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_rejects_missing_bls_pk() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "bls_pk_invalid");
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_returns_precheck_failed_for_non_committee_bls_pk() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let other_kp =
        bls_keygen_from_ikm(&[0x92u8; 32]).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        hex::encode(other_kp.pk.to_bytes())
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "local_precommit_precheck_failed");
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_returns_service_unavailable_for_invalid_committee_k() -> Result<()>
{
    let server = spawn_live_precommit_server_with_modes(
        GenesisNoteMode::InvalidCommitteeK,
        PayloadMode::Bootstrap,
    )
    .await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        server.bls_pk_hex
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "local_precommit_precheck_failed");
    assert!(resp
        .detail
        .as_deref()
        .is_some_and(|detail| detail.starts_with("committee_k_invalid:")));
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_returns_context_failed_for_state_invalid_payload() -> Result<()> {
    let server = spawn_live_precommit_server_with_modes(
        GenesisNoteMode::Present,
        PayloadMode::InvalidMicroTx,
    )
    .await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(server.payload_root),
        server.bls_pk_hex
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "local_precommit_context_failed");
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_rejects_invalid_creator_index() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=abc",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "creator_index_invalid");
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_returns_precheck_failed_for_out_of_range_creator_index() -> Result<()>
{
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=1",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "precommit_precheck_failed");
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_returns_service_unavailable_for_invalid_committee_k() -> Result<()> {
    let server = spawn_live_precommit_server_with_modes(
        GenesisNoteMode::InvalidCommitteeK,
        PayloadMode::Bootstrap,
    )
    .await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=0",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "precommit_precheck_failed");
    assert!(resp
        .detail
        .as_deref()
        .is_some_and(|detail| detail.starts_with("committee_k_invalid:")));
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_returns_context_failed_for_state_invalid_payload() -> Result<()> {
    let server = spawn_live_precommit_server_with_modes(
        GenesisNoteMode::Present,
        PayloadMode::InvalidMicroTx,
    )
    .await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=0",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "precommit_context_failed");
    Ok(())
}

#[tokio::test]
async fn local_precommit_context_returns_payload_unavailable_for_unknown_root() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let missing_root = [0x77u8; 32];
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(missing_root),
        server.bls_pk_hex
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "payload_unavailable");
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_returns_payload_unavailable_for_unknown_root() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let missing_root = [0x78u8; 32];
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=0",
        hex::encode(missing_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, Some(&server.token)).await?;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "payload_unavailable");
    Ok(())
}

#[tokio::test]
async fn precommit_state_root_requires_auth() -> Result<()> {
    let server = spawn_live_precommit_server().await?;
    let client = http_client()?;
    let path = format!(
        "/consensus/precommit_state_root?payload_root={}&creator_index=0",
        hex::encode(server.payload_root)
    );
    let (status, body) = get_text(&client, &server.addr, &path, None).await?;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let resp: ErrorResp = serde_json::from_str(&body)?;
    assert!(!resp.ok);
    assert_eq!(resp.error, "unauthorized");
    Ok(())
}
