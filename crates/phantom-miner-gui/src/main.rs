// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Phantom Miner GUI - Terminal-basierte Mining-Oberfläche
//!
//! Features:
//! - Echtzeit-Hashrate-Anzeige
//! - Gefundene Blöcke / Mints
//! - Node-Verbindungsstatus
//! - Multi-Thread Mining

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::collections::VecDeque;

use futures_util::StreamExt as _;
use serde::de::DeserializeOwned;

use pc_consensus::{current_emission_bucket, mint_pow_seed_v2, pow_hash, pow_meets};
use pc_types::{
    LockCommitment, MintEvent, MintEventJson, MintRoundPhase, MintTemplate, SubmitMintRequest,
    SubmitMintResponse, TxOut, TxOutJson, MINT_VERSION_V2,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "phantom-miner-gui", version, about = "Phantom Mining GUI")]
struct Cli {
    /// Node-URL (z.B. http://127.0.0.1:8080)
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node_url: String,

    /// Anzahl Mining-Threads
    #[arg(long, short = 't', default_value_t = num_cpus())]
    threads: usize,

    /// Ziel-Adresse für geminte Coins (hex, 32 bytes)
    #[arg(long, required = true)]
    address: String,

    /// Mining-Schwierigkeit (führende Null-Bits)
    #[arg(long, default_value_t = 16)]
    difficulty: u8,

    /// TLS: CA-Zertifikat (PEM) für Server-Verifikation (CA-Pinning)
    #[arg(long)]
    tls_ca: Option<PathBuf>,

    /// TLS: Client-Zertifikat inkl. Key (PEM) für mTLS
    #[arg(long)]
    tls_client_pem: Option<PathBuf>,

    /// TLS (UNSAFE): Überspringt Server-Zertifikatsprüfung (nur Loopback). Nur für Debug/Tests.
    #[arg(long)]
    insecure_skip_tls_verify: bool,
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn is_local_url(url: &str) -> bool {
    let trimmed = url.trim();
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    if let Ok(parsed) = reqwest::Url::parse(&with_scheme) {
        if let Some(host) = parsed.host_str() {
            return is_local_host(host);
        }
    }
    let raw = trimmed
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = raw.split('/').next().unwrap_or(raw);
    let host = host.split(':').next().unwrap_or(host);
    is_local_host(host)
}

const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BODY_SNIPPET_CHARS: usize = 1024;

fn content_type_from_response(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn body_snippet_lossy(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let mut snippet: String = raw.chars().take(MAX_BODY_SNIPPET_CHARS).collect();
    snippet = snippet.replace('\n', "\\n");
    snippet = snippet.replace('\r', "\\r");
    snippet
}

async fn read_response_bytes_limited(resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(anyhow!(
                "HTTP response too large (content-length {} > limit {})",
                len,
                max_bytes
            ));
        }
    }
    let mut out: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read HTTP response chunk")?;
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(anyhow!(
                "HTTP response too large (read {} > limit {})",
                out.len().saturating_add(chunk.len()),
                max_bytes
            ));
        }
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn read_self_source() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("main.rs");
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    fn f54_cli_requires_address() {
        let err = Cli::try_parse_from(["phantom-miner-gui"]).err();
        assert!(err.is_some(), "missing --address must be an error");
    }

    #[test]
    fn f57_logs_do_not_use_vec_remove_0_and_use_vecdeque() {
        let src = read_self_source();
        let needle_remove0 = ["remove", "(", "0", ")"].concat();
        assert!(
            !src.contains(&needle_remove0),
            "logs should not use Vec::remove at index 0 (O(n))"
        );
        assert!(
            src.contains("VecDeque"),
            "expected VecDeque to be used for bounded logs"
        );
        assert!(
            src.contains("pop_front"),
            "expected pop_front eviction for bounded logs"
        );
    }

    #[test]
    fn f50_no_tokio_runtime_is_created_in_the_mining_loop() {
        let src = read_self_source();
        let needle_tokio_runtime = ["tokio", "::", "runtime", "::", "Runtime"].concat();
        assert!(
            !src.contains(&needle_tokio_runtime),
            "mining loop should not create tokio runtimes per iteration"
        );
    }
}

async fn read_json_limited<T: DeserializeOwned>(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<T> {
    let status = resp.status();
    let ct = content_type_from_response(&resp).unwrap_or_else(|| "<missing>".to_string());
    let data = read_response_bytes_limited(resp, max_bytes).await?;
    serde_json::from_slice(&data).with_context(|| {
        let snippet = body_snippet_lossy(&data);
        format!("parse json (http {status}, content-type {ct}, body_snippet={snippet})")
    })
}

fn build_http_client(
    node_url: &str,
    tls_ca: Option<&PathBuf>,
    tls_client_pem: Option<&PathBuf>,
    insecure_skip_tls_verify: bool,
    timeout: Duration,
) -> Result<reqwest::Client> {
    if insecure_skip_tls_verify {
        if tls_ca.is_some() {
            return Err(anyhow!(
                "--insecure-skip-tls-verify kann nicht zusammen mit --tls-ca genutzt werden"
            ));
        }
        if !is_local_url(node_url) {
            return Err(anyhow!(
                "refusing to skip TLS verification for non-loopback host: {}",
                node_url
            ));
        }
    }
    let allow_insecure = insecure_skip_tls_verify;
    let connect_timeout = std::cmp::min(timeout, Duration::from_secs(5));
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(allow_insecure)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(connect_timeout);
    if let Some(ca_path) = tls_ca {
        let data = std::fs::read(ca_path)
            .map_err(|e| anyhow!("read tls_ca {}: {}", ca_path.display(), e))?;
        let cert = reqwest::Certificate::from_pem(&data).context("parse tls_ca pem")?;
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert);
    }
    if let Some(pem_path) = tls_client_pem {
        let data = std::fs::read(pem_path)
            .map_err(|e| anyhow!("read tls_client_pem {}: {}", pem_path.display(), e))?;
        let id = reqwest::Identity::from_pem(&data).context("parse tls_client pem")?;
        builder = builder.identity(id);
    }
    builder.build().context("build http client")
}

#[derive(Debug, Clone)]
struct MinerState {
    // Statistiken
    total_hashes: Arc<AtomicU64>,
    valid_shares: Arc<AtomicU64>,
    rejected_shares: Arc<AtomicU64>,

    // Status
    is_mining: Arc<AtomicBool>,
    is_connected: Arc<AtomicBool>,

    // Konfiguration
    threads: usize,
    difficulty: u8,
    node_url: String,
    address: [u8; 32],
    tls_ca: Option<PathBuf>,
    tls_client_pem: Option<PathBuf>,
    insecure_skip_tls_verify: bool,

    // Aktueller Seed
    current_seed: Arc<RwLock<[u8; 32]>>,
}

impl MinerState {
    fn new(
        threads: usize,
        difficulty: u8,
        node_url: String,
        address: [u8; 32],
        tls_ca: Option<PathBuf>,
        tls_client_pem: Option<PathBuf>,
        insecure_skip_tls_verify: bool,
    ) -> Self {
        Self {
            total_hashes: Arc::new(AtomicU64::new(0)),
            valid_shares: Arc::new(AtomicU64::new(0)),
            rejected_shares: Arc::new(AtomicU64::new(0)),
            is_mining: Arc::new(AtomicBool::new(false)),
            is_connected: Arc::new(AtomicBool::new(false)),
            threads,
            difficulty,
            node_url,
            address,
            tls_ca,
            tls_client_pem,
            insecure_skip_tls_verify,
            current_seed: Arc::new(RwLock::new([0u8; 32])),
        }
    }

    fn hashrate(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs <= 0.0 {
            return 0.0;
        }
        self.total_hashes.load(Ordering::Relaxed) as f64 / elapsed_secs
    }
}

#[derive(Debug, Clone)]
struct MiningTemplate {
    prev_mint_id: [u8; 32],
    round_id: [u8; 32],
    hit_bucket: u64,
    bits_used: u8,
    target_bits: u8,
    reward: u64,
    mint_height: u64,
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    match hex::decode(s) {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            Some(arr)
        }
        _ => None,
    }
}

fn resolve_template_round_context(tmpl: &MintTemplate) -> Option<([u8; 32], u64, u8)> {
    let round_id = decode_hex32(&tmpl.round_id)?;
    match tmpl.phase {
        MintRoundPhase::Searching => Some((round_id, current_emission_bucket(), tmpl.target_bits)),
        MintRoundPhase::Collecting => match (tmpl.hit_bucket, tmpl.bits_used) {
            (Some(hit_bucket), Some(bits_used)) => Some((round_id, hit_bucket, bits_used)),
            _ => None,
        },
    }
}

#[derive(Debug)]
enum MinerEvent {
    SolutionFound {
        nonce: u64,
        pow_seed: [u8; 32],
        hash: [u8; 32],
    },
    TemplateUpdate {
        template: MiningTemplate,
    },
    MintAccepted {
        mint_id: String,
    },
    MintRejected {
        error: String,
    },
    Error {
        msg: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Adresse parsen (Pflichtargument)
    let address = {
        let bytes = hex::decode(&cli.address).map_err(|e| anyhow!("Ungültige Adresse: {}", e))?;
        if bytes.len() != 32 {
            return Err(anyhow!("Adresse muss 32 Bytes sein"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };

    let state = MinerState::new(
        cli.threads,
        cli.difficulty,
        cli.node_url,
        address,
        cli.tls_ca,
        cli.tls_client_pem,
        cli.insecure_skip_tls_verify,
    );

    // Terminal initialisieren
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Event-Channel
    let (tx, rx) = mpsc::channel::<MinerEvent>();

    // Mining starten
    let result = run_app(&mut terminal, state, tx, &rx).await;

    // Terminal aufräumen
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Fehler: {}", e);
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    state: MinerState,
    tx: mpsc::Sender<MinerEvent>,
    rx: &mpsc::Receiver<MinerEvent>,
) -> Result<()> {
    let start_time = Instant::now();
    let mut last_template: Option<MiningTemplate> = None;
    let mut logs: VecDeque<String> =
        VecDeque::from(["[INFO] Phantom Miner GUI gestartet".to_string()]);

    // Template-Poller starten (holt /mint/template)
    let node_tx = tx.clone();
    let node_url = state.node_url.clone();
    let is_connected = state.is_connected.clone();
    let address = state.address;
    let current_seed = state.current_seed.clone();
    let tls_ca = state.tls_ca.clone();
    let tls_client_pem = state.tls_client_pem.clone();
    let insecure_skip_tls_verify = state.insecure_skip_tls_verify;
    tokio::spawn(async move {
        let client = match build_http_client(
            &node_url,
            tls_ca.as_ref(),
            tls_client_pem.as_ref(),
            insecure_skip_tls_verify,
            Duration::from_secs(5),
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = node_tx.send(MinerEvent::Error {
                    msg: format!("TLS-Client: {}", e),
                });
                return;
            }
        };

        loop {
            match client
                .get(format!("{}/mint/template", node_url))
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        is_connected.store(false, Ordering::Relaxed);
                        let _ = node_tx.send(MinerEvent::Error {
                            msg: format!("Template-HTTP-Fehler: {}", resp.status()),
                        });
                        continue;
                    }
                    match read_json_limited::<MintTemplate>(resp, MAX_HTTP_RESPONSE_BYTES).await {
                        Ok(tmpl) => {
                            is_connected.store(true, Ordering::Relaxed);

                            // Parse network_id und prev_mint_id
                            let network_id = match decode_hex32(&tmpl.network_id) {
                                Some(v) => v,
                                None => continue,
                            };
                            let prev_mint_id = match decode_hex32(&tmpl.prev_mint_id) {
                                Some(v) => v,
                                None => continue,
                            };
                            let (round_id, hit_bucket, bits_used) =
                                match resolve_template_round_context(&tmpl) {
                                    Some(v) => v,
                                    None => {
                                        let _ = node_tx.send(MinerEvent::Error {
                                            msg: "Template ohne gültigen Emissionskontext".to_string(),
                                        });
                                        continue;
                                    }
                                };

                            // Berechne korrekten pow_seed mit mint_pow_seed_v2
                            let template_event = MintEvent {
                                version: MINT_VERSION_V2,
                                prev_mint_id,
                                outputs: vec![TxOut {
                                    amount: tmpl.reward,
                                    lock: LockCommitment(address),
                                }],
                                pow_seed: [0u8; 32],
                                pow_nonce: 0,
                                minted_at: 0,
                                round_id,
                                hit_bucket,
                                bits_used,
                            };
                            let pow_seed = mint_pow_seed_v2(&network_id, &template_event);

                            // Update current_seed für Mining-Threads
                            match current_seed.write() {
                                Ok(mut guard) => *guard = pow_seed,
                                Err(_) => {
                                    let _ = node_tx.send(MinerEvent::Error {
                                        msg: "current_seed lock poisoned".to_string(),
                                    });
                                    continue;
                                }
                            }

                            let mining_template = MiningTemplate {
                                prev_mint_id,
                                round_id,
                                hit_bucket,
                                bits_used,
                                target_bits: tmpl.target_bits,
                                reward: tmpl.reward,
                                mint_height: tmpl.mint_height,
                            };
                            let _ = node_tx.send(MinerEvent::TemplateUpdate {
                                template: mining_template,
                            });
                        }
                        Err(e) => {
                            is_connected.store(false, Ordering::Relaxed);
                            let _ = node_tx.send(MinerEvent::Error {
                                msg: format!("Template-Parse fehlgeschlagen: {}", e),
                            });
                        }
                    }
                }
                Err(e) => {
                    is_connected.store(false, Ordering::Relaxed);
                    let _ = node_tx.send(MinerEvent::Error {
                        msg: format!("Node-Verbindung fehlgeschlagen: {}", e),
                    });
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    // Mining-Threads starten
    start_mining_threads(&state, tx.clone());
    state.is_mining.store(true, Ordering::Relaxed);
    logs.push_back(format!("[INFO] {} Mining-Threads gestartet", state.threads));

    // Hauptschleife
    loop {
        let elapsed = start_time.elapsed().as_secs_f64();

        // Events verarbeiten
        while let Ok(event) = rx.try_recv() {
            match event {
                MinerEvent::SolutionFound {
                    nonce,
                    pow_seed,
                    hash,
                } => {
                    state.valid_shares.fetch_add(1, Ordering::Relaxed);
                    logs.push_back(format!(
                        "[SOLUTION] Nonce: {} Hash: {}...",
                        nonce,
                        hex::encode(&hash[..4])
                    ));
                    if logs.len() > 100 {
                        let _ = logs.pop_front();
                    }
                    // Submit zum Node (async im Hintergrund)
                    if let Some(ref tmpl) = last_template {
                        let node_url = state.node_url.clone();
                        let address = state.address;
                        let reward = tmpl.reward;
                        let prev_mint_id = tmpl.prev_mint_id;
                        let round_id = tmpl.round_id;
                        let hit_bucket = tmpl.hit_bucket;
                        let bits_used = tmpl.bits_used;
                        let tx_clone = tx.clone();
                        let tls_ca = state.tls_ca.clone();
                        let tls_client_pem = state.tls_client_pem.clone();
                        let insecure_skip_tls_verify = state.insecure_skip_tls_verify;
                        tokio::spawn(async move {
                            let client = match build_http_client(
                                &node_url,
                                tls_ca.as_ref(),
                                tls_client_pem.as_ref(),
                                insecure_skip_tls_verify,
                                Duration::from_secs(10),
                            ) {
                                Ok(c) => c,
                                Err(e) => {
                                    let _ = tx_clone.send(MinerEvent::Error {
                                        msg: format!("TLS-Client: {}", e),
                                    });
                                    return;
                                }
                            };
                            let mint_json = MintEventJson {
                                version: MINT_VERSION_V2,
                                prev_mint_id: hex::encode(prev_mint_id),
                                outputs: vec![TxOutJson {
                                    amount: reward,
                                    lock: hex::encode(address),
                                }],
                                pow_seed: hex::encode(pow_seed),
                                pow_nonce: nonce,
                                minted_at: 0,
                                round_id: Some(hex::encode(round_id)),
                                hit_bucket: Some(hit_bucket),
                                bits_used: Some(bits_used),
                            };
                            let submit = SubmitMintRequest { mint: mint_json };
                            match client
                                .post(format!("{}/mint/submit", node_url))
                                .json(&submit)
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    match read_json_limited::<SubmitMintResponse>(
                                        resp,
                                        MAX_HTTP_RESPONSE_BYTES,
                                    )
                                    .await
                                    {
                                        Ok(result) => {
                                            if result.ok {
                                                let _ = tx_clone.send(MinerEvent::MintAccepted {
                                                    mint_id: result.mint_id.unwrap_or_default(),
                                                });
                                            } else {
                                                let _ = tx_clone.send(MinerEvent::MintRejected {
                                                    error: result
                                                        .error
                                                        .unwrap_or_else(|| "unknown".to_string()),
                                                });
                                            }
                                        }
                                        Err(e) => {
                                            let _ = tx_clone.send(MinerEvent::Error {
                                                msg: format!("Submit-Parse fehlgeschlagen: {}", e),
                                            });
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx_clone.send(MinerEvent::Error {
                                        msg: format!("Submit failed: {}", e),
                                    });
                                }
                            }
                        });
                    }
                }
                MinerEvent::TemplateUpdate { template } => {
                    last_template = Some(template);
                }
                MinerEvent::MintAccepted { mint_id } => {
                    logs.push_back(format!(
                        "[MINT] Akzeptiert: {}...",
                        &mint_id[..16.min(mint_id.len())]
                    ));
                    if logs.len() > 100 {
                        let _ = logs.pop_front();
                    }
                }
                MinerEvent::MintRejected { error } => {
                    state.rejected_shares.fetch_add(1, Ordering::Relaxed);
                    logs.push_back(format!("[REJECT] {}", error));
                    if logs.len() > 100 {
                        let _ = logs.pop_front();
                    }
                }
                MinerEvent::Error { msg } => {
                    logs.push_back(format!("[ERROR] {}", msg));
                    if logs.len() > 100 {
                        let _ = logs.pop_front();
                    }
                }
            }
        }

        // UI rendern
        terminal.draw(|f| {
            ui(f, &state, elapsed, &last_template, &logs);
        })?;

        // Tastatureingaben
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            state.is_mining.store(false, Ordering::Relaxed);
                            return Ok(());
                        }
                        KeyCode::Char(' ') => {
                            let mining = state.is_mining.load(Ordering::Relaxed);
                            state.is_mining.store(!mining, Ordering::Relaxed);
                            if mining {
                                logs.push_back("[INFO] Mining pausiert".to_string());
                            } else {
                                logs.push_back("[INFO] Mining fortgesetzt".to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn start_mining_threads(state: &MinerState, tx: mpsc::Sender<MinerEvent>) {
    let threads = state.threads;

    for thread_id in 0..threads {
        let state = state.clone();
        let tx = tx.clone();

        std::thread::spawn(move || {
            let mut nonce = thread_id as u64;
            let step = threads as u64;

            loop {
                if !state.is_mining.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }

                // Seed aus State lesen (blocking)
                let seed = match state.current_seed.read() {
                    Ok(guard) => *guard,
                    Err(_) => [0u8; 32],
                };

                // Skip wenn kein gültiger Seed
                if seed == [0u8; 32] {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }

                // Batch von Hashes berechnen
                for _ in 0..10000 {
                    if !state.is_mining.load(Ordering::Relaxed) {
                        break;
                    }

                    let hash = pow_hash(&seed, nonce);
                    state.total_hashes.fetch_add(1, Ordering::Relaxed);

                    if pow_meets(state.difficulty, &hash) {
                        let _ = tx.send(MinerEvent::SolutionFound {
                            nonce,
                            pow_seed: seed,
                            hash,
                        });
                    }

                    nonce = nonce.wrapping_add(step);
                }
            }
        });
    }
}

fn ui(
    f: &mut Frame,
    state: &MinerState,
    elapsed: f64,
    template: &Option<MiningTemplate>,
    logs: &VecDeque<String>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(8), // Stats
            Constraint::Length(3), // Hashrate-Gauge
            Constraint::Min(10),   // Logs
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Header
    let title = vec![
        Span::styled("⛏️  ", Style::default().fg(Color::Yellow)),
        Span::styled(
            "PHANTOM MINER",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        if state.is_mining.load(Ordering::Relaxed) {
            Span::styled(
                "● MINING",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                "● PAUSED",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        },
    ];
    let header = Paragraph::new(Line::from(title))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(header, chunks[0]);

    // Stats
    let hashrate = state.hashrate(elapsed);
    let hashrate_str = format_hashrate(hashrate);
    let total_hashes = state.total_hashes.load(Ordering::Relaxed);
    let valid = state.valid_shares.load(Ordering::Relaxed);
    let rejected = state.rejected_shares.load(Ordering::Relaxed);
    let connected = state.is_connected.load(Ordering::Relaxed);

    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let left_stats = [
        format!("Hashrate:      {}", hashrate_str),
        format!("Total Hashes:  {}", format_number(total_hashes)),
        format!("Mints Found:   {}", valid),
        format!("Rejected:      {}", rejected),
        format!("Threads:       {}", state.threads),
    ];

    let right_stats = [
        format!(
            "Node:          {}",
            if connected {
                "✓ Verbunden"
            } else {
                "✗ Offline"
            }
        ),
        format!("URL:           {}", state.node_url),
        format!(
            "Mint-Höhe:     {}",
            template
                .as_ref()
                .map(|t| t.mint_height.to_string())
                .unwrap_or_else(|| "-".to_string())
        ),
        format!(
            "Difficulty:    {} bits",
            template
                .as_ref()
                .map(|t| t.target_bits)
                .unwrap_or(state.difficulty)
        ),
        format!("Laufzeit:      {}", format_duration(elapsed)),
    ];

    let left_widget = Paragraph::new(left_stats.join("\n"))
        .block(Block::default().borders(Borders::ALL).title("Mining"));
    let right_widget = Paragraph::new(right_stats.join("\n"))
        .block(Block::default().borders(Borders::ALL).title("Node"));

    f.render_widget(left_widget, stats_chunks[0]);
    f.render_widget(right_widget, stats_chunks[1]);

    // Hashrate-Gauge
    let gauge_ratio = (hashrate / 1_000_000.0).min(1.0); // Max 1 MH/s für Gauge
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Hashrate"))
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
        .percent((gauge_ratio * 100.0) as u16)
        .label(hashrate_str.clone());
    f.render_widget(gauge, chunks[2]);

    // Logs
    let log_items: Vec<ListItem> = logs
        .iter()
        .rev()
        .take(20)
        .map(|log| {
            let style = if log.contains("[ERROR]") || log.contains("[REJECT]") {
                Style::default().fg(Color::Red)
            } else if log.contains("[MINT]") || log.contains("[SOLUTION]") {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(Line::from(Span::styled(log.clone(), style)))
        })
        .collect();

    let log_list = List::new(log_items).block(Block::default().borders(Borders::ALL).title("Log"));
    f.render_widget(log_list, chunks[3]);

    // Footer
    let footer = Paragraph::new("[SPACE] Pause/Resume  [Q/ESC] Beenden")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[4]);
}

fn format_hashrate(h: f64) -> String {
    if h >= 1_000_000_000.0 {
        format!("{:.2} GH/s", h / 1_000_000_000.0)
    } else if h >= 1_000_000.0 {
        format!("{:.2} MH/s", h / 1_000_000.0)
    } else if h >= 1_000.0 {
        format!("{:.2} KH/s", h / 1_000.0)
    } else {
        format!("{:.0} H/s", h)
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_duration(secs: f64) -> String {
    let total_secs = secs as u64;
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}
