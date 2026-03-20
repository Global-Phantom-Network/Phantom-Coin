use crate::http_util;
use std::collections::VecDeque;
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::Frame;
use tokio::sync::mpsc;

use pc_consensus::{current_emission_bucket, mint_pow_seed_v2, pow_hash, pow_meets};
use pc_types::{
    LockCommitment, MintEvent, MintEventJson, MintRoundPhase, MintTemplate, SubmitMintRequest,
    SubmitMintResponse, TxOut, TxOutJson, MINT_VERSION_V2,
};

fn env_path(name: &str) -> Option<PathBuf> {
    let v = env::var(name).ok()?;
    let t = v.trim();
    if t.is_empty() {
        None
    } else {
        Some(PathBuf::from(t))
    }
}

const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct MinerState {
    total_hashes: Arc<AtomicU64>,
    valid_shares: Arc<AtomicU64>,
    rejected_shares: Arc<AtomicU64>,
    is_mining: Arc<AtomicBool>,
    is_connected: Arc<AtomicBool>,
    threads: usize,
    difficulty: u8,
    node_url: String,
    address: [u8; 32],
    tls_ca: Option<PathBuf>,
    tls_client_pem: Option<PathBuf>,
    insecure_skip_tls_verify: bool,
    current_seed: Arc<RwLock<[u8; 32]>>,
}

impl MinerState {
    fn new(
        threads: usize,
        difficulty: u8,
        node_url: String,
        address: [u8; 32],
        insecure_skip_tls_verify: bool,
    ) -> Self {
        let tls_ca = env_path("PHANTOM_TLS_CA");
        let tls_client_pem = env_path("PHANTOM_TLS_CLIENT_PEM");
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

#[derive(Debug, Clone, Default)]
struct ExternalMinerMetricsSnapshot {
    uptime_seconds: f64,
    threads: u64,
    hashes_total: u64,
    hashrate_hps: f64,
    templates_total: u64,
    template_errors_total: u64,
    submit_accepted_total: u64,
    submit_stale_total: u64,
    submit_rejected_total: u64,
    submit_errors_total: u64,
    last_template_epoch: u64,
    last_submit_ok_epoch: u64,
    rss_bytes: u64,
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
    ExternalMetrics {
        snapshot: ExternalMinerMetricsSnapshot,
    },
    ExternalMetricsErr {
        msg: String,
    },
    Error {
        msg: String,
    },
}

pub struct MinerUi {
    state: MinerState,
    tx: mpsc::Sender<MinerEvent>,
    rx: mpsc::Receiver<MinerEvent>,
    logs: VecDeque<String>,
    last_template: Option<MiningTemplate>,
    external_enabled: bool,
    external_metrics_url: String,
    external_status: String,
    external_snapshot: Option<ExternalMinerMetricsSnapshot>,
    external_inflight: bool,
    external_last_poll: Option<Instant>,
    start_time: Instant,
    rt: tokio::runtime::Runtime,
}

impl MinerUi {
    pub fn new(insecure_skip_tls_verify: bool) -> anyhow::Result<Self> {
        let threads = num_cpus();
        let difficulty = 16;
        let node_url = "http://127.0.0.1:8080".to_string();
        let mut addr = [0u8; 32];
        addr[0] = 0x01;
        let state = MinerState::new(
            threads,
            difficulty,
            node_url,
            addr,
            insecure_skip_tls_verify,
        );
        let (tx, rx) = mpsc::channel::<MinerEvent>(100);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("build tokio runtime")?;
        let external_metrics_url = env::var("PHANTOM_MINER_METRICS_URL")
            .ok()
            .and_then(|s| {
                let t = s.trim().to_string();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            })
            .unwrap_or_else(|| "http://127.0.0.1:9200/metrics".to_string());
        let mut logs = VecDeque::new();
        logs.push_back("[INFO] Phantom Miner UI gestartet".to_string());
        let mut ui = Self {
            state,
            tx,
            rx,
            logs,
            last_template: None,
            external_enabled: false,
            external_metrics_url,
            external_status: String::new(),
            external_snapshot: None,
            external_inflight: false,
            external_last_poll: None,
            start_time: Instant::now(),
            rt,
        };
        ui.start_background();
        Ok(ui)
    }

    fn start_background(&mut self) {
        let node_tx = self.tx.clone();
        let node_url = self.state.node_url.clone();
        let is_connected = self.state.is_connected.clone();
        let address = self.state.address;
        let current_seed = self.state.current_seed.clone();
        let tls_ca = self.state.tls_ca.clone();
        let tls_client_pem = self.state.tls_client_pem.clone();
        let insecure_skip_tls_verify = self.state.insecure_skip_tls_verify;
        let current_template = Arc::new(tokio::sync::RwLock::new(None::<MiningTemplate>));
        let current_template_clone = current_template.clone();
        self.rt.spawn(async move {
            let client = match http_util::build_http_client(
                &node_url,
                tls_ca.as_deref(),
                tls_client_pem.as_deref(),
                insecure_skip_tls_verify,
                Duration::from_secs(5),
            ) {
                Ok(c) => c,
                Err(e) => {
                    let _ = node_tx
                        .send(MinerEvent::Error {
                            msg: format!("TLS-Client: {}", e),
                        })
                        .await;
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
                        if let Ok(tmpl) = http_util::read_json_limited::<MintTemplate>(
                            resp,
                            MAX_HTTP_RESPONSE_BYTES,
                        )
                        .await
                        {
                            is_connected.store(true, Ordering::Relaxed);

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
                                    None => continue,
                                };

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
                            {
                                if let Ok(mut guard) = current_seed.write() {
                                    *guard = pow_seed;
                                } else {
                                    // Poisoned lock: keep the old seed and try again next tick.
                                    continue;
                                }
                            }

                            let template = MiningTemplate {
                                prev_mint_id,
                                round_id,
                                hit_bucket,
                                bits_used,
                                target_bits: tmpl.target_bits,
                                reward: tmpl.reward,
                                mint_height: tmpl.mint_height,
                            };
                            *current_template.write().await = Some(template.clone());
                            let _ = node_tx.send(MinerEvent::TemplateUpdate { template }).await;
                        }
                    }
                    Err(_) => {
                        is_connected.store(false, Ordering::Relaxed);
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        start_mining_threads(&self.state, self.tx.clone(), current_template_clone);
        self.state.is_mining.store(true, Ordering::Relaxed);
        self.logs.push_back(format!(
            "[INFO] {} Mining-Threads gestartet",
            self.state.threads
        ));
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(' ') => {
                let mining = self.state.is_mining.load(Ordering::Relaxed);
                self.state.is_mining.store(!mining, Ordering::Relaxed);
                if mining {
                    self.logs.push_back("[INFO] Mining pausiert".to_string());
                } else {
                    self.logs.push_back("[INFO] Mining fortgesetzt".to_string());
                }
                true
            }
            KeyCode::Char('m') => {
                self.external_enabled = !self.external_enabled;
                self.external_inflight = false;
                self.external_last_poll = None;
                self.external_status.clear();
                if self.external_enabled {
                    self.logs.push_back(format!(
                        "[INFO] External Miner Metrics EIN ({})",
                        self.external_metrics_url
                    ));
                } else {
                    self.logs
                        .push_back("[INFO] External Miner Metrics AUS".to_string());
                }
                true
            }
            _ => false,
        }
    }

    pub fn tick(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(ev) => match ev {
                    MinerEvent::SolutionFound {
                        nonce,
                        pow_seed,
                        hash,
                    } => {
                        self.logs.push_back(format!(
                            "[SOLUTION] Nonce={} Hash={}...",
                            nonce,
                            hex::encode(hash)
                        ));
                        if self.logs.len() > 100 {
                            let _ = self.logs.pop_front();
                        }

                        let tx_clone = self.tx.clone();
                        let node_url = self.state.node_url.clone();
                        let address = self.state.address;
                        let last_template = self.last_template.clone();
                        let tls_ca = self.state.tls_ca.clone();
                        let tls_client_pem = self.state.tls_client_pem.clone();
                        let insecure_skip_tls_verify = self.state.insecure_skip_tls_verify;
                        self.rt.spawn(async move {
                            if let Some(tmpl) = last_template {
                                let mint_event = MintEventJson {
                                    version: MINT_VERSION_V2,
                                    prev_mint_id: hex::encode(tmpl.prev_mint_id),
                                    outputs: vec![TxOutJson {
                                        amount: tmpl.reward,
                                        lock: hex::encode(address),
                                    }],
                                    pow_seed: hex::encode(pow_seed),
                                    pow_nonce: nonce,
                                    minted_at: 0,
                                    round_id: Some(hex::encode(tmpl.round_id)),
                                    hit_bucket: Some(tmpl.hit_bucket),
                                    bits_used: Some(tmpl.bits_used),
                                };

                                let req = SubmitMintRequest { mint: mint_event };
                                let client = match http_util::build_http_client(
                                    &node_url,
                                    tls_ca.as_deref(),
                                    tls_client_pem.as_deref(),
                                    insecure_skip_tls_verify,
                                    Duration::from_secs(10),
                                ) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        let _ = tx_clone
                                            .send(MinerEvent::Error {
                                                msg: format!("TLS-Client: {}", e),
                                            })
                                            .await;
                                        return;
                                    }
                                };

                                match client
                                    .post(format!("{}/mint/submit", node_url))
                                    .json(&req)
                                    .send()
                                    .await
                                {
                                    Ok(resp) => {
                                        if let Ok(json) = http_util::read_json_limited::<
                                            SubmitMintResponse,
                                        >(
                                            resp, MAX_HTTP_RESPONSE_BYTES
                                        )
                                        .await
                                        {
                                            if json.ok {
                                                let mint_id = json
                                                    .mint_id
                                                    .unwrap_or_else(|| "unknown".to_string());
                                                let _ = tx_clone
                                                    .send(MinerEvent::MintAccepted { mint_id })
                                                    .await;
                                            } else {
                                                let error = json
                                                    .error
                                                    .unwrap_or_else(|| "unknown".to_string());
                                                let _ = tx_clone
                                                    .send(MinerEvent::MintRejected { error })
                                                    .await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx_clone
                                            .send(MinerEvent::Error {
                                                msg: format!("Submit failed: {}", e),
                                            })
                                            .await;
                                    }
                                }
                            }
                        });
                    }
                    MinerEvent::TemplateUpdate { template } => {
                        self.last_template = Some(template);
                    }
                    MinerEvent::MintAccepted { mint_id } => {
                        self.state.valid_shares.fetch_add(1, Ordering::Relaxed);
                        self.logs.push_back(format!(
                            "[MINT] Akzeptiert: {}...",
                            &mint_id[..16.min(mint_id.len())]
                        ));
                        if self.logs.len() > 100 {
                            let _ = self.logs.pop_front();
                        }
                    }
                    MinerEvent::MintRejected { error } => {
                        self.state.rejected_shares.fetch_add(1, Ordering::Relaxed);
                        self.logs.push_back(format!("[REJECT] {}", error));
                        if self.logs.len() > 100 {
                            let _ = self.logs.pop_front();
                        }
                    }
                    MinerEvent::ExternalMetrics { snapshot } => {
                        self.external_snapshot = Some(snapshot);
                        self.external_status = "ok".to_string();
                        self.external_inflight = false;
                    }
                    MinerEvent::ExternalMetricsErr { msg } => {
                        self.external_status = format!("error: {}", msg);
                        self.external_inflight = false;
                    }
                    MinerEvent::Error { msg } => {
                        self.logs.push_back(format!("[ERROR] {}", msg));
                        if self.logs.len() > 100 {
                            let _ = self.logs.pop_front();
                        }
                    }
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        if self.external_enabled {
            let due = self
                .external_last_poll
                .map(|t| t.elapsed() >= Duration::from_secs(1))
                .unwrap_or(true);
            if due && !self.external_inflight {
                self.external_inflight = true;
                self.external_last_poll = Some(Instant::now());
                let url = self.external_metrics_url.clone();
                let tx = self.tx.clone();
                self.rt.spawn(async move {
                    match fetch_external_miner_metrics(&url).await {
                        Ok(snap) => {
                            let _ = tx
                                .send(MinerEvent::ExternalMetrics { snapshot: snap })
                                .await;
                        }
                        Err(e) => {
                            let _ = tx.send(MinerEvent::ExternalMetricsErr { msg: e }).await;
                        }
                    }
                });
            }
        }
    }

    pub fn draw(&self, f: &mut Frame, area: Rect) {
        let external = ExternalUi {
            enabled: self.external_enabled,
            url: &self.external_metrics_url,
            status: &self.external_status,
            snapshot: &self.external_snapshot,
        };
        ui(
            f,
            area,
            &self.state,
            self.start_time.elapsed().as_secs_f64(),
            &self.last_template,
            &self.logs,
            external,
        );
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

fn start_mining_threads(
    state: &MinerState,
    tx: mpsc::Sender<MinerEvent>,
    _current_template: Arc<tokio::sync::RwLock<Option<MiningTemplate>>>,
) {
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
                let seed = match state.current_seed.read() {
                    Ok(g) => *g,
                    Err(_) => [0u8; 32],
                };
                if seed == [0u8; 32] {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                let hash = pow_hash(&seed, nonce);
                state.total_hashes.fetch_add(1, Ordering::Relaxed);
                if pow_meets(state.difficulty, &hash) {
                    let _ = tx.blocking_send(MinerEvent::SolutionFound {
                        nonce,
                        pow_seed: seed,
                        hash,
                    });
                }
                nonce = nonce.wrapping_add(step);
            }
        });
    }
}

fn format_hashrate(h: f64) -> String {
    if h >= 1_000_000_000.0 {
        format!("{:.2} GH/s", h / 1_000_000_000.0)
    } else if h >= 1_000_000.0 {
        format!("{:.2} MH/s", h / 1_000_000.0)
    } else if h >= 1_000.0 {
        format!("{:.2} kH/s", h / 1_000.0)
    } else {
        format!("{:.2} H/s", h)
    }
}

fn format_number(n: u64) -> String {
    let mut s = n.to_string();
    let mut i = s.len();
    while i > 3 {
        i -= 3;
        s.insert(i, ',');
    }
    s
}

fn format_duration(secs: f64) -> String {
    let total = secs as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn parse_prom_u64(text: &str, name: &str) -> Option<u64> {
    let needle = format!("{name} ");
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        if l.starts_with(&needle) {
            let mut it = l.split_whitespace();
            let _ = it.next()?;
            let v = it.next()?;
            return v.parse::<u64>().ok();
        }
    }
    None
}

fn parse_prom_f64(text: &str, name: &str) -> Option<f64> {
    let needle = format!("{name} ");
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        if l.starts_with(&needle) {
            let mut it = l.split_whitespace();
            let _ = it.next()?;
            let v = it.next()?;
            return v.parse::<f64>().ok();
        }
    }
    None
}

async fn fetch_external_miner_metrics(
    metrics_url: &str,
) -> Result<ExternalMinerMetricsSnapshot, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("build http client: {e}"))?;
    let resp = client
        .get(metrics_url)
        .send()
        .await
        .map_err(|e| format!("GET /metrics: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("metrics http status {}", resp.status()));
    }
    let text = http_util::read_response_text_limited(resp, MAX_HTTP_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("read metrics body: {e}"))?;

    let snap = ExternalMinerMetricsSnapshot {
        uptime_seconds: parse_prom_f64(&text, "pc_miner_uptime_seconds").unwrap_or(0.0),
        threads: parse_prom_u64(&text, "pc_miner_threads").unwrap_or(0),
        hashes_total: parse_prom_u64(&text, "pc_miner_hashes_total").unwrap_or(0),
        hashrate_hps: parse_prom_f64(&text, "pc_miner_hashrate_hps").unwrap_or(0.0),
        templates_total: parse_prom_u64(&text, "pc_miner_templates_total").unwrap_or(0),
        template_errors_total: parse_prom_u64(&text, "pc_miner_template_errors_total").unwrap_or(0),
        submit_accepted_total: parse_prom_u64(&text, "pc_miner_submit_accepted_total").unwrap_or(0),
        submit_stale_total: parse_prom_u64(&text, "pc_miner_submit_stale_total").unwrap_or(0),
        submit_rejected_total: parse_prom_u64(&text, "pc_miner_submit_rejected_total").unwrap_or(0),
        submit_errors_total: parse_prom_u64(&text, "pc_miner_submit_errors_total").unwrap_or(0),
        last_template_epoch: parse_prom_u64(&text, "pc_miner_last_template_epoch").unwrap_or(0),
        last_submit_ok_epoch: parse_prom_u64(&text, "pc_miner_last_submit_ok_epoch").unwrap_or(0),
        rss_bytes: parse_prom_u64(&text, "pc_miner_process_rss_bytes").unwrap_or(0),
    };
    Ok(snap)
}

#[derive(Clone, Copy)]
struct ExternalUi<'a> {
    enabled: bool,
    url: &'a str,
    status: &'a str,
    snapshot: &'a Option<ExternalMinerMetricsSnapshot>,
}

fn ui(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    elapsed: f64,
    template: &Option<MiningTemplate>,
    logs: &VecDeque<String>,
    external: ExternalUi<'_>,
) {
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(8),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

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

    let mut right_stats = Vec::new();
    right_stats.push(format!(
        "Node:          {}",
        if connected {
            "✓ Verbunden"
        } else {
            "✗ Offline"
        }
    ));
    right_stats.push(format!("URL:           {}", state.node_url));
    right_stats.push(format!(
        "Mint-Höhe:     {}",
        template
            .as_ref()
            .map(|t| t.mint_height.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    right_stats.push(format!(
        "Difficulty:    {} bits",
        template
            .as_ref()
            .map(|t| t.target_bits)
            .unwrap_or(state.difficulty)
    ));
    right_stats.push(format!("Laufzeit:      {}", format_duration(elapsed)));

    right_stats.push(String::new());
    right_stats.push(format!(
        "Ext Metrics:   {}",
        if external.enabled { "ON" } else { "OFF" }
    ));
    if external.enabled {
        if let Some(snap) = external.snapshot {
            right_stats.push(format!(
                "Ext Hashrate:  {}",
                format_hashrate(snap.hashrate_hps)
            ));
            right_stats.push(format!("Ext Threads:   {}", snap.threads));
            right_stats.push(format!(
                "Ext Uptime:    {}",
                format_duration(snap.uptime_seconds)
            ));
            right_stats.push(format!(
                "Ext Hashes:    {}",
                format_number(snap.hashes_total)
            ));
            right_stats.push(format!(
                "Ext Templates: {} (err={})",
                snap.templates_total, snap.template_errors_total
            ));
            right_stats.push(format!(
                "Ext Submit:    ok={} stale={} rej={}",
                snap.submit_accepted_total, snap.submit_stale_total, snap.submit_rejected_total
            ));
            right_stats.push(format!("Ext SubmitErr: {}", snap.submit_errors_total));
            right_stats.push(format!(
                "Ext Last:      tpl_epoch={} ok_epoch={}",
                snap.last_template_epoch, snap.last_submit_ok_epoch
            ));
            right_stats.push(format!(
                "Ext RSS:       {} MB",
                snap.rss_bytes / 1024 / 1024
            ));
        } else if !external.status.trim().is_empty() {
            right_stats.push(format!("Ext Status:    {}", external.status.trim()));
        } else {
            right_stats.push("Ext Status:    (kein Snapshot)".to_string());
        }
        right_stats.push(format!("Ext URL:       {}", external.url));
    }

    let left_widget = Paragraph::new(left_stats.join("\n"))
        .block(Block::default().borders(Borders::ALL).title("Mining"));
    let right_widget = Paragraph::new(right_stats.join("\n"))
        .block(Block::default().borders(Borders::ALL).title("Node"));

    f.render_widget(left_widget, stats_chunks[0]);
    f.render_widget(right_widget, stats_chunks[1]);

    let gauge_ratio = (hashrate / 1_000_000.0).min(1.0);
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Hashrate"))
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
        .percent((gauge_ratio * 100.0) as u16)
        .label(hashrate_str.clone());
    f.render_widget(gauge, chunks[2]);

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

    let footer = Paragraph::new("[SPACE] Pause/Resume  |  [m] External Metrics")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[4]);
}

#[cfg(test)]
mod tests {
    fn miner_rs_src() -> &'static str {
        include_str!("miner.rs")
    }

    #[test]
    fn f112_miner_uses_single_tokio_runtime_and_std_rwlock_for_seed() {
        let src = miner_rs_src();
        let needle_rt = ["rt", ": ", "tokio", "::", "runtime", "::", "Runtime"].concat();
        assert!(
            src.contains(&needle_rt),
            "expected MinerUi to own a single tokio runtime (not create one per hash iteration)"
        );
        let needle_builder = [
            "tokio",
            "::",
            "runtime",
            "::",
            "Builder",
            "::",
            "new_multi_thread",
        ]
        .concat();
        assert!(
            src.matches(&needle_builder).count() == 1,
            "expected exactly one runtime builder invocation in miner.rs"
        );
        let needle_seed = [
            "current_seed",
            ": ",
            "Arc",
            "<",
            "RwLock",
            "<",
            "[u8; 32]",
            ">",
            ">",
        ]
        .concat();
        assert!(
            src.contains(&needle_seed),
            "expected current_seed to be shared via std::sync::RwLock"
        );
    }

    #[test]
    fn f116_logs_use_vecdeque_and_do_not_shift_with_remove0() {
        let src = miner_rs_src();
        let needle_logs = ["logs", ": ", "VecDeque", "<", "String", ">"].concat();
        assert!(
            src.contains(&needle_logs),
            "expected logs to be stored in VecDeque"
        );
        let needle_remove0 = ["remove", "(", "0", ")"].concat();
        assert!(
            !src.contains(&needle_remove0),
            "expected no Vec::remove at index 0 O(n) log shifting"
        );
    }
}
