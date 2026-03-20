// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use pc_consensus::{current_emission_bucket, mint_pow_seed_v2, pow_hash, pow_meets};
use pc_types::{
    LockCommitment, MintEvent, MintEventJson, MintRoundPhase, MintStatus, MintTemplate,
    SubmitMintRequest, SubmitMintResponse, TxOut, TxOutJson, MINT_VERSION_V2,
};
use sysinfo::{Pid, System};

#[derive(Debug, Parser)]
#[command(name = "phantom-miner", version, about = "Phantom Miner CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Starte den Miner und pollt periodisch eine Node-Status-URL (Debug/Monitoring)
    Run {
        /// Pfad zur Config-Datei (TOML)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Node-Basis-URL, z. B. http://127.0.0.1:8080
        #[arg(long)]
        node_url: Option<String>,
        /// Status-Pfad, z. B. /status
        #[arg(long, default_value = "/status")]
        status_path: String,
        /// Poll-Intervall in Millisekunden
        #[arg(long, default_value_t = 1000u64)]
        interval_ms: u64,
        /// TLS: CA-Zertifikat (PEM) für Server-Verifikation (CA-Pinning)
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        /// TLS: Client-Zertifikat inkl. Key (PEM) für mTLS
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },

    /// Mine Mints gegen einen Phantom Mint RPC Server
    Mine {
        /// Basis-URL des Mint-RPC-Servers, z. B. http://127.0.0.1:9090
        #[arg(long, default_value = "http://127.0.0.1:9090")]
        rpc_url: String,
        /// Empfänger-Lock (32-Byte Hex, z. B. Wallet-LockCommitment)
        #[arg(long)]
        lock: String,
        /// Anzahl Threads (Default: Anzahl CPU-Kerne)
        #[arg(long)]
        threads: Option<usize>,
        /// Fortschrittsintervall in Sekunden (0=aus)
        #[arg(long, default_value_t = 5u64)]
        progress_secs: u64,
        /// TLS: CA-Zertifikat (PEM) für Server-Verifikation (CA-Pinning)
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        /// TLS: Client-Zertifikat inkl. Key (PEM) für mTLS
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
        /// Optional: HTTP Listen-Adresse für Prometheus /metrics (nur loopback), z. B. 127.0.0.1:9200
        #[arg(long)]
        metrics_addr: Option<String>,
    },

    /// Liest Prometheus /metrics von einem laufenden phantom-miner und gibt eine Zusammenfassung aus
    Metrics {
        /// Metrics-URL, z. B. http://127.0.0.1:9200/metrics
        #[arg(long, default_value = "http://127.0.0.1:9200/metrics")]
        metrics_url: String,
        /// Ausgabe als JSON (sonst human readable)
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Debug, Deserialize)]
struct MinerConfig {
    node_url: String,
    #[serde(default = "default_status_path")]
    status_path: String,
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    #[serde(default)]
    tls_ca: Option<PathBuf>,
    #[serde(default)]
    tls_client_pem: Option<PathBuf>,
}

fn default_status_path() -> String {
    "/status".to_string()
}

fn default_interval_ms() -> u64 {
    1000
}

fn build_http_client(
    _base_url: &str,
    tls_ca: Option<&PathBuf>,
    tls_client_pem: Option<&PathBuf>,
    timeout: Duration,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
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

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const MAX_MINT_RPC_BODY_BYTES: usize = 2_097_152;
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
            bail!(
                "HTTP Antwort ist zu groß (content-length {} > limit {})",
                len,
                max_bytes
            );
        }
    }
    let bytes = resp.bytes().await.context("read HTTP response body")?;
    if bytes.len() > max_bytes {
        bail!(
            "HTTP Antwort ist zu groß (read {} > limit {})",
            bytes.len(),
            max_bytes
        );
    }
    Ok(bytes.to_vec())
}

async fn http_error_with_body(
    resp: reqwest::Response,
    max_bytes: usize,
    what: &str,
    url: &str,
) -> Result<anyhow::Error> {
    let status = resp.status();
    let ct = content_type_from_response(&resp).unwrap_or_else(|| "<missing>".to_string());
    let data = read_response_bytes_limited(resp, max_bytes).await?;
    let snippet = body_snippet_lossy(&data);
    Ok(anyhow!(
        "{what} HTTP Fehler (url={url}, http {status}, content-type {ct}): {snippet}"
    ))
}

async fn read_json_response_with_diag<T: DeserializeOwned>(
    resp: reqwest::Response,
    max_bytes: usize,
    what: &str,
    url: &str,
) -> Result<T> {
    let status = resp.status();
    let content_type = content_type_from_response(&resp);
    let data = read_response_bytes_limited(resp, max_bytes).await?;
    serde_json::from_slice::<T>(&data).with_context(|| {
        let ct = content_type.as_deref().unwrap_or("<missing>");
        let snippet = body_snippet_lossy(&data);
        format!(
            "{what}: JSON decode fehlgeschlagen (url={url}, http {status}, content-type {ct}, body_snippet={snippet})"
        )
    })
}

#[derive(Debug)]
struct MinerMetrics {
    started_at: Instant,
    shutdown: AtomicBool,

    // Hashing / performance
    hashes_total: AtomicU64,       // monotonic; across rounds
    hashrate_hps_micro: AtomicU64, // gauge: hashes/s * 1e6
    threads: AtomicU64,            // gauge

    // Mining lifecycle / results
    templates_total: AtomicU64,
    template_errors_total: AtomicU64,
    template_timeout_total: AtomicU64,
    template_connect_total: AtomicU64,
    template_http_4xx_total: AtomicU64,
    template_http_5xx_total: AtomicU64,
    template_json_errors_total: AtomicU64,
    last_template_http_status: AtomicU64, // gauge: HTTP status code; 0 = unknown
    submit_accepted_total: AtomicU64,
    submit_stale_total: AtomicU64,
    submit_rejected_total: AtomicU64,
    submit_errors_total: AtomicU64,
    submit_timeout_total: AtomicU64,
    submit_connect_total: AtomicU64,
    submit_http_4xx_total: AtomicU64,
    submit_http_5xx_total: AtomicU64,
    submit_json_errors_total: AtomicU64,
    last_submit_http_status: AtomicU64, // gauge: HTTP status code; 0 = unknown

    // Last-seen timestamps (epoch seconds; 0 = unknown)
    last_template_epoch: AtomicU64,
    last_submit_ok_epoch: AtomicU64,

    // Last request durations (ms; 0 = unknown)
    last_template_fetch_ms: AtomicU64,
    last_submit_ms: AtomicU64,

    // Process info
    process_rss_bytes: AtomicU64,
    process_cpu_pct_milli: AtomicU64, // gauge: CPU percent * 1e3
}

impl MinerMetrics {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            shutdown: AtomicBool::new(false),
            hashes_total: AtomicU64::new(0),
            hashrate_hps_micro: AtomicU64::new(0),
            threads: AtomicU64::new(0),
            templates_total: AtomicU64::new(0),
            template_errors_total: AtomicU64::new(0),
            template_timeout_total: AtomicU64::new(0),
            template_connect_total: AtomicU64::new(0),
            template_http_4xx_total: AtomicU64::new(0),
            template_http_5xx_total: AtomicU64::new(0),
            template_json_errors_total: AtomicU64::new(0),
            last_template_http_status: AtomicU64::new(0),
            submit_accepted_total: AtomicU64::new(0),
            submit_stale_total: AtomicU64::new(0),
            submit_rejected_total: AtomicU64::new(0),
            submit_errors_total: AtomicU64::new(0),
            submit_timeout_total: AtomicU64::new(0),
            submit_connect_total: AtomicU64::new(0),
            submit_http_4xx_total: AtomicU64::new(0),
            submit_http_5xx_total: AtomicU64::new(0),
            submit_json_errors_total: AtomicU64::new(0),
            last_submit_http_status: AtomicU64::new(0),
            last_template_epoch: AtomicU64::new(0),
            last_submit_ok_epoch: AtomicU64::new(0),
            last_template_fetch_ms: AtomicU64::new(0),
            last_submit_ms: AtomicU64::new(0),
            process_rss_bytes: AtomicU64::new(0),
            process_cpu_pct_milli: AtomicU64::new(0),
        }
    }

    fn render_prometheus(&self) -> String {
        let uptime = self.started_at.elapsed().as_secs_f64();
        let hashes_total = self.hashes_total.load(Ordering::Relaxed);
        let hashrate_hps = (self.hashrate_hps_micro.load(Ordering::Relaxed) as f64) / 1_000_000.0;
        let threads = self.threads.load(Ordering::Relaxed);
        let templates_total = self.templates_total.load(Ordering::Relaxed);
        let template_errors_total = self.template_errors_total.load(Ordering::Relaxed);
        let template_timeout_total = self.template_timeout_total.load(Ordering::Relaxed);
        let template_connect_total = self.template_connect_total.load(Ordering::Relaxed);
        let template_http_4xx_total = self.template_http_4xx_total.load(Ordering::Relaxed);
        let template_http_5xx_total = self.template_http_5xx_total.load(Ordering::Relaxed);
        let template_json_errors_total = self.template_json_errors_total.load(Ordering::Relaxed);
        let last_template_http_status = self.last_template_http_status.load(Ordering::Relaxed);
        let submit_accepted_total = self.submit_accepted_total.load(Ordering::Relaxed);
        let submit_stale_total = self.submit_stale_total.load(Ordering::Relaxed);
        let submit_rejected_total = self.submit_rejected_total.load(Ordering::Relaxed);
        let submit_errors_total = self.submit_errors_total.load(Ordering::Relaxed);
        let submit_timeout_total = self.submit_timeout_total.load(Ordering::Relaxed);
        let submit_connect_total = self.submit_connect_total.load(Ordering::Relaxed);
        let submit_http_4xx_total = self.submit_http_4xx_total.load(Ordering::Relaxed);
        let submit_http_5xx_total = self.submit_http_5xx_total.load(Ordering::Relaxed);
        let submit_json_errors_total = self.submit_json_errors_total.load(Ordering::Relaxed);
        let last_submit_http_status = self.last_submit_http_status.load(Ordering::Relaxed);
        let last_template_epoch = self.last_template_epoch.load(Ordering::Relaxed);
        let last_submit_ok_epoch = self.last_submit_ok_epoch.load(Ordering::Relaxed);
        let last_template_fetch_ms = self.last_template_fetch_ms.load(Ordering::Relaxed);
        let last_submit_ms = self.last_submit_ms.load(Ordering::Relaxed);
        let rss_bytes = self.process_rss_bytes.load(Ordering::Relaxed);
        let cpu_pct = (self.process_cpu_pct_milli.load(Ordering::Relaxed) as f64) / 1_000.0;

        format!(
            "# HELP pc_miner_uptime_seconds Miner process uptime in seconds\n\
# TYPE pc_miner_uptime_seconds gauge\n\
pc_miner_uptime_seconds {uptime}\n\
# HELP pc_miner_threads Mining threads used\n\
# TYPE pc_miner_threads gauge\n\
pc_miner_threads {threads}\n\
# HELP pc_miner_hashes_total Total PoW hashes computed (monotonic)\n\
# TYPE pc_miner_hashes_total counter\n\
pc_miner_hashes_total {hashes_total}\n\
# HELP pc_miner_hashrate_hps Current estimated hashrate (hashes per second)\n\
# TYPE pc_miner_hashrate_hps gauge\n\
pc_miner_hashrate_hps {hashrate_hps}\n\
# HELP pc_miner_templates_total Total /mint/template fetches\n\
# TYPE pc_miner_templates_total counter\n\
pc_miner_templates_total {templates_total}\n\
# HELP pc_miner_template_errors_total Total template/status fetch errors\n\
# TYPE pc_miner_template_errors_total counter\n\
pc_miner_template_errors_total {template_errors_total}\n\
# HELP pc_miner_template_timeout_total Total template fetch timeouts\n\
# TYPE pc_miner_template_timeout_total counter\n\
pc_miner_template_timeout_total {template_timeout_total}\n\
# HELP pc_miner_template_connect_total Total template fetch connection errors\n\
# TYPE pc_miner_template_connect_total counter\n\
pc_miner_template_connect_total {template_connect_total}\n\
# HELP pc_miner_template_http_4xx_total Total template fetch HTTP 4xx responses\n\
# TYPE pc_miner_template_http_4xx_total counter\n\
pc_miner_template_http_4xx_total {template_http_4xx_total}\n\
# HELP pc_miner_template_http_5xx_total Total template fetch HTTP 5xx responses\n\
# TYPE pc_miner_template_http_5xx_total counter\n\
pc_miner_template_http_5xx_total {template_http_5xx_total}\n\
# HELP pc_miner_template_json_errors_total Total template fetch JSON decode errors\n\
# TYPE pc_miner_template_json_errors_total counter\n\
pc_miner_template_json_errors_total {template_json_errors_total}\n\
# HELP pc_miner_last_template_http_status Last observed /mint/template HTTP status code (0=unknown)\n\
# TYPE pc_miner_last_template_http_status gauge\n\
pc_miner_last_template_http_status {last_template_http_status}\n\
# HELP pc_miner_submit_accepted_total Total accepted mint submissions\n\
# TYPE pc_miner_submit_accepted_total counter\n\
pc_miner_submit_accepted_total {submit_accepted_total}\n\
# HELP pc_miner_submit_stale_total Total stale mint submissions (409 CONFLICT)\n\
# TYPE pc_miner_submit_stale_total counter\n\
pc_miner_submit_stale_total {submit_stale_total}\n\
# HELP pc_miner_submit_rejected_total Total rejected mint submissions (non-409)\n\
# TYPE pc_miner_submit_rejected_total counter\n\
pc_miner_submit_rejected_total {submit_rejected_total}\n\
# HELP pc_miner_submit_errors_total Total submit request/parse errors\n\
# TYPE pc_miner_submit_errors_total counter\n\
pc_miner_submit_errors_total {submit_errors_total}\n\
# HELP pc_miner_submit_timeout_total Total submit timeouts\n\
# TYPE pc_miner_submit_timeout_total counter\n\
pc_miner_submit_timeout_total {submit_timeout_total}\n\
# HELP pc_miner_submit_connect_total Total submit connection errors\n\
# TYPE pc_miner_submit_connect_total counter\n\
pc_miner_submit_connect_total {submit_connect_total}\n\
# HELP pc_miner_submit_http_4xx_total Total submit HTTP 4xx responses\n\
# TYPE pc_miner_submit_http_4xx_total counter\n\
pc_miner_submit_http_4xx_total {submit_http_4xx_total}\n\
# HELP pc_miner_submit_http_5xx_total Total submit HTTP 5xx responses\n\
# TYPE pc_miner_submit_http_5xx_total counter\n\
pc_miner_submit_http_5xx_total {submit_http_5xx_total}\n\
# HELP pc_miner_submit_json_errors_total Total submit JSON decode errors\n\
# TYPE pc_miner_submit_json_errors_total counter\n\
pc_miner_submit_json_errors_total {submit_json_errors_total}\n\
# HELP pc_miner_last_submit_http_status Last observed /mint/submit HTTP status code (0=unknown)\n\
# TYPE pc_miner_last_submit_http_status gauge\n\
pc_miner_last_submit_http_status {last_submit_http_status}\n\
# HELP pc_miner_last_template_epoch Last successful template fetch time (epoch seconds)\n\
# TYPE pc_miner_last_template_epoch gauge\n\
pc_miner_last_template_epoch {last_template_epoch}\n\
# HELP pc_miner_last_submit_ok_epoch Last accepted submission time (epoch seconds)\n\
# TYPE pc_miner_last_submit_ok_epoch gauge\n\
pc_miner_last_submit_ok_epoch {last_submit_ok_epoch}\n\
# HELP pc_miner_last_template_fetch_ms Duration of last /mint/template fetch (request+parse) in milliseconds\n\
# TYPE pc_miner_last_template_fetch_ms gauge\n\
pc_miner_last_template_fetch_ms {last_template_fetch_ms}\n\
# HELP pc_miner_last_submit_ms Duration of last /mint/submit (request+parse) in milliseconds\n\
# TYPE pc_miner_last_submit_ms gauge\n\
pc_miner_last_submit_ms {last_submit_ms}\n\
# HELP pc_miner_process_rss_bytes Miner process resident memory (RSS) in bytes\n\
# TYPE pc_miner_process_rss_bytes gauge\n\
pc_miner_process_rss_bytes {rss_bytes}\n\
# HELP pc_miner_process_cpu_pct Miner process CPU usage percent\n\
# TYPE pc_miner_process_cpu_pct gauge\n\
pc_miner_process_cpu_pct {cpu_pct}\n"
        )
    }
}

async fn start_metrics_server(
    metrics: Arc<MinerMetrics>,
    addr_str: &str,
) -> Result<(
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<()>>,
)> {
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| anyhow!("invalid metrics_addr '{}': {e}", addr_str))?;
    if !addr.ip().is_loopback() {
        bail!("metrics_addr darf nur auf 127.0.0.1/::1 binden (nicht öffentlich)");
    }

    let listener =
        std::net::TcpListener::bind(addr).map_err(|e| anyhow!("bind metrics_addr: {e}"))?;
    let actual = listener
        .local_addr()
        .map_err(|e| anyhow!("metrics listener local_addr: {e}"))?;

    let make_svc = make_service_fn(move |_conn| {
        let metrics = metrics.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let metrics = metrics.clone();
                async move {
                    if req.uri().path() != "/metrics" {
                        let mut resp = Response::new(Body::from("Not Found"));
                        *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
                        resp.headers_mut().insert(
                            hyper::header::CONTENT_TYPE,
                            hyper::header::HeaderValue::from_static("text/plain"),
                        );
                        return Ok::<_, Infallible>(resp);
                    }
                    let body = metrics.render_prometheus();
                    let mut resp = Response::new(Body::from(body));
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"),
                    );
                    Ok::<_, Infallible>(resp)
                }
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .map_err(|e| anyhow!("metrics server from_tcp: {e}"))?
        .serve(make_svc);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let graceful = server.with_graceful_shutdown(async move {
        let _ = rx.await;
    });

    let task = tokio::spawn(async move {
        graceful
            .await
            .map_err(|e| anyhow!("metrics server error: {e}"))
    });

    Ok((actual, tx, task))
}

fn spawn_rss_updater(metrics: Arc<MinerMetrics>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        while !metrics.shutdown.load(Ordering::Relaxed) {
            // refresh_process is cheap enough for 1-2s polling.
            sys.refresh_process(pid);
            if let Some(proc_) = sys.process(pid) {
                // sysinfo returns memory in KiB.
                let rss = proc_.memory();
                metrics.process_rss_bytes.store(rss, Ordering::Relaxed);
                // cpu_usage is a percentage and may exceed 100 on multi-core systems.
                let cpu_pct = proc_.cpu_usage() as f64;
                if cpu_pct.is_finite() && cpu_pct >= 0.0 {
                    let milli = (cpu_pct * 1000.0).round().min(u64::MAX as f64) as u64;
                    metrics
                        .process_cpu_pct_milli
                        .store(milli, Ordering::Relaxed);
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Logging initialisieren
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .with_writer(std::io::stdout)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            node_url,
            status_path,
            interval_ms,
            tls_ca,
            tls_client_pem,
        } => {
            let mut cfg = if let Some(p) = config {
                load_config(&p)?
            } else {
                // Fällt auf CLI-Parameter zurück
                MinerConfig {
                    node_url: node_url
                        .ok_or_else(|| anyhow!("--node-url oder --config erforderlich"))?,
                    status_path,
                    interval_ms,
                    tls_ca: None,
                    tls_client_pem: None,
                }
            };

            if let Some(p) = tls_ca {
                cfg.tls_ca = Some(p);
            }
            if let Some(p) = tls_client_pem {
                cfg.tls_client_pem = Some(p);
            }

            run_miner(&mut cfg).await?;
        }
        Commands::Mine {
            rpc_url,
            lock,
            threads,
            progress_secs,
            tls_ca,
            tls_client_pem,
            metrics_addr,
        } => {
            run_mint_miner(
                &rpc_url,
                &lock,
                threads,
                progress_secs,
                tls_ca.as_ref(),
                tls_client_pem.as_ref(),
                metrics_addr.as_deref(),
            )
            .await?;
        }
        Commands::Metrics { metrics_url, json } => {
            run_metrics_summary(&metrics_url, json).await?;
        }
    }

    Ok(())
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

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

async fn run_metrics_summary(metrics_url: &str, json: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build http client")?;
    let resp = client
        .get(metrics_url)
        .send()
        .await
        .context("GET /metrics")?;
    if !resp.status().is_success() {
        bail!("metrics http status {}", resp.status());
    }
    let text = resp.text().await.context("read metrics body")?;

    let uptime_seconds = parse_prom_f64(&text, "pc_miner_uptime_seconds").unwrap_or(0.0);
    let threads = parse_prom_u64(&text, "pc_miner_threads").unwrap_or(0);
    let hashes_total = parse_prom_u64(&text, "pc_miner_hashes_total").unwrap_or(0);
    let hashrate_hps = parse_prom_f64(&text, "pc_miner_hashrate_hps").unwrap_or(0.0);
    let templates_total = parse_prom_u64(&text, "pc_miner_templates_total").unwrap_or(0);
    let template_errors_total =
        parse_prom_u64(&text, "pc_miner_template_errors_total").unwrap_or(0);
    let template_timeout_total =
        parse_prom_u64(&text, "pc_miner_template_timeout_total").unwrap_or(0);
    let template_connect_total =
        parse_prom_u64(&text, "pc_miner_template_connect_total").unwrap_or(0);
    let template_http_4xx_total =
        parse_prom_u64(&text, "pc_miner_template_http_4xx_total").unwrap_or(0);
    let template_http_5xx_total =
        parse_prom_u64(&text, "pc_miner_template_http_5xx_total").unwrap_or(0);
    let template_json_errors_total =
        parse_prom_u64(&text, "pc_miner_template_json_errors_total").unwrap_or(0);
    let last_template_http_status =
        parse_prom_u64(&text, "pc_miner_last_template_http_status").unwrap_or(0);
    let submit_accepted_total =
        parse_prom_u64(&text, "pc_miner_submit_accepted_total").unwrap_or(0);
    let submit_stale_total = parse_prom_u64(&text, "pc_miner_submit_stale_total").unwrap_or(0);
    let submit_rejected_total =
        parse_prom_u64(&text, "pc_miner_submit_rejected_total").unwrap_or(0);
    let submit_errors_total = parse_prom_u64(&text, "pc_miner_submit_errors_total").unwrap_or(0);
    let submit_timeout_total = parse_prom_u64(&text, "pc_miner_submit_timeout_total").unwrap_or(0);
    let submit_connect_total = parse_prom_u64(&text, "pc_miner_submit_connect_total").unwrap_or(0);
    let submit_http_4xx_total =
        parse_prom_u64(&text, "pc_miner_submit_http_4xx_total").unwrap_or(0);
    let submit_http_5xx_total =
        parse_prom_u64(&text, "pc_miner_submit_http_5xx_total").unwrap_or(0);
    let submit_json_errors_total =
        parse_prom_u64(&text, "pc_miner_submit_json_errors_total").unwrap_or(0);
    let last_submit_http_status =
        parse_prom_u64(&text, "pc_miner_last_submit_http_status").unwrap_or(0);
    let last_template_epoch = parse_prom_u64(&text, "pc_miner_last_template_epoch").unwrap_or(0);
    let last_submit_ok_epoch = parse_prom_u64(&text, "pc_miner_last_submit_ok_epoch").unwrap_or(0);
    let last_template_fetch_ms =
        parse_prom_u64(&text, "pc_miner_last_template_fetch_ms").unwrap_or(0);
    let last_submit_ms = parse_prom_u64(&text, "pc_miner_last_submit_ms").unwrap_or(0);
    let rss_bytes = parse_prom_u64(&text, "pc_miner_process_rss_bytes").unwrap_or(0);
    let cpu_pct = parse_prom_f64(&text, "pc_miner_process_cpu_pct").unwrap_or(0.0);

    let now = now_epoch_secs();
    let template_age_s = if last_template_epoch > 0 {
        now.saturating_sub(last_template_epoch)
    } else {
        0
    };
    let submit_age_s = if last_submit_ok_epoch > 0 {
        now.saturating_sub(last_submit_ok_epoch)
    } else {
        0
    };
    let rss_mb = rss_bytes / 1024 / 1024;

    if json {
        println!(
            "{{\"metrics_url\":\"{}\",\"uptime_seconds\":{},\"threads\":{},\"hashes_total\":{},\"hashrate_hps\":{},\"templates_total\":{},\"template_errors_total\":{},\"template_timeout_total\":{},\"template_connect_total\":{},\"template_http_4xx_total\":{},\"template_http_5xx_total\":{},\"template_json_errors_total\":{},\"last_template_http_status\":{},\"submit_accepted_total\":{},\"submit_stale_total\":{},\"submit_rejected_total\":{},\"submit_errors_total\":{},\"submit_timeout_total\":{},\"submit_connect_total\":{},\"submit_http_4xx_total\":{},\"submit_http_5xx_total\":{},\"submit_json_errors_total\":{},\"last_submit_http_status\":{},\"last_template_epoch\":{},\"last_template_age_s\":{},\"last_submit_ok_epoch\":{},\"last_submit_ok_age_s\":{},\"last_template_fetch_ms\":{},\"last_submit_ms\":{},\"process_rss_bytes\":{},\"process_rss_mb\":{},\"process_cpu_pct\":{}}}",
            escape_json_string(metrics_url),
            uptime_seconds,
            threads,
            hashes_total,
            hashrate_hps,
            templates_total,
            template_errors_total,
            template_timeout_total,
            template_connect_total,
            template_http_4xx_total,
            template_http_5xx_total,
            template_json_errors_total,
            last_template_http_status,
            submit_accepted_total,
            submit_stale_total,
            submit_rejected_total,
            submit_errors_total,
            submit_timeout_total,
            submit_connect_total,
            submit_http_4xx_total,
            submit_http_5xx_total,
            submit_json_errors_total,
            last_submit_http_status,
            last_template_epoch,
            template_age_s,
            last_submit_ok_epoch,
            submit_age_s,
            last_template_fetch_ms,
            last_submit_ms,
            rss_bytes,
            rss_mb,
            cpu_pct,
        );
        return Ok(());
    }

    println!("phantom-miner metrics");
    println!("source: {}", metrics_url);
    println!("hashrate_hps: {:.2}", hashrate_hps);
    println!("threads: {}", threads);
    println!("hashes_total: {}", hashes_total);
    println!(
        "templates: total={} errors={} timeout={} connect={} http4xx={} http5xx={} json={}",
        templates_total,
        template_errors_total,
        template_timeout_total,
        template_connect_total,
        template_http_4xx_total,
        template_http_5xx_total,
        template_json_errors_total,
    );
    println!("last_template_http_status: {}", last_template_http_status);
    println!(
        "submit: accepted={} stale={} rejected={} errors={} timeout={} connect={} http4xx={} http5xx={} json={}",
        submit_accepted_total,
        submit_stale_total,
        submit_rejected_total,
        submit_errors_total,
        submit_timeout_total,
        submit_connect_total,
        submit_http_4xx_total,
        submit_http_5xx_total,
        submit_json_errors_total,
    );
    println!("last_submit_http_status: {}", last_submit_http_status);
    if last_template_epoch > 0 {
        println!(
            "last_template_epoch: {} (age {}s)",
            last_template_epoch, template_age_s
        );
    } else {
        println!("last_template_epoch: -");
    }
    if last_submit_ok_epoch > 0 {
        println!(
            "last_submit_ok_epoch: {} (age {}s)",
            last_submit_ok_epoch, submit_age_s
        );
    } else {
        println!("last_submit_ok_epoch: -");
    }
    if last_template_fetch_ms > 0 {
        println!("last_template_fetch_ms: {}", last_template_fetch_ms);
    } else {
        println!("last_template_fetch_ms: -");
    }
    if last_submit_ms > 0 {
        println!("last_submit_ms: {}", last_submit_ms);
    } else {
        println!("last_submit_ms: -");
    }
    println!("process_rss_mb: {}", rss_mb);
    println!("process_cpu_pct: {:.2}", cpu_pct);
    println!("uptime_seconds: {:.1}", uptime_seconds);
    Ok(())
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!(
            "ungültige Hex-Länge (erwartet 64 Zeichen, bekommen {} )",
            s.len()
        );
    }
    let b = hex::decode(s)?;
    if b.len() != 32 {
        bail!("ungültige Bytes-Länge (erwartet 32, bekommen {})", b.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn resolve_template_round_context(tmpl: &MintTemplate) -> Result<([u8; 32], u64, u8)> {
    let round_id = parse_hex32(&tmpl.round_id)?;
    match tmpl.phase {
        MintRoundPhase::Searching => Ok((round_id, current_emission_bucket(), tmpl.target_bits)),
        MintRoundPhase::Collecting => match (tmpl.hit_bucket, tmpl.bits_used) {
            (Some(hit_bucket), Some(bits_used)) => Ok((round_id, hit_bucket, bits_used)),
            _ => bail!("collecting template ohne eingefrorenen Emissionskontext"),
        },
    }
}

fn mine_nonce(
    seed: [u8; 32],
    bits: u8,
    threads: usize,
    progress_secs: u64,
    metrics: Option<Arc<MinerMetrics>>,
) -> Result<(u64, u64)> {
    if (bits as u16) > 256 {
        bail!(
            "difficulty bits {} ist außerhalb des erlaubten Bereichs",
            bits
        );
    }

    let n_threads = std::cmp::max(1, threads);
    if let Some(m) = metrics.as_ref() {
        m.threads.store(n_threads as u64, Ordering::Relaxed);
    }

    let found = Arc::new(AtomicBool::new(false));
    let winner = Arc::new(AtomicU64::new(0));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let base_total_hashes: u64 = metrics
        .as_ref()
        .map(|m| m.hashes_total.load(Ordering::Relaxed))
        .unwrap_or(0);

    let mut handles = Vec::with_capacity(n_threads);
    for tid in 0..n_threads {
        let seed_t = seed;
        let found_t = found.clone();
        let winner_t = winner.clone();
        let total_hashes_t = total_hashes.clone();
        let step = n_threads as u64;
        let bits_t = bits;
        let h = thread::spawn(move || {
            let mut nonce: u64 = tid as u64;
            while !found_t.load(Ordering::Relaxed) {
                let h = pow_hash(&seed_t, nonce);
                total_hashes_t.fetch_add(1, Ordering::Relaxed);
                if pow_meets(bits_t, &h) {
                    if !found_t.swap(true, Ordering::Relaxed) {
                        winner_t.store(nonce, Ordering::Relaxed);
                    }
                    break;
                }
                nonce = nonce.wrapping_add(step);
            }
        });
        handles.push(h);
    }

    let mut progress_handle = None;
    let tick_secs = if progress_secs > 0 {
        progress_secs
    } else if metrics.is_some() {
        // Wenn /metrics aktiviert ist, wollen wir trotzdem laufend Hashrate/Hashes aktualisieren.
        1
    } else {
        0
    };
    let print_progress = progress_secs > 0;
    if tick_secs > 0 {
        let found_p = found.clone();
        let th = total_hashes.clone();
        let secs = tick_secs;
        let metrics_p = metrics.clone();
        let base = base_total_hashes;
        progress_handle = Some(thread::spawn(move || {
            while !found_p.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(secs));
                let elapsed = start.elapsed().as_secs_f64();
                let hashes = th.load(Ordering::Relaxed) as f64;
                let hps = if elapsed > 0.0 { hashes / elapsed } else { 0.0 };
                if print_progress {
                    eprintln!(
                        "{{\"type\":\"progress\",\"elapsed_s\":{:.2},\"hashes\":{},\"hashes_per_s\":{:.2}}}",
                        elapsed,
                        hashes as u64,
                        hps
                    );
                }
                if let Some(m) = metrics_p.as_ref() {
                    let micro = (hps * 1_000_000.0).max(0.0) as u64;
                    m.hashrate_hps_micro.store(micro, Ordering::Relaxed);
                    m.hashes_total
                        .store(base.saturating_add(hashes as u64), Ordering::Relaxed);
                }
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }
    if let Some(h) = progress_handle {
        let _ = h.join();
    }

    let nonce = winner.load(Ordering::Relaxed);
    let hash = pow_hash(&seed, nonce);
    if !pow_meets(bits, &hash) {
        bail!("interner Fehler: gefundene Lösung ist ungültig");
    }
    let total = total_hashes.load(Ordering::Relaxed);
    if let Some(m) = metrics.as_ref() {
        m.hashes_total
            .store(base_total_hashes.saturating_add(total), Ordering::Relaxed);
    }
    Ok((nonce, total))
}

async fn run_mint_miner(
    rpc_url: &str,
    lock_hex: &str,
    threads: Option<usize>,
    progress_secs: u64,
    tls_ca: Option<&PathBuf>,
    tls_client_pem: Option<&PathBuf>,
    metrics_addr: Option<&str>,
) -> Result<()> {
    let _ = parse_hex32(lock_hex)?;
    let base = rpc_url.trim_end_matches('/').to_string();
    let client = build_http_client(&base, tls_ca, tls_client_pem, Duration::from_secs(10))?;

    let metrics: Option<Arc<MinerMetrics>> = metrics_addr.map(|_| Arc::new(MinerMetrics::new()));
    let mut metrics_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>> = None;
    let mut metrics_task: Option<tokio::task::JoinHandle<Result<()>>> = None;
    let mut rss_thread: Option<thread::JoinHandle<()>> = None;
    if let (Some(addr_str), Some(m)) = (metrics_addr, metrics.clone()) {
        let (actual, tx, task) = start_metrics_server(m.clone(), addr_str).await?;
        println!("{{\"type\":\"metrics_serve\",\"addr\":\"{}\"}}", actual);
        metrics_shutdown_tx = Some(tx);
        metrics_task = Some(task);
        rss_thread = Some(spawn_rss_updater(m));
    }

    loop {
        let status_url = format!("{}/mint/status", base);
        let status_resp = match client.get(&status_url).send().await {
            Ok(r) => r,
            Err(e) => {
                if let Some(m) = metrics.as_ref() {
                    m.template_errors_total.fetch_add(1, Ordering::Relaxed);
                }
                return Err(e.into());
            }
        };
        let status_code = status_resp.status();
        if !status_code.is_success() {
            if let Some(m) = metrics.as_ref() {
                m.template_errors_total.fetch_add(1, Ordering::Relaxed);
            }
            return Err(http_error_with_body(
                status_resp,
                MAX_MINT_RPC_BODY_BYTES,
                "mint status",
                &status_url,
            )
            .await?);
        }
        let status: MintStatus = match read_json_response_with_diag(
            status_resp,
            MAX_MINT_RPC_BODY_BYTES,
            "mint status",
            &status_url,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                if let Some(m) = metrics.as_ref() {
                    m.template_errors_total.fetch_add(1, Ordering::Relaxed);
                    m.template_json_errors_total.fetch_add(1, Ordering::Relaxed);
                }
                return Err(e);
            }
        };
        if !status.can_mint {
            info!("can_mint ist false, Mining wird beendet");
            break;
        }

        let tmpl_url = format!("{}/mint/template", base);
        let tmpl_start = Instant::now();
        let tmpl_resp = match client.get(&tmpl_url).send().await {
            Ok(r) => r,
            Err(e) => {
                if let Some(m) = metrics.as_ref() {
                    m.template_errors_total.fetch_add(1, Ordering::Relaxed);
                    if e.is_timeout() {
                        m.template_timeout_total.fetch_add(1, Ordering::Relaxed);
                    } else if e.is_connect() {
                        m.template_connect_total.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return Err(e.into());
            }
        };
        let tmpl_status = tmpl_resp.status();
        if let Some(m) = metrics.as_ref() {
            m.last_template_http_status
                .store(tmpl_status.as_u16() as u64, Ordering::Relaxed);
        }
        if !tmpl_status.is_success() {
            if let Some(m) = metrics.as_ref() {
                m.template_errors_total.fetch_add(1, Ordering::Relaxed);
                if tmpl_status.is_client_error() {
                    m.template_http_4xx_total.fetch_add(1, Ordering::Relaxed);
                } else if tmpl_status.is_server_error() {
                    m.template_http_5xx_total.fetch_add(1, Ordering::Relaxed);
                }
            }
            return Err(http_error_with_body(
                tmpl_resp,
                MAX_MINT_RPC_BODY_BYTES,
                "mint template",
                &tmpl_url,
            )
            .await?);
        }
        let tmpl: MintTemplate = match read_json_response_with_diag(
            tmpl_resp,
            MAX_MINT_RPC_BODY_BYTES,
            "mint template",
            &tmpl_url,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                if let Some(m) = metrics.as_ref() {
                    m.template_errors_total.fetch_add(1, Ordering::Relaxed);
                    m.template_json_errors_total.fetch_add(1, Ordering::Relaxed);
                }
                return Err(e);
            }
        };
        if let Some(m) = metrics.as_ref() {
            let ms = tmpl_start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            m.last_template_fetch_ms.store(ms, Ordering::Relaxed);
            m.templates_total.fetch_add(1, Ordering::Relaxed);
            m.last_template_epoch
                .store(now_epoch_secs(), Ordering::Relaxed);
        }
        if tmpl.reward == 0 {
            info!("reward ist 0, Mining wird beendet");
            break;
        }

        let network_id = parse_hex32(&tmpl.network_id)?;
        let prev_mint_id = parse_hex32(&tmpl.prev_mint_id)?;
        let (round_id, hit_bucket, bits_used) = resolve_template_round_context(&tmpl)?;
        let lock_bytes = parse_hex32(lock_hex)?;
        let template_event = MintEvent {
            version: MINT_VERSION_V2,
            prev_mint_id,
            outputs: vec![TxOut {
                amount: tmpl.reward,
                lock: LockCommitment(lock_bytes),
            }],
            pow_seed: [0u8; 32],
            pow_nonce: 0,
            minted_at: 0,
            round_id,
            hit_bucket,
            bits_used,
        };
        let pow_seed = mint_pow_seed_v2(&network_id, &template_event);
        let pow_seed_hex = hex::encode(pow_seed);

        let bits = bits_used;
        let n_threads = threads.unwrap_or_else(num_cpus::get);
        let n_threads = std::cmp::max(1, n_threads);

        info!(
            prev_mint_id = %tmpl.prev_mint_id,
            round_id = %tmpl.round_id,
            phase = ?tmpl.phase,
            hit_bucket,
            difficulty = bits,
            reward = tmpl.reward,
            threads = n_threads,
            "starting PoW search"
        );

        let seed_for_mining = pow_seed;
        let metrics_for_mining = metrics.clone();
        let mining_res = tokio::task::spawn_blocking(move || {
            mine_nonce(
                seed_for_mining,
                bits,
                n_threads,
                progress_secs,
                metrics_for_mining,
            )
        })
        .await?;
        let (nonce, total_hashes) = mining_res?;

        info!(pow_nonce = nonce, total_hashes, "found valid PoW solution");

        let mint_json = MintEventJson {
            version: MINT_VERSION_V2,
            prev_mint_id: tmpl.prev_mint_id.clone(),
            outputs: vec![TxOutJson {
                amount: tmpl.reward,
                lock: lock_hex.to_string(),
            }],
            pow_seed: pow_seed_hex,
            pow_nonce: nonce,
            minted_at: 0,
            round_id: Some(hex::encode(round_id)),
            hit_bucket: Some(hit_bucket),
            bits_used: Some(bits_used),
        };

        let submit = SubmitMintRequest { mint: mint_json };
        let submit_url = format!("{}/mint/submit", base);
        let submit_start = Instant::now();
        let submit_resp = match client.post(&submit_url).json(&submit).send().await {
            Ok(r) => r,
            Err(e) => {
                if let Some(m) = metrics.as_ref() {
                    m.submit_errors_total.fetch_add(1, Ordering::Relaxed);
                    if e.is_timeout() {
                        m.submit_timeout_total.fetch_add(1, Ordering::Relaxed);
                    } else if e.is_connect() {
                        m.submit_connect_total.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return Err(e.into());
            }
        };
        let status = submit_resp.status();
        if let Some(m) = metrics.as_ref() {
            m.last_submit_http_status
                .store(status.as_u16() as u64, Ordering::Relaxed);
            if status == reqwest::StatusCode::CONFLICT {
                // handled via submit_stale_total, keep 4xx bucket excluding 409 to avoid double-count confusion.
            } else if status.is_client_error() {
                m.submit_http_4xx_total.fetch_add(1, Ordering::Relaxed);
            } else if status.is_server_error() {
                m.submit_http_5xx_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        let submit: SubmitMintResponse = match read_json_response_with_diag(
            submit_resp,
            MAX_MINT_RPC_BODY_BYTES,
            "mint submit",
            &submit_url,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                if let Some(m) = metrics.as_ref() {
                    m.submit_errors_total.fetch_add(1, Ordering::Relaxed);
                    m.submit_json_errors_total.fetch_add(1, Ordering::Relaxed);
                }
                return Err(e);
            }
        };
        if let Some(m) = metrics.as_ref() {
            let ms = submit_start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            m.last_submit_ms.store(ms, Ordering::Relaxed);
        }

        if submit.ok {
            if let Some(mint_id) = submit.mint_id {
                info!(mint_id = %mint_id, "mint accepted by server");
                if let Some(m) = metrics.as_ref() {
                    m.submit_accepted_total.fetch_add(1, Ordering::Relaxed);
                    m.last_submit_ok_epoch
                        .store(now_epoch_secs(), Ordering::Relaxed);
                }
            }
        } else {
            let error_msg = submit
                .error
                .unwrap_or_else(|| "unbekannter Fehler".to_string());
            if status == reqwest::StatusCode::CONFLICT {
                // Stale template - ein anderer Miner war schneller, neues Template holen
                warn!(
                    "stale template (409 CONFLICT): {}, fetching new template",
                    error_msg
                );
                if let Some(m) = metrics.as_ref() {
                    m.submit_stale_total.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            } else {
                if let Some(m) = metrics.as_ref() {
                    m.submit_rejected_total.fetch_add(1, Ordering::Relaxed);
                }
                bail!("mint wurde abgelehnt ({}): {}", status, error_msg);
            }
        }
    }

    if let Some(m) = metrics.as_ref() {
        m.shutdown.store(true, Ordering::Relaxed);
    }
    if let Some(tx) = metrics_shutdown_tx.take() {
        let _ = tx.send(());
    }
    if let Some(task) = metrics_task.take() {
        let _ = task.await;
    }
    if let Some(h) = rss_thread.take() {
        let _ = h.join();
    }

    Ok(())
}

fn load_config(path: &PathBuf) -> Result<MinerConfig> {
    let raw = std::fs::read_to_string(path)?;
    let cfg: MinerConfig = toml::from_str(&raw)?;
    Ok(cfg)
}

async fn run_miner(cfg: &mut MinerConfig) -> Result<()> {
    info!(url = %cfg.node_url, status = %cfg.status_path, interval_ms = cfg.interval_ms, "starting miner");

    // Poll-Loop
    let url = cfg.node_url.clone();
    let path = cfg.status_path.clone();
    let client = build_http_client(
        &url,
        cfg.tls_ca.as_ref(),
        cfg.tls_client_pem.as_ref(),
        Duration::from_secs(5),
    )?;

    let mut ticker = tokio::time::interval(Duration::from_millis(cfg.interval_ms));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let status_url = format!("{}{}", url, path);
                match client.get(&status_url).send().await {
                    Ok(resp) => {
                        let code = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        info!(status_url = %status_url, code = %code, body = %text, "node status");
                    }
                    Err(e) => {
                        error!(error = %e, "status request failed");
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutdown requested");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miner_metrics_prometheus_contains_expected_names() {
        let m = MinerMetrics::new();
        let text = m.render_prometheus();
        for name in [
            "pc_miner_uptime_seconds",
            "pc_miner_threads",
            "pc_miner_hashes_total",
            "pc_miner_hashrate_hps",
            "pc_miner_templates_total",
            "pc_miner_template_errors_total",
            "pc_miner_template_timeout_total",
            "pc_miner_template_connect_total",
            "pc_miner_template_http_4xx_total",
            "pc_miner_template_http_5xx_total",
            "pc_miner_template_json_errors_total",
            "pc_miner_last_template_http_status",
            "pc_miner_submit_accepted_total",
            "pc_miner_submit_stale_total",
            "pc_miner_submit_rejected_total",
            "pc_miner_submit_errors_total",
            "pc_miner_submit_timeout_total",
            "pc_miner_submit_connect_total",
            "pc_miner_submit_http_4xx_total",
            "pc_miner_submit_http_5xx_total",
            "pc_miner_submit_json_errors_total",
            "pc_miner_last_submit_http_status",
            "pc_miner_last_template_epoch",
            "pc_miner_last_submit_ok_epoch",
            "pc_miner_last_template_fetch_ms",
            "pc_miner_last_submit_ms",
            "pc_miner_process_rss_bytes",
            "pc_miner_process_cpu_pct",
        ] {
            assert!(text.contains(name), "missing metric name: {name}");
        }
    }
}
