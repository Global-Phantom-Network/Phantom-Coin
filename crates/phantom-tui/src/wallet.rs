use crate::http_util;
use anyhow::{anyhow, Context, Result};
use bech32::FromBase32;
use bitcoin::bip32::Xpub;
use crossterm::event::{KeyCode, KeyEvent};
use phantom_i18n::{tui_texts, Lang, TuiTexts};
use phantom_signer::walletdb::{WalletAddrMeta, WalletDb};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;
use serde::Deserialize;
use std::borrow::Cow;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

const DEFAULT_RPC_TIMEOUT_SECS: u64 = 10;
const DEFAULT_RPC_CONNECT_TIMEOUT_SECS: u64 = 5;
const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Clone)]
struct HistoryUtxo {
    txid: String,
    vout: u32,
    amount: u64,
    minted_at: u64,
    staked: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct HistoryResp {
    ok: bool,
    lock: String,
    #[serde(default)]
    balance: u64,
    #[serde(default)]
    staked_balance: u64,
    #[serde(default)]
    n_utxos: usize,
    utxos: Vec<HistoryUtxo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiMode {
    Normal,
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendField {
    Recipient,
    Amount,
    Fee,
}

#[derive(Debug)]
struct AppState {
    addrs: Vec<WalletAddrMeta>,
    selected: usize,
    history: Option<HistoryResp>,
    status: String,
    node: String,
    auth_token: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_client_pem: Option<PathBuf>,
    mode: UiMode,
    send_field: SendField,
    send_recipient: String,
    send_amount: String,
    send_fee: String,
    wallet_db_path: PathBuf,
    passphrase: Zeroizing<String>,
    history_job: Option<HistoryJob>,
}

#[derive(Debug)]
struct HistoryJob {
    selected: usize,
    rx: mpsc::Receiver<Result<HistoryResp, String>>,
}

impl AppState {
    fn new(
        addrs: Vec<WalletAddrMeta>,
        node: String,
        auth_token: Option<String>,
        tls_ca: Option<PathBuf>,
        tls_client_pem: Option<PathBuf>,
        wallet_db_path: PathBuf,
        passphrase: Zeroizing<String>,
    ) -> Self {
        Self {
            addrs,
            selected: 0,
            history: None,
            status: String::new(),
            node,
            auth_token,
            tls_ca,
            tls_client_pem,
            mode: UiMode::Normal,
            send_field: SendField::Recipient,
            send_recipient: String::new(),
            send_amount: String::new(),
            send_fee: String::from("0"),
            wallet_db_path,
            passphrase,
            history_job: None,
        }
    }

    fn selected_addr(&self) -> Option<&WalletAddrMeta> {
        self.addrs.get(self.selected)
    }

    fn clear_send_form(&mut self) {
        self.send_recipient.clear();
        self.send_amount.clear();
        self.send_fee = String::from("0");
        self.send_field = SendField::Recipient;
    }
}

pub struct WalletState {
    texts: &'static TuiTexts,
    wallet_db_path: PathBuf,
    node: String,
    auth_token: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_client_pem: Option<PathBuf>,
    login_input: Zeroizing<String>,
    login_error: String,
    show_passphrase: bool,
    app: Option<AppState>,
}

impl WalletState {
    pub fn new(lang: Lang) -> Self {
        let texts = tui_texts(lang);
        let wallet_db_path =
            default_walletdb_path().unwrap_or_else(|_| PathBuf::from("./wallets/default"));
        Self {
            texts,
            wallet_db_path,
            node: "https://127.0.0.1:8080".to_string(),
            auth_token: None,
            tls_ca: None,
            tls_client_pem: None,
            login_input: Zeroizing::new(String::new()),
            login_error: String::new(),
            show_passphrase: false,
            app: None,
        }
    }
}

pub fn tick(state: &mut WalletState) {
    let Some(app) = state.app.as_mut() else {
        return;
    };
    let mut finished: Option<(usize, Result<HistoryResp, String>)> = None;
    if let Some(job) = app.history_job.as_ref() {
        match job.rx.try_recv() {
            Ok(res) => finished = Some((job.selected, res)),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                finished = Some((job.selected, Err("history worker disconnected".to_string())))
            }
        }
    }
    if let Some((selected, res)) = finished {
        app.history_job = None;
        if selected != app.selected {
            // Stale response for a previously selected address.
            // Veraltete Antwort für eine zuvor ausgewählte Adresse.
            return;
        }
        match res {
            Ok(hist) => {
                if !hist.ok {
                    app.status = format!("{}: ok=false", state.texts.history_error);
                } else {
                    app.status.clear();
                }
                app.history = Some(hist);
            }
            Err(e) => {
                app.status = format!("{}: {}", state.texts.history_error, e);
            }
        }
    }
}

pub fn handle_key(state: &mut WalletState, key: KeyEvent) -> bool {
    if state.app.is_none() {
        match key.code {
            KeyCode::Tab => {
                state.show_passphrase = !state.show_passphrase;
                true
            }
            KeyCode::Enter => {
                if let Err(e) = try_unlock(state) {
                    state.login_error = format!("{}", e);
                }
                true
            }
            KeyCode::Backspace => {
                state.login_input.pop();
                true
            }
            KeyCode::Char(c) => {
                state.login_input.push(c);
                true
            }
            _ => false,
        }
    } else if let Some(app) = state.app.as_mut() {
        match app.mode {
            UiMode::Normal => match key.code {
                KeyCode::Char('s') => {
                    app.mode = UiMode::Send;
                    app.clear_send_form();
                    app.status = state.texts.send.to_string();
                    true
                }
                KeyCode::Char('n') => {
                    match generate_new_address(
                        &app.wallet_db_path,
                        &app.passphrase,
                        &app.node,
                        app.auth_token.as_deref(),
                    ) {
                        Ok(new_addr) => {
                            app.addrs.push(new_addr);
                            app.status = state.texts.new_addr_generated.to_string();
                        }
                        Err(e) => {
                            app.status = format!("{}: {}", state.texts.error, e);
                        }
                    }
                    true
                }
                KeyCode::Up => {
                    if app.selected > 0 {
                        app.selected -= 1;
                        refresh_history(app, state.texts);
                    }
                    true
                }
                KeyCode::Down => {
                    if app.selected + 1 < app.addrs.len() {
                        app.selected += 1;
                        refresh_history(app, state.texts);
                    }
                    true
                }
                _ => false,
            },
            UiMode::Send => match key.code {
                KeyCode::Esc => {
                    app.mode = UiMode::Normal;
                    app.clear_send_form();
                    app.status.clear();
                    true
                }
                KeyCode::Tab => {
                    app.send_field = match app.send_field {
                        SendField::Recipient => SendField::Amount,
                        SendField::Amount => SendField::Fee,
                        SendField::Fee => SendField::Recipient,
                    };
                    true
                }
                KeyCode::Enter => {
                    if let Some(from) = app.selected_addr().cloned() {
                        match execute_send(app, &from, state.texts) {
                            Ok(txid) => {
                                app.status =
                                    format!("{} (txid: {})", state.texts.send_success, txid);
                                app.mode = UiMode::Normal;
                                app.clear_send_form();
                                refresh_history(app, state.texts);
                            }
                            Err(e) => {
                                app.status = format!("{}: {}", state.texts.send_failed, e);
                            }
                        }
                    }
                    true
                }
                KeyCode::Backspace => {
                    match app.send_field {
                        SendField::Recipient => {
                            app.send_recipient.pop();
                        }
                        SendField::Amount => {
                            app.send_amount.pop();
                        }
                        SendField::Fee => {
                            app.send_fee.pop();
                        }
                    }
                    true
                }
                KeyCode::Char(c) => {
                    match app.send_field {
                        SendField::Recipient => app.send_recipient.push(c),
                        SendField::Amount => {
                            if c.is_ascii_digit() {
                                app.send_amount.push(c);
                            }
                        }
                        SendField::Fee => {
                            if c.is_ascii_digit() {
                                app.send_fee.push(c);
                            }
                        }
                    }
                    true
                }
                _ => false,
            },
        }
    } else {
        false
    }
}

pub fn draw(f: &mut Frame, area: Rect, state: &WalletState) {
    if state.app.is_none() {
        draw_login(f, area, state);
        return;
    }
    let app = match state.app.as_ref() {
        Some(a) => a,
        None => return,
    };
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    let Some(left_chunk) = chunks.first() else {
        return;
    };
    let Some(right_root) = chunks.get(1) else {
        return;
    };

    let addr_items: Vec<ListItem> = app
        .addrs
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let label = a.label.as_deref().unwrap_or("");
            let line = if label.is_empty() {
                a.addr.clone()
            } else {
                format!("{} [{}]", a.addr, label)
            };
            let mut li = ListItem::new(Line::from(Span::raw(line)));
            if i == app.selected {
                li = li.style(Style::default().add_modifier(Modifier::REVERSED));
            }
            li
        })
        .collect();
    let addr_block = List::new(addr_items).block(
        Block::default()
            .title(state.texts.addresses)
            .borders(Borders::ALL),
    );
    f.render_widget(addr_block, *left_chunk);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(*right_root);

    let (summary_area, main_area, status_area) = match right_chunks.as_ref() {
        [s, m, t] => (*s, *m, *t),
        _ => return,
    };

    match app.mode {
        UiMode::Normal => {
            let summary_text =
                if let (Some(sel), Some(hist)) = (app.selected_addr(), app.history.as_ref()) {
                    format!(
                        "Addr: {}\nLock: {}\n{}: {}\n{}: {}\nUTXOs: {}",
                        sel.addr,
                        hist.lock,
                        state.texts.balance,
                        hist.balance,
                        state.texts.staked,
                        hist.staked_balance,
                        hist.n_utxos
                    )
                } else {
                    state.texts.no_history.to_string()
                };
            let summary = Paragraph::new(summary_text).block(
                Block::default()
                    .title(state.texts.summary)
                    .borders(Borders::ALL),
            );
            f.render_widget(summary, summary_area);

            let utxo_lines: Vec<Line> = if let Some(hist) = app.history.as_ref() {
                hist.utxos
                    .iter()
                    .take(16)
                    .map(|u| {
                        let prefix: String = u.txid.chars().take(8).collect();
                        Line::from(Span::raw(format!(
                            "{}:{} amt={} minted_at={} staked={}",
                            prefix, u.vout, u.amount, u.minted_at, u.staked
                        )))
                    })
                    .collect()
            } else {
                vec![Line::from(Span::raw(""))]
            };
            let utxo_para = Paragraph::new(utxo_lines).block(
                Block::default()
                    .title(state.texts.utxos)
                    .borders(Borders::ALL),
            );
            f.render_widget(utxo_para, main_area);
        }
        UiMode::Send => {
            let combined_area = summary_area.union(main_area);
            let send_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(1),
                ])
                .split(combined_area);

            let (recipient_area, amount_area, fee_area, hint_area) = match send_chunks.as_ref() {
                [r, a, f, h] => (*r, *a, *f, *h),
                _ => return,
            };

            let recipient_style = if app.send_field == SendField::Recipient {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let recipient_input = Paragraph::new(app.send_recipient.as_str())
                .style(recipient_style)
                .block(
                    Block::default()
                        .title(state.texts.recipient)
                        .borders(Borders::ALL),
                );
            f.render_widget(recipient_input, recipient_area);

            let amount_style = if app.send_field == SendField::Amount {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let amount_input = Paragraph::new(app.send_amount.as_str())
                .style(amount_style)
                .block(
                    Block::default()
                        .title(state.texts.amount)
                        .borders(Borders::ALL),
                );
            f.render_widget(amount_input, amount_area);

            let fee_style = if app.send_field == SendField::Fee {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let fee_input = Paragraph::new(app.send_fee.as_str())
                .style(fee_style)
                .block(
                    Block::default()
                        .title(state.texts.fee)
                        .borders(Borders::ALL),
                );
            f.render_widget(fee_input, fee_area);

            let hint_text = format!("{} | {}", state.texts.confirm_send, state.texts.cancel);
            let hint = Paragraph::new(hint_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(state.texts.send),
            );
            f.render_widget(hint, hint_area);
        }
    }

    let status_hint = match app.mode {
        UiMode::Normal => state.texts.menu_hint,
        UiMode::Send => "Tab=Feld wechseln, Enter=Senden, Esc=Abbrechen",
    };
    let status_line = Paragraph::new(format!("{} | {}", app.status, status_hint))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status_line, status_area);
}

fn draw_login(f: &mut Frame, area: Rect, state: &WalletState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(area);
    let title = Paragraph::new(state.texts.title.to_string())
        .block(Block::default().borders(Borders::ALL).title("Wallet Login"));
    f.render_widget(title, chunks[0]);

    let path_line = format!(
        "{}: {}",
        state.texts.wallet_db_label,
        state.wallet_db_path.display()
    );
    let path =
        Paragraph::new(path_line).block(Block::default().borders(Borders::ALL).title("Pfad"));
    f.render_widget(path, chunks[1]);

    let pass_display: Cow<'_, str> = if state.show_passphrase {
        Cow::Borrowed(state.login_input.as_str())
    } else if state.login_input.is_empty() {
        Cow::Borrowed("")
    } else {
        Cow::Owned("•".repeat(state.login_input.chars().count()))
    };
    let pass = Paragraph::new(pass_display.as_ref()).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Passphrase (Enter=Login, Tab=Anzeige)"),
    );
    f.render_widget(pass, chunks[2]);

    let mut lines = Vec::new();
    if !state.login_error.is_empty() {
        lines.push(Line::from(Span::styled(
            state.login_error.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
    } else {
        lines.push(Line::from(state.texts.passphrase_policy));
    }
    if !state.wallet_db_path.exists() {
        lines.push(Line::from(""));
        lines.push(Line::from(state.texts.no_wallet_found.to_uppercase()));
        lines.push(Line::from(state.texts.create_wallet_cmd));
        lines.push(Line::from("phantom-signer wallet-init"));
        lines.push(Line::from(state.texts.restore_wallet_cmd));
        lines.push(Line::from("phantom-signer wallet-restore"));
    }
    let info = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Info"));
    f.render_widget(info, chunks[3]);
}

fn try_unlock(state: &mut WalletState) -> Result<()> {
    if !state.wallet_db_path.exists() {
        return Err(anyhow!("{}", state.texts.no_wallet_found));
    }
    validate_passphrase(state.login_input.as_str(), state.texts)?;
    let wdb = WalletDb::open_locked(&state.wallet_db_path, state.login_input.as_str())?;
    let addrs = wdb.all_addresses()?;
    if addrs.is_empty() {
        return Err(anyhow!("{}", state.texts.wallet_db_empty));
    }
    let passphrase = std::mem::replace(&mut state.login_input, Zeroizing::new(String::new()));
    let mut app = AppState::new(
        addrs,
        state.node.clone(),
        state.auth_token.clone(),
        state.tls_ca.clone(),
        state.tls_client_pem.clone(),
        state.wallet_db_path.clone(),
        passphrase,
    );
    refresh_history(&mut app, state.texts);
    state.app = Some(app);
    state.login_error.clear();
    Ok(())
}

fn default_walletdb_path() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home)
        .join(".phantom")
        .join("wallets")
        .join("default"))
}

fn seed_store_path_for_wallet_db(wallet_db_path: &Path) -> Result<PathBuf> {
    let base = wallet_db_path
        .parent()
        .ok_or_else(|| anyhow!("wallet_db_path hat keinen parent()"))?;
    let p = base.join("seeds").join("default.toml");
    let canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
    if !canonical.exists() {
        return Err(anyhow!(
            "Seed-Store nicht gefunden: {}",
            canonical.to_string_lossy()
        ));
    }
    Ok(canonical)
}

fn lock_from_pc_address(addr: &str) -> Result<[u8; 32]> {
    let (hrp, data, variant) = bech32::decode(addr).map_err(|e| anyhow!("bech32 decode: {e}"))?;
    if hrp != "pc" {
        return Err(anyhow!("unexpected hrp: {hrp}"));
    }
    if variant != bech32::Variant::Bech32m {
        return Err(anyhow!("expected Bech32m variant"));
    }
    let (ver_u5, prog_u5) = data
        .split_first()
        .ok_or_else(|| anyhow!("bech32 data empty"))?;
    if ver_u5.to_u8() != 1 {
        return Err(anyhow!("unsupported witness version: {}", ver_u5.to_u8()));
    }
    let prog: Vec<u8> =
        Vec::<u8>::from_base32(prog_u5).map_err(|e| anyhow!("bech32 program decode: {e}"))?;
    if prog.len() != 32 {
        return Err(anyhow!(
            "program length must be 32 bytes, got {}",
            prog.len()
        ));
    }
    let mut lock = [0u8; 32];
    lock.copy_from_slice(&prog);
    Ok(lock)
}

fn validate_passphrase(pass: &str, texts: &TuiTexts) -> Result<()> {
    if pass.chars().count() < 8 {
        return Err(anyhow!("{}", texts.passphrase_min_chars));
    }
    Ok(())
}

fn fetch_history(
    node: &str,
    auth: Option<&str>,
    tls_ca: Option<&Path>,
    tls_client_pem: Option<&Path>,
    addr: &str,
) -> Result<HistoryResp> {
    let lock = lock_from_pc_address(addr)?;
    let lock_hex = hex::encode(lock);
    let url = format!("{}/wallet/history/{}", node.trim_end_matches('/'), lock_hex);

    let client = http_util::build_http_client_blocking(
        node,
        tls_ca,
        tls_client_pem,
        false,
        Duration::from_secs(DEFAULT_RPC_TIMEOUT_SECS),
        Duration::from_secs(DEFAULT_RPC_CONNECT_TIMEOUT_SECS),
    )?;
    let parsed_url = http_util::parse_http_url(&url)?;
    http_util::ensure_bearer_transport_safe(&parsed_url, auth)?;
    let mut req = client.get(parsed_url);
    if let Some(token) = auth.map(str::trim).filter(|s| !s.is_empty()) {
        req = req.bearer_auth(token);
    }
    let resp = req.send().context("wallet history request")?;
    let status = resp.status();
    let text = http_util::read_response_text_limited_blocking(resp, MAX_HTTP_RESPONSE_BYTES)?;
    if !status.is_success() {
        return Err(anyhow!("history http error: {} {}", status, text));
    }
    let hist: HistoryResp = serde_json::from_str(&text).context("parse history json")?;
    Ok(hist)
}

fn refresh_history(app: &mut AppState, texts: &TuiTexts) {
    let Some(sel) = app.selected_addr() else {
        return;
    };
    let selected = app.selected;
    let addr = sel.addr.clone();
    let node = app.node.clone();
    let auth = app.auth_token.clone();
    let tls_ca = app.tls_ca.clone();
    let tls_client_pem = app.tls_client_pem.clone();

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let res = fetch_history(
            &node,
            auth.as_deref(),
            tls_ca.as_deref(),
            tls_client_pem.as_deref(),
            &addr,
        )
        .map_err(|e| e.to_string());
        let _ = tx.send(res);
    });
    app.history_job = Some(HistoryJob { selected, rx });
    app.status = format!("{}...", texts.history_error);
}

fn execute_send(app: &AppState, from: &WalletAddrMeta, texts: &TuiTexts) -> Result<String> {
    let recipient = app.send_recipient.trim();
    if recipient.is_empty() {
        return Err(anyhow!("{}", texts.invalid_address));
    }
    if lock_from_pc_address(recipient).is_err() {
        return Err(anyhow!("{}", texts.invalid_address));
    }
    let amount: u64 = app
        .send_amount
        .trim()
        .parse()
        .map_err(|_| anyhow!("{}", texts.invalid_amount))?;
    let fee: u64 = app
        .send_fee
        .trim()
        .parse()
        .map_err(|_| anyhow!("{}", texts.invalid_amount))?;

    let mut cmd = if let Some(bin) = crate::binutil::find_program("phantom-signer") {
        std::process::Command::new(bin)
    } else {
        #[cfg(debug_assertions)]
        {
            let mut cmd = std::process::Command::new("cargo");
            cmd.args(["run", "-p", "phantom-signer", "--"]);
            cmd
        }
        #[cfg(not(debug_assertions))]
        {
            return Err(anyhow!(
                "phantom-signer Binary nicht gefunden (Release-Build startet kein cargo)."
            ));
        }
    };

    let seed_store_path = seed_store_path_for_wallet_db(&app.wallet_db_path)?;

    cmd.args([
        "wallet-send",
        "--from-addr",
        &from.addr,
        "--change-addr",
        &from.addr,
        "--to-addr",
        recipient,
        "--amount",
        &amount.to_string(),
        "--fee",
        &fee.to_string(),
        "--seed-store",
        seed_store_path.to_string_lossy().as_ref(),
        "--wallet-db",
        app.wallet_db_path.to_string_lossy().as_ref(),
        "--node",
        app.node.trim(),
    ]);
    let auth_token = app.auth_token.as_deref();
    if let Some(tls_ca) = app.tls_ca.as_ref() {
        cmd.args(["--tls-ca", tls_ca.to_string_lossy().as_ref()]);
    }
    if let Some(pem) = app.tls_client_pem.as_ref() {
        cmd.args(["--tls-client-pem", pem.to_string_lossy().as_ref()]);
    }
    let output = if let Some(token) = auth_token {
        // Hardening: avoid leaking secrets via argv (process list/crash dumps/logging).
        http_util::with_temp_secret_file("phantom_status_auth_token", token, |tf| {
            cmd.arg("--auth-token-file");
            cmd.arg(tf);
            http_util::with_temp_secret_file("phantom_passphrase", &app.passphrase, |pf| {
                cmd.args(["--passphrase-file", pf.to_string_lossy().as_ref()]);
                cmd.output().context("run phantom-signer wallet-send")
            })
        })?
    } else {
        http_util::with_temp_secret_file("phantom_passphrase", &app.passphrase, |pf| {
            cmd.args(["--passphrase-file", pf.to_string_lossy().as_ref()]);
            cmd.output().context("run phantom-signer wallet-send")
        })?
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("wallet-send failed: {}", stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let txid = stdout
        .lines()
        .find(|l| l.contains("txid"))
        .unwrap_or("unknown");
    Ok(txid.to_string())
}

fn generate_new_address(
    wallet_db_path: &Path,
    passphrase: &str,
    node: &str,
    auth: Option<&str>,
) -> Result<WalletAddrMeta> {
    let wdb = WalletDb::open_locked(wallet_db_path, passphrase)?;
    let addrs = wdb.all_addresses()?;
    let new_index = addrs
        .iter()
        .map(|a| a.index)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let xpubstore_path = addrs
        .first()
        .map(|a| a.xpubstore_path.clone())
        .ok_or_else(|| anyhow!("no addresses in wallet"))?;
    let xpub_data =
        std::fs::read_to_string(&xpubstore_path).map_err(|e| anyhow!("read xpubstore: {e}"))?;
    let xpub_store: serde_json::Value =
        toml::from_str(&xpub_data).map_err(|e| anyhow!("parse xpubstore: {e}"))?;
    let xpub_str = xpub_store
        .get("xpub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("xpub not found in xpubstore"))?;
    let hrp = xpub_store
        .get("hrp")
        .and_then(|v| v.as_str())
        .unwrap_or("pc");
    let derivation = xpub_store
        .get("derivation")
        .and_then(|v| v.as_str())
        .unwrap_or("m/86'/12345'/0'");
    let fingerprint = xpub_store
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let xpub: Xpub = xpub_str.parse().map_err(|e| anyhow!("parse xpub: {e}"))?;
    let child_path = format!("0/{}", new_index);
    let child_derivation: bitcoin::bip32::DerivationPath = child_path
        .parse()
        .map_err(|e| anyhow!("parse child path: {e}"))?;
    let secp = secp256k1::Secp256k1::new();
    let child_xpub = xpub
        .derive_pub(&secp, &child_derivation)
        .map_err(|e| anyhow!("derive child: {e}"))?;
    let (xonly, _parity) = child_xpub.public_key.x_only_public_key();

    use bech32::{ToBase32, Variant};
    let mut prog = vec![bech32::u5::try_from_u8(1).map_err(|e| anyhow!("u5: {e}"))?];
    prog.extend(xonly.serialize().to_base32());
    let addr =
        bech32::encode(hrp, prog, Variant::Bech32m).map_err(|e| anyhow!("bech32 encode: {e}"))?;

    let new_meta = WalletAddrMeta {
        version: 1,
        addr: addr.clone(),
        hrp: hrp.to_string(),
        change: 0,
        index: new_index,
        xpub_derivation: derivation.to_string(),
        fingerprint,
        xpubstore_path: xpubstore_path.clone(),
        label: None,
    };
    wdb.put_address(&new_meta)?;
    let _ = (node, auth);
    Ok(new_meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(prefix: &str) -> PathBuf {
        let ts = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos(),
            Err(_) => 0,
        };
        std::env::temp_dir().join(format!("phantom_tui_wallet_{prefix}_{ts}"))
    }

    #[test]
    fn seed_store_path_for_wallet_db_ok() -> Result<()> {
        let base = tmp_dir("seed_store_ok");
        let wallets_dir = base.join("wallets");
        let wallet_db_path = wallets_dir.join("default");
        let seeds_dir = wallets_dir.join("seeds");
        let seed_file = seeds_dir.join("default.toml");

        fs::create_dir_all(&wallet_db_path)?;
        fs::create_dir_all(&seeds_dir)?;
        fs::write(&seed_file, "dummy")?;

        let got = seed_store_path_for_wallet_db(&wallet_db_path)?;
        let expected = match seed_file.canonicalize() {
            Ok(p) => p,
            Err(_) => seed_file,
        };
        assert_eq!(got, expected);

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn seed_store_path_for_wallet_db_missing_err() -> Result<()> {
        let base = tmp_dir("seed_store_missing");
        let wallets_dir = base.join("wallets");
        let wallet_db_path = wallets_dir.join("default");

        fs::create_dir_all(&wallet_db_path)?;

        let err = seed_store_path_for_wallet_db(&wallet_db_path)
            .err()
            .ok_or_else(|| anyhow!("expected seed_store_path_for_wallet_db() to fail"))?
            .to_string();
        assert!(err.contains("Seed-Store nicht gefunden"));

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    fn dummy_pc_address() -> Result<String> {
        use bech32::{ToBase32, Variant};
        let hrp = "pc";
        let mut prog = vec![bech32::u5::try_from_u8(1).map_err(|e| anyhow!("u5: {e}"))?];
        prog.extend([1u8; 32].to_base32());
        let addr =
            bech32::encode(hrp, prog, Variant::Bech32m).map_err(|e| anyhow!("bech32: {e}"))?;
        Ok(addr)
    }

    fn dummy_meta() -> Result<WalletAddrMeta> {
        let mut m = WalletAddrMeta::default();
        m.addr = dummy_pc_address()?;
        m.hrp = "pc".to_string();
        Ok(m)
    }

    #[test]
    fn f69_refresh_history_is_offloaded_to_background_thread() -> Result<()> {
        let texts = tui_texts(Lang::En);
        let mut app = AppState::new(
            vec![dummy_meta()?],
            "http://127.0.0.1:1".to_string(), // unreachable is fine: the job must still be async
            None,
            None,
            None,
            PathBuf::from("/tmp/phantom_walletdb"),
            Zeroizing::new("passphrase-123".to_string()),
        );
        refresh_history(&mut app, &texts);
        assert!(
            app.history_job.is_some(),
            "expected refresh_history to schedule a background HistoryJob"
        );
        Ok(())
    }

    #[test]
    fn f73_appstate_passphrase_is_zeroizing_string() -> Result<()> {
        fn assert_zeroizing(_: &Zeroizing<String>) {}
        let app = AppState::new(
            vec![dummy_meta()?],
            "http://127.0.0.1:1".to_string(),
            None,
            None,
            None,
            PathBuf::from("/tmp/phantom_walletdb"),
            Zeroizing::new("passphrase-123".to_string()),
        );
        assert_zeroizing(&app.passphrase);
        Ok(())
    }

    #[test]
    fn f111_wallet_passphrase_is_zeroizing_and_not_plain_string() -> Result<()> {
        // Compile-time type enforcement: AppState.passphrase must be Zeroizing<String>.
        fn assert_zeroizing(_: &Zeroizing<String>) {}
        let app = AppState::new(
            vec![dummy_meta()?],
            "http://127.0.0.1:1".to_string(),
            None,
            None,
            None,
            PathBuf::from("/tmp/phantom_walletdb"),
            Zeroizing::new("passphrase-123".to_string()),
        );
        assert_zeroizing(&app.passphrase);
        Ok(())
    }

    #[test]
    fn f113_wallet_history_fetch_does_not_block_ui_thread() -> Result<()> {
        // Behavior-level evidence: refresh_history schedules work and returns immediately (no blocking HTTP).
        let texts = tui_texts(Lang::En);
        let mut app = AppState::new(
            vec![dummy_meta()?],
            "http://127.0.0.1:1".to_string(),
            None,
            None,
            None,
            PathBuf::from("/tmp/phantom_walletdb"),
            Zeroizing::new("passphrase-123".to_string()),
        );
        refresh_history(&mut app, &texts);
        assert!(app.history_job.is_some());
        Ok(())
    }

    #[test]
    fn f114_invalid_fee_is_rejected_instead_of_silent_zero() -> Result<()> {
        let texts = tui_texts(Lang::En);
        let meta = dummy_meta()?;
        let mut app = AppState::new(
            vec![meta.clone()],
            "http://127.0.0.1:1".to_string(),
            None,
            None,
            None,
            PathBuf::from("/tmp/phantom_walletdb"),
            Zeroizing::new("passphrase-123".to_string()),
        );
        app.send_recipient = dummy_pc_address()?;
        app.send_amount = "1".to_string();
        app.send_fee = "abc".to_string();
        let err = execute_send(&app, &meta, &texts)
            .err()
            .ok_or_else(|| anyhow!("expected invalid fee to fail"))?
            .to_string();
        assert!(
            err.contains(texts.invalid_amount),
            "expected fee parse error to return a user-facing invalid_amount message"
        );
        Ok(())
    }

    #[test]
    fn f115_seed_store_path_is_resolved_relative_to_wallet_parent() -> Result<()> {
        // This asserts we use `wallet_db_path.parent().join("seeds/default.toml")` semantics
        // (no format! traversal).
        let base = tmp_dir("f115_seed_store");
        let wallets_dir = base.join("wallets");
        let wallet_db_path = wallets_dir.join("mywallet");
        let seeds_dir = wallets_dir.join("seeds");
        let seed_file = seeds_dir.join("default.toml");

        fs::create_dir_all(&wallet_db_path)?;
        fs::create_dir_all(&seeds_dir)?;
        fs::write(&seed_file, "dummy")?;

        let got = seed_store_path_for_wallet_db(&wallet_db_path)?;
        assert!(
            got.to_string_lossy().contains("seeds/default.toml"),
            "expected seed store to be resolved in the sibling seeds/ dir"
        );
        let _ = fs::remove_dir_all(&base);
        Ok(())
    }
}
