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

use std::env;
use std::io;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use phantom_i18n::{tui_texts, Lang};
use phantom_signer::walletdb::{WalletAddrMeta, WalletDb};
use phantom_wallet_common::address::lock_from_pc_address;
use phantom_wallet_common::binutil::find_signer_binary;
use phantom_wallet_common::history::{fetch_history as fetch_history_common, HistoryResp};
use phantom_wallet_common::secrets::with_temp_secret_file;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use rpassword::read_password;
use zeroize::Zeroizing;

fn read_secret_file_trimmed(path: &Path) -> Result<String> {
    let mut s = String::new();
    std::fs::File::open(path)
        .with_context(|| format!("open secret file {}", path.display()))?
        .read_to_string(&mut s)
        .with_context(|| format!("read secret file {}", path.display()))?;
    let v = s.trim().to_string();
    if v.is_empty() {
        return Err(anyhow!("secret file is empty: {}", path.display()));
    }
    Ok(v)
}

#[derive(Debug, Parser)]
struct Args {
    /// Pfad zum Wallet-DB-Verzeichnis (verschlüsselt)
    /// Falls nicht angegeben: ~/.phantom/wallets/default
    #[arg(long)]
    wallet_db: Option<PathBuf>,
    /// Node-URL, z. B. https://127.0.0.1:8080
    #[arg(long, default_value = "https://127.0.0.1:8080")]
    node: String,
    /// Optional (UNSAFE): Bearer-Token für Node-HTTP. Sichtbar in Prozesslisten.
    /// Bevorzuge --auth-token-file.
    #[arg(long)]
    auth_token: Option<String>,
    /// Optional: Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
    #[arg(long)]
    auth_token_file: Option<PathBuf>,
    /// Optionales TLS-CA-Zertifikat (PEM) für die HTTPS-Verbindung zum Node
    #[arg(long)]
    tls_ca: Option<PathBuf>,
    /// Optionales Client-Zertifikat (PEM) für mTLS zum Node
    #[arg(long)]
    tls_client_pem: Option<PathBuf>,
    /// Language for TUI messages (en, de, es, fr, it, pt, nl, ru, zh, ja, ko, tr, ar, pl)
    #[arg(long, default_value = "de", env = "PHANTOM_LANG")]
    lang: String,
}

fn default_walletdb_path() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home)
        .join(".phantom")
        .join("wallets")
        .join("default"))
}

fn seed_store_path_for_wallet_db(wallet_db_path: &Path) -> Result<PathBuf> {
    let wallet_name = wallet_db_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("wallet_db_path hat keinen gültigen Wallet-Namen"))?;
    let home = env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home)
        .join(".phantom")
        .join("seeds")
        .join(format!("{}.toml", wallet_name)))
}

/// UI-Modus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiMode {
    Normal,
    Send,
}

/// Eingabefeld-Fokus im Send-Modus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendField {
    Recipient,
    Amount,
    Fee,
}

struct AppState {
    addrs: Vec<WalletAddrMeta>,
    selected: usize,
    history: Option<HistoryResp>,
    status: String,
    node: String,
    auth_token: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_client_pem: Option<PathBuf>,
    // Erweiterte Felder
    mode: UiMode,
    send_field: SendField,
    send_recipient: String,
    send_amount: String,
    send_fee: String,
    wallet_db_path: std::path::PathBuf,
    passphrase: Zeroizing<String>,
}

impl AppState {
    fn new(
        addrs: Vec<WalletAddrMeta>,
        node: String,
        auth_token: Option<String>,
        tls_ca: Option<PathBuf>,
        tls_client_pem: Option<PathBuf>,
        wallet_db_path: std::path::PathBuf,
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

fn validate_passphrase(pass: &str, texts: &phantom_i18n::TuiTexts) -> Result<()> {
    if pass.chars().count() < 8 {
        return Err(anyhow!("{}", texts.passphrase_min_chars));
    }
    Ok(())
}

const DEFAULT_RPC_TIMEOUT_SECS: u64 = 10;
const DEFAULT_RPC_CONNECT_TIMEOUT_SECS: u64 = 5;

fn fetch_history(
    node: &str,
    auth: Option<&str>,
    tls_ca: Option<&std::path::Path>,
    tls_client_pem: Option<&std::path::Path>,
    addr: &str,
) -> Result<HistoryResp> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_RPC_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(DEFAULT_RPC_CONNECT_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(ca_path) = tls_ca {
        let data =
            std::fs::read(ca_path).with_context(|| format!("read tls_ca {}", ca_path.display()))?;
        let cert = reqwest::Certificate::from_pem(&data).context("parse tls_ca pem")?;
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert);
    }
    if let Some(pem_path) = tls_client_pem {
        let data = std::fs::read(pem_path)
            .with_context(|| format!("read tls_client_pem {}", pem_path.display()))?;
        let id = reqwest::Identity::from_pem(&data).context("parse client pem")?;
        builder = builder.identity(id);
    }
    let client = builder.build().context("build http client")?;
    fetch_history_common(&client, node, auth, addr)
}

fn refresh_history(app: &mut AppState, texts: &phantom_i18n::TuiTexts) {
    if let Some(sel) = app.selected_addr() {
        match fetch_history(
            &app.node,
            app.auth_token.as_deref(),
            app.tls_ca.as_deref(),
            app.tls_client_pem.as_deref(),
            &sel.addr,
        ) {
            Ok(hist) => {
                app.history = Some(hist);
                app.status.clear();
            }
            Err(e) => {
                app.status = format!("{}: {}", texts.history_error, e);
            }
        }
    }
}

fn generate_new_address(
    wallet_db_path: &std::path::Path,
    passphrase: &str,
    _node: &str,
    _auth_token: Option<&str>,
) -> Result<WalletAddrMeta> {
    let wdb = WalletDb::open_locked(wallet_db_path, passphrase)?;
    let addrs = wdb.all_addresses()?;

    // Finde den höchsten Index
    let new_index = next_address_index(&addrs)?;

    // Hole xpubstore_path von der ersten Adresse
    let xpubstore_path = addrs
        .first()
        .map(|a| a.xpubstore_path.clone())
        .ok_or_else(|| anyhow!("no addresses in wallet"))?;

    // Lade XpubStore und leite neue Adresse ab
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

    // Derive neue Adresse
    use bitcoin::bip32::Xpub;
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

    // Bech32m Adresse
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

    // Speichere in WalletDb
    wdb.put_address(&new_meta)?;

    Ok(new_meta)
}

fn next_address_index(addrs: &[WalletAddrMeta]) -> Result<u32> {
    let max_index = addrs.iter().map(|a| a.index).max().unwrap_or(0);
    max_index
        .checked_add(1)
        .ok_or_else(|| anyhow!("address index overflow"))
}

fn execute_send(
    app: &AppState,
    from_addr: &WalletAddrMeta,
    texts: &phantom_i18n::TuiTexts,
) -> Result<String> {
    // Parse Betrag und Fee
    let amount: u64 = app
        .send_amount
        .parse()
        .map_err(|_| anyhow!("{}", texts.invalid_amount))?;
    let fee: u64 = if app.send_fee.trim().is_empty() {
        0
    } else {
        app.send_fee
            .trim()
            .parse()
            .map_err(|_| anyhow!("{}", texts.invalid_amount))?
    };

    // Validiere Empfängeradresse
    let to_addr = &app.send_recipient;
    if to_addr.is_empty() {
        return Err(anyhow!("{}", texts.invalid_address));
    }
    lock_from_pc_address(to_addr)?;

    // Prüfe Guthaben
    if let Some(hist) = &app.history {
        let total = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("amount + fee overflow"))?;
        if hist.balance < total {
            return Err(anyhow!("{}", texts.insufficient_balance));
        }
    } else {
        return Err(anyhow!("no balance info"));
    }

    let seed_store = seed_store_path_for_wallet_db(&app.wallet_db_path)?;
    if !seed_store.exists() {
        return Err(anyhow!("seed-store fehlt: {}", seed_store.display()));
    }

    // Rufe phantom-signer wallet-send auf (Release: nur Binary, kein cargo-run).
    let mut cmd = if let Some(bin) = find_signer_binary() {
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
    cmd.arg("wallet-send")
        .arg("--from-addr")
        .arg(&from_addr.addr)
        .arg("--to-addr")
        .arg(to_addr)
        .arg("--amount")
        .arg(amount.to_string())
        .arg("--fee")
        .arg(fee.to_string())
        // Avoid phantom-signer prompting for wallet-db passphrase for change derivation:
        // explicitly send change back to the sending address.
        .arg("--change-addr")
        .arg(&from_addr.addr)
        .arg("--wallet-db")
        .arg(&app.wallet_db_path)
        .arg("--seed-store")
        .arg(&seed_store)
        .arg("--node")
        .arg(&app.node);
    if let Some(ca) = app.tls_ca.as_ref() {
        cmd.arg("--tls-ca");
        cmd.arg(ca);
    }

    if let Some(pem) = app.tls_client_pem.as_ref() {
        cmd.arg("--tls-client-pem");
        cmd.arg(pem);
    }

    let auth_token = app.auth_token.as_deref();

    let output = if let Some(token) = auth_token {
        // Hardening: avoid leaking secrets via argv (process list/crash dumps/logging).
        with_temp_secret_file("phantom_status_auth_token", token, |tf| {
            cmd.arg("--auth-token-file");
            cmd.arg(tf);
            with_temp_secret_file("phantom_passphrase", &app.passphrase, |pf| {
                cmd.args(["--passphrase-file", pf.to_string_lossy().as_ref()]);
                cmd.output().map_err(|e| anyhow!("run wallet-send: {e}"))
            })
        })?
    } else {
        with_temp_secret_file("phantom_passphrase", &app.passphrase, |pf| {
            cmd.args(["--passphrase-file", pf.to_string_lossy().as_ref()]);
            cmd.output().map_err(|e| anyhow!("run wallet-send: {e}"))
        })?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("wallet-send failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Extrahiere txid aus Ausgabe (vereinfacht)
    let txid = stdout
        .lines()
        .find(|l| l.contains("txid"))
        .unwrap_or("unknown")
        .to_string();

    Ok(txid)
}

fn draw<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &AppState,
    texts: &phantom_i18n::TuiTexts,
) -> Result<()> {
    terminal.draw(|f| {
        let size = f.area();
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(size);

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
                .title(texts.addresses)
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
                // Summary
                let summary_text =
                    if let (Some(sel), Some(hist)) = (app.selected_addr(), app.history.as_ref()) {
                        format!(
                            "Addr: {}\nLock: {}\n{}: {}\n{}: {}\nUTXOs: {}",
                            sel.addr,
                            hist.lock,
                            texts.balance,
                            hist.balance,
                            texts.staked,
                            hist.staked_balance,
                            hist.n_utxos
                        )
                    } else {
                        texts.no_history.to_string()
                    };
                let summary = Paragraph::new(summary_text)
                    .block(Block::default().title(texts.summary).borders(Borders::ALL));
                f.render_widget(summary, summary_area);

                // UTXOs
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
                let utxo_para = Paragraph::new(utxo_lines)
                    .block(Block::default().title(texts.utxos).borders(Borders::ALL));
                f.render_widget(utxo_para, main_area);
            }
            UiMode::Send => {
                // Send-Formular
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

                let (recipient_area, amount_area, fee_area, hint_area) = match send_chunks.as_ref()
                {
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
                            .title(texts.recipient)
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
                    .block(Block::default().title(texts.amount).borders(Borders::ALL));
                f.render_widget(amount_input, amount_area);

                let fee_style = if app.send_field == SendField::Fee {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                let fee_input = Paragraph::new(app.send_fee.as_str())
                    .style(fee_style)
                    .block(Block::default().title(texts.fee).borders(Borders::ALL));
                f.render_widget(fee_input, fee_area);

                let hint_text = format!("{} | {}", texts.confirm_send, texts.cancel);
                let hint = Paragraph::new(hint_text)
                    .block(Block::default().borders(Borders::ALL).title(texts.send));
                f.render_widget(hint, hint_area);
            }
        }

        // Status-Zeile
        let status_hint = match app.mode {
            UiMode::Normal => texts.menu_hint,
            UiMode::Send => "Tab=Feld wechseln, Enter=Senden, Esc=Abbrechen",
        };
        let status_line = Paragraph::new(format!("{} | {}", app.status, status_hint))
            .block(Block::default().borders(Borders::ALL).title("Status"));
        f.render_widget(status_line, status_area);
    })?;
    Ok(())
}

fn run_app(mut app: AppState, texts: &phantom_i18n::TuiTexts) -> Result<()> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    stdout
        .execute(EnterAlternateScreen)
        .context("enter alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("terminal new")?;

    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    if let Some(first) = app.selected_addr() {
        match fetch_history(
            &app.node,
            app.auth_token.as_deref(),
            app.tls_ca.as_deref(),
            app.tls_client_pem.as_deref(),
            &first.addr,
        ) {
            Ok(hist) => {
                app.history = Some(hist);
            }
            Err(e) => {
                app.status = format!("{}: {}", texts.history_error, e);
            }
        }
    }

    loop {
        draw(&mut terminal, &app, texts)?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout).context("event poll")? {
            if let CEvent::Key(key) = event::read().context("event read")? {
                if key.kind == KeyEventKind::Press {
                    match app.mode {
                        UiMode::Normal => {
                            match key.code {
                                KeyCode::Char('q') => break,
                                KeyCode::Char('s') => {
                                    app.mode = UiMode::Send;
                                    app.clear_send_form();
                                    app.status = texts.send.to_string();
                                }
                                KeyCode::Char('n') => {
                                    // Neue Adresse generieren
                                    match generate_new_address(
                                        &app.wallet_db_path,
                                        &app.passphrase,
                                        &app.node,
                                        app.auth_token.as_deref(),
                                    ) {
                                        Ok(new_addr) => {
                                            app.addrs.push(new_addr);
                                            app.status = texts.new_addr_generated.to_string();
                                        }
                                        Err(e) => {
                                            app.status = format!("{}: {}", texts.error, e);
                                        }
                                    }
                                }
                                KeyCode::Up => {
                                    if app.selected > 0 {
                                        app.selected -= 1;
                                        refresh_history(&mut app, texts);
                                    }
                                }
                                KeyCode::Down => {
                                    if app.selected + 1 < app.addrs.len() {
                                        app.selected += 1;
                                        refresh_history(&mut app, texts);
                                    }
                                }
                                _ => {}
                            }
                        }
                        UiMode::Send => {
                            match key.code {
                                KeyCode::Esc => {
                                    app.mode = UiMode::Normal;
                                    app.clear_send_form();
                                    app.status.clear();
                                }
                                KeyCode::Tab => {
                                    app.send_field = match app.send_field {
                                        SendField::Recipient => SendField::Amount,
                                        SendField::Amount => SendField::Fee,
                                        SendField::Fee => SendField::Recipient,
                                    };
                                }
                                KeyCode::Enter => {
                                    // Transaktion senden
                                    if let Some(from) = app.selected_addr().cloned() {
                                        match execute_send(&app, &from, texts) {
                                            Ok(txid) => {
                                                app.status = format!(
                                                    "{} (txid: {})",
                                                    texts.send_success, txid
                                                );
                                                app.mode = UiMode::Normal;
                                                app.clear_send_form();
                                                refresh_history(&mut app, texts);
                                            }
                                            Err(e) => {
                                                app.status =
                                                    format!("{}: {}", texts.send_failed, e);
                                            }
                                        }
                                    }
                                }
                                KeyCode::Backspace => match app.send_field {
                                    SendField::Recipient => {
                                        app.send_recipient.pop();
                                    }
                                    SendField::Amount => {
                                        app.send_amount.pop();
                                    }
                                    SendField::Fee => {
                                        app.send_fee.pop();
                                    }
                                },
                                KeyCode::Char(c) => match app.send_field {
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
                                },
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    disable_raw_mode().ok();
    let mut stdout = io::stdout();
    let _ = stdout.execute(LeaveAlternateScreen);
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse language
    let lang = match args.lang.to_lowercase().as_str() {
        "en" => Lang::En,
        "de" => Lang::De,
        "es" => Lang::Es,
        "fr" => Lang::Fr,
        "it" => Lang::It,
        "pt" => Lang::Pt,
        "nl" => Lang::Nl,
        "ru" => Lang::Ru,
        "zh" => Lang::Zh,
        "ja" => Lang::Ja,
        "ko" => Lang::Ko,
        "tr" => Lang::Tr,
        "ar" => Lang::Ar,
        "pl" => Lang::Pl,
        _ => Lang::De,
    };
    let texts = tui_texts(lang);

    let wallet_db_path = match args.wallet_db {
        Some(p) => p,
        None => default_walletdb_path()?,
    };

    let auth_token = if let Some(p) = args.auth_token_file.as_deref() {
        Some(read_secret_file_trimmed(p)?)
    } else {
        if !cfg!(debug_assertions) && args.auth_token.is_some() {
            return Err(anyhow!(
                "--auth-token ist in Release-Builds deaktiviert (Token-Leak via Prozessliste). Nutze --auth-token-file."
            ));
        }
        args.auth_token.clone()
    };

    if !wallet_db_path.exists() {
        eprintln!("╔════════════════════════════════════════════════════════════════════╗");
        eprintln!(
            "║  {}                                             ║",
            texts.no_wallet_found.to_uppercase()
        );
        eprintln!("╚════════════════════════════════════════════════════════════════════╝");
        eprintln!();
        eprintln!("{}: {}", texts.wallet_db_label, wallet_db_path.display());
        eprintln!();
        eprintln!("{}", texts.create_wallet_cmd);
        eprintln!();
        eprintln!("    phantom-signer wallet-init");
        eprintln!("    # oder (Dev): cargo run -p phantom-signer -- wallet-init");
        eprintln!();
        eprintln!("{}", texts.restore_wallet_cmd);
        eprintln!();
        eprintln!("    phantom-signer wallet-restore");
        eprintln!("    # oder (Dev): cargo run -p phantom-signer -- wallet-restore");
        eprintln!();
        return Ok(());
    }

    eprintln!("╔════════════════════════════════════════════════════════════════════╗");
    eprintln!(
        "║  {}                                                ║",
        texts.title.to_uppercase()
    );
    eprintln!("╚════════════════════════════════════════════════════════════════════╝");
    eprintln!("{}: {}", texts.wallet_db_label, wallet_db_path.display());
    eprintln!();
    eprintln!("{}", texts.passphrase_policy);
    let pass = Zeroizing::new(read_password().context("read walletdb passphrase")?);
    validate_passphrase(&pass, texts)?;
    let wdb = WalletDb::open_locked(&wallet_db_path, &pass)?;
    let addrs = wdb.all_addresses()?;
    if addrs.is_empty() {
        return Err(anyhow!("{}", texts.wallet_db_empty));
    }

    let app = AppState::new(
        addrs,
        args.node.clone(),
        auth_token,
        args.tls_ca.clone(),
        args.tls_client_pem.clone(),
        wallet_db_path,
        pass,
    );
    if let Err(e) = run_app(app, texts) {
        eprintln!("{}: {}", texts.error, e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn seed_store_path_resolves_to_phantom_seeds_dir() -> Result<()> {
        let _g = HOME_LOCK
            .lock()
            .map_err(|_| anyhow!("HOME_LOCK poisoned"))?;

        let tmp = std::env::temp_dir().join(format!(
            "phantom_tui_wallet_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| anyhow!("system time before unix epoch: {e}"))?
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp)?;

        // IMPORTANT: this test mutates HOME.
        std::env::set_var("HOME", &tmp);

        let wdb = tmp.join(".phantom").join("wallets").join("default");
        let expected = tmp.join(".phantom").join("seeds").join("default.toml");

        let got = seed_store_path_for_wallet_db(&wdb)?;
        assert_eq!(got, expected);

        // Cleanup best-effort. (Ignore failures on Windows/locked files.)
        let _ = std::fs::remove_dir_all(&tmp);
        Ok(())
    }

    #[test]
    fn next_address_index_errors_on_overflow() -> Result<()> {
        let m = WalletAddrMeta {
            index: u32::MAX,
            ..Default::default()
        };
        let addrs = vec![m];

        let err = next_address_index(&addrs)
            .err()
            .ok_or_else(|| anyhow!("expected overflow error"))?;
        assert!(err.to_string().contains("address index overflow"));
        Ok(())
    }

    #[test]
    fn execute_send_errors_on_amount_plus_fee_overflow() -> Result<()> {
        use bech32::{ToBase32 as _, Variant};

        let texts = phantom_i18n::tui_texts(phantom_i18n::Lang::De);

        let mut prog: Vec<bech32::u5> =
            vec![bech32::u5::try_from_u8(1).map_err(|e| anyhow!("u5: {e}"))?];
        prog.extend([7u8; 32].to_base32());
        let to_addr = bech32::encode("pc", prog, Variant::Bech32m)
            .map_err(|e| anyhow!("bech32 encode: {e}"))?;

        let from = WalletAddrMeta {
            addr: to_addr.clone(),
            hrp: "pc".to_string(),
            ..Default::default()
        };

        let mut app = AppState::new(
            vec![from.clone()],
            "https://127.0.0.1:8080".to_string(),
            None,
            None,
            None,
            std::env::temp_dir().join("phantom_tui_wallet_test_walletdb"),
            Zeroizing::new("passphrase-123".to_string()),
        );
        app.history = Some(HistoryResp {
            ok: true,
            lock: "00".to_string(),
            balance: u64::MAX,
            staked_balance: 0,
            n_utxos: 0,
            utxos: vec![],
        });
        app.send_recipient = to_addr;
        app.send_amount = u64::MAX.to_string();
        app.send_fee = "1".to_string();

        let err = execute_send(&app, &from, texts)
            .err()
            .ok_or_else(|| anyhow!("expected overflow error"))?;
        assert!(err.to_string().contains("amount + fee overflow"));
        Ok(())
    }

    #[test]
    fn execute_send_errors_on_invalid_fee_instead_of_silent_zero() -> Result<()> {
        use bech32::{ToBase32 as _, Variant};

        let texts = phantom_i18n::tui_texts(phantom_i18n::Lang::De);

        let mut prog: Vec<bech32::u5> =
            vec![bech32::u5::try_from_u8(1).map_err(|e| anyhow!("u5: {e}"))?];
        prog.extend([9u8; 32].to_base32());
        let to_addr = bech32::encode("pc", prog, Variant::Bech32m)
            .map_err(|e| anyhow!("bech32 encode: {e}"))?;

        let from = WalletAddrMeta {
            addr: to_addr.clone(),
            hrp: "pc".to_string(),
            ..Default::default()
        };

        let mut app = AppState::new(
            vec![from.clone()],
            "https://127.0.0.1:8080".to_string(),
            None,
            None,
            None,
            std::env::temp_dir().join("phantom_tui_wallet_test_walletdb"),
            Zeroizing::new("passphrase-123".to_string()),
        );
        app.history = Some(HistoryResp {
            ok: true,
            lock: "00".to_string(),
            balance: u64::MAX,
            staked_balance: 0,
            n_utxos: 0,
            utxos: vec![],
        });
        app.send_recipient = to_addr;
        app.send_amount = "1".to_string();
        app.send_fee = "abc".to_string();

        let err = execute_send(&app, &from, texts)
            .err()
            .ok_or_else(|| anyhow!("expected fee parse error"))?;
        assert!(
            err.to_string().contains(texts.invalid_amount),
            "unexpected error: {err:#}"
        );
        Ok(())
    }
}
