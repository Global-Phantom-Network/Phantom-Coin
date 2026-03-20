use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use bitbox_api::{self, runtime::DefaultRuntime, usb, Keypath, NoiseConfig, PersistedNoiseConfig};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use crossterm::event::{KeyCode, KeyEvent};
use futures::executor::block_on;
use pc_codec::Decodable;
use pc_crypto::{blake3_32, bls, schnorr, Hash32};
use pc_types::NetworkId;
use phantom_signer::{payjoin, psbt, slashdb};
use rand::RngCore;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Commands,
    Fields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandId {
    Keygen,
    Import,
    ExportPub,
    Sign,
    Verify,
    PsbtCreate,
    PsbtSighash,
    PsbtSign,
    PsbtVerify,
    PsbtFinalize,
    SlashDbInit,
    SlashDbGet,
    SlashDbPut,
    SeatVoteSign,
    SeatVoteVerify,
    BitboxSettings,
    HwiEnumerate,
    HwiGetXpub,
    HwiSignMessage,
    HwiSignTx,
    PayjoinInitiate,
    PayjoinRespond,
    PayjoinFinalize,
    PayjoinParseUri,
}

#[derive(Debug, Clone)]
struct InputField {
    label: &'static str,
    value: String,
    secret: bool,
}

#[derive(Debug, Clone)]
struct CommandForm {
    id: CommandId,
    label: &'static str,
    fields: Vec<InputField>,
    implemented: bool,
    help: Vec<&'static str>,
}

pub struct SignerState {
    forms: Vec<CommandForm>,
    selected: usize,
    active_field: usize,
    focus: Focus,
    output: Vec<String>,
    bitbox_transport: String,
    bitbox_bridge_url: String,
}

impl SignerState {
    #[allow(clippy::vec_init_then_push)]
    pub fn new() -> Self {
        let bitbox_transport = normalize_bitbox_transport(
            &env::var("PHANTOM_BITBOX_TRANSPORT").unwrap_or_else(|_| "auto".to_string()),
        )
        .unwrap_or_else(|_| "auto".to_string());
        let bitbox_bridge_url = normalize_bitbox_bridge_url(
            &env::var("PHANTOM_BITBOX_BRIDGE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8178".to_string()),
        )
        .unwrap_or_else(|_| "http://127.0.0.1:8178".to_string());

        let mut forms = Vec::new();
        forms.push(CommandForm {
            id: CommandId::Keygen,
            label: "Keygen",
            implemented: true,
            fields: vec![
                InputField {
                    label: "key_type (seat|bond|payout)",
                    value: "seat".to_string(),
                    secret: false,
                },
                InputField {
                    label: "algo (schnorr|bls)",
                    value: "schnorr".to_string(),
                    secret: false,
                },
                InputField {
                    label: "out (pfad)",
                    value: "keystore.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "force (true|false)",
                    value: "false".to_string(),
                    secret: false,
                },
                InputField {
                    label: "passphrase",
                    value: String::new(),
                    secret: true,
                },
                InputField {
                    label: "role (none|validator|miner)",
                    value: "none".to_string(),
                    secret: false,
                },
            ],
            help: vec![
                "Erzeugt einen neuen Key und speichert ihn als Keystore.",
                "Passphrase optional per Rolle ableiten (validator/miner).",
            ],
        });
        forms.push(CommandForm {
            id: CommandId::Import,
            label: "Import",
            implemented: true,
            fields: vec![
                InputField {
                    label: "key_type (seat|bond|payout)",
                    value: "seat".to_string(),
                    secret: false,
                },
                InputField {
                    label: "algo (schnorr|bls)",
                    value: "schnorr".to_string(),
                    secret: false,
                },
                InputField {
                    label: "secret_hex (32B)",
                    value: String::new(),
                    secret: true,
                },
                InputField {
                    label: "out (pfad)",
                    value: "keystore.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "force (true|false)",
                    value: "false".to_string(),
                    secret: false,
                },
                InputField {
                    label: "passphrase",
                    value: String::new(),
                    secret: true,
                },
                InputField {
                    label: "role (none|validator|miner)",
                    value: "none".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Importiert einen existierenden Secret (32B hex) in einen Keystore."],
        });
        forms.push(CommandForm {
            id: CommandId::ExportPub,
            label: "ExportPub",
            implemented: true,
            fields: vec![InputField {
                label: "keystore (pfad)",
                value: "keystore.toml".to_string(),
                secret: false,
            }],
            help: vec!["Liest den Public Key aus einem Keystore."],
        });
        forms.push(CommandForm {
            id: CommandId::Sign,
            label: "Sign",
            implemented: true,
            fields: vec![
                InputField {
                    label: "keystore (pfad)",
                    value: "keystore.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "msg (pfad)",
                    value: "msg.bin".to_string(),
                    secret: false,
                },
                InputField {
                    label: "out (optional)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "passphrase",
                    value: String::new(),
                    secret: true,
                },
                InputField {
                    label: "role (none|validator|miner)",
                    value: "none".to_string(),
                    secret: false,
                },
            ],
            help: vec![
                "Signiert eine Datei mit dem Keystore.",
                "Schnorr: blake3-32(msg). BLS: raw msg.",
            ],
        });
        forms.push(CommandForm {
            id: CommandId::Verify,
            label: "Verify",
            implemented: true,
            fields: vec![
                InputField {
                    label: "algo (schnorr|bls)",
                    value: "schnorr".to_string(),
                    secret: false,
                },
                InputField {
                    label: "pub_hex",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "msg (pfad)",
                    value: "msg.bin".to_string(),
                    secret: false,
                },
                InputField {
                    label: "sig_hex",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Verifiziert eine Signatur gegen den Public Key."],
        });
        forms.push(CommandForm {
            id: CommandId::PsbtCreate,
            label: "PSBT Create",
            implemented: true,
            fields: vec![
                InputField {
                    label: "tx_bin (pfad)",
                    value: "tx.bin".to_string(),
                    secret: false,
                },
                InputField {
                    label: "paths (csv)",
                    value: "m/86'/12345'/0'/0/0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "out (pfad)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Erstellt Phantom-PSBT aus MicroTx (pc-codec)."],
        });
        forms.push(CommandForm {
            id: CommandId::PsbtSighash,
            label: "PSBT Sighash",
            implemented: true,
            fields: vec![
                InputField {
                    label: "psbt (pfad)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "network_id (64 hex)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Berechnet den Sighash der PSBT."],
        });
        forms.push(CommandForm {
            id: CommandId::PsbtSign,
            label: "PSBT Sign",
            implemented: true,
            fields: vec![
                InputField {
                    label: "psbt (pfad)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "keystore (pfad)",
                    value: "keystore.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "out (optional)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "passphrase",
                    value: String::new(),
                    secret: true,
                },
                InputField {
                    label: "role (none|validator|miner)",
                    value: "none".to_string(),
                    secret: false,
                },
                InputField {
                    label: "network_id (64 hex)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Signiert PSBT (Schnorr) mit Keystore."],
        });
        forms.push(CommandForm {
            id: CommandId::PsbtVerify,
            label: "PSBT Verify",
            implemented: true,
            fields: vec![
                InputField {
                    label: "psbt (pfad)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "algo (schnorr)",
                    value: "schnorr".to_string(),
                    secret: false,
                },
                InputField {
                    label: "pub_hex",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "sig_hex",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "network_id (64 hex)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Verifiziert PSBT-Signatur gegen Public Key."],
        });
        forms.push(CommandForm {
            id: CommandId::PsbtFinalize,
            label: "PSBT Finalize",
            implemented: true,
            fields: vec![
                InputField {
                    label: "psbt (pfad)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "pubkeys (csv)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "sigs (csv)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "out (pfad)",
                    value: "tx_final.bin".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Fügt Witnesses hinzu und schreibt finale TX."],
        });
        forms.push(CommandForm {
            id: CommandId::SlashDbInit,
            label: "SlashDB Init",
            implemented: true,
            fields: vec![InputField {
                label: "db_dir (pfad)",
                value: "./slashing-db".to_string(),
                secret: false,
            }],
            help: vec!["Initialisiert die Slashing-DB."],
        });
        forms.push(CommandForm {
            id: CommandId::SlashDbGet,
            label: "SlashDB Get",
            implemented: true,
            fields: vec![
                InputField {
                    label: "db_dir (pfad)",
                    value: "./slashing-db".to_string(),
                    secret: false,
                },
                InputField {
                    label: "epoch",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "shard",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "round",
                    value: "0".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Liest Vote aus Slashing-DB (header_id hex)."],
        });
        forms.push(CommandForm {
            id: CommandId::SlashDbPut,
            label: "SlashDB Put",
            implemented: true,
            fields: vec![
                InputField {
                    label: "db_dir (pfad)",
                    value: "./slashing-db".to_string(),
                    secret: false,
                },
                InputField {
                    label: "epoch",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "shard",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "round",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "header_hex (32B)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Schreibt Vote idempotent in Slashing-DB."],
        });
        forms.push(CommandForm {
            id: CommandId::SeatVoteSign,
            label: "SeatVote Sign",
            implemented: true,
            fields: vec![
                InputField {
                    label: "db_dir (pfad)",
                    value: "./slashing-db".to_string(),
                    secret: false,
                },
                InputField {
                    label: "epoch",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "shard",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "round",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "header_hex (32B)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "keystore (pfad)",
                    value: "keystore.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "out (optional)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "passphrase",
                    value: String::new(),
                    secret: true,
                },
                InputField {
                    label: "role (none|validator|miner)",
                    value: "none".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Signiert Seat-Vote mit Slashing-Enforcement (Schnorr)."],
        });
        forms.push(CommandForm {
            id: CommandId::SeatVoteVerify,
            label: "SeatVote Verify",
            implemented: true,
            fields: vec![
                InputField {
                    label: "epoch",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "shard",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "round",
                    value: "0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "header_hex (32B)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "pub_hex (32B)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "sig_hex (64B)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Verifiziert Seat-Vote (Schnorr)."],
        });
        forms.push(CommandForm {
            id: CommandId::BitboxSettings,
            label: "BitBox Settings",
            implemented: true,
            fields: vec![
                InputField {
                    label: "transport (auto|usb|bridge)",
                    value: bitbox_transport.clone(),
                    secret: false,
                },
                InputField {
                    label: "bridge_url",
                    value: bitbox_bridge_url.clone(),
                    secret: false,
                },
                InputField {
                    label: "bridge_check (true|false)",
                    value: "true".to_string(),
                    secret: false,
                },
            ],
            help: vec![
                "Setzt BitBox02-Transport (USB/Bridge).",
                "Optional: Bridge-Check ausführen.",
            ],
        });
        forms.push(CommandForm {
            id: CommandId::HwiEnumerate,
            label: "HWI Enumerate",
            implemented: true,
            fields: vec![],
            help: vec!["Listet BitBox02 Geräte (HWI)."],
        });
        forms.push(CommandForm {
            id: CommandId::HwiGetXpub,
            label: "HWI Get Xpub",
            implemented: true,
            fields: vec![
                InputField {
                    label: "derivation",
                    value: "m/86'/12345'/0'".to_string(),
                    secret: false,
                },
                InputField {
                    label: "fingerprint (optional)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Liest Xpub vom BitBox02 (HWI)."],
        });
        forms.push(CommandForm {
            id: CommandId::HwiSignMessage,
            label: "HWI Sign Message",
            implemented: true,
            fields: vec![
                InputField {
                    label: "derivation",
                    value: "m/86'/12345'/0'/0/0".to_string(),
                    secret: false,
                },
                InputField {
                    label: "msg (pfad)",
                    value: "message.txt".to_string(),
                    secret: false,
                },
                InputField {
                    label: "fingerprint (optional)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Signiert Nachricht via HWI (BitBox02)."],
        });
        forms.push(CommandForm {
            id: CommandId::HwiSignTx,
            label: "HWI Sign Tx",
            implemented: true,
            fields: vec![
                InputField {
                    label: "psbt (pfad)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "fingerprint (optional)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "external_cmd (optional)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "out (optional)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "network_id (64 hex)",
                    value: String::new(),
                    secret: false,
                },
            ],
            help: vec!["Signiert PSBT via externem BitBox02-Signer."],
        });
        forms.push(CommandForm {
            id: CommandId::PayjoinInitiate,
            label: "PayJoin Initiate",
            implemented: true,
            fields: vec![
                InputField {
                    label: "psbt (pfad)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "endpoint (optional)",
                    value: String::new(),
                    secret: false,
                },
                InputField {
                    label: "out (pfad)",
                    value: "payjoin_request.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "force (true|false)",
                    value: "false".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Erstellt PayJoin-Request (Sender)."],
        });
        forms.push(CommandForm {
            id: CommandId::PayjoinRespond,
            label: "PayJoin Respond",
            implemented: true,
            fields: vec![
                InputField {
                    label: "request (pfad)",
                    value: "payjoin_request.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "add_inputs (pfad)",
                    value: "txins.bin".to_string(),
                    secret: false,
                },
                InputField {
                    label: "out (pfad)",
                    value: "payjoin_response.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "force (true|false)",
                    value: "false".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Erstellt PayJoin-Response (Empfänger)."],
        });
        forms.push(CommandForm {
            id: CommandId::PayjoinFinalize,
            label: "PayJoin Finalize",
            implemented: true,
            fields: vec![
                InputField {
                    label: "original (psbt)",
                    value: "psbt.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "response (pfad)",
                    value: "payjoin_response.toml".to_string(),
                    secret: false,
                },
                InputField {
                    label: "out (pfad)",
                    value: "tx_final.bin".to_string(),
                    secret: false,
                },
            ],
            help: vec!["Validiert Response und schreibt finale TX."],
        });
        forms.push(CommandForm {
            id: CommandId::PayjoinParseUri,
            label: "PayJoin Parse URI",
            implemented: true,
            fields: vec![InputField {
                label: "uri",
                value: "pc:address?amount=1000&pj=https://endpoint".to_string(),
                secret: false,
            }],
            help: vec!["Parst pc: URI inkl. PayJoin-Endpoint."],
        });

        Self {
            forms,
            selected: 0,
            active_field: 0,
            focus: Focus::Commands,
            output: vec!["Signer bereit.".to_string()],
            bitbox_transport,
            bitbox_bridge_url,
        }
    }
}

pub fn handle_key(state: &mut SignerState, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Tab => {
            state.focus = match state.focus {
                Focus::Commands => Focus::Fields,
                Focus::Fields => Focus::Commands,
            };
            true
        }
        KeyCode::Up => {
            match state.focus {
                Focus::Commands => {
                    if state.selected > 0 {
                        state.selected -= 1;
                        state.active_field = 0;
                    }
                }
                Focus::Fields => {
                    if state.active_field > 0 {
                        state.active_field -= 1;
                    }
                }
            }
            true
        }
        KeyCode::Down => {
            match state.focus {
                Focus::Commands => {
                    if state.selected + 1 < state.forms.len() {
                        state.selected += 1;
                        state.active_field = 0;
                    }
                }
                Focus::Fields => {
                    let field_len = state.forms[state.selected].fields.len();
                    if state.active_field + 1 < field_len {
                        state.active_field += 1;
                    }
                }
            }
            true
        }
        KeyCode::Enter => {
            run_current(state);
            true
        }
        KeyCode::Backspace => {
            if let Focus::Fields = state.focus {
                let field = &mut state.forms[state.selected].fields[state.active_field];
                field.value.pop();
                return true;
            }
            false
        }
        KeyCode::Delete => {
            if let Focus::Fields = state.focus {
                let field = &mut state.forms[state.selected].fields[state.active_field];
                field.value.clear();
                return true;
            }
            false
        }
        KeyCode::Char(c) => {
            if let Focus::Fields = state.focus {
                let field = &mut state.forms[state.selected].fields[state.active_field];
                field.value.push(c);
                return true;
            }
            false
        }
        _ => false,
    }
}

pub fn draw(f: &mut Frame, area: Rect, state: &SignerState, expert_mode: bool) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    let items: Vec<ListItem> = state
        .forms
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut label = c.label.to_string();
            if !c.implemented {
                label.push_str(" (coming)");
            }
            let style = if i == state.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Signer Commands"),
    );
    f.render_widget(list, cols[0]);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(cols[1]);

    let form = &state.forms[state.selected];
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        format!(
            "{}{}",
            form.label,
            if expert_mode { " (Experte)" } else { "" }
        ),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    for (idx, field) in form.fields.iter().enumerate() {
        let mut value = if field.secret {
            if field.value.is_empty() {
                String::new()
            } else {
                "•".repeat(field.value.chars().count())
            }
        } else {
            field.value.clone()
        };
        if value.is_empty() {
            value = "<leer>".to_string();
        }
        let style = if state.focus == Focus::Fields && idx == state.active_field {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::styled(field.label, Style::default().fg(Color::Gray)),
            Span::raw(": "),
            Span::styled(value, style),
        ]));
    }
    if form.fields.is_empty() {
        lines.push(Line::from("Keine Eingaben nötig."));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Enter = ausführen · Tab = Fokus wechseln · Del = Feld leeren",
    ));
    for h in &form.help {
        lines.push(Line::from(Span::styled(
            *h,
            Style::default().fg(Color::DarkGray),
        )));
    }
    let form_widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Eingaben"))
        .wrap(Wrap { trim: true });
    f.render_widget(form_widget, rows[0]);

    let out_lines: Vec<Line> = state
        .output
        .iter()
        .map(|l| Line::from(Span::raw(l.clone())))
        .collect();
    let out_widget = Paragraph::new(out_lines)
        .block(Block::default().borders(Borders::ALL).title("Ausgabe"))
        .wrap(Wrap { trim: true });
    f.render_widget(out_widget, rows[1]);
}

fn run_current(state: &mut SignerState) {
    let selected = state.selected;
    if !state.forms[selected].implemented {
        state.output = vec!["Noch nicht implementiert.".to_string()];
        return;
    }

    let form = state.forms[selected].clone();
    let res = match form.id {
        CommandId::Keygen => run_keygen(&form),
        CommandId::Import => run_import(&form),
        CommandId::ExportPub => run_export_pub(&form),
        CommandId::Sign => run_sign(&form),
        CommandId::Verify => run_verify(&form),
        CommandId::PsbtCreate => run_psbt_create(&form),
        CommandId::PsbtSighash => run_psbt_sighash(&form),
        CommandId::PsbtSign => run_psbt_sign(&form),
        CommandId::PsbtVerify => run_psbt_verify(&form),
        CommandId::PsbtFinalize => run_psbt_finalize(&form),
        CommandId::SlashDbInit => run_slashdb_init(&form),
        CommandId::SlashDbGet => run_slashdb_get(&form),
        CommandId::SlashDbPut => run_slashdb_put(&form),
        CommandId::SeatVoteSign => run_seat_vote_sign(&form),
        CommandId::SeatVoteVerify => run_seat_vote_verify(&form),
        CommandId::BitboxSettings => run_bitbox_settings(state, &form),
        CommandId::HwiEnumerate => run_hwi_enumerate(state, &form),
        CommandId::HwiGetXpub => run_hwi_get_xpub(state, &form),
        CommandId::HwiSignMessage => run_hwi_sign_message(state, &form),
        CommandId::HwiSignTx => run_hwi_sign_tx(&form),
        CommandId::PayjoinInitiate => run_payjoin_initiate(&form),
        CommandId::PayjoinRespond => run_payjoin_respond(&form),
        CommandId::PayjoinFinalize => run_payjoin_finalize(&form),
        CommandId::PayjoinParseUri => run_payjoin_parse_uri(&form),
    };
    match res {
        Ok(lines) => state.output = lines,
        Err(e) => state.output = vec![format!("Fehler: {e}")],
    }
}

fn run_keygen(form: &CommandForm) -> Result<Vec<String>> {
    let key_type = field(form, 0)?;
    let algo = field(form, 1)?;
    let out = field(form, 2)?;
    let force = field(form, 3)?;
    let passphrase = field(form, 4)?;
    let role = field(form, 5)?;

    let key_type = parse_key_type(&key_type)?;
    let algo = parse_algo(&algo)?;
    let force = parse_bool(&force)?;
    let passphrase = validate_passphrase(passphrase)?;
    let passphrase = maybe_derive_passphrase(passphrase, &role)?;

    if Path::new(&out).exists() && !force {
        return Err(anyhow!("Keystore existiert bereits; force=true verwenden"));
    }

    let (pub_hex, secret_bytes) = match algo {
        Algo::Schnorr => {
            let mut sk = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut sk);
            let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sk)
                .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
            (hex::encode(kp.public_xonly_bytes()), sk.to_vec())
        }
        Algo::Bls => {
            let mut ikm = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut ikm);
            let kp = bls::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen"))?;
            (hex::encode(kp.pk.to_bytes()), ikm.to_vec())
        }
    };

    let kdf_params = default_kdf_params();
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_key(&passphrase, &salt, &kdf_params)?;
    let (ct, nonce) = encrypt_secret(&key, &secret_bytes)?;

    let ks = Keystore {
        version: 1,
        key_type: key_type.to_string(),
        algo: algo.to_string(),
        kdf: KdfSection {
            name: "argon2id".to_string(),
            salt_b64: general_purpose::STANDARD.encode(salt),
            params: kdf_params,
        },
        enc: EncSection {
            cipher: "xchacha20poly1305".to_string(),
            nonce_b64: general_purpose::STANDARD.encode(nonce),
            ct_b64: general_purpose::STANDARD.encode(&ct),
        },
        pub_hex,
    };
    save_keystore(&ks, Path::new(&out))?;
    Ok(vec![format!("Keystore erstellt: {}", out)])
}

fn run_import(form: &CommandForm) -> Result<Vec<String>> {
    let key_type = field(form, 0)?;
    let algo = field(form, 1)?;
    let secret_hex = field(form, 2)?;
    let out = field(form, 3)?;
    let force = field(form, 4)?;
    let passphrase = field(form, 5)?;
    let role = field(form, 6)?;

    let key_type = parse_key_type(&key_type)?;
    let algo = parse_algo(&algo)?;
    let force = parse_bool(&force)?;
    let passphrase = validate_passphrase(passphrase)?;
    let passphrase = maybe_derive_passphrase(passphrase, &role)?;

    if Path::new(&out).exists() && !force {
        return Err(anyhow!("Keystore existiert bereits; force=true verwenden"));
    }
    let secret_bytes = hex::decode(secret_hex).map_err(|_| anyhow!("secret_hex decode"))?;
    if secret_bytes.len() != 32 {
        return Err(anyhow!("secret muss 32 bytes sein"));
    }

    let pub_hex = match algo {
        Algo::Schnorr => {
            let mut sec32 = [0u8; 32];
            sec32.copy_from_slice(&secret_bytes);
            let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
                .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
            hex::encode(kp.public_xonly_bytes())
        }
        Algo::Bls => {
            let mut sec32 = [0u8; 32];
            sec32.copy_from_slice(&secret_bytes);
            let kp =
                bls::bls_keygen_from_ikm(sec32.as_ref()).ok_or_else(|| anyhow!("bls keygen"))?;
            hex::encode(kp.pk.to_bytes())
        }
    };

    let kdf_params = default_kdf_params();
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_key(&passphrase, &salt, &kdf_params)?;
    let (ct, nonce) = encrypt_secret(&key, &secret_bytes)?;

    let ks = Keystore {
        version: 1,
        key_type: key_type.to_string(),
        algo: algo.to_string(),
        kdf: KdfSection {
            name: "argon2id".to_string(),
            salt_b64: general_purpose::STANDARD.encode(salt),
            params: kdf_params,
        },
        enc: EncSection {
            cipher: "xchacha20poly1305".to_string(),
            nonce_b64: general_purpose::STANDARD.encode(nonce),
            ct_b64: general_purpose::STANDARD.encode(&ct),
        },
        pub_hex,
    };
    save_keystore(&ks, Path::new(&out))?;
    Ok(vec![format!("Keystore importiert: {}", out)])
}

fn run_export_pub(form: &CommandForm) -> Result<Vec<String>> {
    let keystore = field(form, 0)?;
    let ks = load_keystore(Path::new(&keystore))?;
    Ok(vec![ks.pub_hex])
}

fn run_sign(form: &CommandForm) -> Result<Vec<String>> {
    let keystore = field(form, 0)?;
    let msg_path = field(form, 1)?;
    let out = field(form, 2)?;
    let passphrase = field(form, 3)?;
    let role = field(form, 4)?;

    let passphrase = validate_passphrase(passphrase)?;
    let passphrase = maybe_derive_passphrase(passphrase, &role)?;

    let ks = load_keystore(Path::new(&keystore))?;
    let key = Zeroizing::new(derive_key_from_keystore(&ks, &passphrase)?);
    let secret = Zeroizing::new(decrypt_keystore_secret(&ks, &key)?);
    if secret.len() != 32 {
        return Err(anyhow!("invalid secret length"));
    }
    let msg = fs::read(&msg_path)?;
    let sig_hex = match ks.algo.as_str() {
        "schnorr" => {
            let mut sec32 = Zeroizing::new([0u8; 32]);
            sec32.copy_from_slice(secret.as_slice());
            let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
                .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
            let digest: Hash32 = blake3_32(&msg);
            let sig = schnorr::schnorr_sign(&digest, &kp);
            hex::encode(sig)
        }
        "bls" => {
            let mut sec32 = Zeroizing::new([0u8; 32]);
            sec32.copy_from_slice(secret.as_slice());
            let kp =
                bls::bls_keygen_from_ikm(sec32.as_ref()).ok_or_else(|| anyhow!("bls keygen"))?;
            let sig = bls::bls_sign(&msg, &kp.sk);
            hex::encode(sig)
        }
        _ => return Err(anyhow!("unbekannter algo")),
    };
    if !out.trim().is_empty() {
        fs::write(out.trim(), &sig_hex)?;
        Ok(vec![format!("Signatur gespeichert: {}", out.trim())])
    } else {
        Ok(vec![sig_hex])
    }
}

fn run_verify(form: &CommandForm) -> Result<Vec<String>> {
    let algo = field(form, 0)?;
    let pub_hex = field(form, 1)?;
    let msg_path = field(form, 2)?;
    let sig_hex = field(form, 3)?;

    let algo = parse_algo(&algo)?;
    let msg = fs::read(&msg_path)?;
    match algo {
        Algo::Schnorr => {
            let pk = hex::decode(pub_hex)?;
            if pk.len() != 32 {
                return Err(anyhow!("schnorr pubkey xonly muss 32 bytes sein"));
            }
            let mut pk32 = [0u8; 32];
            pk32.copy_from_slice(&pk);
            let sig = hex::decode(sig_hex)?;
            if sig.len() != 64 {
                return Err(anyhow!("schnorr sig muss 64 bytes sein"));
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&sig);
            let digest: Hash32 = blake3_32(&msg);
            let ok = schnorr::schnorr_verify_xonly_bytes(&digest, &sig64, &pk32);
            Ok(vec![format!("OK: {}", ok)])
        }
        Algo::Bls => {
            let pk = hex::decode(pub_hex)?;
            if pk.len() != 48 {
                return Err(anyhow!("bls pubkey muss 48 bytes sein"));
            }
            let sig = hex::decode(sig_hex)?;
            if sig.len() != 96 {
                return Err(anyhow!("bls sig muss 96 bytes sein"));
            }
            let mut pk48 = [0u8; 48];
            pk48.copy_from_slice(&pk);
            let mut sig96 = [0u8; 96];
            sig96.copy_from_slice(&sig);
            let pk = pc_crypto::bls_pk_from_bytes(&pk48)
                .ok_or_else(|| anyhow!("ungültiger bls pubkey"))?;
            let ok = bls::bls_verify(&msg, &sig96, &pk);
            Ok(vec![format!("OK: {}", ok)])
        }
    }
}

fn run_psbt_create(form: &CommandForm) -> Result<Vec<String>> {
    let tx_bin = field(form, 0)?;
    let paths = field(form, 1)?;
    let out = field(form, 2)?;

    let raw = fs::read(&tx_bin)?;
    let tx = psbt::decode_tx(&raw)?;
    let ders = split_csv(&paths)
        .into_iter()
        .map(|p| psbt::Derivation { path: p })
        .collect::<Vec<_>>();
    if ders.len() != tx.inputs.len() {
        return Err(anyhow!(
            "paths len ({}) != inputs len ({})",
            ders.len(),
            tx.inputs.len()
        ));
    }
    psbt::to_toml_file(&tx, &ders, Path::new(&out))?;
    Ok(vec![format!("PSBT erstellt: {}", out)])
}

fn run_psbt_sighash(form: &CommandForm) -> Result<Vec<String>> {
    let psbt_path = field(form, 0)?;
    let network_id = field(form, 1)?;
    let (tx, _) = psbt::from_toml_file(Path::new(&psbt_path))?;
    let nid = parse_network_id_hex(&network_id)?;
    let h = psbt::sighash_of_tx(&nid, &tx);
    Ok(vec![hex::encode(h)])
}

fn run_psbt_sign(form: &CommandForm) -> Result<Vec<String>> {
    let psbt_path = field(form, 0)?;
    let keystore = field(form, 1)?;
    let out = field(form, 2)?;
    let passphrase = field(form, 3)?;
    let role = field(form, 4)?;
    let network_id = field(form, 5)?;

    let passphrase = validate_passphrase(passphrase)?;
    let passphrase = maybe_derive_passphrase(passphrase, &role)?;

    let (tx, _) = psbt::from_toml_file(Path::new(&psbt_path))?;
    let ks = load_keystore(Path::new(&keystore))?;
    if ks.algo.as_str() != "schnorr" {
        return Err(anyhow!("nur schnorr unterstützt"));
    }
    let key = Zeroizing::new(derive_key_from_keystore(&ks, &passphrase)?);
    let secret = Zeroizing::new(decrypt_keystore_secret(&ks, &key)?);
    if secret.len() != 32 {
        return Err(anyhow!("invalid secret length"));
    }
    let mut sec32 = Zeroizing::new([0u8; 32]);
    sec32.copy_from_slice(secret.as_slice());
    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
    let nid = parse_network_id_hex(&network_id)?;
    let digest = psbt::sighash_of_tx(&nid, &tx);
    let sig = schnorr::schnorr_sign(&digest, &kp);
    let sig_hex = hex::encode(sig);
    if !out.is_empty() {
        fs::write(&out, &sig_hex)?;
        Ok(vec![format!("Signatur gespeichert: {}", out)])
    } else {
        Ok(vec![sig_hex])
    }
}

fn run_psbt_verify(form: &CommandForm) -> Result<Vec<String>> {
    let psbt_path = field(form, 0)?;
    let algo = field(form, 1)?;
    let pub_hex = field(form, 2)?;
    let sig_hex = field(form, 3)?;
    let network_id = field(form, 4)?;

    let algo = parse_algo(&algo)?;
    if !matches!(algo, Algo::Schnorr) {
        return Err(anyhow!("nur schnorr unterstützt"));
    }
    let (tx, _) = psbt::from_toml_file(Path::new(&psbt_path))?;
    let nid = parse_network_id_hex(&network_id)?;
    let digest = psbt::sighash_of_tx(&nid, &tx);
    let pk = hex::decode(pub_hex)?;
    if pk.len() != 32 {
        return Err(anyhow!("schnorr pubkey xonly muss 32 bytes sein"));
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pk);
    let sig = hex::decode(sig_hex)?;
    if sig.len() != 64 {
        return Err(anyhow!("schnorr sig muss 64 bytes sein"));
    }
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig);
    let ok = schnorr::schnorr_verify_xonly_bytes(&digest, &sig64, &pk32);
    Ok(vec![format!("OK: {}", ok)])
}

fn run_psbt_finalize(form: &CommandForm) -> Result<Vec<String>> {
    let psbt_path = field(form, 0)?;
    let pubkeys = field(form, 1)?;
    let sigs = field(form, 2)?;
    let out = field(form, 3)?;

    let (tx, _) = psbt::from_toml_file(Path::new(&psbt_path))?;
    let pub_list = split_csv(&pubkeys);
    let sig_list = split_csv(&sigs);
    if pub_list.len() != tx.inputs.len() {
        return Err(anyhow!(
            "pubkeys len ({}) != inputs len ({})",
            pub_list.len(),
            tx.inputs.len()
        ));
    }
    if sig_list.len() != tx.inputs.len() {
        return Err(anyhow!(
            "sigs len ({}) != inputs len ({})",
            sig_list.len(),
            tx.inputs.len()
        ));
    }
    let mut witnesses: Vec<Vec<u8>> = Vec::with_capacity(tx.inputs.len());
    for (i, (pk_hex, sig_hex)) in pub_list.iter().zip(sig_list.iter()).enumerate() {
        let pkv = hex::decode(pk_hex)?;
        if pkv.len() != 32 {
            return Err(anyhow!("xonly pubkey muss 32 bytes sein (input #{})", i));
        }
        let mut pk32 = [0u8; 32];
        pk32.copy_from_slice(&pkv);
        let sv = hex::decode(sig_hex)?;
        if sv.len() != 64 {
            return Err(anyhow!(
                "schnorr signature muss 64 bytes sein (input #{})",
                i
            ));
        }
        let mut s64 = [0u8; 64];
        s64.copy_from_slice(&sv);
        witnesses.push(psbt::build_witness(&pk32, &s64));
    }
    let final_tx = psbt::attach_witnesses(tx, &witnesses)?;
    let bin = psbt::encode_tx(&final_tx)?;
    fs::write(&out, &bin)?;
    Ok(vec![format!("Finale TX geschrieben: {}", out)])
}

fn run_slashdb_init(form: &CommandForm) -> Result<Vec<String>> {
    let db_dir = field(form, 0)?;
    slashdb::SlashDb::init(Path::new(&db_dir))?;
    Ok(vec!["OK".to_string()])
}

fn run_slashdb_get(form: &CommandForm) -> Result<Vec<String>> {
    let db_dir = field(form, 0)?;
    let epoch = parse_u64(&field(form, 1)?)?;
    let shard = parse_u16(&field(form, 2)?)?;
    let round = parse_u64(&field(form, 3)?)?;
    let sdb = slashdb::SlashDb::open_locked(Path::new(&db_dir))?;
    match sdb.get_vote(epoch, shard, round)? {
        Some(h) => Ok(vec![hex::encode(h)]),
        None => Ok(vec!["".to_string()]),
    }
}

fn run_slashdb_put(form: &CommandForm) -> Result<Vec<String>> {
    let db_dir = field(form, 0)?;
    let epoch = parse_u64(&field(form, 1)?)?;
    let shard = parse_u16(&field(form, 2)?)?;
    let round = parse_u64(&field(form, 3)?)?;
    let header_hex = field(form, 4)?;
    let header_id = parse_hex32(&header_hex)?;
    let sdb = slashdb::SlashDb::open_locked(Path::new(&db_dir))?;
    sdb.put_vote_if_absent(epoch, shard, round, header_id)?;
    Ok(vec!["OK".to_string()])
}

fn run_seat_vote_sign(form: &CommandForm) -> Result<Vec<String>> {
    let db_dir = field(form, 0)?;
    let epoch = parse_u64(&field(form, 1)?)?;
    let shard = parse_u16(&field(form, 2)?)?;
    let round = parse_u64(&field(form, 3)?)?;
    let header_hex = field(form, 4)?;
    let keystore = field(form, 5)?;
    let out = field(form, 6)?;
    let passphrase = field(form, 7)?;
    let role = field(form, 8)?;

    let header_id = parse_hex32(&header_hex)?;

    let sdb = slashdb::SlashDb::open_locked(Path::new(&db_dir))?;
    if let Some(existing) = sdb.get_vote(epoch, shard, round)? {
        if existing != header_id {
            return Err(anyhow!(
                "Equivocation: existierender Vote differiert (epoch={}, shard={}, round={})",
                epoch,
                shard,
                round
            ));
        }
    }
    sdb.put_vote_if_absent(epoch, shard, round, header_id)?;

    let ks = load_keystore(Path::new(&keystore))?;
    if ks.key_type.as_str() != "seat" {
        return Err(anyhow!("Keystore ist kein Seat-Key"));
    }
    if ks.algo.as_str() != "schnorr" {
        return Err(anyhow!("SeatVoteSign unterstützt nur Schnorr"));
    }
    let passphrase = validate_passphrase(passphrase)?;
    let passphrase = maybe_derive_passphrase(passphrase, &role)?;
    let key = Zeroizing::new(derive_key_from_keystore(&ks, &passphrase)?);
    let secret = Zeroizing::new(decrypt_keystore_secret(&ks, &key)?);
    if secret.len() != 32 {
        return Err(anyhow!("invalid secret length"));
    }
    let mut sec32 = Zeroizing::new([0u8; 32]);
    sec32.copy_from_slice(secret.as_slice());
    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;

    const DOMAIN: &[u8] = b"pc:vote:seat:v1\x01";
    let mut msg = Vec::with_capacity(DOMAIN.len() + 8 + 2 + 8 + 32);
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&shard.to_le_bytes());
    msg.extend_from_slice(&round.to_le_bytes());
    msg.extend_from_slice(&header_id);
    let digest: Hash32 = blake3_32(&msg);
    let sig = schnorr::schnorr_sign(&digest, &kp);
    let sig_hex = hex::encode(sig);

    if !out.is_empty() {
        fs::write(&out, &sig_hex)?;
        Ok(vec![format!("Signatur gespeichert: {}", out)])
    } else {
        Ok(vec![sig_hex])
    }
}

fn run_seat_vote_verify(form: &CommandForm) -> Result<Vec<String>> {
    let epoch = parse_u64(&field(form, 0)?)?;
    let shard = parse_u16(&field(form, 1)?)?;
    let round = parse_u64(&field(form, 2)?)?;
    let header_hex = field(form, 3)?;
    let pub_hex = field(form, 4)?;
    let sig_hex = field(form, 5)?;

    let header_id = parse_hex32(&header_hex)?;
    let pk = parse_hex32(&pub_hex)?;
    let sig = hex::decode(sig_hex)?;
    if sig.len() != 64 {
        return Err(anyhow!("schnorr sig muss 64 bytes sein"));
    }
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig);

    const DOMAIN: &[u8] = b"pc:vote:seat:v1\x01";
    let mut msg = Vec::with_capacity(DOMAIN.len() + 8 + 2 + 8 + 32);
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&shard.to_le_bytes());
    msg.extend_from_slice(&round.to_le_bytes());
    msg.extend_from_slice(&header_id);
    let digest: Hash32 = blake3_32(&msg);
    let ok = schnorr::schnorr_verify_xonly_bytes(&digest, &sig64, &pk);
    Ok(vec![format!("OK: {}", ok)])
}

fn run_bitbox_settings(state: &mut SignerState, form: &CommandForm) -> Result<Vec<String>> {
    let transport = normalize_bitbox_transport(&field(form, 0)?)?;
    let bridge_url = normalize_bitbox_bridge_url(&field(form, 1)?)?;
    let do_check = parse_bool(&field(form, 2)?)?;

    state.bitbox_transport = transport.clone();
    state.bitbox_bridge_url = bridge_url.clone();

    let mut out = vec![
        format!("BitBox Transport gesetzt: {}", transport),
        format!("Bridge URL: {}", bridge_url),
    ];
    if do_check {
        out.push(bitbox_bridge_check(&bridge_url)?);
    }
    Ok(out)
}

fn run_hwi_enumerate(state: &SignerState, _form: &CommandForm) -> Result<Vec<String>> {
    let (paired, transport) = bitbox_connect_paired(state)?;
    let fingerprint = block_on(paired.root_fingerprint())
        .map_err(|e| anyhow!("bitbox root_fingerprint: {e:?}"))?;
    let transport_str = match transport {
        BitboxTransport::Usb => "usb",
        BitboxTransport::Bridge => "bridge",
    };
    let value = json!([
        {
            "type": "bitbox02",
            "model": "BitBox02",
            "fingerprint": fingerprint,
            "transport": transport_str,
        }
    ]);
    Ok(vec![serde_json::to_string(&value)?])
}

fn run_hwi_get_xpub(state: &SignerState, form: &CommandForm) -> Result<Vec<String>> {
    let derivation = field(form, 0)?;
    let _fingerprint = field(form, 1)?;
    let (paired, _) = bitbox_connect_paired(state)?;
    let keypath = Keypath::try_from(derivation.as_str())
        .map_err(|e| anyhow!("ungültige derivation '{}': {e}", derivation))?;
    let xpub = block_on(paired.btc_xpub(
        bitbox_api::pb::BtcCoin::Btc,
        &keypath,
        bitbox_api::pb::btc_pub_request::XPubType::Xpub,
        false,
    ))
    .map_err(|e| anyhow!("bitbox btc_xpub: {e:?}"))?;
    let value = json!({ "xpub": xpub });
    Ok(vec![serde_json::to_string(&value)?])
}

fn btc_simple_type_from_derivation(
    derivation: &str,
) -> bitbox_api::pb::btc_script_config::SimpleType {
    // Best-effort guess from BIP purpose field.
    // 49' => p2wpkh-p2sh, 84' => p2wpkh, 86' => p2tr.
    let s = derivation.trim();
    let mut it = s.split('/');
    if let Some(first) = it.next() {
        if first != "m" {
            // It might start directly with the purpose.
            it = s.split('/');
        }
    }
    let purpose = it.next().and_then(|seg| {
        seg.trim_end_matches(&['\'', 'h', 'H'][..])
            .parse::<u32>()
            .ok()
    });
    match purpose {
        Some(49) => bitbox_api::pb::btc_script_config::SimpleType::P2wpkhP2sh,
        Some(84) => bitbox_api::pb::btc_script_config::SimpleType::P2wpkh,
        Some(86) => bitbox_api::pb::btc_script_config::SimpleType::P2tr,
        _ => bitbox_api::pb::btc_script_config::SimpleType::P2wpkh,
    }
}

fn run_hwi_sign_message(state: &SignerState, form: &CommandForm) -> Result<Vec<String>> {
    let derivation = field(form, 0)?;
    let msg_path = field(form, 1)?;
    let fingerprint = field(form, 2)?;
    let m = fs::read_to_string(&msg_path).map_err(|e| anyhow!("read msg: {e}"))?;
    let keypath = Keypath::try_from(derivation.as_str())
        .map_err(|e| anyhow!("ungültige derivation '{}': {e}", derivation))?;

    let (paired, _) = bitbox_connect_paired(state)?;
    let actual_fp = block_on(paired.root_fingerprint())
        .map_err(|e| anyhow!("bitbox root_fingerprint: {e:?}"))?;
    if !fingerprint.trim().is_empty() && fingerprint.trim() != actual_fp {
        return Err(anyhow!(
            "fingerprint mismatch: erwartet {}, verbunden {}",
            fingerprint.trim(),
            actual_fp
        ));
    }

    let simple_type = btc_simple_type_from_derivation(&derivation);
    let script_config = bitbox_api::pb::BtcScriptConfig {
        config: Some(bitbox_api::pb::btc_script_config::Config::SimpleType(
            simple_type as i32,
        )),
    };
    let script_cfg_w_keypath = bitbox_api::pb::BtcScriptConfigWithKeypath {
        script_config: Some(script_config),
        keypath: keypath.to_vec(),
    };

    let sig = block_on(paired.btc_sign_message(
        bitbox_api::pb::BtcCoin::Btc,
        script_cfg_w_keypath,
        m.as_bytes(),
    ))
    .map_err(|e| anyhow!("bitbox btc_sign_message: {e:?}"))?;
    let signature_b64 = general_purpose::STANDARD.encode(sig.electrum_sig65);
    let value = json!({ "signature": signature_b64 });
    Ok(vec![serde_json::to_string(&value)?])
}

fn run_hwi_sign_tx(form: &CommandForm) -> Result<Vec<String>> {
    let psbt_path = field(form, 0)?;
    let fingerprint = field(form, 1)?;
    let external_cmd = field(form, 2)?;
    let out = field(form, 3)?;
    let network_id = field(form, 4)?;

    if network_id.trim().is_empty() {
        return Err(anyhow!("network_id fehlt (64 hex)"));
    }
    let (tx, ders) = psbt::from_toml_file(Path::new(&psbt_path))?;
    let nid = parse_network_id_hex(&network_id)?;
    let digest = psbt::sighash_of_tx(&nid, &tx);
    let cmd_path = if !external_cmd.trim().is_empty() {
        PathBuf::from(external_cmd.trim())
    } else if let Ok(p) = env::var("PHANTOM_BITBOX2_SIGNER") {
        PathBuf::from(p)
    } else {
        PathBuf::from("bitbox02-signer")
    };
    let mut witnesses: Vec<Vec<u8>> = Vec::with_capacity(tx.inputs.len());
    for (i, d) in ders.iter().enumerate() {
        let mut cmd = Command::new(&cmd_path);
        cmd.args(["--digest", &hex::encode(digest)])
            .args(["--path", &d.path]);
        if !fingerprint.trim().is_empty() {
            cmd.args(["--fingerprint", fingerprint.trim()]);
        }
        let outp = cmd
            .output()
            .map_err(|e| anyhow!("external signer exec (input #{}): {e}", i))?;
        if !outp.status.success() {
            return Err(anyhow!(
                "external signer failed (input #{}): {}",
                i,
                String::from_utf8_lossy(&outp.stderr)
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&outp.stdout)
            .map_err(|e| anyhow!("parse signer json (input #{}): {e}", i))?;
        let pk_hex = v
            .get("pub_xonly_hex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing pub_xonly_hex"))?;
        let sig_hex = v
            .get("sig_hex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing sig_hex"))?;
        let pkb = hex::decode(pk_hex).map_err(|e| anyhow!("pub_xonly_hex decode: {e}"))?;
        if pkb.len() != 32 {
            return Err(anyhow!("xonly pubkey muss 32 bytes sein (input #{})", i));
        }
        let mut pk32 = [0u8; 32];
        pk32.copy_from_slice(&pkb);
        let sv = hex::decode(sig_hex).map_err(|e| anyhow!("sig_hex decode: {e}"))?;
        if sv.len() != 64 {
            return Err(anyhow!(
                "schnorr signature muss 64 bytes sein (input #{})",
                i
            ));
        }
        let mut s64 = [0u8; 64];
        s64.copy_from_slice(&sv);
        let ok = schnorr::schnorr_verify_xonly_bytes(&digest, &s64, &pk32);
        if !ok {
            return Err(anyhow!("signaturprüfung fehlgeschlagen (input #{})", i));
        }
        witnesses.push(psbt::build_witness(&pk32, &s64));
    }
    if !out.trim().is_empty() {
        let final_tx = psbt::attach_witnesses(tx, &witnesses)?;
        let enc = psbt::encode_tx(&final_tx)?;
        fs::write(out.trim(), &enc)?;
        Ok(vec![format!("Finale TX geschrieben: {}", out.trim())])
    } else {
        let arr: Vec<serde_json::Value> = witnesses
            .into_iter()
            .map(|w| {
                let (pk, sig) = w.split_at(32);
                json!({
                    "pub_xonly_hex": hex::encode(pk),
                    "sig_hex": hex::encode(sig),
                })
            })
            .collect();
        Ok(vec![serde_json::to_string_pretty(&arr)?])
    }
}

fn run_payjoin_initiate(form: &CommandForm) -> Result<Vec<String>> {
    let psbt_path = field(form, 0)?;
    let endpoint = field(form, 1)?;
    let out = field(form, 2)?;
    let force = parse_bool(&field(form, 3)?)?;

    let (tx, derivations) = psbt::from_toml_file(Path::new(&psbt_path))?;
    let enc = psbt::encode_tx(&tx)?;
    let psbt_toml = psbt::PhantomPsbtToml {
        version: 1,
        algo: "schnorr".to_string(),
        tx_b64: general_purpose::STANDARD.encode(enc),
        derivations,
    };
    let endpoint = if endpoint.trim().is_empty() {
        None
    } else {
        Some(endpoint)
    };
    let request = payjoin::initiate_payjoin(psbt_toml, endpoint)?;
    payjoin::save_payjoin_request(&request, Path::new(&out), force)?;
    Ok(vec![format!("PayJoin-Request erstellt: {}", out)])
}

fn run_payjoin_respond(form: &CommandForm) -> Result<Vec<String>> {
    let request_path = field(form, 0)?;
    let add_inputs = field(form, 1)?;
    let out = field(form, 2)?;
    let force = parse_bool(&field(form, 3)?)?;

    let req = payjoin::load_payjoin_request(Path::new(&request_path))?;
    let inputs_bytes = fs::read(&add_inputs)?;
    let mut cursor: &[u8] = &inputs_bytes;
    let mut additional_inputs = Vec::new();
    while !cursor.is_empty() {
        match pc_types::TxIn::decode(&mut cursor) {
            Ok(inp) => additional_inputs.push(inp),
            Err(_) => break,
        }
    }
    if additional_inputs.is_empty() {
        return Err(anyhow!("No inputs found in add_inputs file"));
    }
    let additional_derivations: Vec<psbt::Derivation> = additional_inputs
        .iter()
        .map(|_| psbt::Derivation {
            path: "m/86'/12345'/0'/0/0".to_string(),
        })
        .collect();
    let response = payjoin::respond_payjoin(&req, additional_inputs, additional_derivations, None)?;
    payjoin::save_payjoin_response(&response, Path::new(&out), force)?;
    Ok(vec![
        format!("PayJoin-Response erstellt: {}", out),
        format!("inputs_added: {}", response.inputs_added),
    ])
}

fn run_payjoin_finalize(form: &CommandForm) -> Result<Vec<String>> {
    let original = field(form, 0)?;
    let response = field(form, 1)?;
    let out = field(form, 2)?;

    let (orig_tx, orig_derivations) = psbt::from_toml_file(Path::new(&original))?;
    let enc = psbt::encode_tx(&orig_tx)?;
    let orig_psbt = psbt::PhantomPsbtToml {
        version: 1,
        algo: "schnorr".to_string(),
        tx_b64: general_purpose::STANDARD.encode(enc),
        derivations: orig_derivations,
    };
    let resp = payjoin::load_payjoin_response(Path::new(&response))?;
    payjoin::validate_payjoin_response(&orig_psbt, &resp)?;
    let resp_bytes = general_purpose::STANDARD.decode(resp.modified_psbt.tx_b64.as_bytes())?;
    let final_tx = pc_types::MicroTx::decode(&mut &resp_bytes[..])?;
    let enc = psbt::encode_tx(&final_tx)?;
    fs::write(&out, &enc)?;
    Ok(vec![format!("Finalisierte TX gespeichert: {}", out)])
}

fn run_payjoin_parse_uri(form: &CommandForm) -> Result<Vec<String>> {
    let uri = field(form, 0)?;
    let (addr, amount, pj_endpoint) = payjoin::parse_pc_uri(&uri)?;
    let mut out = vec![format!("Address: {}", addr)];
    if let Some(amt) = amount {
        out.push(format!("Amount: {} sats", amt));
    }
    if let Some(ep) = pj_endpoint {
        out.push(format!("PayJoin-Endpoint: {}", ep));
    }
    Ok(out)
}

fn field(form: &CommandForm, idx: usize) -> Result<String> {
    form.fields
        .get(idx)
        .map(|f| f.value.trim().to_string())
        .ok_or_else(|| anyhow!("fehlendes Feld"))
}

fn parse_key_type(s: &str) -> Result<KeyType> {
    match s.to_lowercase().as_str() {
        "seat" => Ok(KeyType::Seat),
        "bond" => Ok(KeyType::Bond),
        "payout" => Ok(KeyType::Payout),
        _ => Err(anyhow!("key_type muss seat|bond|payout sein")),
    }
}

fn parse_algo(s: &str) -> Result<Algo> {
    match s.to_lowercase().as_str() {
        "schnorr" => Ok(Algo::Schnorr),
        "bls" => Ok(Algo::Bls),
        _ => Err(anyhow!("algo muss schnorr|bls sein")),
    }
}

fn parse_network_id_hex(s: &str) -> Result<NetworkId> {
    let raw = hex::decode(s).map_err(|e| anyhow!("network_id ist kein hex: {e}"))?;
    if raw.len() != 32 {
        return Err(anyhow!("network_id muss 32 bytes sein (64 hex Zeichen)"));
    }
    let mut nid = [0u8; 32];
    nid.copy_from_slice(&raw);
    Ok(nid)
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).map_err(|e| anyhow!("hex decode: {e}"))?;
    if v.len() != 32 {
        return Err(anyhow!("hex muss 32 bytes sein"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn parse_u64(s: &str) -> Result<u64> {
    s.trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("ungültige Zahl (u64)"))
}

fn parse_u16(s: &str) -> Result<u16> {
    s.trim()
        .parse::<u16>()
        .map_err(|_| anyhow!("ungültige Zahl (u16)"))
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect()
}

enum BitboxTransport {
    Usb,
    Bridge,
}

fn normalize_bitbox_transport(input: &str) -> Result<String> {
    let mode = input.trim().to_lowercase();
    match mode.as_str() {
        "auto" | "usb" | "bridge" => Ok(mode),
        _ => Err(anyhow!("transport muss auto|usb|bridge sein")),
    }
}

fn normalize_bitbox_bridge_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok("http://127.0.0.1:8178".to_string());
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    Ok(format!("http://{}", trimmed))
}

fn bitbox_bridge_opt_in_enabled() -> bool {
    matches!(
        env::var("PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE"),
        Ok(v) if matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    )
}

fn ensure_bitbox_bridge_opt_in() -> Result<()> {
    if bitbox_bridge_opt_in_enabled() {
        return Ok(());
    }
    Err(anyhow!(
        "BitBox bridge ist standardmäßig deaktiviert; setze PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE=1 für ein explizites Opt-in"
    ))
}

fn bitbox_bridge_check(bridge_url: &str) -> Result<String> {
    ensure_bitbox_bridge_opt_in()?;
    let devices = bitbox_api::bridge::list_devices(bridge_url)
        .map_err(|e| anyhow!("Bridge Check fehlgeschlagen: {e}"))?;
    let count = devices.len();
    let has_bitbox = devices
        .iter()
        .any(|d| d.product.to_lowercase().contains("bitbox02"));
    let note = if count == 0 {
        "Bridge erreichbar (0 Geräte)".to_string()
    } else if has_bitbox {
        format!("Bridge erreichbar ({} Geräte, BitBox02 erkannt)", count)
    } else {
        format!("Bridge erreichbar ({} Geräte, keine BitBox02)", count)
    };
    Ok(note)
}

fn bitbox_noise_config() -> Result<Box<dyn NoiseConfig>> {
    let home = env::var("HOME").context("HOME not set for BitBox noise config")?;
    let config_dir = PathBuf::from(home).join(".phantom").join("bitbox");
    fs::create_dir_all(&config_dir)
        .with_context(|| format!("create BitBox noise config dir '{}'", config_dir.display()))?;
    Ok(Box::new(PersistedNoiseConfig::new(
        &config_dir.to_string_lossy(),
    )))
}

fn bitbox_connect_usb() -> Result<bitbox_api::BitBox<DefaultRuntime>> {
    let device = usb::get_any_bitbox02().map_err(|e| anyhow!("bitbox usb: {e}"))?;
    let noise_cfg = bitbox_noise_config()?;
    let bitbox = block_on(bitbox_api::BitBox::<DefaultRuntime>::from_hid_device(
        device, noise_cfg,
    ))
    .map_err(|e| anyhow!("bitbox connect (usb): {e:?}"))?;
    Ok(bitbox)
}

fn bitbox_connect_bridge(bridge_url: &str) -> Result<bitbox_api::BitBox<DefaultRuntime>> {
    ensure_bitbox_bridge_opt_in()?;
    let noise_cfg = bitbox_noise_config()?;
    let bitbox = block_on(bitbox_api::bridge::connect_any_bitbox02::<DefaultRuntime>(
        bridge_url, noise_cfg,
    ))
    .map_err(|e| anyhow!("bitbox connect (bridge): {e}"))?;
    Ok(bitbox)
}

fn bitbox_pair(
    bitbox: bitbox_api::BitBox<DefaultRuntime>,
) -> Result<bitbox_api::PairedBitBox<DefaultRuntime>> {
    let pairing_bitbox =
        block_on(bitbox.unlock_and_pair()).map_err(|e| anyhow!("bitbox unlock/pair: {e:?}"))?;
    if let Some(code) = pairing_bitbox.get_pairing_code().as_ref() {
        eprintln!("BitBox pairing code:\n{}", code);
    }
    let paired = block_on(pairing_bitbox.wait_confirm())
        .map_err(|e| anyhow!("bitbox wait_confirm: {e:?}"))?;
    Ok(paired)
}

fn bitbox_connect_paired(
    state: &SignerState,
) -> Result<(bitbox_api::PairedBitBox<DefaultRuntime>, BitboxTransport)> {
    let mode = state.bitbox_transport.to_lowercase();
    let want_usb = mode != "bridge";
    let want_bridge = mode != "usb";

    let mut usb_err: Option<anyhow::Error> = None;
    let mut bridge_err: Option<anyhow::Error> = None;

    if want_usb {
        match bitbox_connect_usb() {
            Ok(bitbox) => return Ok((bitbox_pair(bitbox)?, BitboxTransport::Usb)),
            Err(e) => usb_err = Some(e),
        }
    }
    if want_bridge {
        match bitbox_connect_bridge(&state.bitbox_bridge_url) {
            Ok(bitbox) => return Ok((bitbox_pair(bitbox)?, BitboxTransport::Bridge)),
            Err(e) => bridge_err = Some(e),
        }
    }

    let mut msg = String::from("BitBox02 Verbindung fehlgeschlagen.");
    if let Some(e) = usb_err {
        msg.push_str(&format!(" USB: {}", e));
    }
    if let Some(e) = bridge_err {
        msg.push_str(&format!(" Bridge: {}", e));
    }
    Err(anyhow!(msg))
}

fn parse_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => Ok(true),
        "false" | "0" | "no" | "n" | "off" | "" => Ok(false),
        _ => Err(anyhow!("bool erwartet (true/false)")),
    }
}

fn validate_passphrase(pass: String) -> Result<String> {
    if pass.chars().count() < 8 {
        return Err(anyhow!("Passphrase muss mindestens 8 Zeichen lang sein"));
    }
    Ok(pass)
}

fn maybe_derive_passphrase(mut pass: String, role: &str) -> Result<String> {
    let role = role.trim().to_lowercase();
    if role.is_empty() || role == "none" {
        return Ok(pass);
    }
    let salt: &[u8] = match role.as_str() {
        "validator" => b"pc:role:validator:passphrase:v1".as_slice(),
        "miner" => b"pc:role:miner:passphrase:v1".as_slice(),
        _ => return Err(anyhow!("role muss none|validator|miner sein")),
    };
    let key = derive_key(&pass, salt, &default_kdf_params())?;
    pass.zeroize();
    Ok(hex::encode(key))
}

#[derive(Debug, Clone, Copy)]
enum Algo {
    Schnorr,
    Bls,
}

#[derive(Debug, Clone, Copy)]
enum KeyType {
    Seat,
    Bond,
    Payout,
}

impl std::fmt::Display for Algo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Algo::Schnorr => "schnorr",
            Algo::Bls => "bls",
        };
        f.write_str(s)
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyType::Seat => "seat",
            KeyType::Bond => "bond",
            KeyType::Payout => "payout",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_lanes: 1,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct Keystore {
    version: u32,
    key_type: String,
    algo: String,
    kdf: KdfSection,
    enc: EncSection,
    pub_hex: String,
}

impl Default for Keystore {
    fn default() -> Self {
        Self {
            version: 1,
            key_type: String::new(),
            algo: String::new(),
            kdf: KdfSection::default(),
            enc: EncSection::default(),
            pub_hex: String::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct KdfSection {
    name: String,
    salt_b64: String,
    params: KdfParams,
}

impl Default for KdfSection {
    fn default() -> Self {
        Self {
            name: "argon2id".to_string(),
            salt_b64: String::new(),
            params: KdfParams::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct EncSection {
    cipher: String,
    nonce_b64: String,
    ct_b64: String,
}

impl Default for EncSection {
    fn default() -> Self {
        Self {
            cipher: "xchacha20poly1305".to_string(),
            nonce_b64: String::new(),
            ct_b64: String::new(),
        }
    }
}

fn default_kdf_params() -> KdfParams {
    KdfParams::default()
}

fn derive_key(pass: &str, salt: &[u8], kdf: &KdfParams) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_lanes, Some(32))
        .map_err(|_| anyhow!("invalid Argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| anyhow!("argon2 hash into"))?;
    Ok(out)
}

fn encrypt_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24])> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_ga: XNonce = nonce.into();
    let ct = cipher
        .encrypt(&nonce_ga, plaintext)
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok((ct, nonce))
}

fn decrypt_secret(key: &[u8; 32], nonce: &[u8; 24], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_ga: XNonce = (*nonce).into();
    let pt = cipher
        .decrypt(&nonce_ga, ct)
        .map_err(|_| anyhow!("decrypt failed"))?;
    Ok(pt)
}

fn save_keystore(ks: &Keystore, path: &Path) -> Result<()> {
    let data = toml::to_string_pretty(ks)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true).mode(0o600);
        let mut f = opts.open(path)?;
        use std::io::Write;
        f.write_all(data.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
        Ok(())
    }
}

fn load_keystore(path: &Path) -> Result<Keystore> {
    let data = fs::read_to_string(path)?;
    let ks: Keystore = toml::from_str(&data)?;
    Ok(ks)
}

fn derive_key_from_keystore(ks: &Keystore, pass: &str) -> Result<[u8; 32]> {
    let salt = general_purpose::STANDARD.decode(&ks.kdf.salt_b64)?;
    let mut salt16 = [0u8; 16];
    if salt.len() != 16 {
        return Err(anyhow!("salt length != 16"));
    }
    salt16.copy_from_slice(&salt);
    derive_key(pass, &salt16, &ks.kdf.params)
}

fn decrypt_keystore_secret(ks: &Keystore, key: &[u8; 32]) -> Result<Vec<u8>> {
    let nonce = general_purpose::STANDARD.decode(&ks.enc.nonce_b64)?;
    let ct = general_purpose::STANDARD.decode(&ks.enc.ct_b64)?;
    let mut nonce24 = [0u8; 24];
    if nonce.len() != 24 {
        return Err(anyhow!("nonce length != 24"));
    }
    nonce24.copy_from_slice(&nonce);
    let secret = decrypt_secret(key, &nonce24, &ct)?;
    if secret.len() != 32 {
        return Err(anyhow!("invalid secret length"));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer_rs_src() -> &'static str {
        include_str!("signer.rs")
    }

    #[test]
    fn f105_decrypted_secrets_are_wrapped_in_zeroizing() {
        let src = signer_rs_src();
        assert!(
            src.contains("let key = Zeroizing::new(derive_key_from_keystore"),
            "expected derived keystore key bytes to be wrapped in Zeroizing"
        );
        assert!(
            src.contains("let secret = Zeroizing::new(decrypt_keystore_secret"),
            "expected decrypted secret bytes to be wrapped in Zeroizing"
        );
        assert!(
            src.contains("let mut sec32 = Zeroizing::new([0u8; 32])"),
            "expected algorithm secret key material to be staged in Zeroizing<[u8;32]>"
        );
    }

    #[test]
    fn f106_import_secret_hex_field_is_marked_secret() {
        let state = SignerState::new();
        let import = state
            .forms
            .iter()
            .find(|f| f.id == CommandId::Import)
            .expect("Import form missing");
        let secret_field = import
            .fields
            .iter()
            .find(|f| f.label.starts_with("secret_hex"))
            .expect("secret_hex field missing");
        assert!(
            secret_field.secret,
            "expected secret_hex Import field to be masked (secret=true)"
        );
    }

    #[test]
    fn f107_secret_fields_are_masked_in_ui_rendering() {
        let src = signer_rs_src();
        assert!(
            src.contains("if field.secret") && src.contains("\"•\".repeat("),
            "expected secret fields to be rendered as bullets instead of cloning plaintext values"
        );
    }

    #[test]
    fn f108_signer_does_not_use_env_set_var() {
        let src = signer_rs_src();
        let needle = ["env", "::", "set_var"].concat();
        assert!(
            !src.contains(&needle),
            "process-wide environment mutation (set_var) is unsound in multi-threaded apps; it must not be used"
        );
    }

    #[test]
    fn f109_hwi_signmessage_does_not_leak_message_via_process_argv() {
        let src = signer_rs_src();
        let start = src
            .find("fn run_hwi_sign_message")
            .expect("run_hwi_sign_message missing");
        let end = src[start..]
            .find("fn run_hwi_sign_tx")
            .map(|rel| start + rel)
            .unwrap_or(src.len());
        let body = &src[start..end];
        assert!(
            body.contains("btc_sign_message"),
            "expected HWI sign-message to use BitBox API (btc_sign_message), not a CLI subprocess"
        );
        assert!(
            !body.contains("Command::new"),
            "expected no external process invocation in run_hwi_sign_message"
        );
    }
}
