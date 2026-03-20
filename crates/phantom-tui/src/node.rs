use crate::http_util;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use serde_json::Value;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const MAX_LOGS: usize = 200;
const DEFAULT_RPC_TIMEOUT_SECS: u64 = 10;
const DEFAULT_RPC_CONNECT_TIMEOUT_SECS: u64 = 5;
const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const ALLOWED_NODE_BINARIES: &[&str] = &["phantom-node", "phantom-signer", "phantom-miner"];

fn is_allowed_node_binary(bin: &str) -> bool {
    let name = Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin);
    ALLOWED_NODE_BINARIES.contains(&name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Commands,
    Fields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandId {
    Status,
    Start,
    Stop,
    ClearLogs,
}

#[derive(Debug, Clone)]
struct InputField {
    label: &'static str,
    value: String,
    secret: bool,
    expert_only: bool,
}

#[derive(Debug, Clone)]
struct CommandForm {
    id: CommandId,
    label: &'static str,
    fields: Vec<InputField>,
}

#[derive(Debug, Clone)]
struct NodeStatus {
    ok: bool,
    service: Option<String>,
    ts: Option<u64>,
    network_id: Option<String>,
    network_name: Option<String>,
    version: Option<u64>,
}

#[derive(Debug)]
enum NodeEvent {
    Log(String),
    StatusOk(NodeStatus),
    StatusErr(String),
}

pub struct NodeState {
    forms: Vec<CommandForm>,
    selected: usize,
    active_field: usize,
    focus: Focus,
    status: Option<NodeStatus>,
    logs: VecDeque<String>,
    child: Option<Child>,
    tx: mpsc::Sender<NodeEvent>,
    rx: mpsc::Receiver<NodeEvent>,
    insecure_skip_tls_verify: bool,
}

impl NodeState {
    #[allow(clippy::vec_init_then_push)]
    pub fn new(insecure_skip_tls_verify: bool) -> Self {
        let (tx, rx) = mpsc::channel();
        let mut forms = Vec::new();
        forms.push(CommandForm {
            id: CommandId::Status,
            label: "Status",
            fields: vec![
                InputField {
                    label: "node_url",
                    value: "https://127.0.0.1:8080".to_string(),
                    secret: false,
                    expert_only: false,
                },
                InputField {
                    label: "auth_token (optional)",
                    value: String::new(),
                    secret: true,
                    expert_only: true,
                },
                InputField {
                    label: "tls_ca (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
                InputField {
                    label: "tls_client_pem (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
            ],
        });
        forms.push(CommandForm {
            id: CommandId::Start,
            label: "Start Node",
            fields: vec![
                InputField {
                    label: "binary",
                    value: "phantom-node".to_string(),
                    secret: false,
                    // Hardening: avoid shipping a generic process launcher in release builds.
                    // In debug, expert mode can still override the binary path.
                    expert_only: true,
                },
                InputField {
                    label: "role (fullnode|validator|miner)",
                    value: "fullnode".to_string(),
                    secret: false,
                    expert_only: false,
                },
                InputField {
                    label: "addr",
                    // Safer default: local-only. Use 0.0.0.0:9000 + unsafe_confirm to accept inbound peers.
                    value: "127.0.0.1:9000".to_string(),
                    secret: false,
                    expert_only: false,
                },
                InputField {
                    label: "unsafe_confirm (true/false)",
                    // Required when binding to non-loopback addresses (e.g. 0.0.0.0) to avoid
                    // accidental public exposure.
                    value: "false".to_string(),
                    secret: false,
                    expert_only: false,
                },
                InputField {
                    label: "store_dir",
                    value: "pc-data".to_string(),
                    secret: false,
                    expert_only: false,
                },
                InputField {
                    label: "config (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
                InputField {
                    label: "genesis (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
                InputField {
                    label: "mint_amount (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
                InputField {
                    label: "mint_lock (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
                InputField {
                    label: "validator_id (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
                InputField {
                    label: "bls_pk (optional)",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
                InputField {
                    label: "extra_args",
                    value: String::new(),
                    secret: false,
                    expert_only: true,
                },
            ],
        });
        forms.push(CommandForm {
            id: CommandId::Stop,
            label: "Stop Node",
            fields: vec![],
        });
        forms.push(CommandForm {
            id: CommandId::ClearLogs,
            label: "Logs löschen",
            fields: vec![],
        });

        Self {
            forms,
            selected: 0,
            active_field: 0,
            focus: Focus::Commands,
            status: None,
            logs: VecDeque::new(),
            child: None,
            tx,
            rx,
            insecure_skip_tls_verify,
        }
    }

    pub fn tick(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                NodeEvent::Log(msg) => self.push_log(msg),
                NodeEvent::StatusOk(st) => {
                    self.status = Some(st);
                    self.push_log("[INFO] Status aktualisiert".to_string());
                }
                NodeEvent::StatusErr(err) => {
                    self.push_log(format!("[ERROR] Status fehlgeschlagen: {}", err));
                }
            }
        }

        let mut finished = None;
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => finished = Some(status),
                Ok(None) => {}
                Err(e) => {
                    self.push_log(format!("[ERROR] wait: {}", e));
                    finished = None;
                }
            }
        }
        if let Some(status) = finished {
            let code = status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string());
            self.push_log(format!("[PROC] beendet (code: {})", code));
            self.child = None;
        }
    }

    fn push_log(&mut self, msg: String) {
        self.logs.push_back(msg);
        while self.logs.len() > MAX_LOGS {
            self.logs.pop_front();
        }
    }
}

pub fn handle_key(state: &mut NodeState, key: KeyEvent, expert_mode: bool) -> bool {
    match key.code {
        KeyCode::Tab => {
            let has_fields =
                !visible_field_indices(&state.forms[state.selected], expert_mode).is_empty();
            state.focus = match state.focus {
                Focus::Commands => {
                    if has_fields {
                        Focus::Fields
                    } else {
                        Focus::Commands
                    }
                }
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
                    let field_len =
                        visible_field_indices(&state.forms[state.selected], expert_mode).len();
                    if field_len > 0 && state.active_field + 1 < field_len {
                        state.active_field += 1;
                    }
                }
            }
            true
        }
        KeyCode::Enter => {
            run_current(state, expert_mode);
            true
        }
        KeyCode::Char('x') => {
            stop_node(state);
            true
        }
        KeyCode::Char('c') => {
            state.logs.clear();
            true
        }
        KeyCode::Backspace => {
            if let Focus::Fields = state.focus {
                if let Some(field) = current_field_mut(state, expert_mode) {
                    field.value.pop();
                    return true;
                }
            }
            false
        }
        KeyCode::Delete => {
            if let Focus::Fields = state.focus {
                if let Some(field) = current_field_mut(state, expert_mode) {
                    field.value.clear();
                    return true;
                }
            }
            false
        }
        KeyCode::Char(c) => {
            if let Focus::Fields = state.focus {
                if let Some(field) = current_field_mut(state, expert_mode) {
                    field.value.push(c);
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

pub fn draw(f: &mut Frame, area: Rect, state: &NodeState, expert_mode: bool) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    let items: Vec<ListItem> = state
        .forms
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == state.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(Line::from(Span::styled(c.label, style)))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Node-Kommandos"),
    );
    f.render_widget(list, cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Min(7),
        ])
        .split(cols[1]);

    let running = state.child.is_some();
    let fields_title = if running {
        "Node (RUNNING)"
    } else {
        "Node (STOPPED)"
    };
    let fields_block = Block::default().borders(Borders::ALL).title(fields_title);
    let mut lines: Vec<Line> = Vec::new();
    let form = &state.forms[state.selected];
    let indices = visible_field_indices(form, expert_mode);
    if indices.is_empty() {
        lines.push(Line::from("Keine Eingabefelder."));
    } else {
        for (pos, idx) in indices.iter().enumerate() {
            let field = &form.fields[*idx];
            let mut v = field.value.clone();
            if field.secret {
                v = "*".repeat(v.chars().count());
            }
            let style = if matches!(state.focus, Focus::Fields) && pos == state.active_field {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", field.label),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(v, style),
            ]));
        }
    }
    let fields = Paragraph::new(lines)
        .block(fields_block)
        .wrap(Wrap { trim: true });
    f.render_widget(fields, right[0]);

    let status_lines = format_status_lines(state.status.as_ref(), state.child.is_some());
    let status = Paragraph::new(status_lines.join("\n"))
        .block(Block::default().borders(Borders::ALL).title("Status"))
        .wrap(Wrap { trim: true });
    f.render_widget(status, right[1]);

    let log_items: Vec<ListItem> = state
        .logs
        .iter()
        .rev()
        .take(20)
        .map(|log| {
            let style = if log.contains("[ERROR]") {
                Style::default().fg(Color::Red)
            } else if log.contains("[INFO]") || log.contains("[PROC]") {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(Line::from(Span::styled(log.clone(), style)))
        })
        .collect();
    let logs = List::new(log_items).block(Block::default().borders(Borders::ALL).title("Logs"));
    f.render_widget(logs, right[2]);
}

fn visible_field_indices(form: &CommandForm, expert_mode: bool) -> Vec<usize> {
    form.fields
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.expert_only || expert_mode)
        .map(|(i, _)| i)
        .collect()
}

fn current_field_mut(state: &mut NodeState, expert_mode: bool) -> Option<&mut InputField> {
    let form = &state.forms[state.selected];
    let indices = visible_field_indices(form, expert_mode);
    let idx = *indices.get(state.active_field)?;
    state.forms[state.selected].fields.get_mut(idx)
}

fn run_current(state: &mut NodeState, expert_mode: bool) {
    let form = &state.forms[state.selected];
    match form.id {
        CommandId::Status => run_status(state),
        CommandId::Start => start_node(state, expert_mode),
        CommandId::Stop => stop_node(state),
        CommandId::ClearLogs => state.logs.clear(),
    }
}

fn run_status(state: &mut NodeState) {
    let form = &state.forms[state.selected];
    let node_url = get_field(form, "node_url");
    let token = get_field(form, "auth_token (optional)");
    let tls_ca = get_field(form, "tls_ca (optional)");
    let tls_client_pem = get_field(form, "tls_client_pem (optional)");
    let auth = if token.is_empty() { None } else { Some(token) };
    let tls_ca_opt = if tls_ca.trim().is_empty() {
        None
    } else {
        Some(tls_ca.trim().to_string())
    };
    let tls_client_opt = if tls_client_pem.trim().is_empty() {
        None
    } else {
        Some(tls_client_pem.trim().to_string())
    };
    let url = if node_url.ends_with("/status") {
        node_url
    } else {
        format!("{}/status", node_url.trim_end_matches('/'))
    };
    let tx = state.tx.clone();
    let insecure_skip_tls_verify = state.insecure_skip_tls_verify;
    thread::spawn(move || {
        let tls_ca_path = tls_ca_opt.as_ref().map(Path::new);
        let tls_client_path = tls_client_opt.as_ref().map(Path::new);
        let res = fetch_status(
            &url,
            auth.as_deref(),
            tls_ca_path,
            tls_client_path,
            insecure_skip_tls_verify,
        );
        let _ = match res {
            Ok(st) => tx.send(NodeEvent::StatusOk(st)),
            Err(e) => tx.send(NodeEvent::StatusErr(e)),
        };
    });
}

fn fetch_status(
    url: &str,
    auth: Option<&str>,
    tls_ca: Option<&Path>,
    tls_client_pem: Option<&Path>,
    insecure_skip_tls_verify: bool,
) -> std::result::Result<NodeStatus, String> {
    let client = http_util::build_http_client_blocking(
        url,
        tls_ca,
        tls_client_pem,
        insecure_skip_tls_verify,
        Duration::from_secs(DEFAULT_RPC_TIMEOUT_SECS),
        Duration::from_secs(DEFAULT_RPC_CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| e.to_string())?;
    let parsed_url = http_util::parse_http_url(url).map_err(|e| e.to_string())?;
    http_util::ensure_bearer_transport_safe(&parsed_url, auth).map_err(|e| e.to_string())?;
    let mut req = client.get(parsed_url);
    if let Some(tok) = auth.map(str::trim).filter(|s| !s.is_empty()) {
        req = req.bearer_auth(tok);
    }
    let resp = req.send().map_err(|e| format!("request: {e}"))?;
    let status = resp.status();
    let body = http_util::read_response_text_limited_blocking(resp, MAX_HTTP_RESPONSE_BYTES)
        .map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status, body));
    }
    let v: Value = serde_json::from_str(&body).map_err(|e| format!("json: {e}"))?;
    let ok = v.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let service = v
        .get("service")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let ts = v.get("ts").and_then(Value::as_u64);
    let genesis = v.get("genesis");
    let network_id = genesis
        .and_then(|g| g.get("network_id"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let network_name = genesis
        .and_then(|g| g.get("network_name"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let version = genesis
        .and_then(|g| g.get("version"))
        .and_then(Value::as_u64);

    Ok(NodeStatus {
        ok,
        service,
        ts,
        network_id,
        network_name,
        version,
    })
}

fn start_node(state: &mut NodeState, expert_mode: bool) {
    if state.child.is_some() {
        state.push_log("[WARN] Node läuft bereits".to_string());
        return;
    }
    let form = &state.forms[state.selected];
    let binary = get_field(form, "binary");
    let binary: String = if cfg!(debug_assertions) {
        binary
    } else {
        // Release builds: fixed allowlist (phantom-node only).
        "phantom-node".to_string()
    };
    if binary.is_empty() {
        state.push_log("[ERROR] binary ist leer".to_string());
        return;
    }
    if !is_allowed_node_binary(&binary) {
        state.push_log(format!(
            "[ERROR] Binary '{}' ist nicht erlaubt (Allowlist: phantom-node, phantom-signer, phantom-miner).",
            binary
        ));
        return;
    }
    let role = get_field(form, "role (fullnode|validator|miner)");
    let addr = get_field(form, "addr");
    let unsafe_confirm = get_field(form, "unsafe_confirm (true/false)");
    let store_dir = get_field(form, "store_dir");
    let config = get_field(form, "config (optional)");
    let genesis = get_field(form, "genesis (optional)");
    let mint_amount = get_field(form, "mint_amount (optional)");
    let mint_lock = get_field(form, "mint_lock (optional)");
    let validator_id = get_field(form, "validator_id (optional)");
    let bls_pk = get_field(form, "bls_pk (optional)");
    let extra_args = get_field(form, "extra_args");

    let binary_path: PathBuf = if binary.contains('/') || binary.contains('\\') {
        PathBuf::from(binary)
    } else if let Some(p) = crate::binutil::find_program(&binary) {
        p
    } else if cfg!(debug_assertions) {
        // Debug convenience: allow PATH lookup (Command::new will resolve it).
        PathBuf::from(binary)
    } else {
        state.push_log(
            "[ERROR] phantom-node Binary nicht gefunden. Release-Build nutzt kein PATH-Fallback; bitte phantom-node neben die TUI legen oder aus dem Repo (target/release) starten."
                .to_string(),
        );
        return;
    };

    let mut cmd = Command::new(&binary_path);
    cmd.arg("run");
    if is_truthy(&unsafe_confirm) {
        cmd.arg("--unsafe-confirm");
    }
    if !role.is_empty() {
        cmd.arg("--role").arg(role);
    }
    if !addr.is_empty() {
        cmd.arg("--addr").arg(addr);
    }
    if !store_dir.is_empty() {
        cmd.arg("--store-dir").arg(store_dir);
    }
    if !config.is_empty() {
        cmd.arg("--config").arg(config);
    }
    if !genesis.is_empty() {
        cmd.arg("--genesis").arg(genesis);
    }
    if !mint_amount.is_empty() {
        cmd.arg("--mint-amount").arg(mint_amount);
    }
    if !mint_lock.is_empty() {
        cmd.arg("--mint-lock").arg(mint_lock);
    }
    if !validator_id.is_empty() {
        cmd.arg("--validator-id").arg(validator_id);
    }
    if !bls_pk.is_empty() {
        cmd.arg("--bls-pk").arg(bls_pk);
    }
    if expert_mode && !extra_args.trim().is_empty() {
        for part in extra_args.split_whitespace() {
            cmd.arg(part);
        }
    }

    let mut child = match cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            state.push_log(format!("[ERROR] Start fehlgeschlagen: {}", e));
            return;
        }
    };

    let pid = child.id();
    let tx = state.tx.clone();
    if let Some(out) = child.stdout.take() {
        spawn_reader(out, tx.clone(), "OUT");
    }
    if let Some(err) = child.stderr.take() {
        spawn_reader(err, tx.clone(), "ERR");
    }
    state.child = Some(child);
    state.push_log(format!("[INFO] Node gestartet (pid {})", pid));
}

fn stop_node(state: &mut NodeState) {
    let Some(mut child) = state.child.take() else {
        state.push_log("[WARN] Kein laufender Node".to_string());
        return;
    };
    let pid = child.id();
    match child.kill() {
        Ok(_) => state.push_log(format!("[INFO] Node gestoppt (pid {})", pid)),
        Err(e) => state.push_log(format!("[ERROR] Stop fehlgeschlagen: {}", e)),
    }
    let _ = child.wait();
}

fn spawn_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    tx: mpsc::Sender<NodeEvent>,
    prefix: &'static str,
) {
    thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            match line {
                Ok(l) => {
                    let _ = tx.send(NodeEvent::Log(format!("[{}] {}", prefix, l)));
                }
                Err(_) => break,
            }
        }
    });
}

fn format_status_lines(status: Option<&NodeStatus>, mint_prop_active: bool) -> Vec<String> {
    let Some(st) = status else {
        let mut lines = vec!["Kein Status (noch nicht abgefragt).".to_string()];
        lines.push(format!(
            "mint_propagation: {}",
            if mint_prop_active { "aktiv" } else { "inaktiv" }
        ));
        return lines;
    };
    let mut lines = Vec::new();
    lines.push(format!("ok: {}", st.ok));
    if let Some(svc) = st.service.as_ref() {
        lines.push(format!("service: {}", svc));
    }
    if let Some(ts) = st.ts {
        lines.push(format!("ts: {}", ts));
    }
    if let Some(nid) = st.network_id.as_ref() {
        lines.push(format!("network_id: {}", nid));
    }
    if let Some(name) = st.network_name.as_ref() {
        lines.push(format!("network_name: {}", name));
    }
    if let Some(ver) = st.version {
        lines.push(format!("genesis_version: {}", ver));
    }
    lines.push(format!(
        "mint_propagation: {}",
        if mint_prop_active { "aktiv" } else { "inaktiv" }
    ));
    if lines.is_empty() {
        lines.push("Status: (leer)".to_string());
    }
    lines
}

fn get_field(form: &CommandForm, label: &str) -> String {
    form.fields
        .iter()
        .find(|f| f.label == label)
        .map(|f| f.value.clone())
        .unwrap_or_default()
}

fn is_truthy(s: &str) -> bool {
    let s = s.trim();
    s == "1"
        || s.eq_ignore_ascii_case("true")
        || s.eq_ignore_ascii_case("yes")
        || s.eq_ignore_ascii_case("on")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f63_node_binary_allowlist_blocks_arbitrary_binaries() {
        assert!(!is_allowed_node_binary("rm"));
        assert!(!is_allowed_node_binary("/bin/rm"));
        assert!(is_allowed_node_binary("phantom-node"));
    }

    #[test]
    fn f70_node_rs_has_no_duplicate_loopback_helper_functions() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("node.rs");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let needle_local = ["fn", " ", "is_local_host"].concat();
        let needle_loop = ["fn", " ", "is_loopback_host"].concat();
        assert!(!src.contains(&needle_local));
        assert!(!src.contains(&needle_loop));
    }

    #[test]
    fn f110_auth_token_field_is_marked_secret_in_forms() {
        let st = NodeState::new(false);
        let form = st
            .forms
            .iter()
            .find(|f| matches!(f.id, CommandId::Status))
            .expect("status form");
        let field = form
            .fields
            .iter()
            .find(|f| f.label == "auth_token (optional)")
            .expect("auth_token field");
        assert!(
            field.secret,
            "auth_token input must be masked (secret=true)"
        );
    }

    #[test]
    fn f117_tui_util_functions_are_not_duplicated_across_modules() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let count = |needle: &str| -> usize {
            let mut n = 0usize;
            for e in std::fs::read_dir(&src_dir).expect("read_dir") {
                let p = e.expect("dirent").path();
                if p.extension().and_then(|s| s.to_str()) != Some("rs") {
                    continue;
                }
                let s = std::fs::read_to_string(&p).expect("read file");
                n += s.matches(needle).count();
            }
            n
        };
        let needle_is_local = ["fn", " ", "is_local_host"].concat();
        let needle_parse_http_url = ["fn", " ", "parse_http_url"].concat();
        let needle_ensure_bearer = ["fn", " ", "ensure_bearer_transport_safe"].concat();
        assert!(count(&needle_is_local) <= 1);
        assert!(count(&needle_parse_http_url) <= 1);
        assert!(count(&needle_ensure_bearer) <= 1);
    }
}
