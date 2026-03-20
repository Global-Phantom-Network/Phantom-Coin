use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;

const MAX_LOGS: usize = 200;
const ALLOWED_TOOL_BINS: &[&str] = &[
    "genesis_bootstrap",
    "phantom-mint-rpc",
    "phantom-node-status",
    "phantom-node",
    "mine_mint",
    "gen_headers",
    "gen_payloads",
    "phantom-signer",
    "phantom-miner",
];

fn is_allowed_tool_program(prog: &str) -> bool {
    let name = Path::new(prog)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(prog);
    ALLOWED_TOOL_BINS.contains(&name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    List,
    Input,
}

#[derive(Debug, Clone)]
struct ToolTemplate {
    label: &'static str,
    command: String,
    help: Vec<&'static str>,
}

#[derive(Debug)]
enum ToolEvent {
    Log(String),
}

pub struct ToolsState {
    tools: Vec<ToolTemplate>,
    selected: usize,
    focus: Focus,
    input: String,
    logs: VecDeque<String>,
    child: Option<Child>,
    tx: mpsc::Sender<ToolEvent>,
    rx: mpsc::Receiver<ToolEvent>,
}

impl ToolsState {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let tools = vec![
            ToolTemplate {
                label: "genesis_bootstrap",
                command: "genesis_bootstrap --mempool-dir /tmp/phantom-coin/data/mempool --network-name localnet"
                    .to_string(),
                help: vec!["Erzeugt genesis_note.bin (inkl. optional role_policy)."],
            },
            ToolTemplate {
                label: "phantom-mint-rpc",
                command: "phantom-mint-rpc --addr 127.0.0.1:9090 --store-dir /tmp/phantom-coin/data --no-tls"
                    .to_string(),
                help: vec![
                    "Startet Mint-RPC (Template/Submit/Status).",
                    "Hinweis: --store-dir muss zum Node passen, sonst keine Mint-Propagation.",
                ],
            },
            ToolTemplate {
                label: "phantom-node-status",
                command: "phantom-node-status --addr 127.0.0.1:8443 --store-dir /tmp/phantom-coin/data".to_string(),
                help: vec!["Status-HTTP (TLS) für Wallet/Monitoring."],
            },
            ToolTemplate {
                label: "p2p-quic-listen (metrics)",
                command: "phantom-node p2p-quic-listen --addr 127.0.0.1:9001 --metrics-addr 127.0.0.1:9101 --store-dir /tmp/phantom-coin/data".to_string(),
                help: vec!["QUIC Listener + Prometheus /metrics (in-process)."],
            },
            ToolTemplate {
                label: "mine_mint",
                command: "mine_mint --pow-seed 0000000000000000000000000000000000000000000000000000000000000000 --bits 16".to_string(),
                help: vec!["Test-Mining für Pow-Seed."],
            },
            ToolTemplate {
                label: "gen_headers",
                command: "gen_headers --out ./test_headers.bin --count 5".to_string(),
                help: vec!["Generiert AnchorHeader Testdaten."],
            },
            ToolTemplate {
                label: "gen_payloads",
                command: "gen_payloads --out ./test_payloads.bin --count 3".to_string(),
                help: vec!["Generiert AnchorPayload Testdaten."],
            },
            ToolTemplate {
                label: "phantom-signer (CLI)",
                command: "phantom-signer --help".to_string(),
                help: vec!["CLI-Runner für alle phantom-signer Befehle."],
            },
            ToolTemplate {
                label: "phantom-miner (CLI)",
                command: "phantom-miner --help".to_string(),
                help: vec!["CLI-Runner für phantom-miner Befehle."],
            },
            ToolTemplate {
                label: "phantom-node (CLI)",
                command: "phantom-node --help".to_string(),
                help: vec!["CLI-Runner für phantom-node Befehle."],
            },
        ];
        let input = tools.first().map(|t| t.command.clone()).unwrap_or_default();

        Self {
            tools,
            selected: 0,
            focus: Focus::List,
            input,
            logs: VecDeque::new(),
            child: None,
            tx,
            rx,
        }
    }

    pub fn tick(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                ToolEvent::Log(msg) => self.push_log(msg),
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

pub fn handle_key(state: &mut ToolsState, key: KeyEvent, _expert_mode: bool) -> bool {
    // Expert mode allows arbitrary command editing/spawning; keep it debug-only.
    let expert_mode = _expert_mode && cfg!(debug_assertions);
    match key.code {
        KeyCode::Tab => {
            state.focus = match state.focus {
                Focus::List => Focus::Input,
                Focus::Input => Focus::List,
            };
            true
        }
        KeyCode::Up => {
            if matches!(state.focus, Focus::List) && state.selected > 0 {
                state.selected -= 1;
                state.input = state.tools[state.selected].command.clone();
            }
            true
        }
        KeyCode::Down => {
            if matches!(state.focus, Focus::List) && state.selected + 1 < state.tools.len() {
                state.selected += 1;
                state.input = state.tools[state.selected].command.clone();
            }
            true
        }
        KeyCode::Enter => {
            if matches!(state.focus, Focus::Input) {
                run_command(state, expert_mode);
                return true;
            }
            false
        }
        KeyCode::Char('x') => {
            stop_command(state);
            true
        }
        KeyCode::Char('c') => {
            state.logs.clear();
            true
        }
        KeyCode::Backspace => {
            if matches!(state.focus, Focus::Input) && expert_mode {
                state.input.pop();
                return true;
            }
            false
        }
        KeyCode::Delete => {
            if matches!(state.focus, Focus::Input) && expert_mode {
                state.input.clear();
                return true;
            }
            false
        }
        KeyCode::Char(c) => {
            if matches!(state.focus, Focus::Input) && expert_mode {
                state.input.push(c);
                return true;
            }
            false
        }
        _ => false,
    }
}

pub fn draw(f: &mut Frame, area: Rect, state: &ToolsState, expert_mode: bool) {
    // Expert mode is debug-only (allows arbitrary command editing/spawning).
    let expert_mode = expert_mode && cfg!(debug_assertions);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    let items: Vec<ListItem> = state
        .tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let style = if i == state.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(Line::from(Span::styled(t.label, style)))
        })
        .collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Tools"));
    f.render_widget(list, cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Min(8),
        ])
        .split(cols[1]);

    let help_lines = state.tools[state.selected]
        .help
        .iter()
        .map(|l| Line::from(*l))
        .collect::<Vec<_>>();
    let help = Paragraph::new(help_lines)
        .block(Block::default().borders(Borders::ALL).title("Info"))
        .wrap(Wrap { trim: true });
    f.render_widget(help, right[0]);

    let running = state.child.is_some();
    let input_title = match (running, expert_mode) {
        (true, true) => "Command (RUNNING, Experte)",
        (true, false) => "Command (RUNNING)",
        (false, true) => "Command (Experte)",
        (false, false) => "Command",
    };
    let input_style = if matches!(state.focus, Focus::Input) {
        Style::default().fg(Color::Yellow)
    } else if !expert_mode {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };
    let input = Paragraph::new(Line::from(Span::styled(state.input.clone(), input_style)))
        .block(Block::default().borders(Borders::ALL).title(input_title))
        .wrap(Wrap { trim: true });
    f.render_widget(input, right[1]);

    let log_items: Vec<ListItem> = state
        .logs
        .iter()
        .rev()
        .take(30)
        .map(|log| {
            let style = if log.contains("[ERROR]") {
                Style::default().fg(Color::Red)
            } else if log.contains("[PROC]") {
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

fn run_command(state: &mut ToolsState, expert_mode: bool) {
    // Expert mode is debug-only (allows arbitrary command editing/spawning).
    let expert_mode = expert_mode && cfg!(debug_assertions);
    if state.child.is_some() {
        state.push_log("[WARN] Tool läuft bereits".to_string());
        return;
    }
    let cmdline = if expert_mode {
        state.input.clone()
    } else {
        state
            .tools
            .get(state.selected)
            .map(|t| t.command.clone())
            .unwrap_or_default()
    };
    let parts: Vec<String> = cmdline.split_whitespace().map(|s| s.to_string()).collect();
    if parts.is_empty() {
        state.push_log("[ERROR] command ist leer".to_string());
        return;
    }
    let prog = &parts[0];
    if !is_allowed_tool_program(prog) {
        state.push_log(format!(
            "[ERROR] Programm '{}' ist nicht erlaubt (Allowlist).",
            prog
        ));
        return;
    }
    let prog_path: PathBuf = if prog.contains('/') || prog.contains('\\') {
        PathBuf::from(prog)
    } else if let Some(p) = crate::binutil::find_program(prog) {
        p
    } else if cfg!(debug_assertions) {
        // Debug convenience: allow PATH lookup (Command::new will resolve it).
        PathBuf::from(prog)
    } else {
        state.push_log(format!(
            "[ERROR] Programm '{}' nicht gefunden. Release-Build nutzt kein PATH-Fallback; bitte Binary neben die TUI legen oder absoluten Pfad verwenden.",
            prog
        ));
        return;
    };
    let mut cmd = Command::new(&prog_path);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
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
    state.push_log(format!("[INFO] Tool gestartet (pid {})", pid));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f62_tools_command_allowlist_blocks_arbitrary_programs() {
        assert!(!is_allowed_tool_program("rm"));
        assert!(!is_allowed_tool_program("/bin/rm"));
        assert!(is_allowed_tool_program("phantom-node"));
    }
}

fn stop_command(state: &mut ToolsState) {
    let Some(mut child) = state.child.take() else {
        state.push_log("[WARN] Kein laufender Tool-Prozess".to_string());
        return;
    };
    let pid = child.id();
    match child.kill() {
        Ok(_) => state.push_log(format!("[INFO] Tool gestoppt (pid {})", pid)),
        Err(e) => state.push_log(format!("[ERROR] Stop fehlgeschlagen: {}", e)),
    }
    let _ = child.wait();
}

fn spawn_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    tx: mpsc::Sender<ToolEvent>,
    prefix: &'static str,
) {
    thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            match line {
                Ok(l) => {
                    let _ = tx.send(ToolEvent::Log(format!("[{}] {}", prefix, l)));
                }
                Err(_) => break,
            }
        }
    });
}
