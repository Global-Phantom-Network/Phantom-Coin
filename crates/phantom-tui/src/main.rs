// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
use ratatui::Terminal;

mod binutil;
mod http_util;
mod miner;
mod node;
mod signer;
mod tools;
mod wallet;

#[derive(Debug, Parser)]
#[command(name = "phantom-tui", version, about = "Unified Phantom TUI")]
struct Args {
    /// Tick interval in ms
    #[arg(long, default_value_t = 200)]
    tick_ms: u64,

    /// TLS (UNSAFE): Überspringt Server-Zertifikatsprüfung (nur Loopback). Nur für Debug/Tests.
    #[arg(long)]
    insecure_skip_tls_verify: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Home,
    Node,
    Wallet,
    Miner,
    Signer,
    Tools,
}

impl ActiveTab {
    fn index(self) -> usize {
        match self {
            ActiveTab::Home => 0,
            ActiveTab::Node => 1,
            ActiveTab::Wallet => 2,
            ActiveTab::Miner => 3,
            ActiveTab::Signer => 4,
            ActiveTab::Tools => 5,
        }
    }
}

struct App {
    tab: ActiveTab,
    show_help: bool,
    expert_mode: bool,
    last_tick: Instant,
    miner: miner::MinerUi,
    node: node::NodeState,
    signer: signer::SignerState,
    tools: tools::ToolsState,
    wallet: wallet::WalletState,
}

impl App {
    fn new(insecure_skip_tls_verify: bool) -> Result<Self> {
        Ok(Self {
            tab: ActiveTab::Home,
            show_help: true,
            expert_mode: false,
            last_tick: Instant::now(),
            miner: miner::MinerUi::new(insecure_skip_tls_verify)?,
            node: node::NodeState::new(insecure_skip_tls_verify),
            signer: signer::SignerState::new(),
            tools: tools::ToolsState::new(),
            wallet: wallet::WalletState::new(phantom_i18n::Lang::De),
        })
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(args.insecure_skip_tls_verify)?;
    let tick_rate = Duration::from_millis(args.tick_ms);

    let result = run_app(&mut terminal, &mut app, tick_rate);

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_rate: Duration,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        let timeout = tick_rate.saturating_sub(app.last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if matches!(key.code, KeyCode::Char('q')) {
                        return Ok(());
                    }
                    if app.tab == ActiveTab::Miner && app.miner.handle_key(key) {
                        continue;
                    }
                    if app.tab == ActiveTab::Node
                        && node::handle_key(&mut app.node, key, app.expert_mode)
                    {
                        continue;
                    }
                    if app.tab == ActiveTab::Wallet && wallet::handle_key(&mut app.wallet, key) {
                        continue;
                    }
                    if app.tab == ActiveTab::Signer && signer::handle_key(&mut app.signer, key) {
                        continue;
                    }
                    if app.tab == ActiveTab::Tools
                        && tools::handle_key(&mut app.tools, key, app.expert_mode)
                    {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('?') | KeyCode::Char('h') => {
                            app.show_help = !app.show_help;
                        }
                        KeyCode::Char('e') => {
                            // Expert mode enables powerful process spawning/editing in some tabs.
                            // Keep it debug-only to avoid surprising behavior in release builds.
                            if cfg!(debug_assertions) {
                                app.expert_mode = !app.expert_mode;
                            }
                        }
                        KeyCode::Char('1') => app.tab = ActiveTab::Home,
                        KeyCode::Char('2') => app.tab = ActiveTab::Node,
                        KeyCode::Char('3') => app.tab = ActiveTab::Wallet,
                        KeyCode::Char('4') => app.tab = ActiveTab::Miner,
                        KeyCode::Char('5') => app.tab = ActiveTab::Signer,
                        KeyCode::Char('6') => app.tab = ActiveTab::Tools,
                        KeyCode::Esc => app.tab = ActiveTab::Home,
                        _ => {}
                    }
                }
            }
        }
        if app.last_tick.elapsed() >= tick_rate {
            app.last_tick = Instant::now();
            app.miner.tick();
            app.node.tick();
            wallet::tick(&mut app.wallet);
            app.tools.tick();
        }
    }
}

fn ui(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(f.area());

    let titles = [
        Line::from("1 Home"),
        Line::from("2 Node"),
        Line::from("3 Wallet"),
        Line::from("4 Miner"),
        Line::from("5 Signer"),
        Line::from("6 Tools"),
    ];
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .block(Block::default().borders(Borders::ALL).title("Phantom TUI"))
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    match app.tab {
        ActiveTab::Home => f.render_widget(home_view(app), chunks[1]),
        ActiveTab::Node => node::draw(f, chunks[1], &app.node, app.expert_mode),
        ActiveTab::Wallet => wallet::draw(f, chunks[1], &app.wallet),
        ActiveTab::Miner => app.miner.draw(f, chunks[1]),
        ActiveTab::Signer => signer::draw(f, chunks[1], &app.signer, app.expert_mode),
        ActiveTab::Tools => tools::draw(f, chunks[1], &app.tools, app.expert_mode),
    }

    let status = Paragraph::new(Line::from(vec![
        Span::raw("Tasten: "),
        Span::styled("1-6", Style::default().fg(Color::Cyan)),
        Span::raw(" Tab · "),
        Span::styled("e", Style::default().fg(Color::Cyan)),
        Span::raw(" Expertenmodus · "),
        Span::styled("h/?", Style::default().fg(Color::Cyan)),
        Span::raw(" Hilfe · "),
        Span::styled("q", Style::default().fg(Color::Cyan)),
        Span::raw(" Beenden"),
    ]))
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Center);
    f.render_widget(status, chunks[2]);

    if app.show_help {
        let help = help_overlay(app);
        let area = centered_rect(70, 60, f.area());
        f.render_widget(help, area);
    }
}

fn home_view(app: &App) -> Paragraph<'static> {
    let mut lines = vec![
        Line::from("Willkommen im Phantom TUI (Unified)"),
        Line::from(""),
        Line::from("Ziel: Eine Oberfläche für Node, Wallet, Miner, Signer und Tools."),
        Line::from("Die eigentlichen Module werden nativ integriert."),
        Line::from(""),
        Line::from("Wähle einen Tab (1-6)."),
    ];
    if app.expert_mode {
        lines.push(Line::from("Expertenmodus: aktiv"));
    } else {
        lines.push(Line::from("Expertenmodus: aus"));
    }
    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Home"))
        .wrap(Wrap { trim: true })
}

fn help_overlay(app: &App) -> Paragraph<'static> {
    let mut lines = vec![
        Line::from("Hilfe / Bedienung"),
        Line::from(""),
        Line::from("1-6  Tabs wechseln"),
        Line::from("e    Expertenmodus an/aus"),
        Line::from("h/? Hilfe an/aus"),
        Line::from("Esc  Zurück zu Home"),
        Line::from("q    Beenden"),
        Line::from(""),
        Line::from("Tab-spezifische Tasten:"),
        Line::from("  Miner: [SPACE] Pause/Resume"),
        Line::from("  Node/Tools: Tab Feld/Liste, Enter Ausführen"),
        Line::from("  Node/Tools: x Stop, c Logs löschen"),
        Line::from(""),
        Line::from("Hinweis: Module werden nativ integriert."),
    ];
    if app.expert_mode {
        lines.push(Line::from("Expertenmodus ist aktiv."));
    }
    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Hilfe"))
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Left)
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    let vertical = popup_layout[1];
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical);
    horizontal[1]
}
