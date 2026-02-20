//! Aegis TUI - Interactive Terminal Dashboard
//!
//! Features:
//! - Real-time connection monitoring with geo-location
//! - Live statistics from eBPF STATS map
//! - Module toggle hotkeys (1-6, 0=all)
//! - IP blocking/unblocking via SPACE
//! - Tab switching between views

#![allow(dead_code)]

use std::{
    io,
    time::{Duration, Instant},
    sync::{Arc, Mutex},
    collections::{VecDeque, HashMap},
    net::{IpAddr, Ipv4Addr},
    thread,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap, Sparkline},
    Terminal,
    Frame,
};
use sysinfo::System;
use aya::maps::{HashMap as BpfHashMap, MapData};
use aegis_common::{FlowKey, Stats};
use crate::geo::SharedGeoLookup;

// ============================================================
// TAB ENUM
// ============================================================

#[derive(Clone, Copy, PartialEq)]
pub enum Tab {
    Connections,
    Stats,
    Logs,
}

impl Tab {
    fn next(self) -> Self {
        match self {
            Tab::Connections => Tab::Stats,
            Tab::Stats => Tab::Logs,
            Tab::Logs => Tab::Connections,
        }
    }

    fn prev(self) -> Self {
        match self {
            Tab::Connections => Tab::Logs,
            Tab::Stats => Tab::Connections,
            Tab::Logs => Tab::Stats,
        }
    }
}

// ============================================================
// APP STATE
// ============================================================

pub struct App<T: std::borrow::BorrowMut<MapData> + 'static> {
    pub connections: Vec<ConnectionInfo>,
    pub logs: VecDeque<String>,
    pub state: ListState,
    pub system: System,
    pub should_quit: bool,
    pub geo_db: SharedGeoLookup,
    pub blocklist: Arc<Mutex<BpfHashMap<T, FlowKey, u32>>>,
    pub current_tab: Tab,
    // Stats history for sparklines
    pub pkt_history: VecDeque<u64>,
    pub drop_history: VecDeque<u64>,
    pub last_stats: Stats,
}

#[derive(Clone)]
pub struct ConnectionInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub proto: String,
    pub process: String,
    pub status: String,
    pub geo: String,
    pub isp: String,
    pub is_blocked: bool,
}

impl<T: std::borrow::BorrowMut<MapData> + 'static> App<T> {
    pub fn new(blocklist: Arc<Mutex<BpfHashMap<T, FlowKey, u32>>>, geo_db: SharedGeoLookup) -> Self {
        let system = System::new_all();
        Self {
            connections: Vec::new(),
            logs: VecDeque::with_capacity(100),
            state: ListState::default(),
            system,
            should_quit: false,
            geo_db,
            blocklist,
            current_tab: Tab::Connections,
            pkt_history: VecDeque::with_capacity(200),
            drop_history: VecDeque::with_capacity(200),
            last_stats: Stats::default(),
        }
    }

    pub fn on_tick(&mut self) {
        let raw_conns = read_proc_net_tcp();
        let mut enriched_conns = Vec::new();
        // cache variable removed as it was referring to non-existent field

        for conn in raw_conns {
            let ip = conn.ip;
            let geo;

            // Check if IP is private/internal
            let is_private = match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    octets[0] == 10 ||
                    (octets[0] == 172 && (octets[1] & 0xF0) == 16) ||
                    (octets[0] == 192 && octets[1] == 168) ||
                    (octets[0] == 100 && (octets[1] & 0xC0) == 64) ||
                    octets[0] == 127
                }
                IpAddr::V6(ipv6) => ipv6.is_loopback(),
            };

            if is_private {
                geo = match ip {
                    IpAddr::V4(ipv4) => {
                        let octets = ipv4.octets();
                        if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                            "VPN/CGNAT".to_string()
                        } else if octets[0] == 127 {
                            "Localhost".to_string()
                        } else {
                            "LAN".to_string()
                        }
                    }
                    _ => "Private".to_string(),
                };
            } else {
                // Geo lookup for public IPs — offline database
                if let Some(ref db) = self.geo_db {
                    match db.lookup(ip) {
                        Some(result) => {
                            let geo_str = if result.city.is_empty() {
                                result.country_code
                            } else {
                                format!("{} {}", result.country_code, result.city)
                            };
                            let intel = if !result.isp.is_empty() {
                                result.isp
                            } else {
                                String::new()
                            };
                            if intel.is_empty() {
                                geo = geo_str;
                            } else {
                                geo = format!("{}|{}", geo_str, intel);
                            }
                        }
                        None => {
                             geo = "Unknown".to_string();
                        }
                    }
                } else {
                    geo = "No GeoDB".to_string();
                }
            }

            // Check block status
            let is_blocked = if let IpAddr::V4(ipv4) = ip {
                let key = FlowKey {
                    src_ip: u32::from(ipv4).to_be(),
                    dst_port: 0,
                    proto: 0,
                    _pad: 0,
                };
                let map = self.blocklist.lock().unwrap();
                map.get(&key, 0).is_ok()
            } else {
                false
            };

            // Parse geo|isp from cache value
            let (geo_display, isp_display) = if geo.contains('|') {
                let mut parts = geo.splitn(2, '|');
                let g = parts.next().unwrap_or("").to_string();
                let i = parts.next().unwrap_or("").to_string();
                (g, i)
            } else if geo.is_empty() {
                ("Retry...".to_string(), String::new())
            } else {
                (geo, String::new())
            };

            enriched_conns.push(ConnectionInfo {
                ip: conn.ip,
                port: conn.port,
                proto: conn.proto,
                process: conn.process,
                status: conn.status,
                geo: geo_display,
                isp: isp_display,
                is_blocked,
            });
        }
        self.connections = enriched_conns;
    }

    pub fn next(&mut self) {
        let len = self.connections.len();
        if len == 0 { return; }
        let i = match self.state.selected() {
            Some(i) => if i >= len - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let len = self.connections.len();
        if len == 0 { return; }
        let i = match self.state.selected() {
            Some(i) => if i == 0 { len - 1 } else { i - 1 },
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn toggle_block(&mut self) {
        if let Some(i) = self.state.selected() {
            if let Some(conn) = self.connections.get(i) {
                if let IpAddr::V4(ipv4) = conn.ip {
                    let mut map = self.blocklist.lock().unwrap();
                    let key = FlowKey {
                        src_ip: u32::from(ipv4).to_be(),
                        dst_port: 0,
                        proto: 0,
                        _pad: 0,
                    };

                    if conn.is_blocked {
                        match map.remove(&key) {
                            Ok(_) => self.logs.push_back(format!("UNBLOCKED {}", ipv4)),
                            Err(e) => self.logs.push_back(format!("ERR unblock {}: {}", ipv4, e)),
                        }
                    } else {
                        match map.insert(key, 2, 0) {
                            Ok(_) => self.logs.push_back(format!("BLOCKED {}", ipv4)),
                            Err(e) => self.logs.push_back(format!("ERR block {}: {}", ipv4, e)),
                        }
                    }
                }
            }
        }
    }

    pub fn update_stats(&mut self, stats: &Stats) {
        // Calculate deltas for sparkline
        let delta_pkts = stats.pkts_seen.saturating_sub(self.last_stats.pkts_seen);
        let delta_drops = stats.pkts_drop.saturating_sub(self.last_stats.pkts_drop);

        self.pkt_history.push_back(delta_pkts);
        self.drop_history.push_back(delta_drops);

        // Keep only last 200 samples (wide terminals)
        while self.pkt_history.len() > 200 {
            self.pkt_history.pop_front();
        }
        while self.drop_history.len() > 200 {
            self.drop_history.pop_front();
        }

        self.last_stats = stats.clone();
    }
}

// ============================================================
// RAW CONNECTION READER
// ============================================================

struct RawConnection {
    ip: IpAddr,
    port: u16,
    proto: String,
    process: String,
    status: String,
}

fn read_proc_net_tcp() -> Vec<RawConnection> {
    use std::fs::read_to_string;
    let mut conns = Vec::new();

    for file in ["/proc/net/tcp", "/proc/net/udp"] {
        if let Ok(content) = read_to_string(file) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 { continue; }

                let remote_parts: Vec<&str> = parts[2].split(':').collect();
                if remote_parts.len() != 2 { continue; }

                let remote_ip_hex = remote_parts[0];
                let remote_port_hex = remote_parts[1];

                if let (Ok(ip_u32), Ok(port)) = (
                    u32::from_str_radix(remote_ip_hex, 16),
                    u16::from_str_radix(remote_port_hex, 16)
                ) {
                    let ip = Ipv4Addr::from(u32::from_be(ip_u32));
                    if ip.is_loopback() || ip.is_unspecified() { continue; }

                    let proto = if file.contains("tcp") { "TCP" } else { "UDP" };
                    conns.push(RawConnection {
                        ip: IpAddr::V4(ip),
                        port,
                        proto: proto.to_string(),
                        process: String::new(),
                        status: parts.get(3).unwrap_or(&"").to_string(),
                    });
                }
            }
        }
    }
    conns
}

// ============================================================
// MAIN TUI LOOP
// ============================================================

pub async fn run_tui<T, C, S>(
    blocklist: Arc<Mutex<BpfHashMap<T, FlowKey, u32>>>,
    logs: Arc<Mutex<VecDeque<String>>>,
    config: Arc<Mutex<aya::maps::HashMap<C, u32, u32>>>,
    stats: Arc<Mutex<aya::maps::PerCpuArray<S, Stats>>>,
    geo_db: SharedGeoLookup,
) -> Result<(), anyhow::Error>
where
    T: std::borrow::BorrowMut<MapData> + 'static,
    C: std::borrow::BorrowMut<MapData> + 'static,
    S: std::borrow::BorrowMut<MapData> + 'static,
{
    use std::os::unix::io::{AsRawFd, FromRawFd};

    // ── FD-LEVEL STDOUT ISOLATION ──────────────────────────────
    // Save real TTY fd, then redirect stdout+stderr to /dev/null.
    // Ratatui gets the ONLY handle to the real terminal.
    // All println!/eprintln!/log::* from any thread → /dev/null.
    let saved_stdout = unsafe { libc::dup(1) };
    let saved_stderr = unsafe { libc::dup(2) };

    let devnull = std::fs::OpenOptions::new()
        .read(true).write(true)
        .open("/dev/null")?;
    unsafe {
        libc::dup2(devnull.as_raw_fd(), 1); // stdout → /dev/null
        libc::dup2(devnull.as_raw_fd(), 2); // stderr → /dev/null
    }
    drop(devnull); // fd is cloned, original can close

    // Create a File from the saved real TTY fd — ratatui's exclusive handle
    let tty_write = unsafe { std::fs::File::from_raw_fd(saved_stdout) };

    enable_raw_mode()?;
    // Use the private TTY fd for crossterm, NOT io::stdout()
    let mut tty_for_setup = unsafe { std::fs::File::from_raw_fd(libc::dup(tty_write.as_raw_fd())) };
    execute!(tty_for_setup, EnterAlternateScreen)?;
    drop(tty_for_setup);

    let backend = CrosstermBackend::new(tty_write);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new(blocklist, geo_db);
    let tick_rate = Duration::from_millis(1000);
    let mut last_tick = Instant::now();

    loop {
        // Sync logs from shared deque
        {
            let shared = logs.lock().unwrap();
            app.logs = shared.clone();
        }

        // Read and aggregate per-CPU stats
        {
            if let Ok(stats_map) = stats.lock() {
                if let Ok(per_cpu) = stats_map.get(&0, 0) {
                    let mut total = Stats::default();
                    for cpu_stats in per_cpu.iter() {
                        total.pkts_seen += cpu_stats.pkts_seen;
                        total.pkts_pass += cpu_stats.pkts_pass;
                        total.pkts_drop += cpu_stats.pkts_drop;
                        total.events_ok += cpu_stats.events_ok;
                        total.events_fail += cpu_stats.events_fail;
                        total.block_manual += cpu_stats.block_manual;
                        total.block_cidr += cpu_stats.block_cidr;
                        total.portscan_hits += cpu_stats.portscan_hits;
                        total.conntrack_hits += cpu_stats.conntrack_hits;
                    }
                    app.update_stats(&total);
                }
            }
        }

        terminal.draw(|f| ui(f, &mut app, &config))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO);

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => app.should_quit = true,
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Up | KeyCode::Char('k') => app.previous(),
                        KeyCode::Char(' ') => app.toggle_block(),
                        KeyCode::Tab => app.current_tab = app.current_tab.next(),
                        KeyCode::BackTab => app.current_tab = app.current_tab.prev(),
                        KeyCode::Char(c @ '0'..='6') => {
                            handle_module_toggle(c, &config, &mut app.logs);
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    // ── CLEANUP: restore fds, leave alternate screen ───────────
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    // Restore stdout and stderr so post-TUI println! works
    unsafe {
        // terminal drop will close saved_stdout fd, so restore before that
        libc::dup2(saved_stderr, 2);
        libc::close(saved_stderr);
    }

    // Drop terminal explicitly to release the tty_write fd
    drop(terminal);

    // Restore stdout from /dev/null back to real TTY
    unsafe {
        // saved_stdout was consumed by from_raw_fd → tty_write → terminal
        // We need a fresh dup of the TTY. Since we just did LeaveAlternateScreen
        // through the backend, the TTY state is clean. Reopen /dev/tty.
        if let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
            libc::dup2(tty.as_raw_fd(), 1);
        }
    }

    Ok(())
}

// ============================================================
// MODULE TOGGLE HANDLER
// ============================================================

fn handle_module_toggle<C: std::borrow::BorrowMut<MapData>>(
    key: char,
    config: &Arc<Mutex<aya::maps::HashMap<C, u32, u32>>>,
    logs: &mut VecDeque<String>,
) {
    let module_names = ["ALL", "PortScan", "RateLimit", "Threats", "ConnTrack", "ScanDetect", "Verbose"];

    if let Ok(mut cfg) = config.lock() {
        if key == '0' {
            // Toggle all
            let any_on = (1u32..=5u32).any(|k| cfg.get(&k, 0).unwrap_or(1) == 1);
            let new_val = if any_on { 0u32 } else { 1u32 };
            for k in 1u32..=5u32 {
                let _ = cfg.insert(k, new_val, 0);
            }
            let state = if new_val == 1 { "ON" } else { "OFF" };
            logs.push_back(format!("ALL MODULES: {}", state));
        } else if let Some(digit) = key.to_digit(10) {
            let k = digit as u32;
            let default = if k == 6 { 0 } else { 1 }; // Verbose defaults OFF
            let cur = cfg.get(&k, 0).unwrap_or(default);
            let new_val = if cur == 1 { 0u32 } else { 1u32 };
            let _ = cfg.insert(k, new_val, 0);
            let name = module_names.get(k as usize).unwrap_or(&"?");
            let state = if new_val == 1 { "ON" } else { "OFF" };
            logs.push_back(format!("{}: {}", name, state));
        }
    }
}

// ============================================================
// UI RENDER
// ============================================================

fn ui<T, C>(
    f: &mut Frame,
    app: &mut App<T>,
    config: &Arc<Mutex<aya::maps::HashMap<C, u32, u32>>>,
)
where
    T: std::borrow::BorrowMut<MapData> + 'static,
    C: std::borrow::BorrowMut<MapData> + 'static,
{
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header with stats
            Constraint::Length(1),  // Tab bar
            Constraint::Min(10),    // Main content
            Constraint::Length(3),  // Footer/help
        ])
        .split(f.size());

    // --- HEADER WITH LIVE STATS ---
    let stats = &app.last_stats;
    let drop_rate = if stats.pkts_seen > 0 {
        (stats.pkts_drop as f64 / stats.pkts_seen as f64 * 100.0) as u16
    } else {
        0
    };

    let header_text = format!(
        " Pkts: {} | Pass: {} | Drop: {} ({:.1}%) | ConnTrack: {} | PortScan: {} | Blocks: M:{} C:{}",
        format_num(stats.pkts_seen),
        format_num(stats.pkts_pass),
        format_num(stats.pkts_drop),
        drop_rate,
        format_num(stats.conntrack_hits),
        format_num(stats.portscan_hits),
        stats.block_manual,
        stats.block_cidr,
    );

    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::White).bg(Color::Rgb(30, 30, 50)))
        .block(Block::default().borders(Borders::ALL).title(" AEGIS FIREWALL "));
    f.render_widget(header, chunks[0]);

    // --- TAB BAR ---
    let tab_titles = vec![
        ("Connections", Tab::Connections),
        ("Stats", Tab::Stats),
        ("Logs", Tab::Logs),
    ];
    let tab_spans: Vec<Span> = tab_titles.iter().map(|(name, tab)| {
        let style = if *tab == app.current_tab {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        Span::styled(format!(" [{}] ", name), style)
    }).collect();
    let tabs = Paragraph::new(Line::from(tab_spans))
        .style(Style::default().bg(Color::Rgb(20, 20, 30)));
    f.render_widget(tabs, chunks[1]);

    // --- MAIN CONTENT ---
    match app.current_tab {
        Tab::Connections => render_connections(f, app, chunks[2]),
        Tab::Stats => render_stats(f, app, chunks[2]),
        Tab::Logs => render_logs(f, app, chunks[2]),
    }

    // --- FOOTER ---
    let (m1, m2, m3, m4, m5, m6) = if let Ok(cfg) = config.lock() {
        (
            cfg.get(&1u32, 0).unwrap_or(1) == 1,
            cfg.get(&2u32, 0).unwrap_or(1) == 1,
            cfg.get(&3u32, 0).unwrap_or(1) == 1,
            cfg.get(&4u32, 0).unwrap_or(1) == 1,
            cfg.get(&5u32, 0).unwrap_or(1) == 1,
            cfg.get(&6u32, 0).unwrap_or(0) == 1,
        )
    } else {
        (true, true, true, true, true, false)
    };

    let on = Style::default().fg(Color::Green).add_modifier(Modifier::BOLD);
    let off = Style::default().fg(Color::DarkGray);
    let help = Line::from(vec![
        Span::raw(" "),
        Span::styled("Tab", Style::default().fg(Color::Cyan)),
        Span::raw(":switch "),
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::raw(":quit "),
        Span::styled("Space", Style::default().fg(Color::Yellow)),
        Span::raw(":block | "),
        Span::styled("1", if m1 { on } else { off }),
        Span::raw(":Port "),
        Span::styled("2", if m2 { on } else { off }),
        Span::raw(":Rate "),
        Span::styled("3", if m3 { on } else { off }),
        Span::raw(":Threat "),
        Span::styled("4", if m4 { on } else { off }),
        Span::raw(":Conn "),
        Span::styled("5", if m5 { on } else { off }),
        Span::raw(":Scan "),
        Span::styled("6", if m6 { on } else { off }),
        Span::raw(":Verb "),
        Span::styled("0", Style::default().fg(Color::Magenta)),
        Span::raw(":ALL"),
    ]);

    let footer = Paragraph::new(help)
        .style(Style::default().bg(Color::Rgb(20, 20, 30)));
    f.render_widget(footer, chunks[3]);
}

// ============================================================
// TAB RENDERERS
// ============================================================

fn render_connections<T: std::borrow::BorrowMut<MapData> + 'static>(
    f: &mut Frame,
    app: &mut App<T>,
    area: Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Connection list
    let items: Vec<ListItem> = app.connections.iter().map(|c| {
        let style = if c.is_blocked {
            Style::default().fg(Color::Red).add_modifier(Modifier::CROSSED_OUT)
        } else if c.proto == "TCP" {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Yellow)
        };

        let line = format!(
            "{:<15} :{:<5} {:3} [{}]",
            c.ip, c.port, c.proto, c.geo
        );
        ListItem::new(line).style(style)
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Active Connections "))
        .highlight_style(Style::default().bg(Color::Rgb(50, 50, 80)).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(list, chunks[0], &mut app.state);

    // Details panel
    let details = if let Some(i) = app.state.selected() {
        if let Some(conn) = app.connections.get(i) {
            let status = if conn.is_blocked { "BLOCKED" } else { "ALLOWED" };
            let status_color = if conn.is_blocked { Color::Red } else { Color::Green };

            let isp_display = if conn.isp.is_empty() { "N/A".to_string() } else { conn.isp.clone() };
            vec![
                Line::from(Span::styled("Target Details", Style::default().add_modifier(Modifier::BOLD))),
                Line::from(""),
                Line::from(vec![Span::raw("IP:      "), Span::styled(format!("{}", conn.ip), Style::default().fg(Color::White))]),
                Line::from(vec![Span::raw("Port:    "), Span::styled(format!("{}", conn.port), Style::default().fg(Color::White))]),
                Line::from(vec![Span::raw("Proto:   "), Span::styled(&conn.proto, Style::default().fg(Color::White))]),
                Line::from(vec![Span::raw("Geo:     "), Span::styled(&conn.geo, Style::default().fg(Color::Magenta))]),
                Line::from(vec![Span::raw("ISP:     "), Span::styled(isp_display, Style::default().fg(Color::Yellow))]),
                Line::from(vec![Span::raw("Status:  "), Span::styled(status, Style::default().fg(status_color).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from(Span::styled("SPACE to toggle block", Style::default().fg(Color::DarkGray))),
            ]
        } else {
            vec![Line::from("Select a connection...")]
        }
    } else {
        vec![Line::from("Select a connection...")]
    };

    let details_widget = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title(" Intel "))
        .wrap(Wrap { trim: true });
    f.render_widget(details_widget, chunks[1]);
}

fn render_stats<T: std::borrow::BorrowMut<MapData> + 'static>(
    f: &mut Frame,
    app: &mut App<T>,
    area: Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Packet sparkline
            Constraint::Length(5),  // Drop sparkline
            Constraint::Min(5),     // Stats details
        ])
        .split(area);

    // Packet rate sparkline
    let pkt_data: Vec<u64> = app.pkt_history.iter().copied().collect();
    let pkt_len = pkt_data.len();
    let pkt_sum: u64 = pkt_data.iter().sum();
    let pkt_max = pkt_data.iter().copied().max().unwrap_or(1).max(1);
    let sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(format!(" Pkts/s n={} sum={} max={} ", pkt_len, pkt_sum, pkt_max)))
        .data(&pkt_data)
        .max(pkt_max)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(sparkline, chunks[0]);

    // Drop rate sparkline
    let drop_data: Vec<u64> = app.drop_history.iter().copied().collect();
    let drop_len = drop_data.len();
    let drop_sum: u64 = drop_data.iter().sum();
    let drop_max = drop_data.iter().copied().max().unwrap_or(1).max(1);
    let drop_sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(format!(" Drops/s n={} sum={} max={} ", drop_len, drop_sum, drop_max)))
        .data(&drop_data)
        .max(drop_max)
        .style(Style::default().fg(Color::Red));
    f.render_widget(drop_sparkline, chunks[1]);

    // Detailed stats
    let stats = &app.last_stats;
    let stats_text = vec![
        Line::from(vec![
            Span::raw("Total Packets:     "),
            Span::styled(format_num(stats.pkts_seen), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::raw("Passed:            "),
            Span::styled(format_num(stats.pkts_pass), Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::raw("Dropped:           "),
            Span::styled(format_num(stats.pkts_drop), Style::default().fg(Color::Red)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Manual Blocks:     "),
            Span::styled(format!("{}", stats.block_manual), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("CIDR Blocks:       "),
            Span::styled(format!("{}", stats.block_cidr), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("ConnTrack Hits:    "),
            Span::styled(format_num(stats.conntrack_hits), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("PortScan Detect:   "),
            Span::styled(format!("{}", stats.portscan_hits), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::raw("Events OK/Fail:    "),
            Span::styled(format!("{}/{}", stats.events_ok, stats.events_fail), Style::default().fg(Color::White)),
        ]),
    ];

    let stats_widget = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::ALL).title(" Detailed Statistics "));
    f.render_widget(stats_widget, chunks[2]);
}

fn render_logs<T: std::borrow::BorrowMut<MapData> + 'static>(
    f: &mut Frame,
    app: &mut App<T>,
    area: Rect,
) {
    let items: Vec<ListItem> = app.logs.iter().rev().take(50).map(|log| {
        let style = if log.contains("BLOCK") || log.contains("DROP") || log.contains("SCAN") {
            Style::default().fg(Color::Red)
        } else if log.contains("UNBLOCK") || log.contains("PASS") {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Gray)
        };
        ListItem::new(log.as_str()).style(style)
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Security Events "));
    f.render_widget(list, area);
}

// ============================================================
// HELPERS
// ============================================================

fn format_num(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}G", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}
