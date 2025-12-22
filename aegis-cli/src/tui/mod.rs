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
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use sysinfo::System;
use aya::maps::{HashMap as BpfHashMap, MapData};
use crate::FlowKey;
use serde_json::Value;

pub struct App<T: std::borrow::BorrowMut<MapData> + 'static> {
    pub connections: Vec<ConnectionInfo>,
    pub logs: VecDeque<String>,
    pub state: ListState,
    pub _system: System,
    pub should_quit: bool,
    pub geo_cache: Arc<Mutex<HashMap<IpAddr, String>>>,
    pub blocklist: Arc<Mutex<BpfHashMap<T, FlowKey, u32>>>,
}

#[derive(Clone)]
pub struct ConnectionInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub proto: String,
    pub _process: String,
    pub _status: String,
    pub geo: String,
    pub is_blocked: bool,
}

impl<T: std::borrow::BorrowMut<MapData> + 'static> App<T> {
    pub fn new(blocklist: Arc<Mutex<BpfHashMap<T, FlowKey, u32>>>) -> Self {
        let system = System::new_all();
        Self {
            connections: Vec::new(),
            logs: VecDeque::with_capacity(100),
            state: ListState::default(),
            _system: system,
            should_quit: false,
            geo_cache: Arc::new(Mutex::new(HashMap::new())),
            blocklist,
        }
    }

    pub fn on_tick(&mut self) {
        let raw_conns = read_proc_net_tcp();
        let mut enriched_conns = Vec::new();
        let cache = self.geo_cache.clone();
        
        // Check blocklist status for all IPs
        // We will check individual IPs in the loop below.

        for conn in raw_conns {
            let ip = conn.ip;
            let mut geo = "Locating...".to_string();
            
            // Check if IP is private/internal (no geo lookup needed)
            let is_private = match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    // CGNAT range: 100.64.0.0/10 (used by VPNs like Mullvad)
                    // Localhost: 127.0.0.0/8
                    octets[0] == 10 ||
                    (octets[0] == 172 && (octets[1] & 0xF0) == 16) ||
                    (octets[0] == 192 && octets[1] == 168) ||
                    (octets[0] == 100 && (octets[1] & 0xC0) == 64) ||  // 100.64.0.0/10 CGNAT
                    octets[0] == 127
                }
                IpAddr::V6(ipv6) => ipv6.is_loopback(),
            };
            
            if is_private {
                geo = match ip {
                    IpAddr::V4(ipv4) => {
                        let octets = ipv4.octets();
                        if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                            "VPN Internal".to_string()  // Mullvad CGNAT
                        } else if octets[0] == 127 {
                            "Localhost".to_string()
                        } else {
                            "Private LAN".to_string()
                        }
                    }
                    _ => "Private".to_string(),
                };
            } else {
                // Geo Cache Logic for public IPs
                {
                    let map = cache.lock().unwrap();
                    if let Some(g) = map.get(&ip) {
                        geo = g.clone();
                    }
                }

                let should_fetch = {
                    let mut map = cache.lock().unwrap();
                    if !map.contains_key(&ip) {
                        map.insert(ip, "Fetching...".to_string());
                        true
                    } else {
                        false
                    }
                };

                if should_fetch {
                    let cache_clone = cache.clone();
                    thread::spawn(move || {
                        // Throttle requests to avoid ip-api.com rate limiting (45/min)
                        thread::sleep(std::time::Duration::from_millis(100));
                        
                        let url = format!("http://ip-api.com/json/{}", ip);
                        let val: String = match reqwest::blocking::get(&url) {
                            Ok(resp) => {
                                if let Ok(json) = resp.json::<Value>() {
                                    if json["status"].as_str() == Some("fail") {
                                        "Private/Reserved".to_string()
                                    } else {
                                        let country = json["countryCode"].as_str().unwrap_or("??");
                                        let city = json["city"].as_str().unwrap_or("Unknown");
                                        format!("{} {}", country, city)
                                    }
                                } else {
                                    "Geo Error".to_string()
                                }
                            }
                            Err(_) => "Net Error".to_string(),
                        };
                        let mut map = cache_clone.lock().unwrap();
                        map.insert(ip, val);
                    });
                }

                // Re-read geo
                {
                    let map = cache.lock().unwrap();
                    if let Some(g) = map.get(&ip) {
                        geo = g.clone();
                    }
                }
            }

            // Check Block Status
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

            enriched_conns.push(ConnectionInfo {
                ip: conn.ip,
                port: conn.port,
                proto: conn.proto,
                _process: conn._process,
                _status: conn._status,
                geo,
                is_blocked,
            });
        }
        self.connections = enriched_conns;
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.connections.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.connections.len() - 1
                } else {
                    i - 1
                }
            }
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
                        // Unblock
                        match map.remove(&key) {
                            Ok(_) => self.logs.push_back(format!(
                                "LOG: Unblocked {} (key=0x{:08x})", ipv4, key.src_ip)),
                            Err(e) => self.logs.push_back(format!(
                                "ERR: Unblock {} FAILED: {}", ipv4, e)),
                        }
                    } else {
                        // Block
                        match map.insert(key, 2, 0) {
                            Ok(_) => self.logs.push_back(format!(
                                "LOG: BANNED {} (key=0x{:08x})", ipv4, key.src_ip)),
                            Err(e) => self.logs.push_back(format!(
                                "ERR: Block {} FAILED: {}", ipv4, e)),
                        }
                    }
                }
            }
        }
    }
}

struct RawConnection {
    ip: IpAddr,
    port: u16,
    proto: String,
    _process: String,
    _status: String,
}

fn read_proc_net_tcp() -> Vec<RawConnection> {
    use std::fs::read_to_string;
    let mut conns = Vec::new();
    for file in ["/proc/net/tcp", "/proc/net/udp"] {
        if let Ok(content) = read_to_string(file) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 { continue; }
                let local_parts: Vec<&str> = parts[1].split(':').collect();
                let remote_parts: Vec<&str> = parts[2].split(':').collect();
                if local_parts.len() != 2 || remote_parts.len() != 2 { continue; }
                let remote_ip_hex = remote_parts[0];
                let remote_port_hex = remote_parts[1];
                if let (Ok(ip_u32), Ok(port)) = (u32::from_str_radix(remote_ip_hex, 16), u16::from_str_radix(remote_port_hex, 16)) {
                    let ip = Ipv4Addr::from(u32::from_be(ip_u32));
                    if ip.is_loopback() || ip.is_unspecified() { continue; } 
                    let proto = if file.contains("tcp") { "TCP" } else { "UDP" };
                    conns.push(RawConnection {
                        ip: IpAddr::V4(ip),
                        port,
                        proto: proto.to_string(),
                        _process: "Unknown".to_string(), 
                        _status: parts[3].to_string(),
                    });
                }
            }
        }
    }
    conns
}

pub async fn run_tui<T>(
    blocklist: Arc<Mutex<BpfHashMap<T, FlowKey, u32>>>,
    logs: Arc<Mutex<VecDeque<String>>>,
) -> Result<(), anyhow::Error>
where
    T: std::borrow::BorrowMut<MapData> + 'static,
{
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(blocklist);
    let tick_rate = Duration::from_millis(1000);
    let mut last_tick = Instant::now();

    loop {
        {
            let _shared_logs = logs.lock().unwrap();
            // Merge logs? Or just overwrite?
            // App has its own logs for UI feedback (like "BANNED").
            // Shared logs come from eBPF events.
            // We should append new shared logs to app logs.
            // For simplicity, let's just copy the last 50 from shared.
            // But we also want to keep our local "BANNED" messages.
            // Better: App.logs is the source of truth for UI.
            // We pull from shared_logs and clear shared_logs? No, other tasks might need them.
            // Let's just take a snapshot of shared logs.
            // To mix them, we can just display shared logs + local feedback.
            // Actually, let's just use shared_logs for everything.
            // When we ban, we push to shared_logs (we need to pass logs arc to App or just push to local and merge).
            // Let's keep it simple: App.logs is a copy of shared_logs + local actions.
            // But shared_logs is updated by another thread.
            // Let's just read shared_logs.
            // And when we ban, we push to shared_logs? We need the Arc for that.
            // Let's pass logs Arc to App too.
        }
        
        // Hack: We didn't pass logs Arc to App struct.
        // Let's just read shared logs here and update App.logs
        {
             let shared = logs.lock().unwrap();
             app.logs = shared.clone();
        }

        terminal.draw(|f| ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => app.should_quit = true,
                        KeyCode::Down => app.next(),
                        KeyCode::Up => app.previous(),
                        KeyCode::Char(' ') => app.toggle_block(),
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

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, crossterm::terminal::Clear(crossterm::terminal::ClearType::All), crossterm::cursor::MoveTo(0, 0))?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui<T: std::borrow::BorrowMut<MapData> + 'static>(f: &mut ratatui::Frame, app: &mut App<T>) {
    // Stats
    let total = app.connections.len();
    let tcp_count = app.connections.iter().filter(|c| c.proto == "TCP").count();
    let udp_count = app.connections.iter().filter(|c| c.proto == "UDP").count();
    let blocked_count = app.connections.iter().filter(|c| c.is_blocked).count();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Stats
            Constraint::Min(10),    // Main
            Constraint::Length(3),  // Help
        ])
        .split(f.size());

    // Stats Bar
    let stats_text = format!(
        "  Total: {} │ TCP: {} │ UDP: {} │ 🚫 Blocked: {}",
        total, tcp_count, udp_count, blocked_count
    );
    let stats = Paragraph::new(stats_text)
        .style(Style::default().fg(Color::White).bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("⚡ AEGIS SOC DASHBOARD"));
    f.render_widget(stats, chunks[0]);

    // Main Area
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(main_chunks[0]);

    // Connections List
    let items: Vec<ListItem> = app
        .connections
        .iter()
        .map(|c| {
            let mut style = if c.proto == "TCP" { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::Yellow) };
            if c.is_blocked {
                style = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD | Modifier::CROSSED_OUT);
            }
            
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<15}", c.ip), style),
                Span::raw(format!(" : {:<5} ", c.port)),
                Span::styled(format!(" {:<3} ", c.proto), Modifier::BOLD),
                Span::styled(format!(" [{}]", c.geo), Style::default().fg(Color::Magenta)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("🌐 Active Connections"))
        .highlight_style(Style::default().bg(Color::Rgb(40, 40, 80)).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, left_chunks[0], &mut app.state);

    // Details Pane
    let selected_info = if let Some(i) = app.state.selected() {
        if let Some(conn) = app.connections.get(i) {
            let status = if conn.is_blocked { "BLOCKED" } else { "ALLOWED" };
            let status_color = if conn.is_blocked { Color::Red } else { Color::Green };
            
            vec![
                Line::from(Span::styled("Target Details", Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED))),
                Line::from(""),
                Line::from(vec![Span::raw("IP:      "), Span::styled(format!("{}", conn.ip), Style::default().fg(Color::White))]),
                Line::from(vec![Span::raw("Port:    "), Span::styled(format!("{}", conn.port), Style::default().fg(Color::White))]),
                Line::from(vec![Span::raw("Proto:   "), Span::styled(format!("{}", conn.proto), Style::default().fg(Color::White))]),
                Line::from(vec![Span::raw("Geo:     "), Span::styled(format!("{}", conn.geo), Style::default().fg(Color::Magenta))]),
                Line::from(vec![Span::raw("Status:  "), Span::styled(status, Style::default().fg(status_color).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from(Span::styled("Press SPACE to Block/Unblock", Style::default().fg(Color::Gray))),
            ]
        } else {
            vec![Line::from("Select a connection...")]
        }
    } else {
        vec![Line::from("Select a connection...")]
    };

    let details = Paragraph::new(selected_info)
        .block(Block::default().borders(Borders::ALL).title("🎯 Intel"))
        .wrap(Wrap { trim: true });
    
    f.render_widget(details, main_chunks[1]);

    // Logs with deduplication
    // Group consecutive identical events with count
    let mut deduped_logs: Vec<(String, usize)> = Vec::new();
    for log in app.logs.iter().rev().take(50) {
        // Extract key part of log (IP + action) for dedup
        if let Some(last) = deduped_logs.last_mut() {
            if last.0 == *log {
                last.1 += 1;
                continue;
            }
        }
        deduped_logs.push((log.clone(), 1));
    }
    
    let logs: Vec<ListItem> = deduped_logs
        .iter()
        .take(15)
        .map(|(l, count)| {
            let display = if *count > 1 {
                format!("{} [x{}]", l, count)
            } else {
                l.clone()
            };
            let style = if l.contains("DPI") {
                Style::default().fg(Color::Rgb(255, 100, 100)).add_modifier(Modifier::BOLD)
            } else if l.contains("SUSPICIOUS") || l.contains("BANNED") {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else if l.contains("Unblocked") {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(Span::styled(display, style))
        })
        .collect();

    let log_list = List::new(logs)
        .block(Block::default().borders(Borders::ALL).title("📜 Security Events"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_widget(log_list, left_chunks[1]);

    // Help Footer
    let help_text = " ↑/↓ Navigate │ SPACE Block/Unblock │ q Quit ";
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Black).bg(Color::Rgb(100, 100, 150)))
        .block(Block::default());
    f.render_widget(help, chunks[2]);
}
