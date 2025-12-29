mod config;
mod tui;
mod feeds;

use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::{HashMap, MapData};
use aya::maps::perf::AsyncPerfEventArray;
use clap::{Parser, Subcommand};
use tokio::signal;
use std::net::Ipv4Addr;
use std::convert::TryInto;
use tokio::io::{self, AsyncBufReadExt};
use futures::stream::{FuturesUnordered, StreamExt};
use aya::util::online_cpus;
use bytes::BytesMut;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use chrono;
use serde_json;

// Import PacketLog from aegis-common (IDS/IPS extended structure)
use aegis_common::PacketLog;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: u8,
}

// Implement Pod for FlowKey to allow using it as a map key safely
unsafe impl aya::Pod for FlowKey {}

#[derive(Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
    
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Load,
    Tui, // TUI mode
    Daemon, // Headless daemon mode (no REPL)
    Save {
        #[clap(short, long, default_value = "aegis.yaml")]
        file: String,
    },
    Restore {
        #[clap(short, long, default_value = "aegis.yaml")]
        file: String,
    },
    /// Threat feed management
    Feeds {
        #[clap(subcommand)]
        action: FeedsAction,
    },
}

#[derive(Subcommand)]
enum FeedsAction {
    /// Update all enabled threat feeds (download only, no sudo required)
    Update,
    /// List configured feeds
    List,
    /// Show feed statistics
    Stats,
    /// Load feeds into eBPF blocklist (requires sudo)
    Load,
}

/// Format TCP flags byte into human-readable string
fn format_tcp_flags(flags: u8) -> String {
    let mut result = String::new();
    if flags & 0x01 != 0 { result.push_str("FIN "); }
    if flags & 0x02 != 0 { result.push_str("SYN "); }
    if flags & 0x04 != 0 { result.push_str("RST "); }
    if flags & 0x08 != 0 { result.push_str("PSH "); }
    if flags & 0x10 != 0 { result.push_str("ACK "); }
    if flags & 0x20 != 0 { result.push_str("URG "); }
    if result.is_empty() {
        format!("0x{:02x}", flags)
    } else {
        result.trim().to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // Banner shown conditionally (not for TUI - it has its own header)
    if !matches!(opt.command, Commands::Tui) {
        println!(r#"
    ██████╗ ███████╗ ██████╗ ██╗███████╗
   ██╔═══██╗██╔════╝██╔════╝ ██║██╔════╝
   ████████║█████╗  ██║  ███╗██║███████╗
   ██╔═══██║██╔══╝  ██║   ██║██║╚════██║
   ██║   ██║███████╗╚██████╔╝██║███████║
   ╚═╝   ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
      eBPF FIREWALL :: SECURITY MATRIX
    "#);
    }

    // Bump memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        println!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // Load Config
    let config_path = "aegis.yaml";
    let cfg = config::Config::load(config_path).unwrap_or_else(|_| config::Config { rules: vec![], remote_log: None });

    // Handle Feeds command early (no eBPF needed)
    if let Commands::Feeds { action } = &opt.command {
        match action {
            FeedsAction::Update => {
                println!("🔄 Updating threat feeds...\n");
                let configs = feeds::FeedConfig::defaults();
                let mut total_ips = 0usize;
                
                for config in configs.iter().filter(|c| c.enabled) {
                    print!("  {} ... ", config.name);
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    match feeds::download_feed_blocking(config) {
                        Ok(result) => {
                            println!("✅ {} IPs", result.ip_count);
                            total_ips += result.ip_count;
                        }
                        Err(e) => {
                            println!("❌ {}", e);
                        }
                    }
                }
                println!("\n📊 Total: {} IPs loaded", total_ips);
            }
            FeedsAction::List => {
                println!("📋 Configured Threat Feeds:\n");
                for config in feeds::FeedConfig::defaults() {
                    let status = if config.enabled { "✅" } else { "❌" };
                    println!("  {} {} ({:?})", status, config.name, config.category);
                    println!("     URL: {}", config.url);
                    println!("     Update: every {}h\n", config.update_interval_secs / 3600);
                }
            }
            FeedsAction::Stats => {
                println!("📊 Feed Statistics:\n");
                println!("  Cache dir: {:?}", feeds::cache_dir());
                println!("  (Run 'feeds update' first to load feeds)");
            }
            FeedsAction::Load => {
                println!("🔄 Loading threat feeds into eBPF blocklist...\n");
                println!("⚠️  This requires sudo and eBPF program loaded.\n");
                
                // Load eBPF just for map access
                let ebpf_path = "/usr/local/share/aegis/aegis.o";
                let mut bpf = match Ebpf::load_file(ebpf_path) {
                    Ok(b) => b,
                    Err(e) => {
                        println!("❌ Failed to load eBPF: {}", e);
                        return Ok(());
                    }
                };
                
                // Get CIDR_BLOCKLIST map
                let mut cidr_map: aya::maps::LpmTrie<_, aegis_common::LpmKeyIpv4, aegis_common::CidrBlockEntry> = 
                    match aya::maps::LpmTrie::try_from(bpf.map_mut("CIDR_BLOCKLIST").unwrap()) {
                        Ok(m) => m,
                        Err(e) => {
                            println!("❌ Failed to get CIDR_BLOCKLIST map: {}", e);
                            return Ok(());
                        }
                    };
                
                // Load feeds
                match feeds::load_feeds_to_map(&mut cidr_map) {
                    Ok(count) => {
                        println!("✅ Loaded {} IPs into CIDR blocklist", count);
                    }
                    Err(e) => {
                        println!("❌ Failed to load feeds: {}", e);
                    }
                }
            }
        }
        return Ok(());
    }

    // Load eBPF (only for commands that need it)
    let ebpf_path = "/usr/local/share/aegis/aegis.o";
    let mut bpf = Ebpf::load_file(ebpf_path)?;
    
    // Common setup for Load, Tui, and Daemon
    match opt.command {
        Commands::Load | Commands::Tui | Commands::Daemon => {
            let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
            program.load()?;
            
            let flags = if opt.iface == "lo" || opt.iface.starts_with("wg") {
                println!("ℹ️  Using XDP Generic Mode (SKB) for virtual interface: {}", opt.iface);
                XdpFlags::SKB_MODE
            } else {
                XdpFlags::default()
            };
            program.attach(&opt.iface, flags)?;
            
            // Take ownership of BLOCKLIST
            let blocklist_map = bpf.take_map("BLOCKLIST").expect("BLOCKLIST not found");
            let blocklist: HashMap<_, FlowKey, u32> = HashMap::try_from(blocklist_map)?;
            let blocklist_arc = Arc::new(Mutex::new(blocklist)); // Wrap in Arc<Mutex> for sharing
            
            // Restore rules from config
            {
                let mut map = blocklist_arc.lock().unwrap();
                for rule in &cfg.rules {
                    let key = FlowKey {
                        src_ip: u32::from(rule.ip).to_be(),
                        dst_port: rule.port,
                        proto: config::parse_proto(&rule.proto),
                        _pad: 0,
                    };
                    let _ = map.insert(key, 2, 0);
                }
            }
            
            // Set interface mode and initialize defense modules in CONFIG map
            let config_map = bpf.take_map("CONFIG").expect("CONFIG map not found");
            let mut config: HashMap<_, u32, u32> = HashMap::try_from(config_map)?;
            
            // Key 0: Interface mode (L3 for WireGuard/tun, L2 for Ethernet)
            let mode: u32 = if opt.iface.starts_with("wg") || opt.iface.starts_with("tun") {
                println!("ℹ️  Setting L3 mode (raw IP) for interface: {}", opt.iface);
                1
            } else {
                0
            };
            config.insert(0u32, mode, 0)?;
            
            // Keys 1-5: Defense modules (all enabled by default)
            // 1=PortScan, 2=RateLimit, 3=ThreatFeeds, 4=ConnTrack, 5=ScanDetect
            for key in 1u32..=5u32 {
                config.insert(key, 1u32, 0)?;
            }
            println!("🛡️  All defense modules ENABLED");
            let config_arc = Arc::new(Mutex::new(config));
            
            // Shared Logs
            let logs_arc = Arc::new(Mutex::new(VecDeque::new()));

            // Take ownership of EVENTS
            let events_map = bpf.take_map("EVENTS").expect("EVENTS map not found");
            let mut events = AsyncPerfEventArray::try_from(events_map)?;

            // Setup event logging futures
            let mut event_futures = FuturesUnordered::new();
            let cpus = online_cpus().map_err(|(_, e)| e)?;
            
            let logs_clone = logs_arc.clone();
            let remote_log_base = cfg.remote_log.clone();
            let blocklist_clone = blocklist_arc.clone(); // Clone for event loop

            for cpu_id in cpus {
                let mut buf = events.open(cpu_id, None)?;
                let logs_inner = logs_clone.clone();
                let remote_log = remote_log_base.clone();
                let blocklist_inner = blocklist_clone.clone(); // Clone for this CPU task
                
                event_futures.push(async move {
                    let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
                    loop {
                        match buf.read_events(&mut buffers).await {
                            Ok(events) => {
                                for i in 0..events.read {
                                    let buf = &mut buffers[i];
                                    let ptr = buf.as_ptr() as *const PacketLog;
                                    let log = unsafe { ptr.read_unaligned() };
                                    let src_ip = Ipv4Addr::from(u32::from_be(log.src_ip));
                                    let dst_ip = Ipv4Addr::from(u32::from_be(log.dst_ip));
                                    
                                    // Format threat type
                                    let threat_str = match log.threat_type {
                                        1 => "XMAS_SCAN",
                                        2 => "NULL_SCAN",
                                        3 => "SYNFIN_SCAN",
                                        4 => "PORT_SCAN",
                                        5 => "SYN_FLOOD",
                                        6 => "BLOCKLIST",
                                        7 => "INCOMING_SYN",
                                        _ => "UNKNOWN",
                                    };
                                    
                                    // Format TCP flags
                                    let flags_str = format_tcp_flags(log.tcp_flags);
                                    
                                    let msg = match log.threat_type {
                                        1 => format!("🎄 XMAS SCAN: {} -> {}:{} [{}]", src_ip, dst_ip, log.dst_port, flags_str),
                                        2 => format!("⚫ NULL SCAN: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        3 => format!("💀 SYNFIN: {} -> {}:{} [{}]", src_ip, dst_ip, log.dst_port, flags_str),
                                        4 => format!("🔍 PORT SCAN: {} scanned port {}", src_ip, log.dst_port),
                                        5 => format!("🔥 SYN FLOOD: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        6 => format!("🚫 BLOCKED: {} (blocklist)", src_ip),
                                        7 => format!("🛡️ DROP SYN: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        _ => format!("📋 LOG: {} -> {}:{} [{}] threat={}", 
                                            src_ip, dst_ip, log.dst_port, flags_str, threat_str),
                                    };

                                    // Remote Logging (JSON)
                                    if let Some(ref remote) = remote_log {
                                        let json_log = serde_json::json!({
                                            "src_ip": src_ip.to_string(),
                                            "dst_ip": dst_ip.to_string(),
                                            "src_port": log.src_port,
                                            "dst_port": log.dst_port,
                                            "proto": log.proto,
                                            "tcp_flags": log.tcp_flags,
                                            "action": log.action,
                                            "threat_type": threat_str,
                                            "packet_len": log.packet_len,
                                            "timestamp": chrono::Utc::now().to_rfc3339()
                                        });
                                        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();
                                        if let Some(s) = socket {
                                            let _ = s.send_to(json_log.to_string().as_bytes(), remote);
                                        }
                                    }
                                    {
                                        let mut logs = logs_inner.lock().unwrap();
                                        if logs.len() >= 100 { logs.pop_front(); }
                                        logs.push_back(msg.clone());
                                    }

                                    // --- DYNAMIC AUTO-BAN (OODA Loop) ---
                                    // Auto-ban on SYN FLOOD or PORT SCAN
                                    if log.threat_type == 5 || log.threat_type == 4 {
                                        let mut blocklist = blocklist_inner.lock().unwrap();
                                        let key = FlowKey {
                                            src_ip: log.src_ip, // Already Network Byte Order from eBPF
                                            dst_port: 0,           // Wildcard port
                                            proto: 0,              // Wildcard proto
                                            _pad: 0,
                                        };
                                        // Insert into map with action 2 (DROP)
                                        // Note: We use insert(key, 2, 0)
                                        if let Err(e) = blocklist.insert(key, 2, 0) {
                                            let mut logs = logs_inner.lock().unwrap();
                                            logs.push_back(format!("❌ AUTO-BAN FAILED for {}: {}", src_ip, e));
                                        } else {
                                            let mut logs = logs_inner.lock().unwrap();
                                            logs.push_back(format!("⛔ AUTO-BANNED {} (OODA Trigger)", src_ip));
                                        }
                                    }
                                    // ------------------------------------
                                }
                            }
                            Err(_e) => {
                                break;
                            }
                        }
                    }
                });
            }

            if let Commands::Tui = opt.command {
                // Run TUI (Blocking)
                // We spawn the event listener in background (already done above via event_futures)
                // But wait, event_futures needs to be polled.
                // In the previous code:
                // TUI mode: spawned a task to poll event_futures.
                // REPL mode: polled event_futures in the select! loop.
                
                // We need a unified approach.
                // Let's spawn the event poller globally for both modes.
                // But in REPL mode we wanted to print logs?
                // The REPL printer task reads from shared logs.
                
                // Spawn event poller
                tokio::spawn(async move {
                    loop {
                        event_futures.next().await;
                    }
                });

                tui::run_tui(blocklist_arc.clone(), logs_arc.clone(), config_arc.clone()).await?;
                println!("\nExiting Aegis...");
                return Ok(());
            } else if let Commands::Daemon = opt.command {
                // Daemon mode: no REPL, just run until SIGTERM
                tokio::spawn(async move {
                    loop {
                        event_futures.next().await;
                    }
                });
                
                println!("Daemon mode active on {}. Send SIGTERM to stop.", opt.iface);
                signal::ctrl_c().await?;
                println!("Shutting down...");
                return Ok(());
            } else {
                 // For Load command, we also need to poll events.
                 // If we didn't run TUI, we still need the event loop.
                 tokio::spawn(async move {
                    loop {
                        event_futures.next().await;
                    }
                });
            }

            // Interactive CLI Mode (REPL) - Runs after TUI or directly
            println!("Attached to {}, waiting for Ctrl-C...", opt.iface);
            println!("Commands:");
            println!("  block <IP> [port] [proto]");
            println!("  unblock <IP> [port] [proto]");
            println!("  save [file] | restore [file] | list");
            
            let stdin = io::stdin();
            let mut reader = io::BufReader::new(stdin);
            let mut line = String::new();
            
            // Log Printer Task
            // Prints new logs from the shared buffer to stdout
            let logs_printer = logs_arc.clone();
            tokio::spawn(async move {
                let mut last_len = 0;
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    let logs = logs_printer.lock().unwrap();
                    if logs.len() > last_len {
                        for i in last_len..logs.len() {
                            println!("{}", logs[i]);
                        }
                        last_len = logs.len();
                    }
                }
            });

            loop {
                tokio::select! {
                    _ = signal::ctrl_c() => {
                        println!("Exiting...");
                        break;
                    }
                    bytes = reader.read_line(&mut line) => {
                        match bytes {
                            Ok(0) => break, // EOF
                            Ok(_) => {
                                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                                if !parts.is_empty() {
                                    let mut blocklist = blocklist_arc.lock().unwrap();
                                    handle_command(&mut blocklist, parts).await?;
                                }
                                line.clear();
                            }
                            Err(e) => println!("Error reading line: {}", e),
                        }
                    }
                }
            }
        }
        Commands::Save { file: _ } => {
             println!("Please use the 'save' command inside the running 'load' session.");
        }
        Commands::Restore { file: _ } => {
             println!("Please use the 'restore' command inside the running 'load' session.");
        }
        Commands::Feeds { .. } => {
            // Handled before eBPF loading - should never reach here
            unreachable!("Feeds command should be handled before eBPF loading");
        }
    }

    Ok(())
}

async fn handle_command<T>(blocklist: &mut HashMap<T, FlowKey, u32>, parts: Vec<&str>) -> Result<(), anyhow::Error> 
where T: std::borrow::BorrowMut<MapData>
{
    let cmd = parts[0];
    match cmd {
        "block" | "unblock" => {
            if let Some(ip_str) = parts.get(1) {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    let port = parts.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    let proto = parts.get(3).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
                    
                    let key = FlowKey {
                        src_ip: u32::from(ip).to_be(), // Network Byte Order
                        dst_port: port,                // Host Byte Order
                        proto: proto,
                        _pad: 0,
                    };
                    
                    if cmd == "block" {
                        blocklist.insert(key, 2, 0)?; // 2 = XDP_DROP
                        println!("Blocked {} Port: {} Proto: {}", ip, port, proto);
                    } else {
                        blocklist.remove(&key)?;
                        println!("Unblocked {} Port: {} Proto: {}", ip, port, proto);
                    }
                } else {
                    println!("Invalid IP");
                }
            }
        }
        "save" => {
            let file = parts.get(1).unwrap_or(&"aegis.yaml");
            let mut rules = Vec::new();
            // Iterate over map
            for item in blocklist.iter() {
                let (key, _action) = item?;
                rules.push(config::Rule {
                    ip: Ipv4Addr::from(u32::from_be(key.src_ip)),
                    port: key.dst_port,
                    proto: config::proto_to_str(key.proto),
                    action: "drop".to_string(),
                });
            }
            let cfg = config::Config { rules, remote_log: None };
            cfg.save(file)?;
            println!("Saved rules to {}", file);
        }
        "list" => {
            println!("Active Rules:");
            println!("{:<16} {:<6} {:<6} {:<6}", "IP", "Port", "Proto", "Action");
            for item in blocklist.iter() {
                match item {
                    Ok((key, _action)) => {
                        let ip = Ipv4Addr::from(u32::from_be(key.src_ip));
                        let port = key.dst_port;
                        let proto = config::proto_to_str(key.proto);
                        println!("{:<16} {:<6} {:<6} DROP", ip, port, proto);
                    }
                    Err(e) => println!("Error reading map: {}", e),
                }
            }
        }
        "restore" => {
            let file = parts.get(1).unwrap_or(&"aegis.yaml");
            match config::Config::load(file) {
                Ok(cfg) => {
                    // Strategy: Insert new rules. 
                    // Ideally we should clear old ones, but HashMap doesn't support clear().
                    // We would need to iterate and delete.
                    // For now, let's just Upsert.
                    for rule in cfg.rules {
                        let key = FlowKey {
                            src_ip: u32::from(rule.ip).to_be(),
                            dst_port: rule.port,
                            proto: config::parse_proto(&rule.proto),
                            _pad: 0,
                        };
                        blocklist.insert(key, 2, 0)?;
                        println!("Loaded rule: {} {} {}", rule.ip, rule.port, rule.proto);
                    }
                    println!("Restored configuration from {}", file);
                }
                Err(e) => println!("Failed to load config: {}", e),
            }
        }
        _ => println!("Unknown command"),
    }
    Ok(())
}
