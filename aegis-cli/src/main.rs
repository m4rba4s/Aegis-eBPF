mod config;
mod tui;
mod feeds;

use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags, tc, SchedClassifier, TcAttachType};
use aya::maps::{HashMap, MapData};
use aya::maps::perf::AsyncPerfEventArray;
use std::path::Path;
use std::fs;
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

// Import from aegis-common (Single Source of Truth)
use aegis_common::{
    PacketLog, FlowKey,
    REASON_DEFAULT, REASON_WHITELIST, REASON_CONNTRACK, REASON_MANUAL_BLOCK,
    REASON_CIDR_FEED, REASON_PORTSCAN, REASON_TCP_ANOMALY, REASON_RATELIMIT,
    REASON_IPV6_POLICY, REASON_MALFORMED, REASON_EGRESS_BLOCK,
    THREAT_NONE, THREAT_SCAN_XMAS, THREAT_SCAN_NULL, THREAT_SCAN_SYNFIN,
    THREAT_SCAN_PORT, THREAT_FLOOD_SYN, THREAT_BLOCKLIST, THREAT_INCOMING_SYN,
    THREAT_EGRESS_BLOCKED,
};

#[derive(Parser)]
struct Opt {
    /// Network interface to attach to
    #[clap(short, long, default_value = "lo")]
    iface: String,

    /// Path to XDP eBPF object file
    #[clap(long, default_value = "/usr/local/share/aegis/aegis.o")]
    ebpf_path: String,

    /// Path to TC eBPF object file (for egress filtering)
    #[clap(long, default_value = "/usr/local/share/aegis/aegis-tc.o")]
    tc_path: String,

    /// Disable TC egress program
    #[clap(long)]
    no_tc: bool,

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
                            println!("✅ {} CIDR entries", result.entry_count());
                            total_ips += result.entry_count();
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
                let ebpf_path = &opt.ebpf_path;
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
    let ebpf_path = &opt.ebpf_path;
    let mut bpf = Ebpf::load_file(ebpf_path)?;
    
    // Common setup for Load, Tui, and Daemon
    match opt.command {
        Commands::Load | Commands::Tui | Commands::Daemon => {
            let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
            program.load()?;
            
            let flags = if opt.iface == "lo" || opt.iface.starts_with("wg") || opt.iface.starts_with("wl") {
                println!("ℹ️  Using XDP Generic Mode (SKB) for virtual/wireless interface: {}", opt.iface);
                XdpFlags::SKB_MODE
            } else {
                XdpFlags::default()
            };
            let link_id = program.attach(&opt.iface, flags)?;
            println!("✅ XDP attached to {} (link_id: {:?})", opt.iface, link_id);

            // --- TC EGRESS PROGRAM ---
            let mut tc_bpf: Option<Ebpf> = None;
            if !opt.no_tc && Path::new(&opt.tc_path).exists() {
                match Ebpf::load_file(&opt.tc_path) {
                    Ok(mut tc) => {
                        // Add clsact qdisc (required for TC)
                        if let Err(e) = tc::qdisc_add_clsact(&opt.iface) {
                            // Ignore "already exists" error
                            if !e.to_string().contains("exists") {
                                println!("⚠️  TC qdisc setup warning: {}", e);
                            }
                        }

                        // Load and attach TC egress program
                        let tc_prog: &mut SchedClassifier = tc.program_mut("tc_egress")
                            .expect("tc_egress not found")
                            .try_into()?;
                        tc_prog.load()?;
                        tc_prog.attach(&opt.iface, TcAttachType::Egress)?;
                        println!("✅ TC Egress attached to {}", opt.iface);
                        tc_bpf = Some(tc);
                    }
                    Err(e) => {
                        println!("⚠️  TC program not loaded: {} (egress filtering disabled)", e);
                    }
                }
            } else if opt.no_tc {
                println!("ℹ️  TC egress program disabled (--no-tc)");
            } else {
                println!("ℹ️  TC program not found at {}, egress filtering disabled", opt.tc_path);
            }

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
            
            // Take ownership of STATS for health metrics
            let stats_map = bpf.take_map("STATS").expect("STATS map not found");
            let stats: aya::maps::PerCpuArray<_, aegis_common::Stats> = aya::maps::PerCpuArray::try_from(stats_map)?;
            let stats_arc = Arc::new(Mutex::new(stats));
            
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
                                    
                                    // Format threat type using constants from aegis_common
                                    let threat_str = match log.threat_type {
                                        THREAT_SCAN_XMAS => "XMAS_SCAN",
                                        THREAT_SCAN_NULL => "NULL_SCAN",
                                        THREAT_SCAN_SYNFIN => "SYNFIN_SCAN",
                                        THREAT_SCAN_PORT => "PORT_SCAN",
                                        THREAT_FLOOD_SYN => "SYN_FLOOD",
                                        THREAT_BLOCKLIST => "BLOCKLIST",
                                        THREAT_INCOMING_SYN => "INCOMING_SYN",
                                        THREAT_EGRESS_BLOCKED => "EGRESS_BLOCKED",
                                        THREAT_NONE | _ => "NONE",
                                    };

                                    // Format reason (WHY this action)
                                    let reason_str = match log.reason {
                                        REASON_DEFAULT => "DEFAULT",
                                        REASON_WHITELIST => "WHITELIST",
                                        REASON_CONNTRACK => "CONNTRACK",
                                        REASON_MANUAL_BLOCK => "MANUAL_BLOCK",
                                        REASON_CIDR_FEED => "CIDR_FEED",
                                        REASON_PORTSCAN => "PORTSCAN",
                                        REASON_TCP_ANOMALY => "TCP_ANOMALY",
                                        REASON_RATELIMIT => "RATELIMIT",
                                        REASON_IPV6_POLICY => "IPV6_POLICY",
                                        REASON_MALFORMED => "MALFORMED",
                                        REASON_EGRESS_BLOCK => "EGRESS_BLOCK",
                                        _ => "UNKNOWN",
                                    };
                                    
                                    // Format TCP flags
                                    let flags_str = format_tcp_flags(log.tcp_flags);
                                    
                                    let action_icon = if log.action == 1 { "❌" } else { "✅" };
                                    
                                    let msg = match log.threat_type {
                                        THREAT_SCAN_XMAS => format!("🎄 XMAS SCAN: {} -> {}:{} [{}]", src_ip, dst_ip, log.dst_port, flags_str),
                                        THREAT_SCAN_NULL => format!("⚫ NULL SCAN: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        THREAT_SCAN_SYNFIN => format!("💀 SYNFIN: {} -> {}:{} [{}]", src_ip, dst_ip, log.dst_port, flags_str),
                                        THREAT_SCAN_PORT => format!("🔍 PORT SCAN: {} scanned port {}", src_ip, log.dst_port),
                                        THREAT_FLOOD_SYN => format!("🔥 SYN FLOOD: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        THREAT_BLOCKLIST => format!("🚫 BLOCKED: {} ({})", src_ip, reason_str),
                                        THREAT_INCOMING_SYN => format!("🛡️ DROP SYN: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        THREAT_EGRESS_BLOCKED => format!("🚫 EGRESS BLOCKED: {} -> {} ({})", src_ip, dst_ip, reason_str),
                                        _ => format!("{} {} -> {}:{} [{}] reason={}",
                                            action_icon, src_ip, dst_ip, log.dst_port, flags_str, reason_str),
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
                                            "reason": reason_str,
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
                                    if log.threat_type == THREAT_FLOOD_SYN || log.threat_type == THREAT_SCAN_PORT {
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

                tui::run_tui(blocklist_arc.clone(), logs_arc.clone(), config_arc.clone(), stats_arc.clone()).await?;
                println!("\n🔌 Detaching programs from {}...", opt.iface);
                // Detach by dropping (forces cleanup)
                drop(tc_bpf);  // TC first
                drop(bpf);     // Then XDP
                println!("✅ Programs detached. Exiting Aegis...");
                return Ok(());
            } else if let Commands::Daemon = opt.command {
                // Daemon mode: no REPL, just run until SIGTERM/SIGINT
                let iface_for_shutdown = opt.iface.clone();
                tokio::spawn(async move {
                    loop {
                        event_futures.next().await;
                    }
                });
                
                println!("🔥 Daemon mode active on {}. Send SIGTERM or SIGINT to stop.", opt.iface);
                
                // Handle both SIGTERM (systemd) and SIGINT (Ctrl+C)
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to create SIGTERM handler");
                    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to create SIGINT handler");
                    
                    tokio::select! {
                        _ = sigterm.recv() => println!("\n📥 Received SIGTERM"),
                        _ = sigint.recv() => println!("\n📥 Received SIGINT (Ctrl+C)"),
                    }
                }
                #[cfg(not(unix))]
                {
                    signal::ctrl_c().await?;
                }
                
                println!("🔌 Detaching programs from {}...", iface_for_shutdown);
                drop(tc_bpf);  // TC first
                drop(bpf);     // Then XDP
                println!("✅ Programs detached. Shutdown complete.");
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
