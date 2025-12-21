mod config;
mod tui;

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

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PacketLog {
    pub ipv4_addr: u32,
    pub port: u16,
    pub proto: u8,
    pub action: u32,
}

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

    // Load eBPF
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
            
            // Set interface mode in CONFIG map
            // L3 mode (1) for WireGuard/tun interfaces, L2 mode (0) for Ethernet
            {
                let config_map = bpf.take_map("CONFIG").expect("CONFIG map not found");
                let mut config: HashMap<_, u32, u32> = HashMap::try_from(config_map)?;
                let mode: u32 = if opt.iface.starts_with("wg") || opt.iface.starts_with("tun") {
                    println!("ℹ️  Setting L3 mode (raw IP) for interface: {}", opt.iface);
                    1  // L3 mode
                } else {
                    0  // L2 mode (Ethernet)
                };
                config.insert(0u32, mode, 0)?;
            }
            
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
                                    let src_ip = Ipv4Addr::from(u32::from_be(log.ipv4_addr));
                                    
                                    let msg = match log.action {
                                        2 => format!("LOG: Dropped packet from {}", src_ip),
                                        3 => format!("⚠️  SUSPICIOUS: Heuristic Drop from {}", src_ip),
                                        4 => format!("💀 DPI ALERT: Payload Drop from {}", src_ip),
                                        5 => format!("🔥 RATE LIMIT: SYN Flood from {}", src_ip),
                                        6 => format!("🔍 PORT SCAN: Detected from {} (port {})", src_ip, log.port),
                                        100 => format!("🔍 TCP flags=0x{:02x} from {} port {}", log.proto, src_ip, log.port),
                                        _ => format!("LOG: Unknown action {} from {}", log.action, src_ip),
                                    };

                                    // Remote Logging
                                    if let Some(ref remote) = remote_log {
                                        let json_log = serde_json::json!({
                                            "src_ip": src_ip.to_string(),
                                            "action": log.action,
                                            "msg": msg,
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
                                    // If action is 4 (DPI) or 5 (Rate Limit), auto-ban the IP
                                    if log.action == 4 || log.action == 5 {
                                        let mut blocklist = blocklist_inner.lock().unwrap();
                                        let key = FlowKey {
                                            src_ip: log.ipv4_addr, // Already Network Byte Order from eBPF
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

                tui::run_tui(blocklist_arc.clone(), logs_arc.clone()).await?;
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
