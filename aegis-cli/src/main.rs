mod config;
mod tui;
mod feeds;
mod compat;
mod geo;
mod metrics;
mod dashboard;
mod dpi;

use aya::{Ebpf, EbpfLoader};
use aya::programs::{Xdp, XdpFlags, tc, SchedClassifier, TcAttachType};
use aya::maps::{HashMap, MapData, Map};
use aya::maps::perf::AsyncPerfEventArray;
use std::path::Path;
use clap::{Parser, Subcommand, CommandFactory};
use tokio::signal;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
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
    PacketLog, FlowKey, PacketLogIpv6, Stats,
    REASON_DEFAULT, REASON_WHITELIST, REASON_CONNTRACK, REASON_MANUAL_BLOCK,
    REASON_CIDR_FEED, REASON_PORTSCAN, REASON_TCP_ANOMALY, REASON_RATELIMIT,
    REASON_IPV6_POLICY, REASON_MALFORMED, REASON_EGRESS_BLOCK,
    THREAT_NONE, THREAT_SCAN_XMAS, THREAT_SCAN_NULL, THREAT_SCAN_SYNFIN,
    THREAT_SCAN_PORT, THREAT_FLOOD_SYN, THREAT_BLOCKLIST, THREAT_INCOMING_SYN,
    THREAT_EGRESS_BLOCKED,
    // IPv6 threat types
    THREAT_IPV6_EXT_CHAIN, THREAT_IPV6_ROUTING_TYPE0, THREAT_IPV6_FRAGMENT,
    THREAT_IPV6_HOP_BY_HOP,
};

// ============================================================
// EMBEDDED eBPF BYTECODE (Single Binary Distribution)
// ============================================================
// If compiled with eBPF objects present, they are embedded directly.
// Use --ebpf-path / --tc-path to override with external files.

#[cfg(embedded_xdp)]
static EMBEDDED_XDP: &[u8] = include_bytes!(env!("AEGIS_XDP_OBJ"));

#[cfg(embedded_tc)]
static EMBEDDED_TC: &[u8] = include_bytes!(env!("AEGIS_TC_OBJ"));

/// Default path for external eBPF objects
const DEFAULT_XDP_PATH: &str = "/usr/local/share/aegis/aegis.o";
const DEFAULT_TC_PATH: &str = "/usr/local/share/aegis/aegis-tc.o";

#[derive(Parser)]
#[clap(
    name = "aegis-cli",
    about = "Aegis eBPF XDP/TC Firewall",
    long_version = const_format::concatcp!(
        env!("CARGO_PKG_VERSION"),
        " (", env!("AEGIS_GIT_HASH"), " ", env!("AEGIS_BUILD_DATE"), ")",
        "\nrustc: ", env!("AEGIS_RUSTC"),
    ),
)]
struct Opt {
    /// Network interface to attach to
    #[clap(short, long, default_value = "lo")]
    iface: String,

    /// Path to XDP eBPF object file (uses embedded if not specified)
    #[clap(long, default_value = DEFAULT_XDP_PATH)]
    ebpf_path: String,

    /// Path to TC eBPF object file (uses embedded if not specified)
    #[clap(long, default_value = DEFAULT_TC_PATH)]
    tc_path: String,

    /// Disable TC egress program
    #[clap(long)]
    no_tc: bool,

    /// Load threat feeds on startup (Spamhaus, AbuseIPDB, Firehol)
    #[clap(long)]
    load_feeds: bool,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Load eBPF and enter interactive CLI
    Load,
    /// Interactive TUI dashboard
    Tui,
    /// Headless daemon mode
    Daemon,
    /// Save current blocklist
    Save {
        #[clap(short, long, default_value = "aegis.yaml")]
        file: String,
    },
    /// Show firewall runtime status
    Status,
    /// Restore blocklist from file
    Restore {
        #[clap(short, long, default_value = "aegis.yaml")]
        file: String,
    },
    /// Threat feed management
    Feeds {
        #[clap(subcommand)]
        action: FeedsAction,
    },
    /// Manage Allowlist
    Allow {
        #[clap(subcommand)]
        action: AllowAction,
    },
    /// Generate shell completions
    Completions {
        /// Target shell: bash, zsh, fish, elvish
        #[clap(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Generate man page
    Manpage {
        /// Output directory for man page
        #[clap(default_value = ".")]
        dir: String,
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

#[derive(Subcommand)]
enum AllowAction {
    /// Add IP to allowlist
    Add {
        /// IP address to allow
        ip: IpAddr,
    },
    /// Remove IP from allowlist
    Remove {
        /// IP address to remove
        ip: IpAddr,
    },
    /// List allowed IPs
    List,
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

// ============================================================
// eBPF LOADING (Embedded or File)
// ============================================================

/// Load XDP eBPF program - uses embedded bytecode if available and path is default
fn load_xdp_program(path: &str) -> Result<Ebpf, anyhow::Error> {
    // If embedded and using default path, use embedded bytecode
    #[cfg(embedded_xdp)]
    if path == DEFAULT_XDP_PATH {
        log::debug!("Loading embedded XDP program ({} bytes)", EMBEDDED_XDP.len());
        println!("📦 Loading embedded XDP program");
        return Ok(EbpfLoader::new().load(EMBEDDED_XDP)?);
    }

    // Otherwise load from file
    if Path::new(path).exists() {
        println!("📁 Loading XDP program from: {}", path);
        Ok(Ebpf::load_file(path)?)
    } else {
        #[cfg(embedded_xdp)]
        {
            println!("⚠️  File {} not found, using embedded XDP", path);
            return Ok(EbpfLoader::new().load(EMBEDDED_XDP)?);
        }
        #[cfg(not(embedded_xdp))]
        {
            anyhow::bail!("XDP program not found at {} and no embedded bytecode available", path);
        }
    }
}

/// Load TC eBPF program - uses embedded bytecode if available and path is default
fn load_tc_program(path: &str) -> Result<Ebpf, anyhow::Error> {
    // If embedded and using default path, use embedded bytecode
    #[cfg(embedded_tc)]
    if path == DEFAULT_TC_PATH {
        println!("📦 Loading embedded TC program ({} bytes)", EMBEDDED_TC.len());
        return Ok(EbpfLoader::new().load(EMBEDDED_TC)?);
    }

    // Otherwise load from file
    if Path::new(path).exists() {
        println!("📁 Loading TC program from: {}", path);
        Ok(Ebpf::load_file(path)?)
    } else {
        #[cfg(embedded_tc)]
        {
            println!("⚠️  File {} not found, using embedded TC", path);
            return Ok(EbpfLoader::new().load(EMBEDDED_TC)?);
        }
        #[cfg(not(embedded_tc))]
        {
            anyhow::bail!("TC program not found at {} and no embedded bytecode available", path);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // Initialize tracing subscriber (skip in TUI mode — stderr is redirected)
    if !matches!(opt.command, Commands::Tui) {
        use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        if matches!(opt.command, Commands::Daemon) {
            // Daemon mode: structured JSON output for SIEM/log aggregation
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_target(true).with_thread_ids(true))
                .with(tracing_log::LogTracer::init().ok().and(None::<fmt::Layer<_>>))
                .init();
        } else {
            // CLI mode: human-readable compact output
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().compact().with_target(false))
                .init();
        }
        // Bridge aya-log (uses `log` crate) into tracing
        let _ = tracing_log::LogTracer::init();
    }

    // Validate interface name (IFNAMSIZ = 16, including null terminator → max 15 chars)
    if opt.iface.len() > 15
        || opt.iface.is_empty()
        || !opt.iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!("❌ Invalid interface name: '{}' (max 15 chars, alphanumeric/-/_ only)", opt.iface);
        std::process::exit(1);
    }

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
        tracing::warn!(error = ret, "failed to set memlock limit");
    }

    // Kernel compatibility check (for eBPF commands)
    if matches!(opt.command, Commands::Load | Commands::Tui | Commands::Daemon) {
        let caps = compat::KernelCaps::detect();
        if !matches!(opt.command, Commands::Tui) {
            caps.print_summary();
        }
        if let Err(e) = caps.validate() {
            eprintln!("\n❌ KERNEL REQUIREMENTS NOT MET:\n{}", e);
            eprintln!("\nAegis requires Linux kernel >= {}.{} with BPF support.",
                compat::MIN_KERNEL_VERSION.0, compat::MIN_KERNEL_VERSION.1);
            std::process::exit(1);
        }
    }

    // Load rule config (YAML — blocklist rules)
    let config_path = "aegis.yaml";
    let cfg = config::Config::load(config_path).unwrap_or_else(|_| config::Config { rules: vec![], remote_log: None, blocked_countries: vec![] });

    // Load system config (TOML — /etc/aegis/config.toml)
    let sys_cfg = config::AegisConfig::load(None);

    // Handle Completions command early (no eBPF needed)
    if let Commands::Completions { shell } = &opt.command {
        let mut cmd = Opt::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(*shell, &mut cmd, name, &mut std::io::stdout());
        return Ok(());
    }

    // Handle Manpage command early (no eBPF needed)
    if let Commands::Manpage { dir } = &opt.command {
        let cmd = Opt::command();
        let name = cmd.get_name().to_string();
        let man = clap_mangen::Man::new(cmd);
        let mut buffer: Vec<u8> = Default::default();
        man.render(&mut buffer)?;
        let out_path = std::path::Path::new(dir).join(format!("{}.1", name));
        std::fs::write(&out_path, buffer)?;
        println!("✅ Man page generated at {}", out_path.display());
        return Ok(());
    }

    // Handle Allow command early (no eBPF needed)
    if let Commands::Allow { action } = &opt.command {
        handle_allow_command(action)?;
        return Ok(());
    }

    // Handle Status command early (needs pinned maps)
    if let Commands::Status = &opt.command {
        handle_status_command()?;
        return Ok(());
    }

    // Handle Feeds command early (no eBPF needed)
    if let Commands::Feeds { action } = &opt.command {
        match action {
            FeedsAction::Update => {
                println!("🔄 Updating threat feeds...\n");
                let configs = feeds::FeedConfig::from_config(&cfg);
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
                for config in feeds::FeedConfig::from_config(&cfg) {
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
                let configs = feeds::FeedConfig::from_config(&cfg);
                match feeds::load_feeds_to_map(&mut cidr_map, &configs) {
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
    // Try embedded bytecode first, fallback to file
    let mut bpf = load_xdp_program(&opt.ebpf_path)?;
    
    // Common setup for Load, Tui, and Daemon
    match opt.command {
        Commands::Load | Commands::Tui | Commands::Daemon => {
            let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
            program.load()?;

            // XDP attach with automatic fallback: Driver Mode -> SKB Mode
            let _link_id = match program.attach(&opt.iface, XdpFlags::default()) {
                Ok(id) => {
                    tracing::info!(iface = %opt.iface, link_id = ?id, mode = "driver", "XDP attached");
                    id
                }
                Err(driver_err) => {
                    // Driver mode failed (common for virtual/wireless interfaces)
                    // Fallback to SKB (generic) mode
                    tracing::info!(iface = %opt.iface, "driver mode unavailable, falling back to SKB");
                    match program.attach(&opt.iface, XdpFlags::SKB_MODE) {
                        Ok(id) => {
                            tracing::info!(iface = %opt.iface, link_id = ?id, mode = "skb", "XDP attached");
                            id
                        }
                        Err(skb_err) => {
                            tracing::error!(iface = %opt.iface, driver_err = %driver_err, skb_err = %skb_err, "XDP attach failed on both modes");
                            return Err(skb_err.into());
                        }
                    }
                }
            };

            // Pin maps for external tools (status, allow CLI)
            let _ = std::fs::create_dir_all("/sys/fs/bpf/aegis");
            let maps_to_pin = [
                "BLOCKLIST", "ALLOWLIST", "STATS", "CONFIG", 
                "BLOCKLIST_IPV6", "ALLOWLIST_IPV6", "CIDR_BLOCKLIST",
                "CIDR_BLOCKLIST_IPV6", "CONN_TRACK", "CONN_TRACK_IPV6"
            ];
            for mark in maps_to_pin {
                if let Some(map) = bpf.map_mut(mark) {
                    let path = format!("/sys/fs/bpf/aegis/{}", mark);
                    let _ = std::fs::remove_file(&path); // Force overwrite
                    if let Err(e) = map.pin(&path) {
                        tracing::warn!(map = mark, error = %e, "failed to pin BPF map");
                    }
                }
            }

            // --- TC EGRESS PROGRAM ---
            let mut tc_bpf: Option<Ebpf> = None;
            if !opt.no_tc {
                match load_tc_program(&opt.tc_path) {
                    Ok(mut tc) => {
                        // Add clsact qdisc (required for TC)
                        if let Err(e) = tc::qdisc_add_clsact(&opt.iface) {
                            // Ignore "already exists" error
                            if !e.to_string().contains("exists") {
                                tracing::warn!(error = %e, "TC qdisc setup warning");
                            }
                        }

                        // Load and attach TC egress program
                        let tc_prog: &mut SchedClassifier = tc.program_mut("tc_egress")
                            .expect("tc_egress not found")
                            .try_into()?;
                        tc_prog.load()?;
                        tc_prog.attach(&opt.iface, TcAttachType::Egress)?;
                        tracing::info!(iface = %opt.iface, "TC egress attached");
                        tc_bpf = Some(tc);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "TC program not loaded, egress filtering disabled");
                    }
                }
            } else {
                tracing::info!("TC egress program disabled (--no-tc)");
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
            
            // Keys 1-7: Defense modules (from config.toml)
            config.insert(aegis_common::CFG_PORT_SCAN, sys_cfg.modules.port_scan as u32, 0)?;
            config.insert(aegis_common::CFG_RATE_LIMIT, sys_cfg.modules.rate_limit as u32, 0)?;
            config.insert(aegis_common::CFG_THREAT_FEEDS, sys_cfg.modules.threat_feeds as u32, 0)?;
            config.insert(aegis_common::CFG_CONN_TRACK, sys_cfg.modules.conn_track as u32, 0)?;
            config.insert(aegis_common::CFG_SCAN_DETECT, sys_cfg.modules.scan_detect as u32, 0)?;
            
            // Logging and Entropy
            config.insert(aegis_common::CFG_VERBOSE, sys_cfg.modules.verbose as u32, 0)?;
            config.insert(aegis_common::CFG_ENTROPY, sys_cfg.modules.entropy as u32, 0)?;
            
            let config_arc = Arc::new(Mutex::new(config));

            // Populate Allowlist from config
            if let Some(map) = bpf.take_map("ALLOWLIST") {
                let mut allowlist: HashMap<_, u32, u32> = HashMap::try_from(map)?;
                for ip_str in &sys_cfg.allowlist.ips {
                    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                        let key = u32::from(ip).to_be();
                        let _ = allowlist.insert(key, 0, 0);
                        println!("✅ Allowed IPv4: {}", ip);
                    }
                }
            }

            if let Some(map) = bpf.take_map("ALLOWLIST_IPV6") {
                let mut allowlist6: HashMap<_, [u8; 16], u32> = HashMap::try_from(map)?;
                for ip_str in &sys_cfg.allowlist.ips {
                     if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                        let key = ip.octets();
                        let _ = allowlist6.insert(key, 0, 0);
                        println!("✅ Allowed IPv6: {}", ip);
                     }
                }
            }

            // Load threat feeds if requested
            if opt.load_feeds {
                println!("📡 Loading threat feeds into CIDR blocklist...");
                let cidr_map = bpf.take_map("CIDR_BLOCKLIST").expect("CIDR_BLOCKLIST not found");
                let mut cidr: aya::maps::LpmTrie<_, aegis_common::LpmKeyIpv4, aegis_common::CidrBlockEntry> =
                    aya::maps::LpmTrie::try_from(cidr_map)?;
                let configs = feeds::FeedConfig::from_config(&cfg);
                match feeds::load_feeds_to_map(&mut cidr, &configs) {
                    Ok(count) => println!("✅ Loaded {} IPs from threat feeds", count),
                    Err(e) => println!("⚠️  Feed loading error: {}", e),
                }
            }

            // Take ownership of STATS for health metrics
            let stats_map = bpf.take_map("STATS").expect("STATS map not found");
            let stats: aya::maps::PerCpuArray<_, aegis_common::Stats> = aya::maps::PerCpuArray::try_from(stats_map)?;
            let stats_arc = Arc::new(Mutex::new(stats));
            
            // Shared Logs
            let logs_arc = Arc::new(Mutex::new(VecDeque::new()));

            // Take ownership of EVENTS (IPv4)
            let events_map = bpf.take_map("EVENTS").expect("EVENTS map not found");
            let mut events = AsyncPerfEventArray::try_from(events_map)?;

            // Take ownership of EVENTS_IPV6
            let events_ipv6_map = bpf.take_map("EVENTS_IPV6").expect("EVENTS_IPV6 map not found");
            let mut events_ipv6 = AsyncPerfEventArray::try_from(events_ipv6_map)?;

            // Setup event logging futures
            let mut event_futures = FuturesUnordered::new();
            let cpus = online_cpus().map_err(|(_, e)| e)?;
            
            let logs_clone = logs_arc.clone();
            let remote_log_base = cfg.remote_log.clone();
            let logging_cfg = sys_cfg.logging.clone(); // Pass logging config
            let blocklist_clone = blocklist_arc.clone(); // Clone for event loop

            for cpu_id in cpus {
                let mut buf = events.open(cpu_id, None)?;
                let logs_inner = logs_clone.clone();
                let remote_log = remote_log_base.clone();
                let _logging_cfg_inner = logging_cfg.clone();
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

                                    // Remote Logging (JSON) — UDP, not stdout
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
                                    // Push to shared log deque (TUI reads this, REPL printer prints this)
                                    {
                                        let mut logs = logs_inner.lock().unwrap();
                                        if logs.len() >= 100 { logs.pop_front(); }
                                        let full_msg = format!("{} | Reason: {} | Action: {}", msg, reason_str, if log.action == 1 { "DROP" } else { "PASS" });
                                        logs.push_back(full_msg);
                                    }

                                    // --- DYNAMIC AUTO-BAN (OODA Loop) ---
                                    // Auto-ban on SYN FLOOD or PORT SCAN (with cap + dedup)
                                    if log.threat_type == THREAT_FLOOD_SYN || log.threat_type == THREAT_SCAN_PORT {
                                        let mut blocklist = blocklist_inner.lock().unwrap();
                                        let key = FlowKey {
                                            src_ip: log.src_ip, // Already Network Byte Order from eBPF
                                            dst_port: 0,           // Wildcard port
                                            proto: 0,              // Wildcard proto
                                            _pad: 0,
                                        };
                                        // Skip if already banned (dedup)
                                        if blocklist.get(&key, 0).is_ok() {
                                            // Already banned, skip
                                        } else {
                                            // Cap: don't auto-ban beyond 512 entries to prevent map exhaustion
                                            const AUTO_BAN_MAX: usize = 512;
                                            let ban_count = blocklist.keys().count();
                                            if ban_count >= AUTO_BAN_MAX {
                                                let mut logs = logs_inner.lock().unwrap();
                                                logs.push_back(format!("⚠️ AUTO-BAN LIMIT ({}) reached, skipping {}", AUTO_BAN_MAX, src_ip));
                                            } else if let Err(e) = blocklist.insert(key, 2, 0) {
                                                let mut logs = logs_inner.lock().unwrap();
                                                logs.push_back(format!("❌ AUTO-BAN FAILED for {}: {}", src_ip, e));
                                            } else {
                                                let mut logs = logs_inner.lock().unwrap();
                                                logs.push_back(format!("⛔ AUTO-BANNED {} (OODA Trigger)", src_ip));
                                            }
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

            // --- IPv6 EVENT LOOP ---
            let logs_clone_v6 = logs_arc.clone();
            let logging_cfg_v6 = sys_cfg.logging.clone(); // Config for IPv6 loop
            let cpus_v6 = online_cpus().map_err(|(_, e)| e)?;

            for cpu_id in cpus_v6 {
                let mut buf = events_ipv6.open(cpu_id, None)?;
                let logs_inner = logs_clone_v6.clone();
                let _logging_cfg_inner = logging_cfg_v6.clone();

                tokio::spawn(async move {
                    let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
                    loop {
                        match buf.read_events(&mut buffers).await {
                            Ok(events) => {
                                for i in 0..events.read {
                                    let buf = &mut buffers[i];
                                    let ptr = buf.as_ptr() as *const PacketLogIpv6;
                                    let log = unsafe { ptr.read_unaligned() };

                                    // Convert IPv6 bytes to Ipv6Addr for display
                                    let src_ip = Ipv6Addr::from(log.src_ip);
                                    let dst_ip = Ipv6Addr::from(log.dst_ip);

                                    // Format IPv6 threat type
                                    let threat_str = match log.threat_type {
                                        THREAT_IPV6_EXT_CHAIN => "IPv6_EXT_CHAIN",
                                        THREAT_IPV6_ROUTING_TYPE0 => "IPv6_ROUTING_TYPE0",
                                        THREAT_IPV6_FRAGMENT => "IPv6_FRAGMENT",
                                        THREAT_IPV6_HOP_BY_HOP => "IPv6_HOP_BY_HOP",
                                        THREAT_SCAN_XMAS => "XMAS_SCAN",
                                        THREAT_SCAN_NULL => "NULL_SCAN",
                                        THREAT_SCAN_SYNFIN => "SYNFIN_SCAN",
                                        THREAT_BLOCKLIST => "BLOCKLIST",
                                        _ => "NONE",
                                    };

                                    let msg = match log.threat_type {
                                        THREAT_IPV6_EXT_CHAIN => format!(
                                            "⛓️ IPv6 EXT CHAIN ATTACK: {} ({} hdrs)", src_ip, log.ext_hdr_count),
                                        THREAT_IPV6_ROUTING_TYPE0 => format!(
                                            "🚨 IPv6 TYPE0 ROUTING (deprecated): {}", src_ip),
                                        THREAT_IPV6_FRAGMENT => format!(
                                            "💥 IPv6 FRAGMENT ATTACK: {} -> {}", src_ip, dst_ip),
                                        THREAT_IPV6_HOP_BY_HOP => format!(
                                            "🔗 IPv6 HOP-BY-HOP MISUSE: {}", src_ip),
                                        THREAT_SCAN_XMAS => format!(
                                            "🎄 IPv6 XMAS SCAN: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        THREAT_SCAN_NULL => format!(
                                            "⚫ IPv6 NULL SCAN: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        THREAT_SCAN_SYNFIN => format!(
                                            "💀 IPv6 SYNFIN: {} -> {}:{}", src_ip, dst_ip, log.dst_port),
                                        THREAT_BLOCKLIST => format!(
                                            "🚫 IPv6 BLOCKED: {} ({})", src_ip, threat_str),
                                        _ => format!(
                                            "🌐 IPv6: {} -> {}:{} [{}]", src_ip, dst_ip, log.dst_port, threat_str),
                                    };

                                    // Push to shared log deque only — no stdout
                                    {
                                        let mut logs = logs_inner.lock().unwrap();
                                        if logs.len() >= 100 { logs.pop_front(); }
                                        logs.push_back(msg);
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            // Initialize GeoIP database
            let geo_db = geo::GeoLookup::open().map(Arc::new);

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

                tui::run_tui(blocklist_arc.clone(), logs_arc.clone(), config_arc.clone(), stats_arc.clone(), geo_db.clone()).await?;
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

                // Stdout log printer for daemon mode
                let logs_printer = logs_arc.clone();
                tokio::spawn(async move {
                    let mut last_len = 0;
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        let logs = logs_printer.lock().unwrap();
                        if logs.len() > last_len {
                            for i in last_len..logs.len() {
                                println!("{}", logs[i]);
                            }
                            last_len = logs.len();
                        }
                    }
                });
                
                tracing::info!(iface = %opt.iface, "daemon mode active, send SIGTERM or SIGINT to stop");

                // Spawn Prometheus metrics endpoint
                match metrics::spawn_metrics_server(None).await {
                    Ok(addr) => tracing::info!(%addr, "prometheus /metrics endpoint started"),
                    Err(e) => tracing::warn!(error = %e, "failed to start metrics endpoint (non-fatal)"),
                }

                // Spawn DPI worker (reads DPI_EVENTS perf buffer)
                match dpi::spawn_dpi_worker(&mut bpf) {
                    Ok(()) => tracing::info!("DPI suspect queue worker active"),
                    Err(e) => tracing::warn!(error = %e, "DPI worker not started (non-fatal)"),
                }
                
                // Handle both SIGTERM (systemd) and SIGINT (Ctrl+C)
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to create SIGTERM handler");
                    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to create SIGINT handler");
                    
                    tokio::select! {
                        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
                        _ = sigint.recv() => tracing::info!("received SIGINT"),
                    }
                }
                #[cfg(not(unix))]
                {
                    signal::ctrl_c().await?;
                }
                
                tracing::info!(iface = %iface_for_shutdown, "detaching programs");
                drop(tc_bpf);  // TC first
                drop(bpf);     // Then XDP
                tracing::info!("shutdown complete");
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
            unreachable!("Feeds command should be handled before eBPF loading");
        }
        Commands::Completions { .. } => {
            unreachable!("Completions command should be handled before eBPF loading");
        }
        Commands::Status | Commands::Allow { .. } => {}
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
            let cfg = config::Config { rules, remote_log: None, blocked_countries: vec![] };
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

fn handle_allow_command(action: &AllowAction) -> anyhow::Result<()> {
    // 1. Update config file (Persistent)
    let mut cfg = config::AegisConfig::load(None);
    let mut updated = false;

    match action {
        AllowAction::Add { ip } => {
            let ip_str = ip.to_string();
            if !cfg.allowlist.ips.contains(&ip_str) {
                cfg.allowlist.ips.push(ip_str.clone());
                updated = true;
                println!("✅ Added {} to config allowlist", ip);
            } else {
                println!("ℹ️  IP {} already in config allowlist", ip);
            }
        }
        AllowAction::Remove { ip } => {
            let ip_str = ip.to_string();
            if let Some(pos) = cfg.allowlist.ips.iter().position(|x| x == &ip_str) {
                cfg.allowlist.ips.remove(pos);
                updated = true;
                println!("✅ Removed {} from config allowlist", ip);
            } else {
                println!("ℹ️  IP {} not found in config allowlist", ip);
            }
        }
        AllowAction::List => {
            if cfg.allowlist.ips.is_empty() {
                println!("Allowlist is empty.");
            } else {
                println!("Allowed IPs (Config):");
                for ip in &cfg.allowlist.ips {
                    println!("  - {}", ip);
                }
            }
            return Ok(()); // List doesn't update map
        }
    }

    if updated {
        if let Err(e) = cfg.save(None) {
            eprintln!("❌ Failed to save config: {}", e);
        } else {
            println!("💾 Config saved to /etc/aegis/config.toml");
        }
    }

    // 2. Update runtime BPF Map (Dynamic)
    // Try to open pinned maps
    let map_path = "/sys/fs/bpf/aegis/ALLOWLIST";
    let map_path_v6 = "/sys/fs/bpf/aegis/ALLOWLIST_IPV6";

    // IPv4 Map Update
    if let Ok(md) = MapData::from_pin(map_path) {
        let map = Map::HashMap(md);
        if let Ok(mut hash_map) = HashMap::try_from(map) {
                if let AllowAction::Add { ip: IpAddr::V4(ipv4) } = action {
                     let key = u32::from(*ipv4).to_be();
                     let _ = hash_map.insert(key, 0, 0);
                     println!("⚡ Runtime map updated (IPv4 allowed)");
                } else if let AllowAction::Remove { ip: IpAddr::V4(ipv4) } = action {
                     let key = u32::from(*ipv4).to_be();
                     let _ = hash_map.remove(&key);
                }
            }
        }


    // IPv6 Map Update
    if let Ok(md) = MapData::from_pin(map_path_v6) {
        let map = Map::HashMap(md);
        if let Ok(mut hash_map) = HashMap::try_from(map) {
                if let AllowAction::Add { ip: IpAddr::V6(ipv6) } = action {
                     let key = ipv6.octets();
                     let _ = hash_map.insert(key, 0, 0);
                     println!("⚡ Runtime map updated (IPv6 allowed)");
                } else if let AllowAction::Remove { ip: IpAddr::V6(ipv6) } = action {
                     let key = ipv6.octets();
                     let _ = hash_map.remove(&key);
                }
            }
        }


    Ok(())
}

fn handle_status_command() -> anyhow::Result<()> {
    // 1. Read STATS map (pinned)
    let map_path = "/sys/fs/bpf/aegis/STATS";
    use aya::maps::PerCpuArray;

    // Load map from path
    let map = match aya::maps::MapData::from_pin(map_path) {
        Ok(md) => aya::maps::Map::PerCpuArray(md),
        Err(_) => {
            println!("❌ Aegis is not running (maps not found at {})", map_path);
            return Ok(());
        }
    };
    let array = PerCpuArray::<_, Stats>::try_from(map).map_err(|e| anyhow::anyhow!("Failed into PerCpuArray: {}", e))?;

    // Aggregate stats
    // Aggregate stats
    let mut total = Stats::default();

    // Get values at index 0 from the PERCPU_ARRAY. 
    // This returns a collection of values, one for each CPU.
    if let Ok(values) = array.get(&0, 0) {
        for stat in values.iter() {
           total.pkts_seen += stat.pkts_seen;
           total.pkts_drop += stat.pkts_drop;
           total.pkts_pass += stat.pkts_pass;
           total.events_ok += stat.events_ok;
           total.events_fail += stat.events_fail;
           total.block_manual += stat.block_manual;
           total.block_cidr += stat.block_cidr;
           total.portscan_hits += stat.portscan_hits;
           total.conntrack_hits += stat.conntrack_hits;
        }
    }


    // 2. Read BLOCKLIST count
    let block_path = "/sys/fs/bpf/aegis/BLOCKLIST";
    let block_count = if let Ok(md) = aya::maps::MapData::from_pin(block_path) {
         let map = aya::maps::Map::HashMap(md);
         if let Ok(hm) = HashMap::<_, u32, u32>::try_from(map) {
                 hm.keys().count()
             } else { 0 }
    } else { 0 };


    // 3. Display
    println!("🔥 Aegis Firewall Status 🔥");
    println!("---------------------------");
    println!("Packets Seen:    {}", total.pkts_seen);
    println!("Packets Dropped: {}", total.pkts_drop);
    println!("Packets Passed:  {}", total.pkts_pass);
    println!("Blocklist Size:  {}", block_count);
    println!("Manual Blocks:   {}", total.block_manual);
    println!("CIDR Blocks:     {}", total.block_cidr);
    println!("Port Scans:      {}", total.portscan_hits);
    println!("Conntrack Hits:  {}", total.conntrack_hits);
    println!("Events (OK/Fail): {}/{}", total.events_ok, total.events_fail);

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(embedded_xdp)]
    use super::EMBEDDED_XDP;

    #[test]
    #[cfg(embedded_xdp)]
    fn test_embedded_xdp_elf_valid() {
        // Verify ELF magic
        assert!(EMBEDDED_XDP.len() >= 4, "Embedded XDP too small");
        assert_eq!(&EMBEDDED_XDP[0..4], &[0x7f, b'E', b'L', b'F'], "Invalid ELF magic");

        // Test parsing with object crate (same as aya uses internally)
        let result = object::read::File::parse(EMBEDDED_XDP);
        assert!(result.is_ok(), "Failed to parse embedded XDP: {:?}", result.err());

        let obj = result.unwrap();
        assert_eq!(obj.format(), object::BinaryFormat::Elf, "Not an ELF file");
    }

    #[test]
    #[cfg(embedded_tc)]
    fn test_embedded_tc_elf_valid() {
        use super::EMBEDDED_TC;
        // Verify ELF magic
        assert!(EMBEDDED_TC.len() >= 4, "Embedded TC too small");
        assert_eq!(&EMBEDDED_TC[0..4], &[0x7f, b'E', b'L', b'F'], "Invalid ELF magic");

        // Test parsing with object crate
        let result = object::read::File::parse(EMBEDDED_TC);
        assert!(result.is_ok(), "Failed to parse embedded TC: {:?}", result.err());
    }

    /// Test that aya can parse the embedded XDP program
    /// Note: This does NOT load into the kernel (no root needed)
    #[test]
    #[cfg(embedded_xdp)]
    fn test_aya_parse_embedded_xdp() {
        use aya::EbpfLoader;
        // This will parse the ELF but NOT load into kernel
        // It should fail gracefully if BTF is missing, but the parse should succeed
        let result = EbpfLoader::new()
            .btf(None)  // Skip BTF to avoid kernel access
            .load(EMBEDDED_XDP);
        // This may fail for other reasons (no kernel access in tests),
        // but should NOT fail with "error parsing ELF data"
        match &result {
            Ok(_) => println!("Aya parse succeeded"),
            Err(e) => {
                let err_str = format!("{:?}", e);
                assert!(!err_str.contains("error parsing ELF data"),
                    "ELF parsing failed: {}", err_str);
                println!("Aya load failed (expected in tests without root): {}", e);
            }
        }
    }
}
