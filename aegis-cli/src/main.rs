mod alerts;
mod api_ratelimit;
mod cef_export;
mod command_handler;
mod compat;
mod config;
mod conntrack_gc;
mod dashboard;
mod dpi;
mod event_loop;
mod feeds;
pub mod fleet_client;
mod format;
mod geo;
mod hot_reload;
mod loader;
mod map_manager;
mod metrics;
mod pcap;
mod privilege;
mod reputation;
mod stats_history;
mod tls_fingerprint;
mod tui;
pub mod yara_engine;

use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use clap::{CommandFactory, Parser, Subcommand};
use std::collections::VecDeque;
use std::convert::TryInto;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{self, AsyncBufReadExt};
use tokio::signal;

use aegis_common::FlowKey;

// ============================================================
// EMBEDDED eBPF BYTECODE (Single Binary Distribution)
// ============================================================
// If compiled with eBPF objects present, they are embedded directly.
// Use --ebpf-path / --tc-path to override with external files.

#[cfg(embedded_xdp)]
pub static EMBEDDED_XDP: &[u8] = include_bytes!(env!("AEGIS_XDP_OBJ"));

#[cfg(embedded_tc)]
pub static EMBEDDED_TC: &[u8] = include_bytes!(env!("AEGIS_TC_OBJ"));

/// Default path for external eBPF objects
pub const DEFAULT_XDP_PATH: &str = "/usr/local/share/aegis/aegis.o";
pub const DEFAULT_TC_PATH: &str = "/usr/local/share/aegis/aegis-tc.o";

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
pub enum AllowAction {
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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // Initialize tracing subscriber (skip in TUI mode — stderr is redirected)
    if !matches!(opt.command, Commands::Tui) {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        if matches!(opt.command, Commands::Daemon) {
            // Daemon mode: structured JSON output for SIEM/log aggregation
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_target(true).with_thread_ids(true))
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
        || !opt
            .iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!(
            "❌ Invalid interface name: '{}' (max 15 chars, alphanumeric/-/_ only)",
            opt.iface
        );
        std::process::exit(1);
    }

    // Banner shown conditionally (not for TUI - it has its own header)
    if !matches!(opt.command, Commands::Tui) {
        println!(
            r#"
    ██████╗ ███████╗ ██████╗ ██╗███████╗
   ██╔═══██╗██╔════╝██╔════╝ ██║██╔════╝
   ████████║█████╗  ██║  ███╗██║███████╗
   ██╔═══██║██╔══╝  ██║   ██║██║╚════██║
   ██║   ██║███████╗╚██████╔╝██║███████║
   ╚═╝   ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
      eBPF FIREWALL :: SECURITY MATRIX
    "#
        );
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
    if matches!(
        opt.command,
        Commands::Load | Commands::Tui | Commands::Daemon
    ) {
        let caps = compat::KernelCaps::detect();
        if !matches!(opt.command, Commands::Tui) {
            caps.print_summary();
        }
        if let Err(e) = caps.validate() {
            eprintln!("\n❌ KERNEL REQUIREMENTS NOT MET:\n{}", e);
            eprintln!(
                "\nAegis requires Linux kernel >= {}.{} with BPF support.",
                compat::MIN_KERNEL_VERSION.0,
                compat::MIN_KERNEL_VERSION.1
            );
            std::process::exit(1);
        }
    }

    // Load rule config (YAML — blocklist rules)
    let config_path = "aegis.yaml";
    let cfg = config::Config::load(config_path).unwrap_or_else(|_| config::Config {
        rules: vec![],
        remote_log: None,
        blocked_countries: vec![],
    });

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
        command_handler::handle_allow_command(action)?;
        return Ok(());
    }

    // Handle Status command early (needs pinned maps)
    if let Commands::Status = &opt.command {
        command_handler::handle_status_command()?;
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
                    println!(
                        "     Update: every {}h\n",
                        config.update_interval_secs / 3600
                    );
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
                let mut cidr_map: aya::maps::LpmTrie<
                    _,
                    aegis_common::LpmKeyIpv4,
                    aegis_common::CidrBlockEntry,
                > = match aya::maps::LpmTrie::try_from(bpf.map_mut("CIDR_BLOCKLIST").unwrap()) {
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
    let mut bpf = loader::load_xdp_program(&opt.ebpf_path)?;

    // Common setup for Load, Tui, and Daemon
    match opt.command {
        Commands::Manpage { .. } => {
            log::info!("Manpage command not implemented here");
            return Ok(());
        }
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

            // Clean stale maps from previous SIGKILL'd instances
            if let Ok(entries) = std::fs::read_dir("/sys/fs/bpf/aegis") {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
                tracing::debug!("cleaned stale pinned maps from /sys/fs/bpf/aegis/");
            }

            let maps_to_pin = [
                "BLOCKLIST",
                "ALLOWLIST",
                "STATS",
                "CONFIG",
                "BLOCKLIST_IPV6",
                "ALLOWLIST_IPV6",
                "CIDR_BLOCKLIST",
                "CIDR_BLOCKLIST_IPV6",
                "CONN_TRACK",
                "CONN_TRACK_IPV6",
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
                match loader::load_tc_program(&opt.tc_path) {
                    Ok(mut tc) => {
                        // Add clsact qdisc (required for TC)
                        if let Err(e) = tc::qdisc_add_clsact(&opt.iface) {
                            // Ignore "already exists" error
                            if !e.to_string().contains("exists") {
                                tracing::warn!(error = %e, "TC qdisc setup warning");
                            }
                        }

                        // Load and attach TC egress program
                        let tc_prog: &mut SchedClassifier = tc
                            .program_mut("tc_egress")
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
            let config_arc = map_manager::setup_config_map(&mut bpf, &opt.iface, &sys_cfg)?;

            // Populate Allowlist from config
            map_manager::setup_allowlists(&mut bpf, &sys_cfg)?;

            // Load threat feeds if requested
            if opt.load_feeds {
                if let Err(e) = map_manager::load_threat_feeds(&mut bpf, &cfg) {
                    tracing::warn!("Failed to load threat feeds: {}", e);
                }
            }

            // Take ownership of STATS for health metrics
            let stats_map = bpf.take_map("STATS").expect("STATS map not found");
            let stats: aya::maps::PerCpuArray<_, aegis_common::Stats> =
                aya::maps::PerCpuArray::try_from(stats_map)?;
            let stats_arc = Arc::new(Mutex::new(stats));

            // Shared Logs
            let logs_arc = Arc::new(Mutex::new(VecDeque::new()));

            // --- SPAWN EVENT LOOPS ---
            let ctx = event_loop::EventLoopContext {
                logs_arc: logs_arc.clone(),
                blocklist_arc: blocklist_arc.clone(),
                remote_log_base: cfg.remote_log.clone(),
                logging_cfg: sys_cfg.logging.clone(),
                webhooks_cfg: sys_cfg.webhooks.clone(),
                pcap_on: sys_cfg.pcap.enabled,
            };
            event_loop::spawn_event_loops(&mut bpf, ctx)?;

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

                tui::run_tui(
                    blocklist_arc.clone(),
                    logs_arc.clone(),
                    config_arc.clone(),
                    stats_arc.clone(),
                    geo_db.clone(),
                )
                .await?;
                println!("\n🔌 Detaching programs from {}...", opt.iface);
                // Detach by dropping (forces cleanup)
                drop(tc_bpf); // TC first
                drop(bpf); // Then XDP
                println!("✅ Programs detached. Exiting Aegis...");
                return Ok(());
            } else if let Commands::Daemon = opt.command {
                // Daemon mode: no REPL, just run until SIGTERM/SIGINT
                let iface_for_shutdown = opt.iface.clone();

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

                // Freeze read-only maps (Anti-Tamper Layer 2)
                privilege::freeze_map("/sys/fs/bpf/aegis/STATS");
                privilege::freeze_map("/sys/fs/bpf/aegis/DPI_EVENTS");
                privilege::freeze_map("/sys/fs/bpf/aegis/EVENTS");
                privilege::freeze_map("/sys/fs/bpf/aegis/EVENTS_IPV6");

                // Drop privileges to non-root (Anti-Tamper Layer 1)
                if let Err(e) = privilege::drop_privileges() {
                    tracing::error!(
                        "🛑 Failed to drop privileges: {}. Running as root is a security risk!",
                        e
                    );
                }

                // Initialize CEF/Syslog export (if configured)
                if let Some(ref dest) = sys_cfg.logging.syslog_dest {
                    match cef_export::init_syslog(dest) {
                        Ok(()) => tracing::info!("📡 CEF syslog export active → {}", dest),
                        Err(e) => tracing::warn!(error = %e, "CEF syslog init failed (non-fatal)"),
                    }
                }

                // Initialize PCAP forensics capture (if configured)
                let pcap_enabled = sys_cfg.pcap.enabled;
                if pcap_enabled {
                    match pcap::init_pcap() {
                        Ok(path) => {
                            tracing::info!(path = %path.display(), "📼 PCAP forensic capture active")
                        }
                        Err(e) => tracing::warn!(error = %e, "PCAP init failed (non-fatal)"),
                    }
                }

                match metrics::spawn_metrics_server(None).await {
                    Ok(addr) => tracing::info!(%addr, "prometheus /metrics endpoint started"),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to start metrics endpoint (non-fatal)")
                    }
                }

                // Spawn config hot-reload watcher
                hot_reload::spawn_config_watcher("/etc/aegis/config.toml", "/etc/aegis/aegis.yaml");

                // Spawn historical stats collector
                stats_history::spawn_collector();

                // Spawn ConnTrack garbage collector (removes expired entries)
                conntrack_gc::spawn_gc_task();

                // Spawn Fleet Controller RPC Client (Aegis Tower Sync)
                let fleet_handle = fleet_client::FleetClient::spawn(sys_cfg.clone());

                // Spawn DPI worker (reads DPI_EVENTS perf buffer)
                let fleet_tx = fleet_handle.map(|h| h.event_tx);
                match dpi::spawn_dpi_worker(&mut bpf, &sys_cfg, fleet_tx) {
                    Ok(()) => tracing::info!("DPI suspect queue worker active (YARA enabled)"),
                    Err(e) => tracing::warn!(error = %e, "DPI worker not started (non-fatal)"),
                }

                // Handle both SIGTERM (systemd) and SIGINT (Ctrl+C)
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sigterm =
                        signal(SignalKind::terminate()).expect("Failed to create SIGTERM handler");
                    let mut sigint =
                        signal(SignalKind::interrupt()).expect("Failed to create SIGINT handler");

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
                // NOTE: pinned maps in /sys/fs/bpf/aegis/ survive shutdown.
                // They are cleaned on next startup (before new pins are created).
                // This is intentional — after privilege drop we can't unlink root-owned bpffs.
                drop(tc_bpf); // TC first
                drop(bpf); // Then XDP
                tracing::info!("shutdown complete");
                return Ok(());
            } else {
                // For Load command, we also need to poll events.
                // If we didn't run TUI, we still need the event loop.
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
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if !parts.is_empty() {
                                    let mut blocklist = blocklist_arc.lock().unwrap();
                                    command_handler::handle_command(&mut blocklist, parts)?;
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

#[cfg(test)]
mod tests {
    #[cfg(embedded_xdp)]
    use super::EMBEDDED_XDP;

    #[test]
    #[cfg(embedded_xdp)]
    fn test_embedded_xdp_elf_valid() {
        // Verify ELF magic
        assert!(EMBEDDED_XDP.len() >= 4, "Embedded XDP too small");
        assert_eq!(
            &EMBEDDED_XDP[0..4],
            &[0x7f, b'E', b'L', b'F'],
            "Invalid ELF magic"
        );

        // Test parsing with object crate (same as aya uses internally)
        let result = object::read::File::parse(EMBEDDED_XDP);
        assert!(
            result.is_ok(),
            "Failed to parse embedded XDP: {:?}",
            result.err()
        );

        let obj = result.unwrap();
        assert_eq!(obj.format(), object::BinaryFormat::Elf, "Not an ELF file");
    }

    #[test]
    #[cfg(embedded_tc)]
    fn test_embedded_tc_elf_valid() {
        use super::EMBEDDED_TC;
        // Verify ELF magic
        assert!(EMBEDDED_TC.len() >= 4, "Embedded TC too small");
        assert_eq!(
            &EMBEDDED_TC[0..4],
            &[0x7f, b'E', b'L', b'F'],
            "Invalid ELF magic"
        );

        // Test parsing with object crate
        let result = object::read::File::parse(EMBEDDED_TC);
        assert!(
            result.is_ok(),
            "Failed to parse embedded TC: {:?}",
            result.err()
        );
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
            .btf(None) // Skip BTF to avoid kernel access
            .load(EMBEDDED_XDP);
        // This may fail for other reasons (no kernel access in tests),
        // but should NOT fail with "error parsing ELF data"
        match &result {
            Ok(_) => println!("Aya parse succeeded"),
            Err(e) => {
                let err_str = format!("{:?}", e);
                assert!(
                    !err_str.contains("error parsing ELF data"),
                    "ELF parsing failed: {}",
                    err_str
                );
                println!("Aya load failed (expected in tests without root): {}", e);
            }
        }
    }
}
