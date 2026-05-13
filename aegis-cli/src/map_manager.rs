use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use std::sync::{Arc, Mutex};

/// Type alias to reduce type complexity (clippy::type_complexity)
pub type ConfigMap = Arc<Mutex<HashMap<MapData, u32, u32>>>;

pub fn setup_config_map(
    bpf: &mut Ebpf,
    iface: &str,
    sys_cfg: &crate::config::AegisConfig,
) -> Result<ConfigMap, anyhow::Error> {
    let config_map = bpf
        .take_map("CONFIG")
        .ok_or_else(|| anyhow::anyhow!("CONFIG map not found"))?;
    let mut config: HashMap<_, u32, u32> = HashMap::try_from(config_map)?;

    // Key 0: Interface mode (L3 for WireGuard/tun, L2 for Ethernet)
    let mode: u32 = if iface.starts_with("wg") || iface.starts_with("tun") {
        println!("ℹ️  Setting L3 mode (raw IP) for interface: {}", iface);
        1
    } else {
        0
    };
    config.insert(0u32, mode, 0)?;

    // Keys 1-7: Defense modules (from config.toml)
    config.insert(
        aegis_common::CFG_PORT_SCAN,
        sys_cfg.modules.port_scan as u32,
        0,
    )?;
    config.insert(
        aegis_common::CFG_RATE_LIMIT,
        sys_cfg.modules.rate_limit as u32,
        0,
    )?;
    config.insert(
        aegis_common::CFG_THREAT_FEEDS,
        sys_cfg.modules.threat_feeds as u32,
        0,
    )?;
    config.insert(
        aegis_common::CFG_CONN_TRACK,
        sys_cfg.modules.conn_track as u32,
        0,
    )?;
    config.insert(
        aegis_common::CFG_SCAN_DETECT,
        sys_cfg.modules.scan_detect as u32,
        0,
    )?;

    // Logging and Entropy
    config.insert(aegis_common::CFG_VERBOSE, sys_cfg.modules.verbose as u32, 0)?;
    config.insert(aegis_common::CFG_ENTROPY, sys_cfg.modules.entropy as u32, 0)?;

    // DPI (Deep Packet Inspection) — TLS fingerprinting, YARA, entropy analysis
    config.insert(
        aegis_common::CFG_DPI_ENABLED,
        sys_cfg.dpi.enabled as u32,
        0,
    )?;

    // Skip RFC1918/loopback whitelist when running on lo/tun (for testing/VPN)
    let skip_wl: u32 = if iface == "lo" || iface.starts_with("tun") { 1 } else { 0 };
    config.insert(aegis_common::CFG_SKIP_WHITELIST, skip_wl, 0)?;

    Ok(Arc::new(Mutex::new(config)))
}

pub fn setup_allowlists(
    bpf: &mut Ebpf,
    sys_cfg: &crate::config::AegisConfig,
) -> Result<(), anyhow::Error> {
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
    Ok(())
}

pub fn load_threat_feeds(bpf: &mut Ebpf, cfg: &crate::config::Config) -> Result<(), anyhow::Error> {
    println!("📡 Loading threat feeds into CIDR blocklist...");
    let cidr_map = bpf
        .take_map("CIDR_BLOCKLIST")
        .ok_or_else(|| anyhow::anyhow!("CIDR_BLOCKLIST not found"))?;
    let mut cidr: aya::maps::LpmTrie<_, aegis_common::LpmKeyIpv4, aegis_common::CidrBlockEntry> =
        aya::maps::LpmTrie::try_from(cidr_map)?;
    let configs = crate::feeds::FeedConfig::from_config(cfg);
    match crate::feeds::load_feeds_to_map(&mut cidr, &configs) {
        Ok(count) => println!("✅ Loaded {} IPs from threat feeds", count),
        Err(e) => println!("⚠️  Feed loading error: {}", e),
    }
    Ok(())
}
