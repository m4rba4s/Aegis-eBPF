use aegis_common::{CidrBlockEntry, LpmKeyIpv4, LpmKeyIpv6, CAT_MANUAL};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    config.insert(aegis_common::CFG_DPI_ENABLED, sys_cfg.dpi.enabled as u32, 0)?;

    // Skip RFC1918/loopback whitelist on public-facing interfaces.
    // On non-loopback/non-virtual interfaces, RFC1918 sources are spoofed.
    let is_virtual = iface == "lo"
        || iface.starts_with("tun")
        || iface.starts_with("docker")
        || iface.starts_with("veth")
        || iface.starts_with("br-");
    let skip_wl: u32 = if !is_virtual { 1 } else { 0 };
    config.insert(aegis_common::CFG_SKIP_WHITELIST, skip_wl, 0)?;
    if skip_wl == 1 {
        tracing::info!(
            iface = iface,
            "RFC1918 whitelist DISABLED (public interface)"
        );
    }

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

enum ParsedCidr {
    V4 { addr: Ipv4Addr, prefix: u32 },
    V6 { addr: Ipv6Addr, prefix: u32 },
}

fn normalize_ipv4_cidr(addr: Ipv4Addr, prefix: u32) -> Ipv4Addr {
    let addr = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(addr & mask)
}

fn normalize_ipv6_cidr(addr: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    let mut bytes = addr.octets();
    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = (prefix % 8) as u8;

    if full_bytes < bytes.len() {
        if remaining_bits == 0 {
            bytes[full_bytes] = 0;
        } else {
            bytes[full_bytes] &= u8::MAX << (8 - remaining_bits);
        }
        let mut i = full_bytes + 1;
        while i < bytes.len() {
            bytes[i] = 0;
            i += 1;
        }
    }

    Ipv6Addr::from(bytes)
}

fn parse_egress_cidr(cidr: &str) -> Result<ParsedCidr, anyhow::Error> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("egress CIDR '{cidr}' is missing '/' prefix length"))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid egress CIDR prefix in '{cidr}': {e}"))?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid egress CIDR address in '{cidr}': {e}"))?;

    match ip {
        IpAddr::V4(addr) if prefix <= 32 => Ok(ParsedCidr::V4 {
            addr: normalize_ipv4_cidr(addr, prefix),
            prefix,
        }),
        IpAddr::V6(addr) if prefix <= 128 => Ok(ParsedCidr::V6 {
            addr: normalize_ipv6_cidr(addr, prefix),
            prefix,
        }),
        IpAddr::V4(_) => Err(anyhow::anyhow!(
            "invalid IPv4 egress CIDR prefix in '{cidr}': {prefix}"
        )),
        IpAddr::V6(_) => Err(anyhow::anyhow!(
            "invalid IPv6 egress CIDR prefix in '{cidr}': {prefix}"
        )),
    }
}

pub fn setup_egress_blocklists(
    tc_bpf: &mut Ebpf,
    cfg: &crate::config::Config,
) -> Result<(), anyhow::Error> {
    let drop_exact: Vec<IpAddr> = cfg
        .egress_rules
        .iter()
        .filter(|rule| rule.action.eq_ignore_ascii_case("drop"))
        .map(|rule| rule.ip)
        .collect();
    let drop_cidrs: Vec<ParsedCidr> = cfg
        .egress_cidrs
        .iter()
        .filter(|rule| rule.action.eq_ignore_ascii_case("drop"))
        .map(|rule| parse_egress_cidr(&rule.cidr))
        .collect::<Result<_, _>>()?;

    let has_v4_exact = drop_exact.iter().any(|ip| matches!(ip, IpAddr::V4(_)));
    let has_v6_exact = drop_exact.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
    let has_v4_cidr = drop_cidrs
        .iter()
        .any(|cidr| matches!(cidr, ParsedCidr::V4 { .. }));
    let has_v6_cidr = drop_cidrs
        .iter()
        .any(|cidr| matches!(cidr, ParsedCidr::V6 { .. }));

    if has_v4_exact {
        let map = tc_bpf
            .take_map("EGRESS_BLOCKLIST")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_BLOCKLIST map not found"))?;
        let mut egress: HashMap<_, u32, u32> = HashMap::try_from(map)?;
        for ip in &drop_exact {
            if let IpAddr::V4(ipv4) = ip {
                egress.insert(u32::from(*ipv4).to_be(), 1, 0)?;
            }
        }
    }

    if has_v6_exact {
        let map = tc_bpf
            .take_map("EGRESS_BLOCKLIST_IPV6")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_BLOCKLIST_IPV6 map not found"))?;
        let mut egress6: HashMap<_, [u8; 16], u32> = HashMap::try_from(map)?;
        for ip in &drop_exact {
            if let IpAddr::V6(ipv6) = ip {
                egress6.insert(ipv6.octets(), 1, 0)?;
            }
        }
    }

    let entry = CidrBlockEntry {
        category: CAT_MANUAL,
        _pad: [0u8; 3],
    };

    if has_v4_cidr {
        let map = tc_bpf
            .take_map("EGRESS_CIDR_BLOCKLIST")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR_BLOCKLIST map not found"))?;
        let mut cidr: LpmTrie<_, LpmKeyIpv4, CidrBlockEntry> = LpmTrie::try_from(map)?;
        for cidr_rule in &drop_cidrs {
            if let ParsedCidr::V4 { addr, prefix } = cidr_rule {
                let key = Key::new(
                    *prefix,
                    LpmKeyIpv4 {
                        addr: u32::from(*addr).to_be(),
                    },
                );
                cidr.insert(&key, entry, 0)?;
            }
        }
    }

    if has_v6_cidr {
        let map = tc_bpf
            .take_map("EGRESS_CIDR_BLOCKLIST_IPV6")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR_BLOCKLIST_IPV6 map not found"))?;
        let mut cidr6: LpmTrie<_, LpmKeyIpv6, CidrBlockEntry> = LpmTrie::try_from(map)?;
        for cidr_rule in &drop_cidrs {
            if let ParsedCidr::V6 { addr, prefix } = cidr_rule {
                let key = Key::new(
                    *prefix,
                    LpmKeyIpv6 {
                        addr: addr.octets(),
                    },
                );
                cidr6.insert(&key, entry, 0)?;
            }
        }
    }

    let loaded = drop_exact.len() + drop_cidrs.len();
    if loaded > 0 {
        tracing::info!(rules = loaded, "loaded TC egress blocklist policy");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_egress_cidr, ParsedCidr};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_egress_cidr_ipv4() {
        match parse_egress_cidr("203.0.113.0/24").unwrap() {
            ParsedCidr::V4 { addr, prefix } => {
                assert_eq!(addr, Ipv4Addr::new(203, 0, 113, 0));
                assert_eq!(prefix, 24);
            }
            ParsedCidr::V6 { .. } => panic!("expected IPv4 CIDR"),
        }
    }

    #[test]
    fn test_parse_egress_cidr_ipv6() {
        match parse_egress_cidr("2001:db8::/32").unwrap() {
            ParsedCidr::V6 { addr, prefix } => {
                assert_eq!(addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(prefix, 32);
            }
            ParsedCidr::V4 { .. } => panic!("expected IPv6 CIDR"),
        }
    }

    #[test]
    fn test_parse_egress_cidr_rejects_bad_prefix() {
        assert!(parse_egress_cidr("203.0.113.0/33").is_err());
        assert!(parse_egress_cidr("2001:db8::/129").is_err());
    }

    #[test]
    fn test_parse_egress_cidr_normalizes_host_bits() {
        match parse_egress_cidr("198.51.100.20/24").unwrap() {
            ParsedCidr::V4 { addr, prefix } => {
                assert_eq!(addr, Ipv4Addr::new(198, 51, 100, 0));
                assert_eq!(prefix, 24);
            }
            ParsedCidr::V6 { .. } => panic!("expected IPv4 CIDR"),
        }

        match parse_egress_cidr("2001:db8:dead:beef::20/48").unwrap() {
            ParsedCidr::V6 { addr, prefix } => {
                assert_eq!(addr, "2001:db8:dead::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(prefix, 48);
            }
            ParsedCidr::V4 { .. } => panic!("expected IPv6 CIDR"),
        }
    }
}
