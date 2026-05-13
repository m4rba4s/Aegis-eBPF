use crate::config;
use crate::AllowAction;
use aegis_common::{FlowKey, Stats};
use aya::maps::{HashMap, Map, MapData};
use std::net::{IpAddr, Ipv4Addr};

pub fn handle_command<T>(
    blocklist: &mut HashMap<T, FlowKey, u32>,
    parts: Vec<&str>,
) -> Result<(), anyhow::Error>
where
    T: std::borrow::BorrowMut<MapData>,
{
    let cmd = parts[0];
    match cmd {
        "block" | "unblock" => {
            if let Some(ip_str) = parts.get(1) {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    let port = parts
                        .get(2)
                        .and_then(|s| s.parse::<u16>().ok())
                        .unwrap_or(0);
                    let proto = parts.get(3).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);

                    let key = FlowKey {
                        src_ip: u32::from(ip).to_be(), // Network Byte Order
                        dst_port: port,                // Host Byte Order
                        proto,
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
                    advanced: config::AdvancedConfig::default(),
                    webhooks: config::WebhooksConfig::default(),
                });
            }
            let cfg = config::Config {
                rules,
                remote_log: None,
                blocked_countries: vec![],
            };
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

pub fn handle_allow_command(action: &AllowAction) -> anyhow::Result<()> {
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
            if let AllowAction::Add {
                ip: IpAddr::V4(ipv4),
            } = action
            {
                let key = u32::from(*ipv4).to_be();
                let _ = hash_map.insert(key, 0, 0);
                println!("⚡ Runtime map updated (IPv4 allowed)");
            } else if let AllowAction::Remove {
                ip: IpAddr::V4(ipv4),
            } = action
            {
                let key = u32::from(*ipv4).to_be();
                let _ = hash_map.remove(&key);
            }
        }
    }

    // IPv6 Map Update
    if let Ok(md) = MapData::from_pin(map_path_v6) {
        let map = Map::HashMap(md);
        if let Ok(mut hash_map) = HashMap::try_from(map) {
            if let AllowAction::Add {
                ip: IpAddr::V6(ipv6),
            } = action
            {
                let key = ipv6.octets();
                let _ = hash_map.insert(key, 0, 0);
                println!("⚡ Runtime map updated (IPv6 allowed)");
            } else if let AllowAction::Remove {
                ip: IpAddr::V6(ipv6),
            } = action
            {
                let key = ipv6.octets();
                let _ = hash_map.remove(&key);
            }
        }
    }

    Ok(())
}

pub fn handle_status_command() -> anyhow::Result<()> {
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
    let array = PerCpuArray::<_, Stats>::try_from(map)
        .map_err(|e| anyhow::anyhow!("Failed into PerCpuArray: {}", e))?;

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
        } else {
            0
        }
    } else {
        0
    };

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
    println!(
        "Events (OK/Fail): {}/{}",
        total.events_ok, total.events_fail
    );

    Ok(())
}
