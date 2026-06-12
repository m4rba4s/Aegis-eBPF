//! Config Hot-Reload for Aegis eBPF Firewall
//!
//! Watches `/etc/aegis/config.toml` and `aegis.yaml` for changes.
//! On change: re-parses config, validates, and applies:
//!   - Module toggles → BPF CONFIG map updates (zero downtime)
//!   - Blocklist rules → BPF BLOCKLIST map updates
//!
//! Uses tokio filesystem polling (portable across Linux kernels).

use std::path::Path;
use std::time::Duration;
use tokio::time;
use tracing::{error, info, warn};

use crate::config::AegisConfig;

/// Interval between filesystem polls (seconds)
const POLL_INTERVAL_SECS: u64 = 5;

/// Spawn the config hot-reload watcher as a background tokio task.
pub fn spawn_config_watcher(toml_path: &str, yaml_path: &str) {
    if std::env::var("AEGIS_ENABLE_HOT_RELOAD").ok().as_deref() != Some("1") {
        info!("hot reload disabled by default; set AEGIS_ENABLE_HOT_RELOAD=1 to enable");
        return;
    }
    let toml_path = toml_path.to_string();
    let yaml_path = yaml_path.to_string();

    tokio::spawn(async move {
        let mut last_toml_modified = get_modified(&toml_path);
        let mut last_yaml_modified = get_modified(&yaml_path);

        let mut interval = time::interval(Duration::from_secs(POLL_INTERVAL_SECS));

        loop {
            interval.tick().await;

            // Check TOML config
            let current_toml = get_modified(&toml_path);
            if current_toml != last_toml_modified {
                info!(path = %toml_path, "config change detected — reloading");
                last_toml_modified = current_toml;
                if let Err(e) = apply_toml_config(&toml_path) {
                    error!(error = %e, "TOML reload rejected; preserving last-known-good policy");
                }
            }

            // Check YAML rules
            let current_yaml = get_modified(&yaml_path);
            if current_yaml != last_yaml_modified {
                info!(path = %yaml_path, "rules change detected — reloading");
                last_yaml_modified = current_yaml;
                if let Err(e) = apply_yaml_rules(&yaml_path) {
                    error!(error = %e, "YAML reload rejected; preserving last-known-good policy");
                }
            }
        }
    });

    info!(
        "🔄 Config hot-reload watcher active (poll {}s)",
        POLL_INTERVAL_SECS
    );
}

/// Get file modification timestamp (returns 0 if file doesn't exist)
fn get_modified(path: &str) -> u64 {
    Path::new(path)
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Apply TOML config changes to BPF CONFIG map
fn apply_toml_config(path: &str) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(path)?;
    let cfg: AegisConfig = toml::from_str(&content)?;

    // Update BPF CONFIG map with module toggles
    use aegis_common::{
        CFG_CONN_TRACK, CFG_DPI_ENABLED, CFG_ENTROPY, CFG_PORT_SCAN, CFG_RATE_LIMIT,
        CFG_SCAN_DETECT, CFG_THREAT_FEEDS, CFG_VERBOSE,
    };
    use aya::maps::HashMap;

    let map_path = crate::map_manager::map_path("CONFIG");
    let md = match aya::maps::MapData::from_pin(&map_path) {
        Ok(md) => md,
        Err(e) => {
            warn!(error = %e, "cannot open CONFIG map for hot-reload");
            return Ok(());
        }
    };
    let map = aya::maps::Map::HashMap(md);
    let mut hm = match HashMap::<_, u32, u32>::try_from(map) {
        Ok(hm) => hm,
        Err(e) => {
            warn!(error = %e, "CONFIG map type error");
            return Ok(());
        }
    };
    // Snapshot the current state before any mutation so a failed reload can
    // restore the prior policy instead of leaving a partially applied update.
    let snapshot: Vec<(u32, u32)> = hm.iter().filter_map(|result| result.ok()).collect();

    let toggles: [(u32, bool); 8] = [
        (CFG_PORT_SCAN, cfg.modules.port_scan),
        (CFG_RATE_LIMIT, cfg.modules.rate_limit),
        (CFG_THREAT_FEEDS, cfg.modules.threat_feeds),
        (CFG_CONN_TRACK, cfg.modules.conn_track),
        (CFG_SCAN_DETECT, cfg.modules.scan_detect),
        (CFG_VERBOSE, cfg.modules.verbose),
        (CFG_ENTROPY, cfg.modules.entropy),
        (CFG_DPI_ENABLED, cfg.dpi.enabled),
    ];

    let mut updated = 0u32;
    for (key, enabled) in toggles {
        let val = if enabled { 1u32 } else { 0u32 };
        if let Err(e) = hm.insert(key, val, 0) {
            for (restore_key, restore_val) in snapshot.iter().copied() {
                let _ = hm.insert(restore_key, restore_val, 0);
            }
            return Err(e.into());
        }
        updated += 1;
    }

    info!(
        updated = updated,
        "BPF CONFIG map reloaded — {} module toggles applied", updated
    );
    Ok(())
}

/// Apply YAML rule changes to BPF BLOCKLIST map
fn apply_yaml_rules(path: &str) -> anyhow::Result<()> {
    let cfg = match crate::config::Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to parse YAML rules on reload");
            return Err(e);
        }
    };

    use aegis_common::FlowKey;
    use aya::maps::HashMap;

    let map_path = crate::map_manager::map_path("BLOCKLIST");
    let md = match aya::maps::MapData::from_pin(&map_path) {
        Ok(md) => md,
        Err(e) => {
            warn!(error = %e, "cannot open BLOCKLIST map for rule reload");
            return Ok(());
        }
    };
    let map = aya::maps::Map::HashMap(md);
    let mut hm = match HashMap::<_, FlowKey, u32>::try_from(map) {
        Ok(hm) => hm,
        Err(e) => {
            warn!(error = %e, "BLOCKLIST map type error");
            return Ok(());
        }
    };
    // The reload path is transactional at the map level: capture the current
    // contents first, then replace them as a unit and restore the snapshot on
    // any insertion failure.
    let snapshot: Vec<(FlowKey, u32)> = hm.iter().filter_map(|result| result.ok()).collect();
    let mut desired: Vec<(FlowKey, u32)> = Vec::new();

    for rule in &cfg.rules {
        if rule.action.to_lowercase() == "drop" {
            desired.push((
                FlowKey {
                    src_ip: u32::from(rule.ip).to_be(),
                    dst_port: rule.port,
                    proto: crate::config::parse_proto(&rule.proto),
                    _pad: 0,
                },
                1,
            ));
        }
    }

    let current_keys: Vec<FlowKey> = snapshot.iter().map(|(key, _)| *key).collect();
    for key in &current_keys {
        let _ = hm.remove(key);
    }

    let mut loaded = 0u32;
    let mut inserted: Vec<FlowKey> = Vec::new();
    for (key, value) in desired {
        if let Err(e) = hm.insert(key, value, 0) {
            for inserted_key in inserted.iter().rev() {
                let _ = hm.remove(inserted_key);
            }
            for (restore_key, restore_val) in snapshot.iter().copied() {
                let _ = hm.insert(restore_key, restore_val, 0);
            }
            return Err(e.into());
        }
        inserted.push(key);
        loaded += 1;
    }

    info!(
        rules = loaded,
        "BLOCKLIST reloaded — {} drop rules applied", loaded
    );
    Ok(())
}
