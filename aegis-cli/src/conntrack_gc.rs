//! Connection Tracking Garbage Collector for Aegis eBPF Firewall
//!
//! Periodically scans the CONN_TRACK and CONN_TRACK_IPV6 BPF maps,
//! removing entries that have exceeded their timeout.
//!
//! Without GC, maps fill to max_entries (65536) and new connections
//! silently fail to be tracked, degrading firewall performance.
//!
//! Uses /proc/uptime to synchronize with bpf_ktime_get_ns() (both
//! use CLOCK_MONOTONIC, same epoch since boot).

use std::time::Duration;
use tracing::{debug, info, warn};

use aegis_common::{
    ConnTrackKey, ConnTrackState, CONN_ESTABLISHED, CONN_TIMEOUT_ESTABLISHED_NS,
    CONN_TIMEOUT_OTHER_NS,
};

/// GC interval — how often we scan for expired entries
const GC_INTERVAL_SECS: u64 = 30;

/// Maximum entries to remove per GC cycle (prevent stalls)
const MAX_REMOVALS_PER_CYCLE: usize = 4096;

/// Spawn the ConnTrack GC as a background tokio task.
pub fn spawn_gc_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(GC_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let v4_removed = gc_conntrack_v4();
            let v6_removed = gc_conntrack_v6();
            if v4_removed > 0 || v6_removed > 0 {
                debug!(
                    v4 = v4_removed,
                    v6 = v6_removed,
                    "ConnTrack GC cycle complete"
                );
            }
        }
    });
    info!(
        "🧹 ConnTrack GC task started ({}s interval)",
        GC_INTERVAL_SECS
    );
}

/// Get monotonic clock nanoseconds (same clock as bpf_ktime_get_ns)
fn get_ktime_ns() -> u64 {
    // /proc/uptime uses CLOCK_MONOTONIC — same as bpf_ktime_get_ns()
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .map(|secs| (secs * 1_000_000_000.0) as u64)
        .unwrap_or(0)
}

/// GC for IPv4 connection tracking map
fn gc_conntrack_v4() -> u32 {
    use aya::maps::HashMap;

    let path = "/sys/fs/bpf/aegis/CONN_TRACK";
    let Ok(md) = aya::maps::MapData::from_pin(path) else {
        return 0;
    };
    let map = aya::maps::Map::LruHashMap(md);
    let Ok(mut hm) = HashMap::<_, ConnTrackKey, ConnTrackState>::try_from(map) else {
        return 0;
    };

    let now_ns = get_ktime_ns();
    if now_ns == 0 {
        warn!("ConnTrack GC: failed to read /proc/uptime");
        return 0;
    }

    // Phase 1: Collect keys to remove (don't mutate while iterating)
    let mut keys_to_remove: Vec<ConnTrackKey> = Vec::with_capacity(256);

    for result in hm.iter() {
        if keys_to_remove.len() >= MAX_REMOVALS_PER_CYCLE {
            break; // Rate limit removals per cycle
        }
        if let Ok((key, state)) = result {
            let timeout = if state.state == CONN_ESTABLISHED {
                CONN_TIMEOUT_ESTABLISHED_NS
            } else {
                CONN_TIMEOUT_OTHER_NS
            };
            if now_ns.saturating_sub(state.last_seen) > timeout {
                keys_to_remove.push(key);
            }
        }
    }

    // Phase 2: Remove expired entries
    let mut removed = 0u32;
    for key in &keys_to_remove {
        if hm.remove(key).is_ok() {
            removed += 1;
        }
    }

    removed
}

/// GC for IPv6 connection tracking map
fn gc_conntrack_v6() -> u32 {
    use aegis_common::ConnTrackKeyIpv6;
    use aya::maps::HashMap;

    let path = "/sys/fs/bpf/aegis/CONN_TRACK_IPV6";
    let Ok(md) = aya::maps::MapData::from_pin(path) else {
        return 0;
    };
    let map = aya::maps::Map::LruHashMap(md);
    let Ok(mut hm) = HashMap::<_, ConnTrackKeyIpv6, ConnTrackState>::try_from(map) else {
        return 0;
    };

    let now_ns = get_ktime_ns();
    if now_ns == 0 {
        return 0;
    }

    let mut keys_to_remove: Vec<ConnTrackKeyIpv6> = Vec::with_capacity(256);

    for result in hm.iter() {
        if keys_to_remove.len() >= MAX_REMOVALS_PER_CYCLE {
            break;
        }
        if let Ok((key, state)) = result {
            let timeout = if state.state == CONN_ESTABLISHED {
                CONN_TIMEOUT_ESTABLISHED_NS
            } else {
                CONN_TIMEOUT_OTHER_NS
            };
            if now_ns.saturating_sub(state.last_seen) > timeout {
                keys_to_remove.push(key);
            }
        }
    }

    let mut removed = 0u32;
    for key in &keys_to_remove {
        if hm.remove(key).is_ok() {
            removed += 1;
        }
    }

    removed
}
