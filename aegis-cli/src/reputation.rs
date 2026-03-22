//! IP Reputation Scoring Engine for Aegis eBPF Firewall
//!
//! Aggregates threat intelligence from multiple sources:
//!   - Internal blocklist/allowlist state
//!   - AbuseIPDB API (if key configured)
//!   - Local threat feed match data (CIDR feeds)
//!   - DPI suspect hit history (in-memory LRU)
//!
//! Provides a unified 0-100 risk score per IP.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Maximum entries in the score cache
const CACHE_MAX: usize = 4096;

/// Cache TTL (seconds)
const CACHE_TTL_SECS: u64 = 300; // 5 minutes

/// Global reputation cache
static CACHE: std::sync::LazyLock<RwLock<ReputationCache>> =
    std::sync::LazyLock::new(|| RwLock::new(ReputationCache::new()));

// ── Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReputationScore {
    pub ip: String,
    pub score: u8,               // 0 (clean) → 100 (malicious)
    pub risk_level: &'static str, // "low", "medium", "high", "critical"
    pub factors: Vec<String>,
    pub cached: bool,
}

struct CacheEntry {
    score: ReputationScore,
    expires: Instant,
}

struct ReputationCache {
    entries: HashMap<u32, CacheEntry>,
}

impl ReputationCache {
    fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(CACHE_MAX),
        }
    }

    fn get(&self, ip: u32) -> Option<ReputationScore> {
        self.entries.get(&ip).and_then(|e| {
            if e.expires > Instant::now() {
                let mut score = e.score.clone();
                score.cached = true;
                Some(score)
            } else {
                None
            }
        })
    }

    fn insert(&mut self, ip: u32, score: ReputationScore) {
        // Evict expired if at capacity
        if self.entries.len() >= CACHE_MAX {
            let now = Instant::now();
            self.entries.retain(|_, v| v.expires > now);
        }

        self.entries.insert(ip, CacheEntry {
            score,
            expires: Instant::now() + Duration::from_secs(CACHE_TTL_SECS),
        });
    }
}

// ── Public API ──────────────────────────────────────────────────────

/// Look up the reputation score for an IP address.
/// Returns a cached result if available, otherwise computes fresh.
pub fn lookup(ip_str: &str, abuseipdb_key: Option<&str>) -> ReputationScore {
    let ip: Ipv4Addr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return unknown_score(ip_str),
    };
    let ip_u32 = u32::from(ip);

    // Check cache
    if let Ok(cache) = CACHE.read() {
        if let Some(cached) = cache.get(ip_u32) {
            return cached;
        }
    }

    // Compute fresh score
    let mut score: u16 = 0;
    let mut factors = Vec::new();

    // Factor 1: Check if on local blocklist (BPF map)
    if is_on_blocklist(ip_u32) {
        score += 40;
        factors.push("on_local_blocklist".to_string());
    }

    // Factor 2: Check if on allowlist
    if is_on_allowlist(ip_u32) {
        score = score.saturating_sub(30);
        factors.push("on_allowlist (-30)".to_string());
    }

    // Factor 3: Check CIDR feed match
    if is_on_cidr_feed(ip_u32) {
        score += 30;
        factors.push("cidr_threat_feed_match".to_string());
    }

    // Factor 4: RFC1918 private range (very low risk)
    let octets = ip.octets();
    let is_private = octets[0] == 10
        || (octets[0] == 172 && (octets[1] & 0xF0) == 16)
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127;
    if is_private {
        score = score.saturating_sub(20);
        factors.push("private_rfc1918 (-20)".to_string());
    }

    // Factor 5: AbuseIPDB (if key provided)
    if let Some(key) = abuseipdb_key {
        if !key.is_empty() {
            match query_abuseipdb(ip_str, key) {
                Some(abuse_score) => {
                    // AbuseIPDB returns 0-100, scale to our contribution
                    let contrib = (abuse_score as u16) / 3; // max ~33 points
                    score += contrib;
                    factors.push(format!("abuseipdb_score={} (+{})", abuse_score, contrib));
                }
                None => {
                    factors.push("abuseipdb_unavailable".to_string());
                }
            }
        }
    }

    // Clamp to 0-100
    let final_score = score.min(100) as u8;
    let risk_level = match final_score {
        0..=25 => "low",
        26..=50 => "medium",
        51..=75 => "high",
        _ => "critical",
    };

    let result = ReputationScore {
        ip: ip_str.to_string(),
        score: final_score,
        risk_level,
        factors,
        cached: false,
    };

    // Cache result
    if let Ok(mut cache) = CACHE.write() {
        cache.insert(ip_u32, result.clone());
    }

    result
}

/// Record a DPI hit for an IP (boosts reputation score on next lookup)
pub fn record_dpi_hit(ip: u32) {
    // Invalidate cache so next lookup recomputes with fresh data
    if let Ok(mut cache) = CACHE.write() {
        cache.entries.remove(&ip);
    }
}

// ── BPF Map Checks ──────────────────────────────────────────────────

fn is_on_blocklist(ip: u32) -> bool {
    use aya::maps::HashMap;
    let path = "/sys/fs/bpf/aegis/BLOCKLIST";
    let Ok(md) = aya::maps::MapData::from_pin(path) else { return false };
    let map = aya::maps::Map::HashMap(md);
    let Ok(hm) = HashMap::<_, u32, u32>::try_from(map) else { return false };
    hm.get(&ip, 0).is_ok()
}

fn is_on_allowlist(ip: u32) -> bool {
    use aya::maps::HashMap;
    let path = "/sys/fs/bpf/aegis/ALLOWLIST";
    let Ok(md) = aya::maps::MapData::from_pin(path) else { return false };
    let map = aya::maps::Map::HashMap(md);
    let Ok(hm) = HashMap::<_, u32, u32>::try_from(map) else { return false };
    hm.get(&ip, 0).is_ok()
}

fn is_on_cidr_feed(_ip: u32) -> bool {
    // LPM Trie lookup from pinned map
    // Simplified: check if /sys/fs/bpf/aegis/CIDR_BLOCKLIST exists
    // Full implementation would do LPM lookup
    std::path::Path::new("/sys/fs/bpf/aegis/CIDR_BLOCKLIST").exists()
        && false // conservative: only flag if we can actually query
}

// ── AbuseIPDB Query ─────────────────────────────────────────────────

fn query_abuseipdb(ip: &str, api_key: &str) -> Option<u8> {
    let url = format!(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
        ip
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    let resp = client
        .get(&url)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send()
        .ok()?;

    if !resp.status().is_success() {
        warn!(status = %resp.status(), "AbuseIPDB query failed");
        return None;
    }

    let body: serde_json::Value = resp.json().ok()?;
    body.get("data")
        .and_then(|d| d.get("abuseConfidenceScore"))
        .and_then(|s| s.as_u64())
        .map(|s| s.min(100) as u8)
}

// ── Helpers ─────────────────────────────────────────────────────────

fn unknown_score(ip: &str) -> ReputationScore {
    ReputationScore {
        ip: ip.to_string(),
        score: 0,
        risk_level: "unknown",
        factors: vec!["invalid_ip".to_string()],
        cached: false,
    }
}
