//! Historical Stats Ring Buffer for Aegis Dashboard
//!
//! Maintains a 24-hour rolling window of firewall stats,
//! sampled every 10 seconds. Provides JSON time-series data
//! for dashboard charts via GET /api/history.
//!
//! In-memory only — no disk persistence (intentional for security).

use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Sampling interval
const SAMPLE_INTERVAL_SECS: u64 = 10;

/// 24 hours of 10-second samples = 8640 entries (~275 KB)
const MAX_SAMPLES: usize = 8640;

/// Global stats history ring buffer
static HISTORY: std::sync::LazyLock<RwLock<StatsHistory>> =
    std::sync::LazyLock::new(|| RwLock::new(StatsHistory::new()));

// ── Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatsSample {
    pub timestamp: u64,    // Unix epoch seconds
    pub pkts_seen: u64,
    pub pkts_pass: u64,
    pub pkts_drop: u64,
    pub blocks_manual: u64,
    pub blocks_cidr: u64,
    pub portscan_hits: u64,
    pub conntrack_hits: u64,
}

struct StatsHistory {
    samples: Vec<StatsSample>,
    head: usize,
    count: usize,
}

impl StatsHistory {
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(MAX_SAMPLES),
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, sample: StatsSample) {
        if self.samples.len() < MAX_SAMPLES {
            self.samples.push(sample);
            self.count = self.samples.len();
        } else {
            self.samples[self.head] = sample;
            self.head = (self.head + 1) % MAX_SAMPLES;
            self.count = MAX_SAMPLES;
        }
    }

    /// Get samples in chronological order, optionally limited to last N minutes
    fn get_samples(&self, last_minutes: Option<u64>) -> Vec<StatsSample> {
        if self.count == 0 {
            return Vec::new();
        }

        let cutoff = last_minutes.map(|m| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(m * 60)
        });

        let mut result = Vec::with_capacity(self.count);

        // Read in chronological order from the ring buffer
        let start = if self.samples.len() < MAX_SAMPLES { 0 } else { self.head };
        for i in 0..self.count {
            let idx = (start + i) % MAX_SAMPLES;
            let sample = &self.samples[idx];
            if let Some(cutoff_ts) = cutoff {
                if sample.timestamp >= cutoff_ts {
                    result.push(sample.clone());
                }
            } else {
                result.push(sample.clone());
            }
        }

        result
    }
}

// ── Public API ──────────────────────────────────────────────────────

/// Record a stats sample (called by metrics server on each scrape)
pub fn record_sample(
    pkts_seen: u64,
    pkts_pass: u64,
    pkts_drop: u64,
    blocks_manual: u64,
    blocks_cidr: u64,
    portscan_hits: u64,
    conntrack_hits: u64,
) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sample = StatsSample {
        timestamp: ts,
        pkts_seen,
        pkts_pass,
        pkts_drop,
        blocks_manual,
        blocks_cidr,
        portscan_hits,
        conntrack_hits,
    };

    if let Ok(mut history) = HISTORY.write() {
        history.push(sample);
    }
}

/// Get historical samples as JSON string.
/// `last_minutes`: None = all 24h, Some(60) = last hour, etc.
pub fn get_history_json(last_minutes: Option<u64>) -> String {
    let samples = if let Ok(history) = HISTORY.read() {
        history.get_samples(last_minutes)
    } else {
        Vec::new()
    };

    serde_json::json!({
        "interval_secs": SAMPLE_INTERVAL_SECS,
        "max_samples": MAX_SAMPLES,
        "count": samples.len(),
        "samples": samples,
    })
    .to_string()
}

/// Spawn the background sample collector
pub fn spawn_collector() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(SAMPLE_INTERVAL_SECS));
        tracing::info!("📊 Stats history collector started ({}s interval, 24h window)", SAMPLE_INTERVAL_SECS);

        loop {
            interval.tick().await;

            // Read current stats from BPF STATS map
            match read_bpf_stats() {
                Some((seen, pass, drop, manual, cidr, scan, ct)) => {
                    record_sample(seen, pass, drop, manual, cidr, scan, ct);
                }
                None => {} // BPF not attached yet, skip
            }
        }
    });
}

/// Read aggregated stats from BPF PerCpuArray
fn read_bpf_stats() -> Option<(u64, u64, u64, u64, u64, u64, u64)> {
    use aya::maps::PerCpuArray;
    use aegis_common::Stats;

    let path = "/sys/fs/bpf/aegis/STATS";
    let md = aya::maps::MapData::from_pin(path).ok()?;
    let map = aya::maps::Map::PerCpuArray(md);
    let arr = PerCpuArray::<_, Stats>::try_from(map).ok()?;
    let per_cpu = arr.get(&0, 0).ok()?;

    let mut seen = 0u64;
    let mut pass = 0u64;
    let mut drop = 0u64;
    let mut manual = 0u64;
    let mut cidr = 0u64;
    let mut scan = 0u64;
    let mut ct = 0u64;

    for cpu_stats in per_cpu.iter() {
        seen += cpu_stats.pkts_seen;
        pass += cpu_stats.pkts_pass;
        drop += cpu_stats.pkts_drop;
        manual += cpu_stats.block_manual;
        cidr += cpu_stats.block_cidr;
        scan += cpu_stats.portscan_hits;
        ct += cpu_stats.conntrack_hits;
    }

    Some((seen, pass, drop, manual, cidr, scan, ct))
}
