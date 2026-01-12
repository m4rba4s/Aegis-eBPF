//! Threat Feed Integration Module
//!
//! Downloads and parses external threat intelligence feeds:
//! - Spamhaus DROP/EDROP
//! - Abuse.ch Feodo Tracker
//! - Firehol Level1

mod parser;
mod downloader;
mod loader;

// Re-export used items
pub use downloader::{cache_dir, download_feed_blocking};
pub use loader::load_feeds_to_map;

use std::net::Ipv4Addr;

/// Feed categories for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FeedCategory {
    None = 0,
    Spamhaus = 1,
    AbuseCh = 2,
    Firehol = 3,
    Tracker = 4,
    Manual = 5,
}

/// A blocked IP entry with metadata (for future use)
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BlockedIp {
    pub ip: Ipv4Addr,
    pub category: FeedCategory,
    pub source: String,
}

/// Feed definition
#[derive(Debug, Clone)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub category: FeedCategory,
    pub enabled: bool,
    pub update_interval_secs: u64,
}

impl FeedConfig {
    /// Default feeds
    pub fn defaults() -> Vec<FeedConfig> {
        vec![
            FeedConfig {
                name: "spamhaus_drop".to_string(),
                url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
                category: FeedCategory::Spamhaus,
                enabled: true,
                update_interval_secs: 86400, // 24h
            },
            FeedConfig {
                name: "spamhaus_edrop".to_string(),
                url: "https://www.spamhaus.org/drop/edrop.txt".to_string(),
                category: FeedCategory::Spamhaus,
                enabled: true,
                update_interval_secs: 86400,
            },
            FeedConfig {
                name: "abuse_ch_feodo".to_string(),
                url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
                category: FeedCategory::AbuseCh,
                enabled: true,
                update_interval_secs: 3600, // 1h
            },
            FeedConfig {
                name: "firehol_level1".to_string(),
                url: "https://iplists.firehol.org/files/firehol_level1.netset".to_string(),
                category: FeedCategory::Firehol,
                enabled: true,
                update_interval_secs: 86400,
            },
        ]
    }
}

/// Feed manager for loading and updating feeds (for future use)
#[allow(dead_code)]
pub struct FeedManager {
    pub feeds: Vec<FeedConfig>,
    pub blocked_ips: std::collections::HashSet<u32>, // IPs in network byte order
}

#[allow(dead_code)]
impl FeedManager {
    pub fn new() -> Self {
        Self {
            feeds: FeedConfig::defaults(),
            blocked_ips: std::collections::HashSet::new(),
        }
    }

    /// Get total blocked IP count
    pub fn blocked_count(&self) -> usize {
        self.blocked_ips.len()
    }
}
