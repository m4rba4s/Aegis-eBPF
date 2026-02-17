//! Async Feed Downloader

#![allow(dead_code)]

use reqwest::Client;
use std::time::Duration;
use std::path::PathBuf;
use std::fs;

use super::{FeedConfig, FeedCategory};
use super::parser::parse_feed_cidr;

/// Maximum feed download size (10 MB) — prevents OOM from malicious responses
const MAX_FEED_SIZE: u64 = 10 * 1024 * 1024;

/// CIDR entry ready for eBPF (network byte order)
pub struct CidrEntryBpf {
    pub addr: u32,        // Network byte order
    pub prefix_len: u8,
}

/// Download result with CIDR entries
pub struct DownloadResult {
    pub feed_name: String,
    pub category: FeedCategory,
    pub entries: Vec<CidrEntryBpf>,
}

impl DownloadResult {
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Download a single feed (async)
pub async fn download_feed(config: &FeedConfig) -> Result<DownloadResult, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Aegis-Firewall/1.0")
        .build()
        .map_err(|e| format!("Client error: {}", e))?;
    
    let response = client
        .get(&config.url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    
    // Check Content-Length before reading body
    if let Some(len) = response.content_length() {
        if len > MAX_FEED_SIZE {
            return Err(format!("Feed too large: {} bytes (limit: {} bytes)", len, MAX_FEED_SIZE));
        }
    }
    
    let content = response
        .text()
        .await
        .map_err(|e| format!("Read error: {}", e))?;
    
    if content.len() as u64 > MAX_FEED_SIZE {
        return Err(format!("Feed body exceeded limit: {} bytes", content.len()));
    }
    
    // Parse CIDR entries with real prefix info
    let cidr_entries = parse_feed_cidr(&content);
    
    // Convert to BPF format (network byte order)
    let entries: Vec<CidrEntryBpf> = cidr_entries
        .iter()
        .map(|e| CidrEntryBpf {
            addr: u32::from(e.addr).to_be(),
            prefix_len: e.prefix_len,
        })
        .collect();
    
    Ok(DownloadResult {
        feed_name: config.name.clone(),
        category: config.category,
        entries,
    })
}

/// Download a feed with blocking (for sync contexts)
pub fn download_feed_blocking(config: &FeedConfig) -> Result<DownloadResult, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Aegis-Firewall/1.0")
        .build()
        .map_err(|e| format!("Client error: {}", e))?;
    
    let response = client
        .get(&config.url)
        .send()
        .map_err(|e| format!("Request failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    
    // Check Content-Length before reading body
    if let Some(len) = response.content_length() {
        if len > MAX_FEED_SIZE {
            return Err(format!("Feed too large: {} bytes (limit: {} bytes)", len, MAX_FEED_SIZE));
        }
    }
    
    let content = response
        .text()
        .map_err(|e| format!("Read error: {}", e))?;
    
    if content.len() as u64 > MAX_FEED_SIZE {
        return Err(format!("Feed body exceeded limit: {} bytes", content.len()));
    }
    
    // Parse CIDR entries with real prefix info
    let cidr_entries = parse_feed_cidr(&content);
    
    // Convert to BPF format (network byte order)
    let entries: Vec<CidrEntryBpf> = cidr_entries
        .iter()
        .map(|e| CidrEntryBpf {
            addr: u32::from(e.addr).to_be(),
            prefix_len: e.prefix_len,
        })
        .collect();
    
    Ok(DownloadResult {
        feed_name: config.name.clone(),
        category: config.category,
        entries,
    })
}

/// Cache directory for feeds
pub fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".cache").join("aegis").join("feeds")
}

/// Save feed to cache
pub fn save_to_cache(feed_name: &str, content: &str) -> Result<(), String> {
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("Cache dir error: {}", e))?;
    
    let path = dir.join(format!("{}.txt", feed_name));
    fs::write(path, content).map_err(|e| format!("Write error: {}", e))?;
    
    Ok(())
}

/// Load feed from cache
pub fn load_from_cache(feed_name: &str) -> Option<String> {
    let path = cache_dir().join(format!("{}.txt", feed_name));
    fs::read_to_string(path).ok()
}
