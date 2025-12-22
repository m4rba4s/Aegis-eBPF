//! Async Feed Downloader

use reqwest::Client;
use std::time::Duration;
use std::path::PathBuf;
use std::fs;

use super::{FeedConfig, FeedCategory};
use super::parser::parse_feed;

/// Download result
pub struct DownloadResult {
    pub feed_name: String,
    pub category: FeedCategory,
    pub ip_count: usize,
    pub ips: Vec<u32>,  // In network byte order for eBPF
}

/// Download a single feed
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
    
    let content = response
        .text()
        .await
        .map_err(|e| format!("Read error: {}", e))?;
    
    // Parse IPs
    let ips = parse_feed(&content);
    
    // Convert to network byte order u32 for eBPF
    let ips_u32: Vec<u32> = ips
        .iter()
        .map(|ip| u32::from(*ip).to_be())
        .collect();
    
    Ok(DownloadResult {
        feed_name: config.name.clone(),
        category: config.category,
        ip_count: ips_u32.len(),
        ips: ips_u32,
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
    
    let content = response
        .text()
        .map_err(|e| format!("Read error: {}", e))?;
    
    // Parse IPs
    let ips = parse_feed(&content);
    
    // Convert to network byte order u32 for eBPF
    let ips_u32: Vec<u32> = ips
        .iter()
        .map(|ip| u32::from(*ip).to_be())
        .collect();
    
    Ok(DownloadResult {
        feed_name: config.name.clone(),
        category: config.category,
        ip_count: ips_u32.len(),
        ips: ips_u32,
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
