//! Loader for CIDR blocklist into eBPF map

use aya::maps::lpm_trie::LpmTrie;
use aya::maps::MapData;
use aegis_common::{LpmKeyIpv4, CidrBlockEntry, CAT_SPAMHAUS, CAT_ABUSE_CH, CAT_FIREHOL};

use super::{FeedConfig, FeedCategory, download_feed_blocking};

/// Load all enabled feeds into the CIDR blocklist eBPF map
/// Now preserves real CIDR prefix lengths for proper LPM matching
pub fn load_feeds_to_map<T: std::borrow::BorrowMut<MapData>>(
    cidr_map: &mut LpmTrie<T, LpmKeyIpv4, CidrBlockEntry>,
) -> Result<usize, String> {
    let configs = FeedConfig::defaults();
    let mut total_loaded = 0usize;
    let mut errors = 0usize;
    
    for config in configs.iter().filter(|c| c.enabled) {
        match download_feed_blocking(config) {
            Ok(result) => {
                let category = match config.category {
                    FeedCategory::Spamhaus => CAT_SPAMHAUS,
                    FeedCategory::AbuseCh => CAT_ABUSE_CH,
                    FeedCategory::Firehol => CAT_FIREHOL,
                    _ => 0,
                };
                
                for entry in result.entries.iter() {
                    // Use real prefix_len from the feed
                    let key = aya::maps::lpm_trie::Key::new(
                        entry.prefix_len as u32,
                        LpmKeyIpv4 {
                            prefix_len: entry.prefix_len as u32,
                            addr: entry.addr,  // Already in network byte order
                        },
                    );
                    
                    let bpf_entry = CidrBlockEntry {
                        category,
                        _pad: [0u8; 3],
                    };
                    
                    // Insert, count errors (map might be full)
                    if cidr_map.insert(&key, bpf_entry, 0).is_ok() {
                        total_loaded += 1;
                    } else {
                        errors += 1;
                    }
                }
                
                println!("  ✓ {} {} entries (prefix ranges preserved)", 
                    config.name, result.entry_count());
            }
            Err(e) => {
                println!("  ✗ {} failed: {}", config.name, e);
                continue;
            }
        }
    }
    
    if errors > 0 {
        println!("  ⚠ {} entries failed to insert (map may be full)", errors);
    }
    
    Ok(total_loaded)
}
