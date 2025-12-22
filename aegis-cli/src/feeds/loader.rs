//! Loader for CIDR blocklist into eBPF map

use aya::maps::lpm_trie::LpmTrie;
use aya::maps::MapData;
use aegis_common::{LpmKeyIpv4, CidrBlockEntry, CAT_SPAMHAUS, CAT_ABUSE_CH, CAT_FIREHOL};

use super::{FeedConfig, FeedCategory, download_feed_blocking};

/// Load all enabled feeds into the CIDR blocklist eBPF map
pub fn load_feeds_to_map<T: std::borrow::BorrowMut<MapData>>(
    cidr_map: &mut LpmTrie<T, LpmKeyIpv4, CidrBlockEntry>,
) -> Result<usize, String> {
    let configs = FeedConfig::defaults();
    let mut total_loaded = 0usize;
    
    for config in configs.iter().filter(|c| c.enabled) {
        match download_feed_blocking(config) {
            Ok(result) => {
                let category = match config.category {
                    FeedCategory::Spamhaus => CAT_SPAMHAUS,
                    FeedCategory::AbuseCh => CAT_ABUSE_CH,
                    FeedCategory::Firehol => CAT_FIREHOL,
                    _ => 0,
                };
                
                for ip in result.ips.iter() {
                    let key = aya::maps::lpm_trie::Key::new(
                        32,  // /32 prefix for individual IPs
                        LpmKeyIpv4 {
                            prefix_len: 32,
                            addr: *ip,  // Already in network byte order
                        },
                    );
                    
                    let entry = CidrBlockEntry {
                        category,
                        _pad: [0u8; 3],
                    };
                    
                    // Insert, ignore errors (map might be full)
                    let _ = cidr_map.insert(&key, entry, 0);
                    total_loaded += 1;
                }
            }
            Err(_) => {
                // Skip failed feeds
                continue;
            }
        }
    }
    
    Ok(total_loaded)
}
