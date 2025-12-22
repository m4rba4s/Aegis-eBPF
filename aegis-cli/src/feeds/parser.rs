//! Feed Parser - parses IP lists from various formats

use std::net::Ipv4Addr;
use std::str::FromStr;

/// Parse a line from a feed file, extracting IP or CIDR
/// Returns None for comments, empty lines, or invalid entries
pub fn parse_line(line: &str) -> Option<Vec<Ipv4Addr>> {
    let line = line.trim();
    
    // Skip comments and empty lines
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    
    // Handle inline comments (e.g., "1.2.3.0/24 ; SBL123456")
    let ip_part = line.split(|c| c == ';' || c == '#')
        .next()
        .unwrap_or("")
        .trim();
    
    if ip_part.is_empty() {
        return None;
    }
    
    // Check if it's a CIDR notation
    if ip_part.contains('/') {
        return parse_cidr(ip_part);
    }
    
    // Try to parse as single IP
    if let Ok(ip) = Ipv4Addr::from_str(ip_part) {
        return Some(vec![ip]);
    }
    
    None
}

/// Expand CIDR notation to individual IPs
/// For large ranges, only returns first 256 IPs to avoid memory explosion
fn parse_cidr(cidr: &str) -> Option<Vec<Ipv4Addr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let base_ip = Ipv4Addr::from_str(parts[0]).ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;
    
    if prefix_len > 32 {
        return None;
    }
    
    // For /24 and smaller, expand all IPs
    // For larger ranges, just use the network address
    if prefix_len >= 24 {
        let base: u32 = u32::from(base_ip);
        let mask: u32 = !((1u32 << (32 - prefix_len)) - 1);
        let network = base & mask;
        let host_count = 1u32 << (32 - prefix_len);
        
        let ips: Vec<Ipv4Addr> = (0..host_count)
            .map(|i| Ipv4Addr::from(network + i))
            .collect();
        
        Some(ips)
    } else {
        // For larger ranges (/23 and up), just store the network address
        // The eBPF will need to do prefix matching
        Some(vec![base_ip])
    }
}

/// Parse entire feed content
pub fn parse_feed(content: &str) -> Vec<Ipv4Addr> {
    content
        .lines()
        .filter_map(parse_line)
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_single_ip() {
        let result = parse_line("192.168.1.1");
        assert_eq!(result, Some(vec![Ipv4Addr::new(192, 168, 1, 1)]));
    }
    
    #[test]
    fn test_parse_comment() {
        assert_eq!(parse_line("# comment"), None);
        assert_eq!(parse_line("; comment"), None);
    }
    
    #[test]
    fn test_parse_inline_comment() {
        let result = parse_line("1.2.3.4 ; SBL123");
        assert_eq!(result, Some(vec![Ipv4Addr::new(1, 2, 3, 4)]));
    }
}
