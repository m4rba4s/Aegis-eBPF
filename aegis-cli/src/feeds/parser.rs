//! Feed Parser - parses IP lists from various formats

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::str::FromStr;

/// CIDR entry with network address and prefix length
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrEntry {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

/// Parse a line from a feed file, extracting IP or CIDR
/// Returns None for comments, empty lines, or invalid entries
pub fn parse_line_cidr(line: &str) -> Option<CidrEntry> {
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
        let parts: Vec<&str> = ip_part.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let ip = Ipv4Addr::from_str(parts[0]).ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;
        
        if prefix_len > 32 {
            return None;
        }
        
        // Normalize to network address (mask off host bits)
        let addr_u32 = u32::from(ip);
        let mask: u32 = if prefix_len == 0 { 0 } else { !((1u32 << (32 - prefix_len)) - 1) };
        let network = addr_u32 & mask;
        
        return Some(CidrEntry {
            addr: Ipv4Addr::from(network),
            prefix_len,
        });
    }
    
    // Single IP = /32
    if let Ok(ip) = Ipv4Addr::from_str(ip_part) {
        return Some(CidrEntry {
            addr: ip,
            prefix_len: 32,
        });
    }
    
    None
}

/// Parse entire feed content, returning CIDR entries
pub fn parse_feed_cidr(content: &str) -> Vec<CidrEntry> {
    content
        .lines()
        .filter_map(parse_line_cidr)
        .collect()
}

// Legacy function for backward compatibility
pub fn parse_line(line: &str) -> Option<Vec<Ipv4Addr>> {
    parse_line_cidr(line).map(|e| vec![e.addr])
}

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
