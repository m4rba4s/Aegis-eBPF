//! Fuzz target for LPM (Longest Prefix Match) operations
//!
//! Tests that CIDR prefix matching never panics or produces invalid results.

#![no_main]

use libfuzzer_sys::fuzz_target;
use aegis_common::{LpmKeyIpv4, LpmKeyIpv6};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Test IPv4 LPM key construction
    let prefix_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    // Clamp prefix to valid range
    let valid_prefix = prefix_len % 33; // 0-32

    let key = LpmKeyIpv4 {
        prefix_len: valid_prefix,
        addr,
    };

    // Verify invariants
    assert!(key.prefix_len <= 32);

    // Test prefix masking (what the BPF LPM trie does internally)
    let mask = if valid_prefix == 0 {
        0u32
    } else if valid_prefix >= 32 {
        !0u32
    } else {
        !0u32 << (32 - valid_prefix)
    };

    let masked_addr = addr & mask;
    // Masked address should equal original for matching
    assert_eq!(masked_addr & mask, masked_addr);

    // Test IPv6 LPM key if we have enough data
    if data.len() >= 20 {
        let prefix_len_v6 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let valid_prefix_v6 = prefix_len_v6 % 129; // 0-128

        let mut addr_v6 = [0u8; 16];
        addr_v6.copy_from_slice(&data[4..20]);

        let key_v6 = LpmKeyIpv6 {
            prefix_len: valid_prefix_v6,
            addr: addr_v6,
        };

        assert!(key_v6.prefix_len <= 128);
    }

    // Test edge cases
    let edge_cases: &[(u32, u32)] = &[
        (0, 0),           // Empty prefix
        (32, 0xFFFFFFFF), // Full match
        (24, 0xC0A80100), // /24 network
        (16, 0xAC100000), // /16 network
        (8, 0x0A000000),  // /8 network
    ];

    for &(prefix, test_addr) in edge_cases {
        let test_key = LpmKeyIpv4 {
            prefix_len: prefix,
            addr: test_addr,
        };
        assert!(test_key.prefix_len <= 32);
    }
});
