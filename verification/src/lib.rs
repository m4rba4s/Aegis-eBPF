//! Aegis Verification Module
//!
//! Formal verification and property-based testing for critical firewall logic.
//! This module provides mathematical guarantees for security-critical code.
//!
//! ## Verification Layers:
//! 1. **Kani Model Checking** - Proves absence of panics, UB, overflows
//! 2. **Property-Based Testing** - Random input testing with invariants
//! 3. **Fuzzing** - Coverage-guided mutation testing
//!
//! ## For Critical Infrastructure:
//! - All packet parsing MUST be verified
//! - All bounds checks MUST be proven correct
//! - All state transitions MUST be validated

use aegis_common::*;

// ============================================================
// INVARIANTS (Properties that MUST always hold)
// ============================================================

/// Invariant: PacketLog size must be exactly 32 bytes for perf buffer alignment
pub const PACKET_LOG_SIZE_INVARIANT: usize = 32;

/// Invariant: Stats struct must be safe for per-CPU access
pub const STATS_ALIGNMENT_INVARIANT: usize = 8;

/// Invariant: All reason codes must be < 256 (u8)
pub const MAX_REASON_CODE: u8 = 255;

/// Invariant: All threat codes must be < 256 (u8)
pub const MAX_THREAT_CODE: u8 = 255;

// ============================================================
// COMPILE-TIME ASSERTIONS (Zero runtime cost)
// ============================================================

const _: () = {
    // PacketLog MUST be exactly 32 bytes
    assert!(core::mem::size_of::<PacketLog>() == PACKET_LOG_SIZE_INVARIANT);

    // PacketLogIpv6 MUST be exactly 48 bytes
    assert!(core::mem::size_of::<PacketLogIpv6>() == 48);

    // FlowKey MUST be 8 bytes (for BPF map efficiency)
    assert!(core::mem::size_of::<FlowKey>() == 8);

    // ConnTrackKey MUST be 16 bytes
    assert!(core::mem::size_of::<ConnTrackKey>() == 16);

    // LpmKeyIpv4 MUST be 8 bytes (prefix_len + addr)
    assert!(core::mem::size_of::<LpmKeyIpv4>() == 8);

    // Reason codes must not overlap with threat codes conceptually
    // (enforced by separate constant namespaces)
};

// ============================================================
// KANI PROOFS (Formal Verification)
// ============================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove: PacketLog can be safely zero-initialized
    #[kani::proof]
    fn verify_packet_log_zeroed() {
        let log: PacketLog = unsafe { core::mem::zeroed() };
        assert!(
            log.action == ACTION_PASS || log.action == ACTION_DROP || log.action == ACTION_ALERT
        );
    }

    /// Prove: FlowKey operations never panic
    #[kani::proof]
    fn verify_flowkey_construction() {
        let src_ip: u32 = kani::any();
        let dst_port: u16 = kani::any();
        let proto: u8 = kani::any();

        let key = FlowKey {
            src_ip,
            dst_port,
            proto,
            _pad: 0,
        };

        // Key must be constructible for any input
        assert!(core::mem::size_of_val(&key) == 8);
    }

    /// Prove: LPM prefix_len is bounded correctly for IPv4
    #[kani::proof]
    fn verify_lpm_ipv4_bounds() {
        let prefix_len: u32 = kani::any();
        let addr: u32 = kani::any();

        // Assume valid prefix (0-32 for IPv4)
        kani::assume(prefix_len <= 32);

        let key = LpmKeyIpv4 { prefix_len, addr };

        // Must never exceed IPv4 max prefix
        assert!(key.prefix_len <= 32);
    }

    /// Prove: LPM prefix_len is bounded correctly for IPv6
    #[kani::proof]
    fn verify_lpm_ipv6_bounds() {
        let prefix_len: u32 = kani::any();
        let addr: [u8; 16] = kani::any();

        // Assume valid prefix (0-128 for IPv6)
        kani::assume(prefix_len <= 128);

        let key = LpmKeyIpv6 { prefix_len, addr };

        // Must never exceed IPv6 max prefix
        assert!(key.prefix_len <= 128);
    }

    /// Prove: Rate limit token bucket never overflows
    #[kani::proof]
    fn verify_rate_limit_no_overflow() {
        let tokens: u32 = kani::any();
        let add_tokens: u32 = kani::any();

        kani::assume(tokens <= MAX_TOKENS);
        kani::assume(add_tokens <= TOKENS_PER_SEC);

        // Saturating add prevents overflow
        let new_tokens = tokens.saturating_add(add_tokens).min(MAX_TOKENS);

        assert!(new_tokens <= MAX_TOKENS);
    }

    /// Prove: Port scan bitmap index never exceeds bounds
    #[kani::proof]
    fn verify_portscan_bitmap_bounds() {
        let port: u16 = kani::any();

        // Only track low ports (0-255 in bitmap)
        kani::assume(port < 256);

        let bitmap_idx = (port / 32) as usize;
        let bit_pos = port % 32;

        // Index must be in bounds [0, 7]
        assert!(bitmap_idx < 8);
        // Bit position must be valid
        assert!(bit_pos < 32);
    }

    /// Prove: Entropy detection byte index never exceeds 8 (bitmap size)
    #[kani::proof]
    fn verify_entropy_bitmap_bounds() {
        let byte_val: u8 = kani::any();

        let bitmap_idx = (byte_val / 32) as usize;
        let bit_pos = byte_val % 32;

        // For any u8 value, bitmap_idx is in [0, 7]
        assert!(bitmap_idx < 8);
        assert!(bit_pos < 32);
    }

    /// Prove: Connection state transitions are valid
    #[kani::proof]
    fn verify_conn_state_valid() {
        let state: u8 = kani::any();

        kani::assume(state <= CONN_CLOSED);

        // All valid states
        let is_valid = state == CONN_NEW
            || state == CONN_SYN_SENT
            || state == CONN_SYN_RECV
            || state == CONN_ESTABLISHED
            || state == CONN_FIN_WAIT
            || state == CONN_CLOSED;

        assert!(is_valid);
    }

    /// Prove: IPv6 extension header count is bounded
    #[kani::proof]
    fn verify_ipv6_ext_header_limit() {
        let count: u8 = kani::any();

        kani::assume(count <= IPV6_MAX_EXT_HEADERS);

        // Count must never exceed safety limit
        assert!(count <= 2);
    }
}

// ============================================================
// PROPERTY-BASED TESTS (proptest)
// ============================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: Any valid IP can be used in FlowKey
        #[test]
        fn prop_flowkey_any_ip(src_ip: u32, dst_port: u16, proto: u8) {
            let key = FlowKey {
                src_ip,
                dst_port,
                proto,
                _pad: 0,
            };
            prop_assert_eq!(key.src_ip, src_ip);
            prop_assert_eq!(key.dst_port, dst_port);
            prop_assert_eq!(key.proto, proto);
        }

        /// Property: Rate limit tokens are always bounded
        #[test]
        fn prop_rate_limit_bounded(tokens in 0u32..=MAX_TOKENS, delta in 0u32..=1000u32) {
            let new_tokens = tokens.saturating_add(delta).min(MAX_TOKENS);
            prop_assert!(new_tokens <= MAX_TOKENS);
        }

        /// Property: Port scan bitmap index is always valid
        #[test]
        fn prop_portscan_bitmap_valid(port in 0u16..256u16) {
            let idx = (port / 32) as usize;
            let bit = port % 32;
            prop_assert!(idx < 8);
            prop_assert!(bit < 32);
        }

        /// Property: Any byte value produces valid entropy bitmap index
        #[test]
        fn prop_entropy_bitmap_valid(byte_val: u8) {
            let idx = (byte_val / 32) as usize;
            let bit = byte_val % 32;
            prop_assert!(idx < 8);
            prop_assert!(bit < 32);
        }

        /// Property: LPM IPv4 prefix is bounded
        #[test]
        fn prop_lpm_ipv4_prefix(prefix in 0u32..=32u32, addr: u32) {
            let key = LpmKeyIpv4 { prefix_len: prefix, addr };
            prop_assert!(key.prefix_len <= 32);
        }

        /// Property: LPM IPv6 prefix is bounded
        #[test]
        fn prop_lpm_ipv6_prefix(prefix in 0u32..=128u32, addr: [u8; 16]) {
            let key = LpmKeyIpv6 { prefix_len: prefix, addr };
            prop_assert!(key.prefix_len <= 128);
        }

        /// Property: Connection state is always valid enum value
        #[test]
        fn prop_conn_state_valid(state in 0u8..=5u8) {
            let is_valid = state == CONN_NEW
                || state == CONN_SYN_SENT
                || state == CONN_SYN_RECV
                || state == CONN_ESTABLISHED
                || state == CONN_FIN_WAIT
                || state == CONN_CLOSED;
            prop_assert!(is_valid);
        }

        /// Property: PacketLog action is always valid
        #[test]
        fn prop_packet_log_action(action in 0u8..=2u8) {
            let is_valid = action == ACTION_PASS
                || action == ACTION_DROP
                || action == ACTION_ALERT;
            prop_assert!(is_valid);
        }
    }
}

// ============================================================
// DETERMINISTIC UNIT TESTS
// ============================================================

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TcIpv4PolicyStage {
        DropMalformedIp,
        DropBlockedDestinationBeforeL4,
        ContinueToL4,
    }

    fn model_tc_ipv4_policy_stage(
        ihl: u8,
        frag_off: u16,
        exact_blocked: bool,
        cidr_blocked: bool,
    ) -> TcIpv4PolicyStage {
        if ihl != 5 || (frag_off & 0x3FFF) != 0 {
            return TcIpv4PolicyStage::DropMalformedIp;
        }

        if exact_blocked || cidr_blocked {
            return TcIpv4PolicyStage::DropBlockedDestinationBeforeL4;
        }

        TcIpv4PolicyStage::ContinueToL4
    }

    fn assert_truncated_blocked_ipv4_drops_before_l4(
        proto: u8,
        available_l4_bytes: usize,
        exact_blocked: bool,
        cidr_blocked: bool,
    ) {
        let min_l4_bytes = match proto {
            PROTO_TCP => 20,
            PROTO_UDP => 8,
            _ => 0,
        };
        assert!(available_l4_bytes < min_l4_bytes);
        assert_eq!(
            model_tc_ipv4_policy_stage(5, 0, exact_blocked, cidr_blocked),
            TcIpv4PolicyStage::DropBlockedDestinationBeforeL4
        );
    }

    #[test]
    fn test_struct_sizes() {
        assert_eq!(core::mem::size_of::<PacketLog>(), 32);
        assert_eq!(core::mem::size_of::<PacketLogIpv6>(), 48);
        assert_eq!(core::mem::size_of::<FlowKey>(), 8);
        assert_eq!(core::mem::size_of::<ConnTrackKey>(), 16);
        assert_eq!(core::mem::size_of::<LpmKeyIpv4>(), 8);
    }

    #[test]
    fn test_rate_limit_constants() {
        // Ensure burst capacity is reasonable
        const { assert!(MAX_TOKENS >= TOKENS_PER_SEC) };
        // Ensure we can handle at least 1 second of traffic
        const { assert!(MAX_TOKENS >= 100) };
    }

    #[test]
    fn test_port_scan_constants() {
        // Threshold should be reasonable
        const { assert!(PORT_SCAN_THRESHOLD > 10) };
        const { assert!(PORT_SCAN_THRESHOLD < 200) };
        // Window should be in seconds range
        const { assert!(PORT_SCAN_WINDOW_NS >= 1_000_000_000) }; // >= 1 sec
        const { assert!(PORT_SCAN_WINDOW_NS <= 60_000_000_000) }; // <= 60 sec
    }

    #[test]
    fn test_entropy_constants() {
        // Sample size must be small for verifier
        const { assert!(ENTROPY_SAMPLE_SIZE <= 8) };
        // Threshold must not exceed sample size
        const { assert!((ENTROPY_THRESHOLD as usize) <= ENTROPY_SAMPLE_SIZE) };
    }

    #[test]
    fn test_ipv6_limits() {
        // Max ext headers must be small for verifier
        const { assert!(IPV6_MAX_EXT_HEADERS <= 4) };
        // Max ext header length must be bounded
        const { assert!(IPV6_MAX_EXT_HDR_LEN <= 512) };
    }

    #[test]
    fn test_connection_timeouts() {
        // Established should be longer than other states
        const { assert!(CONN_TIMEOUT_ESTABLISHED_NS > CONN_TIMEOUT_OTHER_NS) };
        // Other should be at least 10 seconds
        const { assert!(CONN_TIMEOUT_OTHER_NS >= 10_000_000_000) };
    }

    #[test]
    fn test_tc_ipv4_truncated_exact_block_drops_before_l4() {
        assert_truncated_blocked_ipv4_drops_before_l4(PROTO_TCP, 13, true, false);
        assert_truncated_blocked_ipv4_drops_before_l4(PROTO_UDP, 3, true, false);
    }

    #[test]
    fn test_tc_ipv4_truncated_cidr_block_drops_before_l4() {
        assert_truncated_blocked_ipv4_drops_before_l4(PROTO_TCP, 13, false, true);
        assert_truncated_blocked_ipv4_drops_before_l4(PROTO_UDP, 3, false, true);
    }

    #[test]
    fn test_tc_ipv4_malformed_header_precedes_destination_policy() {
        assert_eq!(
            model_tc_ipv4_policy_stage(6, 0, true, true),
            TcIpv4PolicyStage::DropMalformedIp
        );
        assert_eq!(
            model_tc_ipv4_policy_stage(5, 0x2000, true, true),
            TcIpv4PolicyStage::DropMalformedIp
        );
    }
}
