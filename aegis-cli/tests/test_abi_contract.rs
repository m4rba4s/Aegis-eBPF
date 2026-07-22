//! ABI contract regression tests: freeze the memory layout shared between
//! the in-kernel eBPF programs (aegis-ebpf / aegis-tc) and the userspace
//! agent (aegis-cli).
//!
//! Why this exists: eBPF and userspace communicate through shared maps whose
//! keys and values are `#[repr(C)]` structs defined in `aegis-common`. If a
//! future refactor silently adds/removes a field or changes a `_pad`, the two
//! sides start reading the same bytes at different offsets. The symptom is the
//! worst kind of bug — the firewall silently stops blocking the right IPs (or
//! blocks the wrong ones) with no panic and no log line.
//!
//! These tests are the canary: any drift in struct size, field offset, or the
//! numeric value of a wire constant turns the build red before it can ship.
//!
//! Scope: pure compile-time / read-only checks. No root, no BPF maps, no
//! network. Runs as an unprivileged integration test and is picked up by
//! `cargo test --workspace --all-features` in the release gate.

use aegis_common::{
    CidrBlockEntry, ConnTrackKey, ConnTrackState, DpiEvent, FlowKey, FlowKeyIpv6, LpmKeyIpv4,
    LpmKeyIpv6, PacketLog, PacketLogIpv6, PortScanState, RateLimitState, Stats,
};

// --- Wire constants that must agree on both sides of the eBPF<->userspace
// boundary. Imported here so the test fails to compile (rather than silently
// passing) if a constant is ever renamed/removed.
use aegis_common::{
    ACTION_ALERT, ACTION_DPI, ACTION_DROP, ACTION_PASS, HOOK_TC_EGRESS, HOOK_TC_INGRESS, HOOK_XDP,
    NEXTHDR_ESP, NEXTHDR_FRAGMENT, NEXTHDR_ROUTING, NEXTHDR_TCP, NEXTHDR_UDP,
    ROUTING_TYPE_0, THREAT_BLOCKLIST, THREAT_FLOOD_SYN, THREAT_HIGH_ENTROPY,
    THREAT_IPV6_FRAGMENT, THREAT_IPV6_ROUTING_TYPE0, THREAT_NONE, THREAT_SCAN_PORT,
};

/// Struct sizes are the coarsest ABI invariant: a size mismatch means the two
/// sides disagree on where the whole record ends. Expected values are derived
/// by hand from the field list in `aegis-common/src/lib.rs` and must match the
/// `// Total:` comments in that file. If this test breaks, either the comment
/// or the struct is wrong — do not "fix" it by changing the number here without
/// understanding why the layout shifted.
#[test]
fn test_struct_sizes_are_stable() {
    assert_eq!(std::mem::size_of::<FlowKey>(), 8, "FlowKey layout drift");
    assert_eq!(
        std::mem::size_of::<PacketLog>(),
        32,
        "PacketLog layout drift"
    );
    assert_eq!(std::mem::size_of::<DpiEvent>(), 48, "DpiEvent layout drift");
    assert_eq!(std::mem::size_of::<Stats>(), 112, "Stats layout drift");
    assert_eq!(
        std::mem::size_of::<ConnTrackKey>(),
        16,
        "ConnTrackKey layout drift"
    );
    assert_eq!(
        std::mem::size_of::<ConnTrackState>(),
        24,
        "ConnTrackState layout drift"
    );
    assert_eq!(
        std::mem::size_of::<LpmKeyIpv4>(),
        4,
        "LpmKeyIpv4 layout drift"
    );
    assert_eq!(
        std::mem::size_of::<CidrBlockEntry>(),
        4,
        "CidrBlockEntry layout drift"
    );
    assert_eq!(
        std::mem::size_of::<RateLimitState>(),
        16,
        "RateLimitState layout drift"
    );
    assert_eq!(
        std::mem::size_of::<PortScanState>(),
        48,
        "PortScanState layout drift"
    );
    assert_eq!(
        std::mem::size_of::<FlowKeyIpv6>(),
        20,
        "FlowKeyIpv6 layout drift"
    );
    assert_eq!(
        std::mem::size_of::<LpmKeyIpv6>(),
        16,
        "LpmKeyIpv6 layout drift"
    );
    assert_eq!(
        std::mem::size_of::<PacketLogIpv6>(),
        48,
        "PacketLogIpv6 layout drift"
    );
}

/// PacketLog is the highest-traffic shared record (emitted on every event).
/// Pin the byte offset of every field so a reorder or a padding change between,
/// say, `action` and `reason` is caught even if the total size stays 32.
#[test]
fn test_packet_log_field_offsets() {
    use std::mem::offset_of;
    assert_eq!(offset_of!(PacketLog, src_ip), 0);
    assert_eq!(offset_of!(PacketLog, dst_ip), 4);
    assert_eq!(offset_of!(PacketLog, src_port), 8);
    assert_eq!(offset_of!(PacketLog, dst_port), 10);
    assert_eq!(offset_of!(PacketLog, proto), 12);
    assert_eq!(offset_of!(PacketLog, tcp_flags), 13);
    assert_eq!(offset_of!(PacketLog, action), 14);
    assert_eq!(offset_of!(PacketLog, reason), 15);
    assert_eq!(offset_of!(PacketLog, threat_type), 16);
    assert_eq!(offset_of!(PacketLog, hook), 17);
    assert_eq!(offset_of!(PacketLog, packet_len), 18);
    assert_eq!(offset_of!(PacketLog, _pad), 20);
    assert_eq!(offset_of!(PacketLog, timestamp), 24);
}

/// FlowKey is the manual-blocklist key. Its wildcard convention (`dst_port: 0,
/// proto: 0`) is part of the contract and is checked elsewhere; here we only
/// lock the offsets so eBPF and userspace agree on where each byte lives.
#[test]
fn test_flowkey_field_offsets() {
    use std::mem::offset_of;
    assert_eq!(offset_of!(FlowKey, src_ip), 0);
    assert_eq!(offset_of!(FlowKey, dst_port), 4);
    assert_eq!(offset_of!(FlowKey, proto), 6);
    assert_eq!(offset_of!(FlowKey, _pad), 7);
}

/// Verdict action byte written by eBPF and read by userspace to decide logging
/// / alerting side effects. A renumber here desyncs DROP vs PASS silently.
#[test]
fn test_action_constants() {
    assert_eq!(ACTION_PASS, 0);
    assert_eq!(ACTION_DROP, 1);
    assert_eq!(ACTION_ALERT, 2);
    assert_eq!(ACTION_DPI, 3);
    // Actions are a dense 0..=3 set; if a new one is inserted in the middle,
    // the ordering above must be revisited intentionally rather than by accident.
    let all = [ACTION_PASS, ACTION_DROP, ACTION_ALERT, ACTION_DPI];
    assert_eq!(all, [0, 1, 2, 3], "ACTION_* constants must stay dense");
}

/// Threat category byte. The userspace OODA auto-ban loop triggers on
/// `THREAT_FLOOD_SYN` and `THREAT_SCAN_PORT`; if either is renumbered without
/// updating both sides, auto-ban silently stops firing.
#[test]
fn test_threat_constants() {
    assert_eq!(THREAT_NONE, 0);
    assert_eq!(THREAT_SCAN_PORT, 4);
    assert_eq!(THREAT_FLOOD_SYN, 5);
    assert_eq!(THREAT_BLOCKLIST, 6);
    assert_eq!(THREAT_HIGH_ENTROPY, 9);
}

/// Hook-point byte identifying which program emitted an event. Userspace uses
/// this to attribute drops to ingress vs egress.
#[test]
fn test_hook_constants() {
    assert_eq!(HOOK_XDP, 1);
    assert_eq!(HOOK_TC_INGRESS, 2);
    assert_eq!(HOOK_TC_EGRESS, 3);
}

/// Cross-module consistency: the L4 protocol number for TCP/UDP is the same
/// IANA constant whether the IPv4 path tags it (`proto == 6`) or the IPv6 path
/// resolves it through `next_header`. Lock that the two symbolic names agree,
/// so a future "cleanup" can't accidentally make them diverge.
#[test]
fn test_protocol_constants_agree() {
    assert_eq!(NEXTHDR_TCP, 6);
    assert_eq!(NEXTHDR_UDP, 17);
}


/// Wire constants introduced/used by the v4.3.0-rc.1 IPv6 hardening. These
/// pin the numeric values the BPF datapath (aegis-ebpf / aegis-tc) writes into
/// PacketLogIpv6.threat_type and reads from the IPv6 next-header / routing
/// bytes. If any of these drift, the P0-1 (Fragment) and P0-2 (RH0) fail-closed
/// branches either stop firing or log the wrong threat category, silently. The
/// canary turns the build red before that can ship.
///
/// Values come from aegis-common/src/lib.rs and MUST match the BPF match-arms.
#[test]
fn test_ipv6_hardening_constants() {
    // IPv6 next-header (protocol) numbers the datapath dispatches on.
    assert_eq!(NEXTHDR_FRAGMENT, 44, "Fragment Header protocol number");
    assert_eq!(NEXTHDR_ROUTING, 43, "Routing Header protocol number");
    assert_eq!(NEXTHDR_ESP, 50, "ESP (IPsec) protocol number");

    // RFC 5095: Routing Header Type 0 must be discarded.
    assert_eq!(ROUTING_TYPE_0, 0, "RH0 routing_type value");

    // Threat categories logged by the new fail-closed branches. These are read
    // by userspace (TUI / metrics / event loop) to attribute the drop.
    assert_eq!(THREAT_IPV6_FRAGMENT, 22, "Fragment drop threat type");
    assert_eq!(
        THREAT_IPV6_ROUTING_TYPE0, 21,
        "RH0 drop threat type"
    );
}
