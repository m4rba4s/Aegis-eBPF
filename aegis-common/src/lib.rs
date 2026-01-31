//! Aegis Common - Single Source of Truth for all shared types
//!
//! This crate contains ALL shared structures between:
//! - aegis-ebpf (XDP program)
//! - aegis-tc (TC egress program)
//! - aegis-cli (userspace controller)
//!
//! IMPORTANT: Any change here affects ALL components!

#![no_std]

// ============================================================
// CONDITIONAL IMPORTS
// ============================================================

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

// ============================================================
// PACKET LOG (Events from eBPF to userspace)
// ============================================================

/// Extended packet log for IDS/IPS mode
/// Size: 32 bytes (aligned for perf buffer)
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, Serialize, Deserialize))]
#[repr(C)]
pub struct PacketLog {
    pub src_ip: u32,       // 4  Source IP address (network byte order)
    pub dst_ip: u32,       // 4  Destination IP address (network byte order)
    pub src_port: u16,     // 2  Source port (host byte order)
    pub dst_port: u16,     // 2  Destination port (host byte order)
    pub proto: u8,         // 1  Protocol (6=TCP, 17=UDP, 1=ICMP)
    pub tcp_flags: u8,     // 1  TCP flags byte
    pub action: u8,        // 1  0=PASS, 1=DROP, 2=ALERT
    pub reason: u8,        // 1  Verdict reason (REASON_* constants)
    pub threat_type: u8,   // 1  Threat category (THREAT_* constants)
    pub hook: u8,          // 1  Hook point (HOOK_* constants)
    pub packet_len: u16,   // 2  Packet length
    pub timestamp: u64,    // 8  Kernel timestamp (nanoseconds)
}                          // Total: 32 bytes

// ============================================================
// STATISTICS (Per-CPU counters)
// ============================================================

/// Health statistics collected per-CPU
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "user", derive(Debug, Serialize, Deserialize))]
#[repr(C)]
pub struct Stats {
    pub pkts_seen: u64,       // Total packets seen
    pub pkts_pass: u64,       // Packets passed
    pub pkts_drop: u64,       // Packets dropped
    pub events_ok: u64,       // Events sent to userspace successfully
    pub events_fail: u64,     // Events failed to send (perf overflow)
    pub ipv6_seen: u64,       // IPv6 packets seen
    pub ipv6_pass: u64,       // IPv6 packets passed
    pub ipv6_drop: u64,       // IPv6 packets dropped
    pub block_manual: u64,    // Manual block hits
    pub block_cidr: u64,      // CIDR feed block hits
    pub portscan_hits: u64,   // Port scan detections
    pub conntrack_hits: u64,  // Connection tracking fast-path hits
}

// ============================================================
// FLOW KEY (Manual blocklist key)
// ============================================================

/// Key for exact-match blocklist (manual blocks)
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct FlowKey {
    pub src_ip: u32,      // Source IP (network byte order)
    pub dst_port: u16,    // Destination port (0 = wildcard)
    pub proto: u8,        // Protocol (0 = wildcard)
    pub _pad: u8,         // Padding for alignment
}

// ============================================================
// CONNECTION TRACKING
// ============================================================

/// 5-tuple connection key for stateful tracking
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct ConnTrackKey {
    pub src_ip: u32,      // Source IP (network byte order)
    pub dst_ip: u32,      // Destination IP (network byte order)
    pub src_port: u16,    // Source port
    pub dst_port: u16,    // Destination port
    pub proto: u8,        // Protocol
    pub _pad: [u8; 3],    // Padding for alignment
}

/// Connection state with timing info
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct ConnTrackState {
    pub state: u8,        // Connection state (CONN_* constants)
    pub direction: u8,    // 0 = outgoing (we initiated), 1 = incoming
    pub _pad: [u8; 2],    // Padding
    pub last_seen: u64,   // Last packet timestamp (ns)
    pub packets: u32,     // Packet count
    pub bytes: u32,       // Byte count
}

// Connection state constants
pub const CONN_NEW: u8 = 0;
pub const CONN_SYN_SENT: u8 = 1;      // Outgoing SYN sent
pub const CONN_SYN_RECV: u8 = 2;      // SYN received, awaiting SYN-ACK
pub const CONN_ESTABLISHED: u8 = 3;   // 3-way handshake complete
pub const CONN_FIN_WAIT: u8 = 4;      // FIN sent/received
pub const CONN_CLOSED: u8 = 5;        // Ready for cleanup

// ============================================================
// CIDR BLOCKLIST (LPM Trie for threat feeds)
// ============================================================

/// LPM key for CIDR matching (prefix + IP)
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct LpmKeyIpv4 {
    pub prefix_len: u32,  // Number of bits in prefix (0-32)
    pub addr: u32,        // IPv4 address in network byte order
}

/// Value for CIDR blocklist entry
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct CidrBlockEntry {
    pub category: u8,     // Feed category (CAT_* constants)
    pub _pad: [u8; 3],    // Padding for alignment
}

// Feed category constants
pub const CAT_NONE: u8 = 0;
pub const CAT_SPAMHAUS: u8 = 1;
pub const CAT_ABUSE_CH: u8 = 2;
pub const CAT_FIREHOL: u8 = 3;
pub const CAT_TRACKER: u8 = 4;
pub const CAT_MANUAL: u8 = 5;

// ============================================================
// RATE LIMITING
// ============================================================

/// Token bucket state for rate limiting (per source IP)
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct RateLimitState {
    pub tokens: u32,       // Current tokens available
    pub last_update: u64,  // Last refill timestamp (ns)
}

// ============================================================
// PORT SCAN DETECTION
// ============================================================

/// Port scan detection state per source IP
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct PortScanState {
    pub port_bitmap: [u32; 8],  // 256 bits = ports 0-255 bitmap
    pub port_count: u16,        // Count of unique ports accessed
    pub first_seen: u64,        // First packet timestamp (ns)
    pub _pad: [u8; 6],          // Padding for alignment
}

// ============================================================
// VERDICT REASON CONSTANTS (WHY action was taken)
// ============================================================

pub const REASON_DEFAULT: u8 = 0;        // Default policy (no rule matched)
pub const REASON_WHITELIST: u8 = 1;      // Private/internal IP whitelist
pub const REASON_CONNTRACK: u8 = 2;      // Connection tracking fast-path
pub const REASON_MANUAL_BLOCK: u8 = 3;   // Manual block via TUI/CLI
pub const REASON_CIDR_FEED: u8 = 4;      // Threat feed CIDR match
pub const REASON_PORTSCAN: u8 = 5;       // Port scan detection
pub const REASON_TCP_ANOMALY: u8 = 6;    // Null/Xmas/SYN+FIN scan
pub const REASON_RATELIMIT: u8 = 7;      // Rate limiting triggered
pub const REASON_IPV6_POLICY: u8 = 8;    // IPv6 policy decision
pub const REASON_MALFORMED: u8 = 9;      // Malformed L2/L3/L4
pub const REASON_EGRESS_BLOCK: u8 = 10;  // Egress blocklist match
pub const REASON_ENTROPY: u8 = 11;       // High entropy payload detected

// ============================================================
// THREAT TYPE CONSTANTS (WHAT was detected)
// ============================================================

pub const THREAT_NONE: u8 = 0;
pub const THREAT_SCAN_XMAS: u8 = 1;      // Xmas tree scan (FIN+URG+PSH)
pub const THREAT_SCAN_NULL: u8 = 2;      // Null scan (no flags)
pub const THREAT_SCAN_SYNFIN: u8 = 3;    // SYN+FIN (illegal combo)
pub const THREAT_SCAN_PORT: u8 = 4;      // Port scan detected
pub const THREAT_FLOOD_SYN: u8 = 5;      // SYN flood rate exceeded
pub const THREAT_BLOCKLIST: u8 = 6;      // IP on blocklist
pub const THREAT_INCOMING_SYN: u8 = 7;   // Incoming SYN (server mode)
pub const THREAT_EGRESS_BLOCKED: u8 = 8; // Egress to bad destination
pub const THREAT_HIGH_ENTROPY: u8 = 9;   // High entropy payload (encrypted C2)

// ============================================================
// ACTION CONSTANTS
// ============================================================

pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;
pub const ACTION_ALERT: u8 = 2;  // Log but don't drop

// ============================================================
// HOOK POINT CONSTANTS
// ============================================================

pub const HOOK_XDP: u8 = 1;
pub const HOOK_TC_INGRESS: u8 = 2;
pub const HOOK_TC_EGRESS: u8 = 3;

// ============================================================
// CONFIG MAP KEYS
// ============================================================

pub const CFG_INTERFACE_MODE: u32 = 0;  // 0 = L2/Ethernet, 1 = L3/raw IP
pub const CFG_PORT_SCAN: u32 = 1;       // Port scan detection toggle
pub const CFG_RATE_LIMIT: u32 = 2;      // Rate limiting toggle
pub const CFG_THREAT_FEEDS: u32 = 3;    // Threat feeds toggle
pub const CFG_CONN_TRACK: u32 = 4;      // Connection tracking toggle
pub const CFG_SCAN_DETECT: u32 = 5;     // Scan detection toggle
pub const CFG_VERBOSE: u32 = 6;         // Verbose logging toggle
pub const CFG_ENTROPY: u32 = 7;         // Entropy analysis toggle

// ============================================================
// AYA POD IMPLEMENTATIONS (userspace only)
// ============================================================

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnTrackKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnTrackState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmKeyIpv4 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CidrBlockEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortScanState {}

// ============================================================
// PROTOCOL CONSTANTS (shared helpers)
// ============================================================

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// ============================================================
// RATE LIMITING DEFAULTS
// ============================================================

pub const TOKENS_PER_SEC: u32 = 100;   // SYN packets/sec allowed
pub const MAX_TOKENS: u32 = 200;       // Burst capacity

// ============================================================
// PORT SCAN DEFAULTS
// ============================================================

pub const PORT_SCAN_THRESHOLD: u16 = 50;          // Unique ports to trigger
pub const PORT_SCAN_WINDOW_NS: u64 = 5_000_000_000;  // 5 second window

// ============================================================
// ENTROPY DETECTION (encrypted C2/tunnels)
// ============================================================

/// Sample size for entropy analysis (bytes)
pub const ENTROPY_SAMPLE_SIZE: usize = 32;
/// Threshold: >28 unique bytes in 32 = high entropy (likely encrypted)
pub const ENTROPY_THRESHOLD: u8 = 28;

// ============================================================
// CONNECTION TIMEOUTS
// ============================================================

pub const CONN_TIMEOUT_ESTABLISHED_NS: u64 = 300_000_000_000; // 5 min
pub const CONN_TIMEOUT_OTHER_NS: u64 = 30_000_000_000;        // 30 sec

// ============================================================
// IPv6 SUPPORT STRUCTURES
// ============================================================

/// IPv6 address as 16 bytes (128 bits)
pub type Ipv6Addr = [u8; 16];

/// LPM key for IPv6 CIDR matching
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct LpmKeyIpv6 {
    pub prefix_len: u32,       // Number of bits in prefix (0-128)
    pub addr: Ipv6Addr,        // IPv6 address in network byte order
}

/// FlowKey for IPv6 manual blocklist
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct FlowKeyIpv6 {
    pub src_ip: Ipv6Addr,      // Source IPv6 (network byte order)
    pub dst_port: u16,         // Destination port (0 = wildcard)
    pub proto: u8,             // Protocol (0 = wildcard)
    pub _pad: u8,              // Padding for alignment
}

/// Connection tracking key for IPv6 (5-tuple)
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(C)]
pub struct ConnTrackKeyIpv6 {
    pub src_ip: Ipv6Addr,      // Source IPv6
    pub dst_ip: Ipv6Addr,      // Destination IPv6
    pub src_port: u16,         // Source port
    pub dst_port: u16,         // Destination port
    pub proto: u8,             // Protocol (next header after ext headers)
    pub _pad: [u8; 3],         // Padding
}

/// Extended packet log for IPv6 events (48 bytes)
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, Serialize, Deserialize))]
#[repr(C)]
pub struct PacketLogIpv6 {
    pub src_ip: Ipv6Addr,      // 16 Source IPv6
    pub dst_ip: Ipv6Addr,      // 16 Destination IPv6
    pub src_port: u16,         // 2
    pub dst_port: u16,         // 2
    pub proto: u8,             // 1  Final protocol after ext headers
    pub tcp_flags: u8,         // 1
    pub action: u8,            // 1
    pub reason: u8,            // 1
    pub threat_type: u8,       // 1
    pub hook: u8,              // 1
    pub packet_len: u16,       // 2
    pub ext_hdr_count: u8,     // 1  Number of extension headers seen
    pub _pad: [u8; 3],         // 3  Padding for alignment
}                              // Total: 48 bytes

// ============================================================
// IPv6 NEXT HEADER (PROTOCOL) CONSTANTS
// ============================================================

pub const NEXTHDR_HOP: u8 = 0;         // Hop-by-Hop Options (DANGEROUS)
pub const NEXTHDR_TCP: u8 = 6;         // TCP
pub const NEXTHDR_UDP: u8 = 17;        // UDP
pub const NEXTHDR_ROUTING: u8 = 43;    // Routing Header (Type 0 = DEPRECATED/ATTACK)
pub const NEXTHDR_FRAGMENT: u8 = 44;   // Fragment Header (DANGEROUS)
pub const NEXTHDR_AUTH: u8 = 51;       // Authentication Header (AH)
pub const NEXTHDR_NONE: u8 = 59;       // No Next Header
pub const NEXTHDR_DEST: u8 = 60;       // Destination Options
pub const NEXTHDR_ICMPV6: u8 = 58;     // ICMPv6
pub const NEXTHDR_ESP: u8 = 50;        // Encapsulating Security Payload

// ============================================================
// IPv6 SECURITY CONSTANTS
// ============================================================

/// Maximum extension headers allowed before DROP (anti-chain attack)
/// RFC recommends processing all, but attackers abuse this
/// NOTE: Reduced to 2 to satisfy eBPF verifier state tracking limits
/// Real-world IPv6 packets rarely have more than 1-2 extension headers
/// (typically just Fragment or Hop-by-Hop if any)
pub const IPV6_MAX_EXT_HEADERS: u8 = 2;

/// Maximum extension header chain length in bytes
pub const IPV6_MAX_EXT_HDR_LEN: u16 = 256;

/// Routing Header Type 0 is DEPRECATED (RFC 5095) - DROP!
pub const ROUTING_TYPE_0: u8 = 0;

/// ICMPv6 types that MUST be allowed for IPv6 to function
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_PKT_TOO_BIG: u8 = 2;        // Required for PMTUD!
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_PARAM_PROBLEM: u8 = 4;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_ROUTER_SOLICITATION: u8 = 133;
pub const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

// ============================================================
// IPv6 THREAT TYPES (extension of THREAT_* constants)
// ============================================================

pub const THREAT_IPV6_EXT_CHAIN: u8 = 20;     // Too many extension headers
pub const THREAT_IPV6_ROUTING_TYPE0: u8 = 21; // Deprecated routing header
pub const THREAT_IPV6_FRAGMENT: u8 = 22;      // Fragment attack (tiny, overlap)
pub const THREAT_IPV6_HOP_BY_HOP: u8 = 23;    // Hop-by-hop outside first
pub const THREAT_IPV6_UNKNOWN_EXT: u8 = 24;   // Unknown extension header

// ============================================================
// IPv6 AYA POD IMPLEMENTATIONS (userspace only)
// ============================================================

#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmKeyIpv6 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKeyIpv6 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnTrackKeyIpv6 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLogIpv6 {}
