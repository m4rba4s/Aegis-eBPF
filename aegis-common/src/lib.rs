#![no_std]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// Extended packet log for IDS/IPS mode (32 bytes, aligned)
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, Serialize, Deserialize))]
#[repr(C)]
pub struct PacketLog {
    pub src_ip: u32,      // 4  Source IP address
    pub dst_ip: u32,      // 4  Destination IP address
    pub src_port: u16,    // 2  Source port
    pub dst_port: u16,    // 2  Destination port
    pub proto: u8,        // 1  Protocol (6=TCP, 17=UDP)
    pub tcp_flags: u8,    // 1  TCP flags byte
    pub action: u8,       // 1  0=PASS, 1=DROP, 2=ALERT
    pub reason: u8,       // 1  Verdict reason (why this action)
    pub threat_type: u8,  // 1  Threat category (if detected)
    pub hook: u8,         // 1  Hook point (XDP=1, TC=2, etc.)
    pub packet_len: u16,  // 2  Packet length
    pub timestamp: u64,   // 8  Kernel timestamp (ns)
}                         // Total: 32 bytes

// Verdict reasons (WHY the action was taken)
pub const REASON_DEFAULT: u8 = 0;        // Default policy (no rule matched)
pub const REASON_WHITELIST: u8 = 1;      // Private/internal IP whitelist
pub const REASON_CONNTRACK: u8 = 2;      // Connection tracking fast-path
pub const REASON_MANUAL_BLOCK: u8 = 3;   // Manual block via TUI
pub const REASON_CIDR_FEED: u8 = 4;      // Threat feed CIDR match
pub const REASON_PORTSCAN: u8 = 5;       // Port scan detection
pub const REASON_TCP_ANOMALY: u8 = 6;    // Null/Xmas/SYN+FIN scan
pub const REASON_RATELIMIT: u8 = 7;      // Rate limiting triggered
pub const REASON_IPV6_POLICY: u8 = 8;    // IPv6 policy decision
pub const REASON_MALFORMED: u8 = 9;      // Malformed L2/L3/L4

// Threat types for IDS categorization (WHAT was detected)
pub const THREAT_NONE: u8 = 0;
pub const THREAT_SCAN_XMAS: u8 = 1;
pub const THREAT_SCAN_NULL: u8 = 2;
pub const THREAT_SCAN_SYNFIN: u8 = 3;
pub const THREAT_SCAN_PORT: u8 = 4;
pub const THREAT_FLOOD_SYN: u8 = 5;
pub const THREAT_BLOCKLIST: u8 = 6;
pub const THREAT_INCOMING_SYN: u8 = 7;

// Actions
pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;
pub const ACTION_ALERT: u8 = 2;

// Hook points
pub const HOOK_XDP: u8 = 1;
pub const HOOK_TC_INGRESS: u8 = 2;
pub const HOOK_TC_EGRESS: u8 = 3;

/// Health statistics (per-CPU counters)
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

/// LPM key for CIDR matching (prefix + IP)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct LpmKeyIpv4 {
    pub prefix_len: u32,  // Number of bits in prefix (0-32)
    pub addr: u32,        // IPv4 address in network byte order
}

/// Value for CIDR blocklist entry
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CidrBlockEntry {
    pub category: u8,    // Feed category (1=Spamhaus, 2=AbuseCh, etc.)
    pub _pad: [u8; 3],
}

// Implement Pod trait for userspace aya compatibility
#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmKeyIpv4 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CidrBlockEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

// Feed categories
pub const CAT_NONE: u8 = 0;
pub const CAT_SPAMHAUS: u8 = 1;
pub const CAT_ABUSE_CH: u8 = 2;
pub const CAT_FIREHOL: u8 = 3;
pub const CAT_TRACKER: u8 = 4;
pub const CAT_MANUAL: u8 = 5;

