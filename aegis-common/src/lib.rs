#![no_std]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// Extended packet log for IDS/IPS mode
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, Serialize, Deserialize))]
#[repr(C)]
pub struct PacketLog {
    pub src_ip: u32,      // Source IP address
    pub dst_ip: u32,      // Destination IP address
    pub src_port: u16,    // Source port
    pub dst_port: u16,    // Destination port
    pub proto: u8,        // Protocol (6=TCP, 17=UDP)
    pub tcp_flags: u8,    // TCP flags byte
    pub action: u8,       // 0=PASS, 1=DROP, 2=ALERT
    pub threat_type: u8,  // Threat category
    pub packet_len: u16,  // Packet length
    pub _pad: u16,        // Padding for alignment
    pub timestamp: u64,   // Kernel timestamp (ns)
}

// Threat types for IDS categorization
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
