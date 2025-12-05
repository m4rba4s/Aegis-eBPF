#![no_std]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, Serialize, Deserialize))]
#[repr(C)]
pub struct PacketLog {
    pub ipv4_addr: u32,
    pub action: u32,
    pub port: u16,
    pub proto: u16,
}

pub const SUSPICIOUS: u32 = 3;
pub const DPI_DROP: u32 = 4;
