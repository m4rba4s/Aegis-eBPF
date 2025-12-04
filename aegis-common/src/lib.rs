#![no_std]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, Serialize, Deserialize))]
#[repr(C)]
pub struct PacketLog {
    pub ipv4_addr: u32,
    pub action: u32,
}
