
#[repr(C)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: u16,
}

impl EthHdr {
    pub const LEN: usize = 14;
}

#[repr(C)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

impl Ipv4Hdr {
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }
}

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;

// ============================================================
// IPv6 HEADERS
// ============================================================

/// IPv6 Base Header (40 bytes fixed)
#[repr(C)]
pub struct Ipv6Hdr {
    /// Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    pub version_tc_flow: u32,
    /// Payload length (excluding this header)
    pub payload_len: u16,
    /// Next header type (protocol or extension)
    pub next_header: u8,
    /// Hop limit (like TTL in IPv4)
    pub hop_limit: u8,
    /// Source address (128 bits)
    pub src_addr: [u8; 16],
    /// Destination address (128 bits)
    pub dst_addr: [u8; 16],
}

impl Ipv6Hdr {
    pub const LEN: usize = 40;

    /// Extract version (should be 6)
    #[inline(always)]
    pub fn version(&self) -> u8 {
        ((u32::from_be(self.version_tc_flow) >> 28) & 0xF) as u8
    }
}

/// Generic IPv6 Extension Header
/// Most extension headers start with next_header + hdr_ext_len
#[repr(C)]
pub struct Ipv6ExtHdr {
    pub next_header: u8,
    /// Length in 8-byte units, NOT including first 8 bytes
    pub hdr_ext_len: u8,
}

impl Ipv6ExtHdr {
    pub const MIN_LEN: usize = 8;

    /// Total header length in bytes
    #[inline(always)]
    pub fn len(&self) -> usize {
        ((self.hdr_ext_len as usize) + 1) * 8
    }
}

/// IPv6 Fragment Header (8 bytes)
#[repr(C)]
pub struct Ipv6FragHdr {
    pub next_header: u8,
    pub reserved: u8,
    /// Fragment offset (13 bits) + Reserved (2 bits) + M flag (1 bit)
    pub frag_off_m: u16,
    pub identification: u32,
}

impl Ipv6FragHdr {
    pub const LEN: usize = 8;

    /// Fragment offset in 8-byte units (multiply by 8 for byte offset)
    #[inline(always)]
    pub fn offset(&self) -> u16 {
        (u16::from_be(self.frag_off_m) >> 3) & 0x1FFF
    }

    /// More Fragments flag
    #[inline(always)]
    pub fn more_fragments(&self) -> bool {
        u16::from_be(self.frag_off_m) & 0x1 != 0
    }
}

/// IPv6 Routing Header
#[repr(C)]
pub struct Ipv6RoutingHdr {
    pub next_header: u8,
    pub hdr_ext_len: u8,
    pub routing_type: u8,
    pub segments_left: u8,
}
