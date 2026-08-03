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

#[allow(dead_code)]
impl Ipv4Hdr {
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }
}

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv6Hdr {
    pub ver_tc_fl: [u8; 4],
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

impl Ipv6Hdr {
    pub const LEN: usize = 40;
}

#[repr(C)]
#[allow(dead_code)]
pub struct Ipv6ExtHdr {
    pub next_header: u8,
    pub hdr_ext_len: u8,
}

#[allow(dead_code)]
impl Ipv6ExtHdr {
    pub const MIN_LEN: usize = 8;

    #[inline(always)]
    pub fn len(&self) -> usize {
        ((self.hdr_ext_len as usize) + 1) * 8
    }
}


/// IPv6 Fragment Header (8 bytes). Used by try_tc_ipv6 for the P0-1 fail-closed
/// fragment drop. Must stay layout-identical to aegis-ebpf/src/headers.rs.
#[repr(C)]
#[allow(dead_code)]
pub struct Ipv6FragHdr {
    pub next_header: u8,
    pub reserved: u8,
    /// Fragment offset (13 bits) + Reserved (2 bits) + M flag (1 bit)
    pub frag_off_m: u16,
    pub identification: u32,
}

#[allow(dead_code)]
impl Ipv6FragHdr {
    pub const LEN: usize = 8;
}

/// IPv6 Routing Header. Used by try_tc_ipv6 for the P0-2 RH0 (RFC 5095) drop.
/// Must stay layout-identical to aegis-ebpf/src/headers.rs.
#[repr(C)]
#[allow(dead_code)]
pub struct Ipv6RoutingHdr {
    pub next_header: u8,
    pub hdr_ext_len: u8,
    pub routing_type: u8,
    pub segments_left: u8,
}
