
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
