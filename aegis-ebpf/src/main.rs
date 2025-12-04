#![no_std]
#![no_main]

mod headers;
mod parsing;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use headers::{EthHdr, Ipv4Hdr, ETH_P_IP};
use parsing::ptr_at;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketLog {
    pub ipv4_addr: u32,
    pub port: u16,
    pub proto: u8,
    pub action: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: u8,
}

#[map]
static BLOCKLIST: HashMap<FlowKey, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    
    // Only handle IPv4
    let ether_type = unsafe { (*eth_hdr).ether_type };
    // Debug: Print ether_type
    // unsafe { aya_ebpf::helpers::gen::bpf_printk(b"EtherType: %x\0".as_ptr() as *const _, 1, u16::from_be(ether_type) as u64) };

    if u16::from_be(ether_type) != ETH_P_IP {
         return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4_hdr).src_addr };
    let proto = unsafe { (*ipv4_hdr).proto };
    
    // Parse L4 Port and Flags
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;
    let ip_len = unsafe { ((*ipv4_hdr).ihl() & 0x0F) * 4 } as usize;
    let l4_offset = EthHdr::LEN + ip_len;

    if proto == 6 { // TCP
        let tcp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?; // dst_port is at offset 2
        dst_port = u16::from_be(unsafe { *tcp_hdr });
        
        // TCP Flags are at offset 13 (12th byte is data offset, 13th is flags)
        // struct tcphdr {
        //   __be16 source;
        //   __be16 dest;
        //   __be32 seq;
        //   __be32 ack_seq;
        //   __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
        //   ...
        // }
        // In raw bytes:
        // Offset 0: Source (2)
        // Offset 2: Dest (2)
        // Offset 4: Seq (4)
        // Offset 8: Ack (4)
        // Offset 12: Data Offset + Res (1)
        // Offset 13: Flags (1)
        let flags_ptr: *const u8 = ptr_at(&ctx, l4_offset + 13)?;
        tcp_flags = unsafe { *flags_ptr };
    } else if proto == 17 { // UDP
        let udp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?; // dst_port is at offset 2
        dst_port = u16::from_be(unsafe { *udp_hdr });
    }

    // --- HEURISTICS ---
    if proto == 6 {
        let fin = tcp_flags & 0x01 != 0;
        let syn = tcp_flags & 0x02 != 0;
        let _rst = tcp_flags & 0x04 != 0;
        let psh = tcp_flags & 0x08 != 0;
        let _ack = tcp_flags & 0x10 != 0;
        let urg = tcp_flags & 0x20 != 0;
        
        // 1. Xmas Tree Scan (FIN + URG + PSH)
        if fin && urg && psh {
            return log_and_return(&ctx, src_addr, dst_port, proto, 3); // 3 = SUSPICIOUS
        }
        
        // 2. Null Scan (No flags set)
        if tcp_flags == 0 {
             return log_and_return(&ctx, src_addr, dst_port, proto, 3);
        }
        
        // 3. SYN + FIN (Illegal)
        if syn && fin {
             return log_and_return(&ctx, src_addr, dst_port, proto, 3);
        }
    }
    // ------------------

    // 1. Exact Match Lookup
    let key_exact = FlowKey {
        src_ip: src_addr, // Keep Network Byte Order for map key
        dst_port: dst_port, // Host Byte Order for simplicity in map? No, let's use Host for Port, Network for IP.
                            // Actually, let's be consistent. IP is BE (from packet). Port is Host (converted).
                            // Let's store Port as Host in Key.
        proto: proto,
        _pad: 0,
    };

    if let Some(action) = unsafe { BLOCKLIST.get(&key_exact) } {
        log_and_return(&ctx, src_addr, dst_port, proto, *action)
    } else {
        // 2. Wildcard Port/Proto Lookup (Block IP entirely)
        let key_wildcard = FlowKey {
            src_ip: src_addr,
            dst_port: 0,
            proto: 0,
            _pad: 0,
        };
        if let Some(action) = unsafe { BLOCKLIST.get(&key_wildcard) } {
            log_and_return(&ctx, src_addr, dst_port, proto, *action)
        } else {
            Ok(xdp_action::XDP_PASS)
        }
    }
}

fn log_and_return(ctx: &XdpContext, ip: u32, port: u16, proto: u8, action: u32) -> Result<u32, ()> {
    let log_entry = PacketLog {
        ipv4_addr: ip,
        port: port,
        proto: proto,
        action: action,
    };
    EVENTS.output(ctx, &log_entry, 0);
    Ok(xdp_action::XDP_DROP)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
