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
    pub src_ip: u32,      // Source IP address
    pub dst_ip: u32,      // Destination IP address
    pub src_port: u16,    // Source port
    pub dst_port: u16,    // Destination port
    pub proto: u8,        // Protocol (6=TCP, 17=UDP)
    pub tcp_flags: u8,    // TCP flags byte
    pub action: u8,       // 0=PASS, 1=DROP, 2=ALERT
    pub threat_type: u8,  // Threat category (see ThreatType)
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

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: u8,
}

// Rate limit state per IP
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RateLimitState {
    pub tokens: u32,      // Current tokens
    pub last_update: u64, // Last update timestamp (ns)
}

// Port Scan detection state per source IP
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PortScanState {
    pub port_bitmap: [u32; 8],  // 256 bits = ports 0-255 (common ports)
    pub port_count: u16,        // Count of unique ports accessed
    pub first_seen: u64,        // First packet timestamp (ns)
    pub _pad: [u8; 6],          // Padding for alignment
}

#[map]
static BLOCKLIST: HashMap<FlowKey, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

// Rate limit map: IP -> RateLimitState
#[map]
static RATE_LIMIT: HashMap<u32, RateLimitState> = HashMap::with_max_entries(4096, 0);

// Config map: key 0 = interface mode (0 = L2/Ethernet, 1 = L3/raw IP like WireGuard)
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

// Port Scan detection map: source IP -> PortScanState
#[map]
static PORT_SCAN: HashMap<u32, PortScanState> = HashMap::with_max_entries(4096, 0);

// Config: tokens per second refill rate, max bucket size
const TOKENS_PER_SEC: u32 = 100;  // 100 SYN packets/sec allowed
const MAX_TOKENS: u32 = 200;      // Burst capacity

// Port Scan detection thresholds
const PORT_SCAN_THRESHOLD: u16 = 10;     // Alert if >10 unique ports accessed
const PORT_SCAN_WINDOW_NS: u64 = 5_000_000_000;  // 5 second window

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Check CONFIG map for interface mode (0 = L2/Ethernet, 1 = L3/raw IP)
    // Default to L2 if not set
    let config_key: u32 = 0;
    let is_l3_mode = unsafe {
        CONFIG.get(&config_key).copied().unwrap_or(0) == 1
    };
    
    let (ip_offset, l4_base_offset) = if is_l3_mode {
        // L3 interface (WireGuard/tun) - IP starts at offset 0
        (0usize, 20usize)
    } else {
        // L2 interface (Ethernet) - check ether_type first
        let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
        let ether_type = unsafe { (*eth_hdr).ether_type };
        if u16::from_be(ether_type) != ETH_P_IP {
            return Ok(xdp_action::XDP_PASS);
        }
        (EthHdr::LEN, EthHdr::LEN + 20)
    };

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, ip_offset)?;
    let src_addr = unsafe { (*ipv4_hdr).src_addr };
    let dst_addr = unsafe { (*ipv4_hdr).dst_addr };
    let proto = unsafe { (*ipv4_hdr).proto };
    let total_len = u16::from_be(unsafe { (*ipv4_hdr).tot_len });
    
    // Check IP header length - SKIP packets with IP options
    let ip_ihl = unsafe { (*ipv4_hdr).ihl() & 0x0F };
    if ip_ihl != 5 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // L4 offset depends on interface type
    let l4_offset = l4_base_offset;
    
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;

    if proto == 6 { // TCP
        // src_port at L4+0
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });
        
        // dst_port at L4+2
        let tcp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *tcp_hdr });
        
        // TCP flags at L4+13
        let flags_ptr: *const u8 = ptr_at(&ctx, l4_offset + 13)?;
        tcp_flags = unsafe { *flags_ptr };
    } else if proto == 17 { // UDP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });
        
        let udp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *udp_hdr });
    }

    // --- HEURISTICS ---
    if proto == 6 {
        let fin = tcp_flags & 0x01 != 0;
        let syn = tcp_flags & 0x02 != 0;
        let psh = tcp_flags & 0x08 != 0;
        let ack = tcp_flags & 0x10 != 0;
        let urg = tcp_flags & 0x20 != 0;
        
        // 1. Xmas Tree Scan (FIN + URG + PSH)
        if fin && urg && psh {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, 
                proto, tcp_flags, ACTION_DROP, THREAT_SCAN_XMAS, total_len);
        }
        
        // 2. Null Scan (No flags set)
        if tcp_flags == 0 {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, THREAT_SCAN_NULL, total_len);
        }
        
        // 3. SYN + FIN (Illegal)
        if syn && fin {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, THREAT_SCAN_SYNFIN, total_len);
        }
        
        // 4. DROP ALL incoming SYN (no ACK) - blocks nmap and all new incoming connections
        // This is aggressive but effective against ALL scans
        if syn && !ack {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, THREAT_INCOMING_SYN, total_len);
        }
    }
    // ------------------

    // --- PORT SCAN DETECTION ---
    // Track unique destination ports per source IP
    // If >10 unique ports in 5 seconds = port scan
    if proto == 6 || proto == 17 { // TCP or UDP
        let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let port_index = (dst_port & 0xFF) as usize; // Only track ports 0-255
        let bitmap_index = port_index / 32;
        let bit_position = port_index % 32;
        
        if let Some(state) = unsafe { PORT_SCAN.get_ptr_mut(&src_addr) } {
            let state_ref = unsafe { &mut *state };
            
            // Reset if window expired
            if now_ns - state_ref.first_seen > PORT_SCAN_WINDOW_NS {
                state_ref.port_bitmap = [0u32; 8];
                state_ref.port_count = 0;
                state_ref.first_seen = now_ns;
            }
            
            // Check if this port was already seen
            if bitmap_index < 8 {
                let bit_mask = 1u32 << bit_position;
                if state_ref.port_bitmap[bitmap_index] & bit_mask == 0 {
                    // New port - mark it
                    state_ref.port_bitmap[bitmap_index] |= bit_mask;
                    state_ref.port_count += 1;
                }
                
                // Check threshold
                if state_ref.port_count > PORT_SCAN_THRESHOLD {
                    // Port scan detected!
                    return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                        proto, tcp_flags, ACTION_DROP, THREAT_SCAN_PORT, total_len);
                }
            }
        } else {
            // First packet from this IP - initialize
            let mut new_state = PortScanState {
                port_bitmap: [0u32; 8],
                port_count: 1,
                first_seen: now_ns,
                _pad: [0u8; 6],
            };
            if bitmap_index < 8 {
                new_state.port_bitmap[bitmap_index] = 1u32 << bit_position;
            }
            let _ = PORT_SCAN.insert(&src_addr, &new_state, 0);
        }
    }
    // ------------------

    // --- SYN FLOOD RATE LIMITING ---
    if proto == 6 {
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;
        
        // Only rate limit pure SYN packets (SYN without ACK)
        if syn && !ack {
            // Get current time in nanoseconds
            let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
            
            // Lookup or create rate limit state
            if let Some(state) = unsafe { RATE_LIMIT.get_ptr_mut(&src_addr) } {
                let state = unsafe { &mut *state };
                
                // Calculate time delta in seconds (approx)
                let delta_ns = now_ns.saturating_sub(state.last_update);
                let delta_sec = (delta_ns / 1_000_000_000) as u32;
                
                // Refill tokens (token bucket)
                let new_tokens = state.tokens.saturating_add(delta_sec * TOKENS_PER_SEC);
                state.tokens = if new_tokens > MAX_TOKENS { MAX_TOKENS } else { new_tokens };
                state.last_update = now_ns;
                
                // Check if we have tokens
                if state.tokens > 0 {
                    state.tokens -= 1;
                    // Allow packet
                } else {
                    // SYN FLOOD DETECTED - drop
                    return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                        proto, tcp_flags, ACTION_DROP, THREAT_FLOOD_SYN, total_len);
                }
            } else {
                // First packet from this IP - initialize with max tokens - 1
                let new_state = RateLimitState {
                    tokens: MAX_TOKENS - 1,
                    last_update: now_ns,
                };
                let _ = unsafe { RATE_LIMIT.insert(&src_addr, &new_state, 0) };
            }
        }
    }
    // ------------------

    // Only inspect TCP packets with NO options (data offset = 5)
    // ETH(14) + IP(20) + TCP(20) = 54 = payload start
    if proto == 6 {
        // Read TCP data offset at L4+12 (upper 4 bits)
        let doff_ptr: *const u8 = ptr_at(&ctx, l4_offset + 12)?;
        let doff = (unsafe { *doff_ptr } >> 4) & 0x0F;
        
        // Only proceed if doff is within reasonable bounds (5..=10)
        // We unroll the loop to satisfy the verifier (no variable offsets allowed)
        let payload_offset = if doff == 5 {
            l4_offset + 20
        } else if doff == 6 {
            l4_offset + 24
        } else if doff == 7 {
            l4_offset + 28
        } else if doff == 8 {
            l4_offset + 32
        } else if doff == 9 {
            l4_offset + 36
        } else if doff == 10 {
            l4_offset + 40
        } else {
            0 // Skip
        };

        if payload_offset > 0 {
            // Check "GET /admin" (10 bytes)
            // G=0x47 E=0x45 T=0x54 ' '=0x20 /=0x2F a=0x61 d=0x64 m=0x6D i=0x69 n=0x6E
            if let Ok(b0) = ptr_at::<u8>(&ctx, payload_offset) {
                if unsafe { *b0 } == 0x47 { // G
                    if let Ok(b1) = ptr_at::<u8>(&ctx, payload_offset + 1) {
                        if unsafe { *b1 } == 0x45 { // E
                            if let Ok(b2) = ptr_at::<u8>(&ctx, payload_offset + 2) {
                                if unsafe { *b2 } == 0x54 { // T
                                    if let Ok(b3) = ptr_at::<u8>(&ctx, payload_offset + 3) {
                                        if unsafe { *b3 } == 0x20 { // ' '
                                            if let Ok(b4) = ptr_at::<u8>(&ctx, payload_offset + 4) {
                                                if unsafe { *b4 } == 0x2F { // /
                                                    if let Ok(b5) = ptr_at::<u8>(&ctx, payload_offset + 5) {
                                                        if unsafe { *b5 } == 0x61 { // a
                                                            if let Ok(b6) = ptr_at::<u8>(&ctx, payload_offset + 6) {
                                                                if unsafe { *b6 } == 0x64 { // d
                                                                    if let Ok(b7) = ptr_at::<u8>(&ctx, payload_offset + 7) {
                                                                        if unsafe { *b7 } == 0x6D { // m
                                                                            if let Ok(b8) = ptr_at::<u8>(&ctx, payload_offset + 8) {
                                                                                if unsafe { *b8 } == 0x69 { // i
                                                                                    if let Ok(b9) = ptr_at::<u8>(&ctx, payload_offset + 9) {
                                                                                        if unsafe { *b9 } == 0x6E { // n
                                                                                            // DPI MATCH: GET /admin
                                                                                            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_DROP, THREAT_NONE, total_len);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // ------------------
    
    // 1. Exact Match Lookup
    let key_exact = FlowKey {
        src_ip: src_addr,
        dst_port: dst_port,
        proto: proto,
        _pad: 0,
    };

    if let Some(_action) = unsafe { BLOCKLIST.get(&key_exact) } {
        log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_DROP, THREAT_BLOCKLIST, total_len)
    } else {
        // 2. Wildcard Port/Proto Lookup (Block IP entirely)
        let key_wildcard = FlowKey {
            src_ip: src_addr,
            dst_port: 0,
            proto: 0,
            _pad: 0,
        };
        if let Some(_action) = unsafe { BLOCKLIST.get(&key_wildcard) } {
            log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_DROP, THREAT_BLOCKLIST, total_len)
        } else {
            // DEBUG: Log PASS for this IP to verify XDP is seeing packets
            // Uncomment next line to enable verbose logging (WARNING: high volume!)
            // EVENTS.output(&ctx, &PacketLog { ipv4_addr: src_addr, port: dst_port, proto, action: 0 }, 0);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

fn log_and_return(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
    action: u8,
    threat_type: u8,
    packet_len: u16,
) -> Result<u32, ()> {
    let timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    
    let log_entry = PacketLog {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        action,
        threat_type,
        packet_len,
        _pad: 0,
        timestamp,
    };
    EVENTS.output(ctx, &log_entry, 0);
    
    if action == ACTION_DROP {
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
