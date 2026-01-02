#![no_std]
#![no_main]

mod headers;
mod parsing;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray, lpm_trie::{LpmTrie, Key}},
    programs::XdpContext,
};
use headers::{EthHdr, Ipv4Hdr, ETH_P_IP};
use parsing::ptr_at;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketLog {
    pub src_ip: u32,      // 4  Source IP address
    pub dst_ip: u32,      // 4  Destination IP address
    pub src_port: u16,    // 2  Source port
    pub dst_port: u16,    // 2  Destination port
    pub proto: u8,        // 1  Protocol (6=TCP, 17=UDP)
    pub tcp_flags: u8,    // 1  TCP flags byte
    pub action: u8,       // 1  0=PASS, 1=DROP
    pub reason: u8,       // 1  Verdict reason
    pub threat_type: u8,  // 1  Threat category
    pub hook: u8,         // 1  Hook point (XDP=1)
    pub packet_len: u16,  // 2  Packet length
    pub timestamp: u64,   // 8  Kernel timestamp (ns)
}                         // Total: 32 bytes

// Verdict reasons (WHY)
pub const REASON_DEFAULT: u8 = 0;
pub const REASON_WHITELIST: u8 = 1;
pub const REASON_CONNTRACK: u8 = 2;
pub const REASON_MANUAL_BLOCK: u8 = 3;
pub const REASON_CIDR_FEED: u8 = 4;
pub const REASON_PORTSCAN: u8 = 5;
pub const REASON_TCP_ANOMALY: u8 = 6;
pub const REASON_RATELIMIT: u8 = 7;
pub const REASON_IPV6_POLICY: u8 = 8;
pub const REASON_MALFORMED: u8 = 9;

// Threat types (WHAT was detected)
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

// Hook point
pub const HOOK_XDP: u8 = 1;

// Stats counters (per-CPU array index)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Stats {
    pub pkts_seen: u64,
    pub pkts_pass: u64,
    pub pkts_drop: u64,
    pub events_ok: u64,
    pub events_fail: u64,
    pub ipv6_seen: u64,
    pub ipv6_pass: u64,
    pub ipv6_drop: u64,
    pub block_manual: u64,
    pub block_cidr: u64,
    pub portscan_hits: u64,
    pub conntrack_hits: u64,
}

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

// Exact match blocklist (legacy, for manual blocks)
#[map]
static BLOCKLIST: HashMap<FlowKey, u32> = HashMap::with_max_entries(1024, 0);

// CIDR prefix blocklist using LPM Trie (for threat feeds)
// Supports up to 50K CIDR prefixes efficiently
#[map]
static CIDR_BLOCKLIST: LpmTrie<LpmKeyIpv4, CidrBlockEntry> = LpmTrie::with_max_entries(65536, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

// Per-CPU health statistics
#[map]
static STATS: aya_ebpf::maps::PerCpuArray<Stats> = aya_ebpf::maps::PerCpuArray::with_max_entries(1, 0);

// Rate limit map: IP -> RateLimitState
#[map]
static RATE_LIMIT: HashMap<u32, RateLimitState> = HashMap::with_max_entries(4096, 0);

// Config map for runtime toggles
// Key 0 = interface mode (0 = L2/Ethernet, 1 = L3/raw IP)
// Keys 1-5 = defense modules (1 = enabled, 0 = disabled)
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

// CONFIG keys
const CFG_INTERFACE_MODE: u32 = 0;
const CFG_PORT_SCAN: u32 = 1;
const CFG_RATE_LIMIT: u32 = 2;
const CFG_THREAT_FEEDS: u32 = 3;
const CFG_CONN_TRACK: u32 = 4;
const CFG_SCAN_DETECT: u32 = 5;
const CFG_VERBOSE: u32 = 6;  // Log ALL packets (noisy!)

// Port Scan detection map: source IP -> PortScanState
#[map]
static PORT_SCAN: HashMap<u32, PortScanState> = HashMap::with_max_entries(4096, 0);

// --- CONNECTION TRACKING (Stateful Firewall) ---

/// Connection states
pub const CONN_NEW: u8 = 0;
pub const CONN_SYN_SENT: u8 = 1;      // Outgoing SYN sent
pub const CONN_SYN_RECV: u8 = 2;      // SYN received, awaiting SYN-ACK
pub const CONN_ESTABLISHED: u8 = 3;   // 3-way handshake complete
pub const CONN_FIN_WAIT: u8 = 4;      // FIN sent/received
pub const CONN_CLOSED: u8 = 5;        // Ready for cleanup

/// 5-tuple connection key
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnTrackKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// Connection state with timing
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnTrackState {
    pub state: u8,          // CONN_* state
    pub direction: u8,      // 0 = outgoing (we initiated), 1 = incoming
    pub _pad: [u8; 2],
    pub last_seen: u64,     // Last packet timestamp (ns)
    pub packets: u32,       // Packet count
    pub bytes: u32,         // Byte count
}

// Connection tracking map: 5-tuple -> state
// Tracks both directions of a connection
#[map]
static CONN_TRACK: HashMap<ConnTrackKey, ConnTrackState> = HashMap::with_max_entries(65536, 0);

// Connection timeout: 5 minutes for ESTABLISHED, 30s for others
const CONN_TIMEOUT_ESTABLISHED_NS: u64 = 300_000_000_000; // 5 min
const CONN_TIMEOUT_OTHER_NS: u64 = 30_000_000_000;        // 30 sec
// ------------------------------------------

// Config: tokens per second refill rate, max bucket size
const TOKENS_PER_SEC: u32 = 100;  // 100 SYN packets/sec allowed
const MAX_TOKENS: u32 = 200;      // Burst capacity

// Port Scan detection thresholds
// Increased to 50 to reduce false positives from browsers/proxies (Burp Suite, etc.)
const PORT_SCAN_THRESHOLD: u16 = 50;     // Alert if >50 unique ports accessed
const PORT_SCAN_WINDOW_NS: u64 = 5_000_000_000;  // 5 second window

// Helper: check if module is enabled (default: enabled if not set)
#[inline(always)]
fn is_module_enabled(key: u32) -> bool {
    unsafe { CONFIG.get(&key).copied().unwrap_or(1) == 1 }
}

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

    // --- WHITELIST CHECK (EARLY) ---
    // MUST be before heuristics to avoid blocking VPN internal traffic
    let src_octets = src_addr.to_be_bytes();
    let is_whitelisted = 
        src_octets[0] == 10 ||  // 10.0.0.0/8
        (src_octets[0] == 172 && (src_octets[1] & 0xF0) == 16) ||  // 172.16.0.0/12
        (src_octets[0] == 192 && src_octets[1] == 168) ||  // 192.168.0.0/16
        (src_octets[0] == 100 && (src_octets[1] & 0xC0) == 64) ||  // 100.64.0.0/10 CGNAT/VPN
        src_octets[0] == 127;  // 127.0.0.0/8 localhost
    
    if is_whitelisted {
        // Verbose logging for whitelisted traffic
        if is_module_enabled(CFG_VERBOSE) {
            log_packet(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_PASS, REASON_WHITELIST, THREAT_NONE, total_len);
        }
        return Ok(xdp_action::XDP_PASS);
    }
    // ------------------

    // --- CONNECTION TRACKING (Stateful Firewall) ---
    // ESTABLISHED connections bypass all detection (fast path)
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    
    // Build connection key (incoming direction: swap src/dst for lookup)
    let conn_key = ConnTrackKey {
        src_ip: dst_addr,      // Our IP as "source" of the connection
        dst_ip: src_addr,      // Remote IP as "destination"
        src_port: dst_port,    // Our port
        dst_port: src_port,    // Remote port  
        proto,
        _pad: [0u8; 3],
    };
    
    // Check if this is an existing ESTABLISHED connection
    if let Some(state) = unsafe { CONN_TRACK.get(&conn_key) } {
        if state.state == CONN_ESTABLISHED {
            // Fast path: ESTABLISHED connection, update last_seen and pass
            let mut updated = *state;
            updated.last_seen = now_ns;
            updated.packets = updated.packets.saturating_add(1);
            updated.bytes = updated.bytes.saturating_add(total_len as u32);
            let _ = CONN_TRACK.insert(&conn_key, &updated, 0);
            return Ok(xdp_action::XDP_PASS);
        }
    }
    
    // Also check the reverse direction (outgoing packets)
    let conn_key_rev = ConnTrackKey {
        src_ip: src_addr,
        dst_ip: dst_addr,
        src_port,
        dst_port,
        proto,
        _pad: [0u8; 3],
    };
    
    if let Some(state) = unsafe { CONN_TRACK.get(&conn_key_rev) } {
        // Check if entry is expired (lazy eviction)
        let timeout = if state.state == CONN_ESTABLISHED {
            CONN_TIMEOUT_ESTABLISHED_NS
        } else {
            CONN_TIMEOUT_OTHER_NS
        };
        
        let age_ns = now_ns.saturating_sub(state.last_seen);
        
        if age_ns > timeout {
            // Entry expired - delete it (lazy cleanup)
            let _ = CONN_TRACK.remove(&conn_key_rev);
            // Continue to normal processing, don't use this entry
        } else if state.state == CONN_ESTABLISHED && is_module_enabled(CFG_CONN_TRACK) {
            // Valid entry - update and fast-path
            let mut updated = *state;
            updated.last_seen = now_ns;
            updated.packets = updated.packets.saturating_add(1);
            updated.bytes = updated.bytes.saturating_add(total_len as u32);
            let _ = CONN_TRACK.insert(&conn_key_rev, &updated, 0);
            // Verbose logging for CT fast-path
            if is_module_enabled(CFG_VERBOSE) {
                log_packet(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_PASS, REASON_CONNTRACK, THREAT_NONE, total_len);
            }
            return Ok(xdp_action::XDP_PASS);
        }
    }
    // ------------------
    
    // --- SCAN DETECTION (Xmas/Null/SYN+FIN) ---
    if is_module_enabled(CFG_SCAN_DETECT) && proto == 6 {
        let fin = tcp_flags & 0x01 != 0;
        let syn = tcp_flags & 0x02 != 0;
        let psh = tcp_flags & 0x08 != 0;
        let ack = tcp_flags & 0x10 != 0;
        let urg = tcp_flags & 0x20 != 0;
        
        // 1. Xmas Tree Scan (FIN + URG + PSH)
        if fin && urg && psh {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, 
                proto, tcp_flags, ACTION_DROP, REASON_TCP_ANOMALY, THREAT_SCAN_XMAS, total_len);
        }
        
        // 2. Null Scan (No flags set)
        if tcp_flags == 0 {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, REASON_TCP_ANOMALY, THREAT_SCAN_NULL, total_len);
        }
        
        // 3. SYN + FIN (Illegal)
        if syn && fin {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, REASON_TCP_ANOMALY, THREAT_SCAN_SYNFIN, total_len);
        }
        
        // NOTE: We intentionally DO NOT block all incoming SYN here.
        // The SYN-ACK (response to our outgoing SYN) is needed for connections to work.
        // Connection tracking handles this: once we get SYN-ACK, connection becomes ESTABLISHED
        // and future packets use the fast-path.
        //
        // For inbound server scenarios (if you're running a server), you'd want to allow
        // incoming SYN to specific ports anyway.
    }
    // ------------------

    // --- PORT SCAN DETECTION ---
    // Track unique destination ports per source IP
    // If >50 unique ports in 5 seconds = port scan
    // NOTE: Only TCP - UDP naturally uses many ports (streaming, gaming, VoIP)
    if is_module_enabled(CFG_PORT_SCAN) && proto == 6 { // TCP only
        let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let port_index = (dst_port & 0xFF) as usize; // Only track ports 0-255
        let bitmap_index = port_index / 32;
        let bit_position = port_index % 32;
        
        if let Some(state) = PORT_SCAN.get_ptr_mut(&src_addr) {
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
                        proto, tcp_flags, ACTION_DROP, REASON_PORTSCAN, THREAT_SCAN_PORT, total_len);
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
    // Module toggle check
    if is_module_enabled(CFG_RATE_LIMIT) && proto == 6 {
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;
        
        // Only rate limit pure SYN packets (SYN without ACK)
        if syn && !ack {
            // Get current time in nanoseconds
            let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
            
            // Lookup or create rate limit state
            if let Some(state) = RATE_LIMIT.get_ptr_mut(&src_addr) {
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
                        proto, tcp_flags, ACTION_DROP, REASON_RATELIMIT, THREAT_FLOOD_SYN, total_len);
                }
            } else {
                // First packet from this IP - initialize with max tokens - 1
                let new_state = RateLimitState {
                    tokens: MAX_TOKENS - 1,
                    last_update: now_ns,
                };
                let _ = RATE_LIMIT.insert(&src_addr, &new_state, 0);
            }
        }
    }
    // ------------------

    // --- DPI SECTION (DISABLED) ---
    // Deep Packet Inspection for specific patterns
    // TODO: Make configurable via CONFIG map
    // Currently disabled - enable only if needed
    #[allow(dead_code)]
    const DPI_ENABLED: bool = false;
    
    if DPI_ENABLED && proto == 6 {
        // Read TCP data offset at L4+12 (upper 4 bits)
        if let Ok(doff_ptr) = ptr_at::<u8>(&ctx, l4_offset + 12) {
            let doff = (unsafe { *doff_ptr } >> 4) & 0x0F;
            if doff >= 5 && doff <= 10 {
                let payload_offset = l4_offset + (doff as usize) * 4;
                // Pattern matching would go here
                // For now, just pass through
                let _ = payload_offset;
            }
        }
    }
    // ------------------
    
    // 0. CIDR Blocklist Lookup (threat feeds - most efficient)
    if is_module_enabled(CFG_THREAT_FEEDS) {
        let cidr_key = Key::new(32, LpmKeyIpv4 {
            prefix_len: 32,
            addr: src_addr,
        });
        
        if let Some(_entry) = CIDR_BLOCKLIST.get(&cidr_key) {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, 
                proto, tcp_flags, ACTION_DROP, REASON_CIDR_FEED, THREAT_BLOCKLIST, total_len);
        }
    }
    
    // 1. Exact Match Lookup (manual blocks)
    let key_exact = FlowKey {
        src_ip: src_addr,
        dst_port: dst_port,
        proto: proto,
        _pad: 0,
    };

    if let Some(_action) = unsafe { BLOCKLIST.get(&key_exact) } {
        log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_DROP, REASON_MANUAL_BLOCK, THREAT_BLOCKLIST, total_len)
    } else {
        // 2. Wildcard Port/Proto Lookup (Block IP entirely)
        let key_wildcard = FlowKey {
            src_ip: src_addr,
            dst_port: 0,
            proto: 0,
            _pad: 0,
        };
        if let Some(_action) = unsafe { BLOCKLIST.get(&key_wildcard) } {
            log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_DROP, REASON_MANUAL_BLOCK, THREAT_BLOCKLIST, total_len)
        } else {
            // --- CREATE/UPDATE CONNECTION TRACKING ---
            // If we reach here, packet is allowed - track the connection
            
            if proto == 6 { // TCP
                let syn = tcp_flags & 0x02 != 0;
                let ack = tcp_flags & 0x10 != 0;
                
                // Incoming SYN-ACK = response to our SYN = ESTABLISHED
                if syn && ack {
                    let new_conn = ConnTrackState {
                        state: CONN_ESTABLISHED,
                        direction: 0, // We initiated
                        _pad: [0u8; 2],
                        last_seen: now_ns,
                        packets: 1,
                        bytes: total_len as u32,
                    };
                    // Key: our outgoing connection (reversed)
                    let out_key = ConnTrackKey {
                        src_ip: dst_addr,
                        dst_ip: src_addr,
                        src_port: dst_port,
                        dst_port: src_port,
                        proto,
                        _pad: [0u8; 3],
                    };
                    let _ = CONN_TRACK.insert(&out_key, &new_conn, 0);
                }
            } else if proto == 17 { // UDP - pseudo-connection
                // Any valid UDP response = ESTABLISHED
                let new_conn = ConnTrackState {
                    state: CONN_ESTABLISHED,
                    direction: 0,
                    _pad: [0u8; 2],
                    last_seen: now_ns,
                    packets: 1,
                    bytes: total_len as u32,
                };
                let out_key = ConnTrackKey {
                    src_ip: dst_addr,
                    dst_ip: src_addr,
                    src_port: dst_port,
                    dst_port: src_port,
                    proto,
                    _pad: [0u8; 3],
                };
                let _ = CONN_TRACK.insert(&out_key, &new_conn, 0);
            }
            // -------------------------------------------
            
            // Verbose logging for normal pass
            if is_module_enabled(CFG_VERBOSE) {
                log_packet(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_PASS, REASON_DEFAULT, THREAT_NONE, total_len);
            }
            Ok(xdp_action::XDP_PASS)
        }
    }
}

// Log packet without returning (for verbose mode)
#[inline(always)]
fn log_packet(
    ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
    action: u8,
    reason: u8,
    threat_type: u8,
    packet_len: u16,
) {
    let timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    
    let log_entry = PacketLog {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        action,
        reason,
        threat_type,
        hook: HOOK_XDP,
        packet_len,
        timestamp,
    };
    EVENTS.output(ctx, &log_entry, 0);
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
    reason: u8,
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
        reason,
        threat_type,
        hook: HOOK_XDP,
        packet_len,
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
