//! Aegis XDP Firewall - eBPF Program
//!
//! This is the XDP (eXpress Data Path) ingress firewall.
//! All shared types are imported from aegis-common (Single Source of Truth).

#![no_std]
#![no_main]

mod headers;
mod parsing;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray, PerCpuArray, lpm_trie::{LpmTrie, Key}},
    programs::XdpContext,
};
use headers::{EthHdr, Ipv4Hdr, ETH_P_IP};
use parsing::ptr_at;

// ============================================================
// IMPORTS FROM aegis-common (Single Source of Truth)
// ============================================================
use aegis_common::{
    // Structures
    PacketLog, Stats, FlowKey, ConnTrackKey, ConnTrackState,
    LpmKeyIpv4, CidrBlockEntry, RateLimitState, PortScanState,
    // Verdict reasons
    REASON_DEFAULT, REASON_WHITELIST, REASON_CONNTRACK, REASON_MANUAL_BLOCK,
    REASON_CIDR_FEED, REASON_PORTSCAN, REASON_TCP_ANOMALY, REASON_RATELIMIT,
    // Threat types
    THREAT_NONE, THREAT_SCAN_XMAS, THREAT_SCAN_NULL, THREAT_SCAN_SYNFIN,
    THREAT_SCAN_PORT, THREAT_FLOOD_SYN, THREAT_BLOCKLIST,
    // Actions
    ACTION_PASS, ACTION_DROP,
    // Hook points
    HOOK_XDP,
    // Connection states
    CONN_ESTABLISHED,
    // Config keys
    CFG_INTERFACE_MODE, CFG_PORT_SCAN, CFG_RATE_LIMIT, CFG_THREAT_FEEDS,
    CFG_CONN_TRACK, CFG_SCAN_DETECT, CFG_VERBOSE,
    // Rate limiting constants
    TOKENS_PER_SEC, MAX_TOKENS,
    // Port scan constants
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW_NS,
    // Connection timeouts
    CONN_TIMEOUT_ESTABLISHED_NS, CONN_TIMEOUT_OTHER_NS,
};

// ============================================================
// BPF MAPS
// ============================================================

/// Exact match blocklist (manual blocks)
#[map]
static BLOCKLIST: HashMap<FlowKey, u32> = HashMap::with_max_entries(1024, 0);

/// CIDR prefix blocklist using LPM Trie (for threat feeds)
#[map]
static CIDR_BLOCKLIST: LpmTrie<LpmKeyIpv4, CidrBlockEntry> = LpmTrie::with_max_entries(65536, 0);

/// Perf event array for logging to userspace
#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

/// Per-CPU health statistics
#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

/// Rate limit map: IP -> RateLimitState
#[map]
static RATE_LIMIT: HashMap<u32, RateLimitState> = HashMap::with_max_entries(4096, 0);

/// Config map for runtime toggles
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

/// Port Scan detection map: source IP -> PortScanState
#[map]
static PORT_SCAN: HashMap<u32, PortScanState> = HashMap::with_max_entries(4096, 0);

/// Connection tracking map: 5-tuple -> state
#[map]
static CONN_TRACK: HashMap<ConnTrackKey, ConnTrackState> = HashMap::with_max_entries(65536, 0);

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/// Check if module is enabled (default: enabled if not set)
#[inline(always)]
fn is_module_enabled(key: u32) -> bool {
    unsafe { CONFIG.get(&key).copied().unwrap_or(1) == 1 }
}

// Stats increment helpers
#[inline(always)]
fn stats_inc_seen() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).pkts_seen = (*s).pkts_seen.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_pass() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).pkts_pass = (*s).pkts_pass.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_drop() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).pkts_drop = (*s).pkts_drop.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_event_ok() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).events_ok = (*s).events_ok.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_portscan() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).portscan_hits = (*s).portscan_hits.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_conntrack() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).conntrack_hits = (*s).conntrack_hits.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_block_manual() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).block_manual = (*s).block_manual.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_block_cidr() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).block_cidr = (*s).block_cidr.wrapping_add(1);
        }
    }
}

// ============================================================
// XDP ENTRY POINT
// ============================================================

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Increment packet counter
    stats_inc_seen();

    // Check CONFIG map for interface mode (0 = L2/Ethernet, 1 = L3/raw IP)
    let is_l3_mode = unsafe {
        CONFIG.get(&CFG_INTERFACE_MODE).copied().unwrap_or(0) == 1
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

    let l4_offset = l4_base_offset;

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;

    if proto == 6 { // TCP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });

        let tcp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *tcp_hdr });

        let flags_ptr: *const u8 = ptr_at(&ctx, l4_offset + 13)?;
        tcp_flags = unsafe { *flags_ptr };
    } else if proto == 17 { // UDP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });

        let udp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *udp_hdr });
    }

    // --- WHITELIST CHECK (EARLY) ---
    let src_octets = src_addr.to_be_bytes();
    let is_whitelisted =
        src_octets[0] == 10 ||  // 10.0.0.0/8
        (src_octets[0] == 172 && (src_octets[1] & 0xF0) == 16) ||  // 172.16.0.0/12
        (src_octets[0] == 192 && src_octets[1] == 168) ||  // 192.168.0.0/16
        (src_octets[0] == 100 && (src_octets[1] & 0xC0) == 64) ||  // 100.64.0.0/10 CGNAT/VPN
        src_octets[0] == 127;  // 127.0.0.0/8 localhost

    if is_whitelisted {
        if is_module_enabled(CFG_VERBOSE) {
            log_packet(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_PASS, REASON_WHITELIST, THREAT_NONE, total_len);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // --- CONNECTION TRACKING (Stateful Firewall) ---
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Build connection key (incoming direction: swap src/dst for lookup)
    let conn_key = ConnTrackKey {
        src_ip: dst_addr,
        dst_ip: src_addr,
        src_port: dst_port,
        dst_port: src_port,
        proto,
        _pad: [0u8; 3],
    };

    // Check if this is an existing ESTABLISHED connection
    if let Some(state) = unsafe { CONN_TRACK.get(&conn_key) } {
        if state.state == CONN_ESTABLISHED {
            let mut updated = *state;
            updated.last_seen = now_ns;
            updated.packets = updated.packets.saturating_add(1);
            updated.bytes = updated.bytes.saturating_add(total_len as u32);
            let _ = CONN_TRACK.insert(&conn_key, &updated, 0);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // Check reverse direction
    let conn_key_rev = ConnTrackKey {
        src_ip: src_addr,
        dst_ip: dst_addr,
        src_port,
        dst_port,
        proto,
        _pad: [0u8; 3],
    };

    if let Some(state) = unsafe { CONN_TRACK.get(&conn_key_rev) } {
        let timeout = if state.state == CONN_ESTABLISHED {
            CONN_TIMEOUT_ESTABLISHED_NS
        } else {
            CONN_TIMEOUT_OTHER_NS
        };

        let age_ns = now_ns.saturating_sub(state.last_seen);

        if age_ns > timeout {
            let _ = CONN_TRACK.remove(&conn_key_rev);
        } else if state.state == CONN_ESTABLISHED && is_module_enabled(CFG_CONN_TRACK) {
            let mut updated = *state;
            updated.last_seen = now_ns;
            updated.packets = updated.packets.saturating_add(1);
            updated.bytes = updated.bytes.saturating_add(total_len as u32);
            let _ = CONN_TRACK.insert(&conn_key_rev, &updated, 0);
            stats_inc_conntrack();
            stats_inc_pass();
            if is_module_enabled(CFG_VERBOSE) {
                log_packet(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_PASS, REASON_CONNTRACK, THREAT_NONE, total_len);
            }
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // --- SCAN DETECTION (Xmas/Null/SYN+FIN) ---
    if is_module_enabled(CFG_SCAN_DETECT) && proto == 6 {
        let fin = tcp_flags & 0x01 != 0;
        let syn = tcp_flags & 0x02 != 0;
        let psh = tcp_flags & 0x08 != 0;
        let urg = tcp_flags & 0x20 != 0;

        // Xmas Tree Scan (FIN + URG + PSH)
        if fin && urg && psh {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, REASON_TCP_ANOMALY, THREAT_SCAN_XMAS, total_len);
        }

        // Null Scan (No flags set)
        if tcp_flags == 0 {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, REASON_TCP_ANOMALY, THREAT_SCAN_NULL, total_len);
        }

        // SYN + FIN (Illegal)
        if syn && fin {
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, REASON_TCP_ANOMALY, THREAT_SCAN_SYNFIN, total_len);
        }
    }

    // --- PORT SCAN DETECTION ---
    if is_module_enabled(CFG_PORT_SCAN) && proto == 6 {
        let port_index = (dst_port & 0xFF) as usize;
        let bitmap_index = port_index / 32;
        let bit_position = port_index % 32;

        if let Some(state) = PORT_SCAN.get_ptr_mut(&src_addr) {
            let state_ref = unsafe { &mut *state };

            if now_ns - state_ref.first_seen > PORT_SCAN_WINDOW_NS {
                state_ref.port_bitmap = [0u32; 8];
                state_ref.port_count = 0;
                state_ref.first_seen = now_ns;
            }

            if bitmap_index < 8 {
                let bit_mask = 1u32 << bit_position;
                if state_ref.port_bitmap[bitmap_index] & bit_mask == 0 {
                    state_ref.port_bitmap[bitmap_index] |= bit_mask;
                    state_ref.port_count += 1;
                }

                if state_ref.port_count > PORT_SCAN_THRESHOLD {
                    stats_inc_portscan();
                    return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                        proto, tcp_flags, ACTION_DROP, REASON_PORTSCAN, THREAT_SCAN_PORT, total_len);
                }
            }
        } else {
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

    // --- SYN FLOOD RATE LIMITING ---
    if is_module_enabled(CFG_RATE_LIMIT) && proto == 6 {
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;

        if syn && !ack {
            if let Some(state) = RATE_LIMIT.get_ptr_mut(&src_addr) {
                let state = unsafe { &mut *state };

                let delta_ns = now_ns.saturating_sub(state.last_update);
                let delta_sec = (delta_ns / 1_000_000_000) as u32;

                let new_tokens = state.tokens.saturating_add(delta_sec * TOKENS_PER_SEC);
                state.tokens = if new_tokens > MAX_TOKENS { MAX_TOKENS } else { new_tokens };
                state.last_update = now_ns;

                if state.tokens > 0 {
                    state.tokens -= 1;
                } else {
                    return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                        proto, tcp_flags, ACTION_DROP, REASON_RATELIMIT, THREAT_FLOOD_SYN, total_len);
                }
            } else {
                let new_state = RateLimitState {
                    tokens: MAX_TOKENS - 1,
                    last_update: now_ns,
                };
                let _ = RATE_LIMIT.insert(&src_addr, &new_state, 0);
            }
        }
    }

    // --- CIDR BLOCKLIST (Threat feeds) ---
    if is_module_enabled(CFG_THREAT_FEEDS) {
        let cidr_key = Key::new(32, LpmKeyIpv4 {
            prefix_len: 32,
            addr: src_addr,
        });

        if let Some(_entry) = CIDR_BLOCKLIST.get(&cidr_key) {
            stats_inc_block_cidr();
            return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, REASON_CIDR_FEED, THREAT_BLOCKLIST, total_len);
        }
    }

    // --- EXACT MATCH BLOCKLIST (Manual blocks) ---
    let key_exact = FlowKey {
        src_ip: src_addr,
        dst_port,
        proto,
        _pad: 0,
    };

    if let Some(_action) = unsafe { BLOCKLIST.get(&key_exact) } {
        stats_inc_block_manual();
        return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
            proto, tcp_flags, ACTION_DROP, REASON_MANUAL_BLOCK, THREAT_BLOCKLIST, total_len);
    }

    // Wildcard port/proto lookup
    let key_wildcard = FlowKey {
        src_ip: src_addr,
        dst_port: 0,
        proto: 0,
        _pad: 0,
    };

    if let Some(_action) = unsafe { BLOCKLIST.get(&key_wildcard) } {
        stats_inc_block_manual();
        return log_and_return(&ctx, src_addr, dst_addr, src_port, dst_port,
            proto, tcp_flags, ACTION_DROP, REASON_MANUAL_BLOCK, THREAT_BLOCKLIST, total_len);
    }

    // --- CREATE/UPDATE CONNECTION TRACKING ---
    if proto == 6 { // TCP
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;

        // Incoming SYN-ACK = response to our SYN = ESTABLISHED
        if syn && ack {
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
    } else if proto == 17 { // UDP
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

    // Verbose logging for normal pass
    if is_module_enabled(CFG_VERBOSE) {
        log_packet(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, ACTION_PASS, REASON_DEFAULT, THREAT_NONE, total_len);
    }

    Ok(xdp_action::XDP_PASS)
}

// ============================================================
// LOGGING HELPERS
// ============================================================

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
    stats_inc_event_ok();

    if action == ACTION_DROP {
        stats_inc_drop();
        Ok(xdp_action::XDP_DROP)
    } else {
        stats_inc_pass();
        Ok(xdp_action::XDP_PASS)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
