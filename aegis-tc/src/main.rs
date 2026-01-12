#![no_std]
#![no_main]

mod headers;
mod parsing;

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{HashMap, PerfEventArray, lpm_trie::{LpmTrie, Key}},
    programs::TcContext,
};
use headers::{EthHdr, Ipv4Hdr, ETH_P_IP};
use parsing::ptr_at;

// ============================================================
// SHARED STRUCTURES (Imported from aegis-common - Single Source of Truth)
// ============================================================
use aegis_common::{
    PacketLog, ConnTrackKey, ConnTrackState, LpmKeyIpv4, CidrBlockEntry,
    HOOK_TC_EGRESS, THREAT_NONE, THREAT_EGRESS_BLOCKED,
    ACTION_PASS, ACTION_DROP,
    CONN_SYN_SENT, CONN_ESTABLISHED, CONN_FIN_WAIT, CONN_CLOSED,
};

// Config keys (only used locally in TC)
const CFG_INTERFACE_MODE: u32 = 0;
const CFG_VERBOSE: u32 = 6;

// ============================================================
// MAPS (Pinned, shared with XDP program)
// ============================================================

/// Shared connection tracking map
#[map]
static CONN_TRACK: HashMap<ConnTrackKey, ConnTrackState> = HashMap::with_max_entries(65536, 0);

/// Egress-specific blocklist (destination IPs we block outgoing to)
/// This is NEW - not shared with XDP
#[map]
static EGRESS_BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

/// CIDR-based egress blocklist (for C2/malware feeds)
#[map]
static EGRESS_CIDR_BLOCKLIST: LpmTrie<LpmKeyIpv4, CidrBlockEntry> = LpmTrie::with_max_entries(65536, 0);

/// Shared config map
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

/// Shared perf event array for logging
#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

// ============================================================
// ENTRY POINT
// ============================================================

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, // Fail-open on parse errors (safety)
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    // Get interface mode (L2 vs L3)
    let is_l3_mode = unsafe {
        CONFIG.get(&CFG_INTERFACE_MODE).copied().unwrap_or(0) == 1
    };
    
    let ip_offset = if is_l3_mode {
        0usize
    } else {
        // Check ether_type for L2
        let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
        let ether_type = unsafe { (*eth_hdr).ether_type };
        if u16::from_be(ether_type) != ETH_P_IP {
            return Ok(TC_ACT_OK);
        }
        EthHdr::LEN
    };

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, ip_offset)?;
    let src_addr = unsafe { (*ipv4_hdr).src_addr };
    let dst_addr = unsafe { (*ipv4_hdr).dst_addr };
    let proto = unsafe { (*ipv4_hdr).proto };
    let total_len = u16::from_be(unsafe { (*ipv4_hdr).tot_len });
    
    // L4 parsing
    let l4_offset = ip_offset + 20;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;

    if proto == 6 { // TCP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });
        
        let dst_port_ptr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *dst_port_ptr });
        
        let flags_ptr: *const u8 = ptr_at(&ctx, l4_offset + 13)?;
        tcp_flags = unsafe { *flags_ptr };
    } else if proto == 17 { // UDP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });
        
        let dst_port_ptr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *dst_port_ptr });
    }

    // --- EGRESS BLOCKLIST CHECK ---
    // 1. Exact IP match
    if let Some(_) = unsafe { EGRESS_BLOCKLIST.get(&dst_addr) } {
        log_and_drop(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, total_len);
        return Ok(TC_ACT_SHOT);
    }
    
    // 2. CIDR match
    let cidr_key = Key::new(32, LpmKeyIpv4 {
        prefix_len: 32,
        addr: dst_addr,
    });
    if let Some(_) = EGRESS_CIDR_BLOCKLIST.get(&cidr_key) {
        log_and_drop(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, total_len);
        return Ok(TC_ACT_SHOT);
    }

    // --- CONNECTION STATE TRACKING ---
    // Track outgoing SYN packets for state synchronization with XDP
    if proto == 6 {
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;
        let fin = tcp_flags & 0x01 != 0;
        
        let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        
        // Outgoing SYN (no ACK) = new connection initiation
        if syn && !ack {
            let conn_key = ConnTrackKey {
                src_ip: src_addr,    // Our IP
                dst_ip: dst_addr,    // Remote IP
                src_port,
                dst_port,
                proto,
                _pad: [0u8; 3],
            };
            
            let new_state = ConnTrackState {
                state: CONN_SYN_SENT,
                direction: 0,  // Outgoing
                _pad: [0u8; 2],
                last_seen: now_ns,
                packets: 1,
                bytes: total_len as u32,
            };
            
            // Insert with BPF_NOEXIST - don't overwrite existing
            let _ = CONN_TRACK.insert(&conn_key, &new_state, 0);
            
            // Always log new outgoing TCP connections (SYN)
            log_pass(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, total_len);
        }
        
        // Outgoing FIN = connection closing
        if fin {
            let conn_key = ConnTrackKey {
                src_ip: src_addr,
                dst_ip: dst_addr,
                src_port,
                dst_port,
                proto,
                _pad: [0u8; 3],
            };
            
            if let Some(state) = unsafe { CONN_TRACK.get(&conn_key) } {
                let mut updated = *state;
                updated.state = CONN_FIN_WAIT;
                updated.last_seen = now_ns;
                updated.packets = updated.packets.saturating_add(1);
                updated.bytes = updated.bytes.saturating_add(total_len as u32);
                let _ = CONN_TRACK.insert(&conn_key, &updated, 0);
            }
        }
    }
    
    // UDP: Track outgoing for pseudo-state
    if proto == 17 {
        let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let conn_key = ConnTrackKey {
            src_ip: src_addr,
            dst_ip: dst_addr,
            src_port,
            dst_port,
            proto,
            _pad: [0u8; 3],
        };
        
        // Create or update state
        let new_state = ConnTrackState {
            state: CONN_SYN_SENT,  // Pseudo-state for UDP
            direction: 0,
            _pad: [0u8; 2],
            last_seen: now_ns,
            packets: 1,
            bytes: total_len as u32,
        };
        let _ = CONN_TRACK.insert(&conn_key, &new_state, 0);
    }

    // Always log egress traffic for visibility in TUI
    // (verbose mode logs additional details if enabled)
    log_pass(&ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, total_len);

    Ok(TC_ACT_OK)
}

// ============================================================
// LOGGING HELPERS
// ============================================================

#[inline(always)]
fn log_and_drop(
    ctx: &TcContext,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
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
        action: ACTION_DROP,
        threat_type: THREAT_EGRESS_BLOCKED,
        packet_len,
        hook: HOOK_TC_EGRESS,
        _pad: 0,
        timestamp,
    };
    EVENTS.output(ctx, &log_entry, 0);
}

#[inline(always)]
fn log_pass(
    ctx: &TcContext,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
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
        action: ACTION_PASS,
        threat_type: THREAT_NONE,
        packet_len,
        hook: HOOK_TC_EGRESS,
        _pad: 0,
        timestamp,
    };
    EVENTS.output(ctx, &log_entry, 0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
