//! Aegis TC Egress Firewall - eBPF Program
//!
//! This is the TC (Traffic Control) egress firewall for outbound traffic.
//! All shared types are imported from aegis-common (Single Source of Truth).

#![no_std]
#![no_main]

mod headers;
mod parsing;

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap, LruHashMap, PerfEventArray,
    },
    programs::TcContext,
};
use headers::{EthHdr, Ipv4Hdr, Ipv6Hdr, ETH_P_IP, ETH_P_IPV6};
use parsing::ptr_at;

// ============================================================
// IMPORTS FROM aegis-common (Single Source of Truth)
// ============================================================
use aegis_common::{
    CidrBlockEntry,
    ConnTrackKey,
    ConnTrackKeyIpv6,
    ConnTrackState,
    LpmKeyIpv4,
    PacketLog,
    ACTION_DROP,
    ACTION_PASS,
    CFG_INTERFACE_MODE,
    CONN_FIN_WAIT,
    CONN_SYN_SENT,
    HOOK_TC_EGRESS,
    REASON_EGRESS_BLOCK,
    THREAT_EGRESS_BLOCKED,
    THREAT_NONE,
    MAP_CAP_CONNTRACK,
    MAP_CAP_EGRESS_BLOCKLIST,
    MAP_CAP_CIDR,
    MAP_CAP_CONFIG,
    NEXTHDR_TCP,
    NEXTHDR_UDP,
};

// ============================================================
// BPF MAPS (Shared with XDP via pinning)
// ============================================================

/// Shared connection tracking map (pinned: shared with XDP)
#[map]
static CONN_TRACK: LruHashMap<ConnTrackKey, ConnTrackState> = LruHashMap::pinned(MAP_CAP_CONNTRACK, 0);

/// IPv6 Connection tracking (pinned: shared with XDP)
#[map]
static CONN_TRACK_IPV6: LruHashMap<ConnTrackKeyIpv6, ConnTrackState> = LruHashMap::pinned(32768, 0);

/// Egress-specific blocklist (destination IPs we block outgoing to)
#[map]
static EGRESS_BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(MAP_CAP_EGRESS_BLOCKLIST, 0);

/// CIDR-based egress blocklist (for C2/malware feeds)
#[map]
static EGRESS_CIDR_BLOCKLIST: LpmTrie<LpmKeyIpv4, CidrBlockEntry> =
    LpmTrie::with_max_entries(MAP_CAP_CIDR, 0);

/// Shared config map (pinned: shared with XDP)
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::pinned(MAP_CAP_CONFIG, 0);

/// Shared perf event array for logging (pinned: shared with XDP)
#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::pinned(0);

// ============================================================
// TC ENTRY POINT
// ============================================================

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, // Fail-open on parse errors (safety)
    }
}

#[inline(always)]
fn try_tc_ipv6(ctx: TcContext, ip_offset: usize) -> Result<i32, ()> {
    let ipv6_hdr: *const Ipv6Hdr = ptr_at(&ctx, ip_offset)?;
    let src_addr = unsafe { (*ipv6_hdr).src_addr };
    let dst_addr = unsafe { (*ipv6_hdr).dst_addr };
    let next_header = unsafe { (*ipv6_hdr).next_header };
    let payload_len = u16::from_be(unsafe { (*ipv6_hdr).payload_len });

    let l4_offset = ip_offset + Ipv6Hdr::LEN;

    if next_header == NEXTHDR_TCP {
        let sp: *const u16 = ptr_at(&ctx, l4_offset)?;
        let src_port = u16::from_be(unsafe { *sp });
        let dp: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        let dst_port = u16::from_be(unsafe { *dp });
        let flags: *const u8 = ptr_at(&ctx, l4_offset + 13)?;
        let tcp_flags = unsafe { *flags };

        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;

        if syn && !ack {
            let conn_key = ConnTrackKeyIpv6 {
                src_ip: src_addr,
                dst_ip: dst_addr,
                src_port,
                dst_port,
                proto: next_header,
                _pad: [0u8; 3],
            };
            let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
            let new_state = ConnTrackState {
                state: CONN_SYN_SENT,
                direction: 0,
                _pad: [0u8; 2],
                last_seen: now_ns,
                packets: 1,
                bytes: payload_len as u32,
            };
            let _ = CONN_TRACK_IPV6.insert(&conn_key, &new_state, 0);
        }
    } else if next_header == NEXTHDR_UDP {
        let sp: *const u16 = ptr_at(&ctx, l4_offset)?;
        let src_port = u16::from_be(unsafe { *sp });
        let dp: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        let dst_port = u16::from_be(unsafe { *dp });

        let conn_key = ConnTrackKeyIpv6 {
            src_ip: src_addr,
            dst_ip: dst_addr,
            src_port,
            dst_port,
            proto: next_header,
            _pad: [0u8; 3],
        };
        let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let new_state = ConnTrackState {
            state: CONN_SYN_SENT,
            direction: 0,
            _pad: [0u8; 2],
            last_seen: now_ns,
            packets: 1,
            bytes: payload_len as u32,
        };
        let _ = CONN_TRACK_IPV6.insert(&conn_key, &new_state, 0);
    }

    Ok(TC_ACT_OK)
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    // Get interface mode (L2 vs L3)
    let is_l3_mode = unsafe { CONFIG.get(&CFG_INTERFACE_MODE).copied().unwrap_or(0) == 1 };

    let ip_offset = if is_l3_mode {
        0usize
    } else {
        // Check ether_type for L2
        let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
        let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });
        if ether_type == ETH_P_IPV6 {
            return try_tc_ipv6(ctx, EthHdr::LEN);
        }
        if ether_type != ETH_P_IP {
            return Ok(TC_ACT_OK);
        }
        EthHdr::LEN
    };

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, ip_offset)?;
    let src_addr = unsafe { (*ipv4_hdr).src_addr };
    let dst_addr = unsafe { (*ipv4_hdr).dst_addr };
    let proto = unsafe { (*ipv4_hdr).proto };
    let total_len = u16::from_be(unsafe { (*ipv4_hdr).tot_len });

    // L3 mode IPv6 detection
    if is_l3_mode {
        let version = unsafe { (*ipv4_hdr).version_ihl >> 4 };
        if version == 6 {
            return try_tc_ipv6(ctx, 0);
        }
    }

    // W-3: Fail-closed on IP options/fragments (Parity with XDP)
    let ip_ihl = unsafe { (*ipv4_hdr).ihl() & 0x0F };
    if ip_ihl != 5 {
        return Ok(TC_ACT_SHOT);
    }
    let frag_off = u16::from_be(unsafe { (*ipv4_hdr).frag_off });
    if (frag_off & 0x3FFF) != 0 {
        return Ok(TC_ACT_SHOT);
    }

    // L4 parsing
    let l4_offset = ip_offset + 20;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;

    if proto == 6 {
        // TCP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });

        let dst_port_ptr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *dst_port_ptr });

        let flags_ptr: *const u8 = ptr_at(&ctx, l4_offset + 13)?;
        tcp_flags = unsafe { *flags_ptr };
    } else if proto == 17 {
        // UDP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });

        let dst_port_ptr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *dst_port_ptr });
    }

    // --- EGRESS BLOCKLIST CHECK ---
    // 1. Exact IP match
    if let Some(_) = unsafe { EGRESS_BLOCKLIST.get(&dst_addr) } {
        log_and_drop(
            &ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, total_len,
        );
        return Ok(TC_ACT_SHOT);
    }

    // 2. CIDR match
    let cidr_key = Key::new(
        32,
        LpmKeyIpv4 {
            prefix_len: 32,
            addr: dst_addr,
        },
    );
    if let Some(_) = EGRESS_CIDR_BLOCKLIST.get(&cidr_key) {
        log_and_drop(
            &ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, total_len,
        );
        return Ok(TC_ACT_SHOT);
    }

    // --- CONNECTION STATE TRACKING ---
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    if proto == 6 {
        // TCP
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;
        let fin = tcp_flags & 0x01 != 0;

        // Outgoing SYN (no ACK) = new connection initiation
        if syn && !ack {
            let conn_key = ConnTrackKey {
                src_ip: src_addr,
                dst_ip: dst_addr,
                src_port,
                dst_port,
                proto,
                _pad: [0u8; 3],
            };

            let new_state = ConnTrackState {
                state: CONN_SYN_SENT,
                direction: 0, // Outgoing
                _pad: [0u8; 2],
                last_seen: now_ns,
                packets: 1,
                bytes: total_len as u32,
            };

            let _ = CONN_TRACK.insert(&conn_key, &new_state, 0);
            log_pass(
                &ctx, src_addr, dst_addr, src_port, dst_port, proto, tcp_flags, total_len,
            );
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
        let conn_key = ConnTrackKey {
            src_ip: src_addr,
            dst_ip: dst_addr,
            src_port,
            dst_port,
            proto,
            _pad: [0u8; 3],
        };

        let new_state = ConnTrackState {
            state: CONN_SYN_SENT, // Pseudo-state for UDP
            direction: 0,
            _pad: [0u8; 2],
            last_seen: now_ns,
            packets: 1,
            bytes: total_len as u32,
        };
        let _ = CONN_TRACK.insert(&conn_key, &new_state, 0);
    }

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
        reason: REASON_EGRESS_BLOCK,
        threat_type: THREAT_EGRESS_BLOCKED,
        hook: HOOK_TC_EGRESS,
        packet_len,
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
        reason: 0, // REASON_DEFAULT
        threat_type: THREAT_NONE,
        hook: HOOK_TC_EGRESS,
        packet_len,
        timestamp,
    };
    EVENTS.output(ctx, &log_entry, 0);
}

#[cfg(not(test))]
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
