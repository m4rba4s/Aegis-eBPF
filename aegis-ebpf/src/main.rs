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
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap, LruHashMap, PerCpuArray, RingBuf,
    },
    programs::XdpContext,
};
use headers::{EthHdr, Ipv4Hdr, Ipv6ExtHdr, Ipv6Hdr, ETH_P_IP, ETH_P_IPV6};
use parsing::ptr_at;

// ============================================================
// IMPORTS FROM aegis-common (Single Source of Truth)
// ============================================================
use aegis_common::{
    CidrBlockEntry,
    FlowKey,
    FlowKeyIpv6,
    LpmKeyIpv4,
    LpmKeyIpv6,
    // Structures - IPv4
    PacketLog,
    // Structures - IPv6
    PacketLogIpv6,
    RateLimitState,
    Stats,
    ACTION_DROP,
    // Actions
    ACTION_PASS,
    CFG_INTERFACE_MODE,
    // Config keys
    CFG_RATE_LIMIT,
    CFG_SCAN_DETECT,
    CFG_SKIP_WHITELIST,
    CFG_THREAT_FEEDS,
    CFG_VERBOSE,
    // Hook points
    HOOK_XDP,
    MAX_TOKENS,
    NEXTHDR_AUTH,
    NEXTHDR_DEST,
    NEXTHDR_FRAGMENT,
    // IPv6 next header protocol constants
    NEXTHDR_HOP,
    NEXTHDR_ICMPV6,
    NEXTHDR_NONE,
    NEXTHDR_ROUTING,
    NEXTHDR_TCP,
    NEXTHDR_UDP,
    REASON_CIDR_FEED,
    // Verdict reasons
    REASON_DEFAULT,
    // IPv6 constants
    REASON_IPV6_POLICY,
    REASON_MANUAL_BLOCK,
    REASON_RATELIMIT,
    REASON_TCP_ANOMALY,
    REASON_WHITELIST,
    THREAT_BLOCKLIST,
    THREAT_FLOOD_SYN,
    THREAT_IPV6_EXT_CHAIN,
    THREAT_IPV6_FRAGMENT,
    // Threat types - IPv4
    THREAT_NONE,
    THREAT_SCAN_NULL,
    THREAT_SCAN_SYNFIN,
    THREAT_SCAN_XMAS,
    // Rate limiting constants
    TOKENS_PER_SEC,
    GLOBAL_SYN_RATE_THRESHOLD,
    // Map capacity constants (ABI contract with TC)
    MAP_CAP_BLOCKLIST,
    MAP_CAP_ALLOWLIST,
    MAP_CAP_CIDR,
    MAP_CAP_DPI_RING_BYTES,
    MAP_CAP_EVENT_RING_BYTES,
    MAP_CAP_RATE_LIMIT,
    MAP_CAP_CONFIG,
    MAP_CAP_STATS,
};

// ============================================================
// BPF MAPS
// ============================================================

/// Exact match blocklist (manual blocks)
#[map]
static BLOCKLIST: HashMap<FlowKey, u32> = HashMap::with_max_entries(MAP_CAP_BLOCKLIST, 0);

/// Dynamic Allowlist (IPs that bypass all checks)
#[map]
static ALLOWLIST: HashMap<u32, u32> = HashMap::with_max_entries(MAP_CAP_ALLOWLIST, 0);

/// CIDR prefix blocklist using LPM Trie (for threat feeds)
#[map]
static CIDR_BLOCKLIST: LpmTrie<LpmKeyIpv4, CidrBlockEntry> = LpmTrie::with_max_entries(MAP_CAP_CIDR, 0);

/// Ring buffer for packet events (pinned: shared with TC)
#[map]
static EVENTS: RingBuf = RingBuf::pinned(MAP_CAP_EVENT_RING_BYTES, 0);

/// Per-CPU health statistics
#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(MAP_CAP_STATS, 0);

/// DPI suspect queue — packets flagged for deep inspection
#[map]
static DPI_EVENTS: RingBuf = RingBuf::with_byte_size(MAP_CAP_DPI_RING_BYTES, 0);

/// Rate limit map: IP -> RateLimitState (LRU: evicts oldest on overflow)
#[map]
static RATE_LIMIT: LruHashMap<u32, RateLimitState> = LruHashMap::with_max_entries(MAP_CAP_RATE_LIMIT, 0);

/// Global SYN flood counter: [0]=syn_count, [1]=window_start_ns (PerCpuArray)
/// Detects distributed SYN floods from random sources where per-IP limiting fails
#[map]
static GLOBAL_SYN_CTR: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

/// Config map for runtime toggles (pinned: shared with TC)
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::pinned(MAP_CAP_CONFIG, 0);

// ============================================================
// IPv6 BPF MAPS
// ============================================================

/// IPv6 exact match blocklist (manual blocks)
#[map]
static BLOCKLIST_IPV6: HashMap<FlowKeyIpv6, u32> = HashMap::with_max_entries(1024, 0);

/// Dynamic Allowlist IPv6
#[map]
static ALLOWLIST_IPV6: HashMap<[u8; 16], u32> = HashMap::with_max_entries(1024, 0);

/// IPv6 CIDR prefix blocklist using LPM Trie
#[map]
static CIDR_BLOCKLIST_IPV6: LpmTrie<LpmKeyIpv6, CidrBlockEntry> =
    LpmTrie::with_max_entries(16384, 0);

/// IPv6 event log (separate due to larger struct size)
#[map]
static EVENTS_IPV6: RingBuf = RingBuf::with_byte_size(MAP_CAP_EVENT_RING_BYTES, 0);

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

#[inline(always)]
fn stats_inc_ipv6_seen() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).ipv6_seen = (*s).ipv6_seen.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_ipv6_pass() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).ipv6_pass = (*s).ipv6_pass.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_ipv6_drop() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).ipv6_drop = (*s).ipv6_drop.wrapping_add(1);
        }
    }
}

#[inline(always)]
fn stats_inc_event_fail() {
    unsafe {
        if let Some(s) = STATS.get_ptr_mut(0) {
            (*s).events_fail = (*s).events_fail.wrapping_add(1);
        }
    }
}

// ============================================================
// XDP ENTRY POINT
// ============================================================

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    let ret = match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    };

    // Check outcome and update global counters
    if ret == xdp_action::XDP_DROP || ret == xdp_action::XDP_ABORTED {
        stats_inc_drop();
    } else if ret == xdp_action::XDP_PASS {
        stats_inc_pass();
    }

    ret
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Increment packet counter
    stats_inc_seen();

    // Check CONFIG map for interface mode (0 = L2/Ethernet, 1 = L3/raw IP)
    let is_l3_mode = unsafe { CONFIG.get(&CFG_INTERFACE_MODE).copied().unwrap_or(0) == 1 };

    // Determine IP version and offset
    let (ip_offset, ether_type) = if is_l3_mode {
        // L3 interface - check IP version from first byte
        // Use black_box to prevent compiler from optimizing away the bounds check pattern
        // The eBPF verifier REQUIRES seeing: if (pkt + N) > pkt_end
        let data = ctx.data();
        let data_end = ctx.data_end();
        let check_end = core::hint::black_box(data + 1);
        if check_end > data_end {
            return Ok(xdp_action::XDP_PASS);
        }
        let version = unsafe { (*(data as *const u8) >> 4) & 0xF };
        let etype = if version == 6 { ETH_P_IPV6 } else { ETH_P_IP };
        (0usize, etype)
    } else {
        // L2 interface - check ether_type
        let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
        let etype = u16::from_be(unsafe { (*eth_hdr).ether_type });
        (EthHdr::LEN, etype)
    };

    // Route to IPv6 handler if needed
    if ether_type == ETH_P_IPV6 {
        return try_xdp_ipv6(&ctx, ip_offset);
    }

    // Not IPv4? Pass through
    if ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- IPv4 PROCESSING ---
    let l4_base_offset = ip_offset + 20;

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, ip_offset)?;
    let src_addr = unsafe { (*ipv4_hdr).src_addr };
    let dst_addr = unsafe { (*ipv4_hdr).dst_addr };
    let proto = unsafe { (*ipv4_hdr).proto };
    let total_len = u16::from_be(unsafe { (*ipv4_hdr).tot_len });

    // Fail-closed: DROP packets with IP options (variable-length headers
    // bypass our fixed L4 offset calculation). <0.01% of legitimate traffic.
    let ip_ihl = unsafe { (*ipv4_hdr).ihl() & 0x0F };
    if ip_ihl != 5 {
        return Ok(xdp_action::XDP_DROP);
    }

    // Fail-closed: DROP fragmented packets. Fragments bypass L4 port/protocol
    // parsing, rate limiting, and scan detection. Kernel reassembly happens
    // after XDP, so legitimate fragmented flows still complete.
    let frag_off = u16::from_be(unsafe { (*ipv4_hdr).frag_off });
    if (frag_off & 0x3FFF) != 0 {
        return Ok(xdp_action::XDP_DROP);
    }

    // W-2: L4 Length Validation
    // Ensure total_len covers at least the IP header (20) + min L4 header
    if proto == 6 {
        // TCP: min 20 bytes
        if total_len < 40 {
            return Ok(xdp_action::XDP_DROP);
        }
    } else if proto == 17 {
        // UDP: min 8 bytes
        if total_len < 28 {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    let l4_offset = l4_base_offset;

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;

    if proto == 6 {
        // TCP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });

        let tcp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *tcp_hdr });

        let flags_ptr: *const u8 = ptr_at(&ctx, l4_offset + 13)?;
        tcp_flags = unsafe { *flags_ptr };
    } else if proto == 17 {
        // UDP
        let src_port_ptr: *const u16 = ptr_at(&ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *src_port_ptr });

        let udp_hdr: *const u16 = ptr_at(&ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *udp_hdr });
    }

    // --- WHITELIST CHECK (EARLY) ---
    let src_octets = src_addr.to_be_bytes();
    let is_whitelisted = src_octets[0] == 10 ||  // 10.0.0.0/8
        (src_octets[0] == 172 && (src_octets[1] & 0xF0) == 16) ||  // 172.16.0.0/12
        (src_octets[0] == 192 && src_octets[1] == 168) ||  // 192.168.0.0/16
        (src_octets[0] == 100 && (src_octets[1] & 0xC0) == 64) ||  // 100.64.0.0/10 CGNAT/VPN
        src_octets[0] == 127; // 127.0.0.0/8 localhost

    // --- DYNAMIC ALLOWLIST ---
    if unsafe { ALLOWLIST.get(&src_addr).is_some() } {
        if is_module_enabled(CFG_VERBOSE) {
            log_packet(
                &ctx,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                proto,
                tcp_flags,
                ACTION_PASS,
                REASON_WHITELIST,
                THREAT_NONE,
                total_len,
            );
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // Skip RFC1918/loopback whitelist when CFG_SKIP_WHITELIST is enabled (for testing on lo)
    if is_whitelisted && !is_module_enabled(CFG_SKIP_WHITELIST) {
        if is_module_enabled(CFG_VERBOSE) {
            log_packet(
                &ctx,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                proto,
                tcp_flags,
                ACTION_PASS,
                REASON_WHITELIST,
                THREAT_NONE,
                total_len,
            );
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // --- BLOCKLIST CHECKS (BEFORE CONNTRACK) ---
    // Critical: these MUST run before conntrack fast-path, otherwise
    // established flows from blocked IPs bypass manual bans and CIDR feeds.
    // Hot-reload bans won't work on active connections without this.

    // Exact match blocklist (manual blocks)
    let key_exact_early = FlowKey {
        src_ip: src_addr,
        dst_port,
        proto,
        _pad: 0,
    };
    if let Some(_) = unsafe { BLOCKLIST.get(&key_exact_early) } {
        stats_inc_block_manual();
        return log_and_return(
            &ctx, src_addr, dst_addr, src_port, dst_port,
            proto, tcp_flags, ACTION_DROP, REASON_MANUAL_BLOCK,
            THREAT_BLOCKLIST, total_len,
        );
    }

    // Wildcard blocklist (IP-only block, any port/proto)
    let key_wild_early = FlowKey {
        src_ip: src_addr,
        dst_port: 0,
        proto: 0,
        _pad: 0,
    };
    if let Some(_) = unsafe { BLOCKLIST.get(&key_wild_early) } {
        stats_inc_block_manual();
        return log_and_return(
            &ctx, src_addr, dst_addr, src_port, dst_port,
            proto, tcp_flags, ACTION_DROP, REASON_MANUAL_BLOCK,
            THREAT_BLOCKLIST, total_len,
        );
    }

    // CIDR blocklist (threat feeds)
    if is_module_enabled(CFG_THREAT_FEEDS) {
        let cidr_key_early = Key::new(32, LpmKeyIpv4 { prefix_len: 32, addr: src_addr });
        if let Some(_) = CIDR_BLOCKLIST.get(&cidr_key_early) {
            stats_inc_block_cidr();
            return log_and_return(
                &ctx, src_addr, dst_addr, src_port, dst_port,
                proto, tcp_flags, ACTION_DROP, REASON_CIDR_FEED,
                THREAT_BLOCKLIST, total_len,
            );
        }
    }

    // XDP stays stateless: stateful inspection/conntrack is owned by TC.
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // --- SCAN DETECTION (Xmas/Null/SYN+FIN) ---
    if is_module_enabled(CFG_SCAN_DETECT) && proto == 6 {
        let fin = tcp_flags & 0x01 != 0;
        let syn = tcp_flags & 0x02 != 0;
        let psh = tcp_flags & 0x08 != 0;
        let urg = tcp_flags & 0x20 != 0;

        // Xmas Tree Scan (FIN + URG + PSH)
        if fin && urg && psh {
            return log_and_return(
                &ctx,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                proto,
                tcp_flags,
                ACTION_DROP,
                REASON_TCP_ANOMALY,
                THREAT_SCAN_XMAS,
                total_len,
            );
        }

        // Null Scan (No flags set)
        if tcp_flags == 0 {
            return log_and_return(
                &ctx,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                proto,
                tcp_flags,
                ACTION_DROP,
                REASON_TCP_ANOMALY,
                THREAT_SCAN_NULL,
                total_len,
            );
        }

        // SYN + FIN (Illegal)
        if syn && fin {
            return log_and_return(
                &ctx,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                proto,
                tcp_flags,
                ACTION_DROP,
                REASON_TCP_ANOMALY,
                THREAT_SCAN_SYNFIN,
                total_len,
            );
        }
    }

    // --- SYN FLOOD RATE LIMITING ---
    if is_module_enabled(CFG_RATE_LIMIT) && proto == 6 {
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;

        if syn && !ack {
            // === Global SYN rate detection (catches --rand-source floods) ===
            let idx_count: u32 = 0;
            let idx_ts: u32 = 1;
            let mut global_drop = false;

            if let Some(syn_count) = GLOBAL_SYN_CTR.get_ptr_mut(idx_count) {
                if let Some(window_ts) = GLOBAL_SYN_CTR.get_ptr_mut(idx_ts) {
                    let count = unsafe { &mut *syn_count };
                    let ts = unsafe { &mut *window_ts };

                    let elapsed_ns = now_ns.saturating_sub(*ts);

                    if elapsed_ns >= 1_000_000_000 {
                        // New 1-second window
                        *count = 1;
                        *ts = now_ns;
                    } else {
                        *count = count.saturating_add(1);
                        if *count > GLOBAL_SYN_RATE_THRESHOLD as u64 {
                            global_drop = true;
                        }
                    }
                }
            }

            if global_drop {
                return log_and_return(
                    &ctx,
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                    proto,
                    tcp_flags,
                    ACTION_DROP,
                    REASON_RATELIMIT,
                    THREAT_FLOOD_SYN,
                    total_len,
                );
            }

            // === Per-IP SYN rate limiting (catches single-source floods) ===
            if let Some(state) = RATE_LIMIT.get_ptr_mut(&src_addr) {
                let state = unsafe { &mut *state };

                let delta_ns = now_ns.saturating_sub(state.last_update);
                let delta_sec = (delta_ns / 1_000_000_000) as u32;

                let new_tokens = state.tokens.saturating_add(delta_sec * TOKENS_PER_SEC);
                state.tokens = if new_tokens > MAX_TOKENS {
                    MAX_TOKENS
                } else {
                    new_tokens
                };
                state.last_update = now_ns;

                if state.tokens > 0 {
                    state.tokens -= 1;
                } else {
                    return log_and_return(
                        &ctx,
                        src_addr,
                        dst_addr,
                        src_port,
                        dst_port,
                        proto,
                        tcp_flags,
                        ACTION_DROP,
                        REASON_RATELIMIT,
                        THREAT_FLOOD_SYN,
                        total_len,
                    );
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

    // --- DPI / TLS FINGERPRINTING: DEFERRED TO v2 ---
    // Moved to dedicated TC ingress program (separate stack frame).
    // DPI_EVENTS map and DpiEvent struct remain in aegis-common for reuse.

    // Verbose logging for normal pass
    if is_module_enabled(CFG_VERBOSE) {
        log_packet(
            &ctx,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            proto,
            tcp_flags,
            ACTION_PASS,
            REASON_DEFAULT,
            THREAT_NONE,
            total_len,
        );
    }

    Ok(xdp_action::XDP_PASS)
}

// ============================================================
// IPv6 PROCESSING (with security bypass protection)
// ============================================================

/// Process IPv6 packets with extension header chain protection
fn try_xdp_ipv6(ctx: &XdpContext, ip_offset: usize) -> Result<u32, ()> {
    stats_inc_ipv6_seen();

    // Parse IPv6 base header
    let ipv6_hdr: *const Ipv6Hdr = ptr_at(ctx, ip_offset)?;
    let src_addr = unsafe { (*ipv6_hdr).src_addr };
    let dst_addr = unsafe { (*ipv6_hdr).dst_addr };
    let payload_len = u16::from_be(unsafe { (*ipv6_hdr).payload_len });
    let next_header = unsafe { (*ipv6_hdr).next_header };

    // Validate version
    let version = unsafe { (*ipv6_hdr).version() };
    if version != 6 {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- EXTENSION HEADER HANDLING ---
    let mut current_nh = next_header;
    let mut l4_offset = ip_offset + Ipv6Hdr::LEN;
    let mut is_valid_l4 = false;
    let mut ext_hdr_count: u8 = 0;

    // Bounded loop: parse up to 4 extension headers.
    // The verifier accepts this because the loop is unrolled, and ptr_at internally
    // checks data_end before every read, ensuring packet boundaries are respected.
    for _ in 0..4 {
        match current_nh {
            NEXTHDR_TCP | NEXTHDR_UDP | NEXTHDR_ICMPV6 => {
                is_valid_l4 = true;
                break;
            }
            NEXTHDR_FRAGMENT => {
                // W-1: Drop all IPv6 fragments at XDP
                stats_inc_ipv6_drop();
                return log_ipv6_drop(
                    ctx, &src_addr, &dst_addr, 0, 0, current_nh, 0,
                    REASON_IPV6_POLICY, THREAT_IPV6_FRAGMENT, payload_len, ext_hdr_count,
                );
            }
            NEXTHDR_AUTH => {
                let ext_hdr: *const Ipv6ExtHdr = ptr_at(ctx, l4_offset)?;
                current_nh = unsafe { (*ext_hdr).next_header };
                let ext_len = unsafe { (*ext_hdr).hdr_ext_len };
                l4_offset += ((ext_len as usize) + 2) * 4;
                ext_hdr_count += 1;
            }
            NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => {
                let ext_hdr: *const Ipv6ExtHdr = ptr_at(ctx, l4_offset)?;
                current_nh = unsafe { (*ext_hdr).next_header };
                let ext_len = unsafe { (*ext_hdr).hdr_ext_len };
                l4_offset += ((ext_len as usize) + 1) * 8;
                ext_hdr_count += 1;
            }
            NEXTHDR_NONE => {
                // No next header -> end of packet payload
                break;
            }
            _ => {
                // Unknown protocol or unknown extension header.
                // Stop parsing, will log drop later.
                break;
            }
        }
    }

    if !is_valid_l4 {
        // SECURITY: Fail-closed — we couldn't find a supported L4 header within 4 hops,
        // or we hit an unknown extension header. Drop the packet.
        stats_inc_ipv6_drop();
        return log_ipv6_drop(
            ctx,
            &src_addr,
            &dst_addr,
            0,
            0,
            current_nh,
            0,
            REASON_IPV6_POLICY,
            THREAT_IPV6_EXT_CHAIN,
            payload_len,
            ext_hdr_count,
        );
    }

    let next_header = current_nh;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;

    if next_header == NEXTHDR_TCP {
        let sp: *const u16 = ptr_at(ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *sp });
        let dp: *const u16 = ptr_at(ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *dp });
        let flags: *const u8 = ptr_at(ctx, l4_offset + 13)?;
        tcp_flags = unsafe { *flags };
    } else if next_header == NEXTHDR_UDP {
        let sp: *const u16 = ptr_at(ctx, l4_offset)?;
        src_port = u16::from_be(unsafe { *sp });
        let dp: *const u16 = ptr_at(ctx, l4_offset + 2)?;
        dst_port = u16::from_be(unsafe { *dp });
    }

    // --- IPv6 WHITELIST (Link-local, Loopback, Multicast) ---
    // Link-local: fe80::/10
    // Loopback: ::1
    // Multicast: ff00::/8
    let is_whitelisted = (src_addr[0] == 0xfe && (src_addr[1] & 0xc0) == 0x80) ||  // Link-local
        (src_addr == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]) ||        // ::1
        (src_addr[0] == 0xff); // Multicast

    // --- DYNAMIC ALLOWLIST ---
    if unsafe { ALLOWLIST_IPV6.get(&src_addr).is_some() } {
        stats_inc_ipv6_pass();
        return Ok(xdp_action::XDP_PASS);
    }

    if is_whitelisted {
        stats_inc_ipv6_pass();
        return Ok(xdp_action::XDP_PASS);
    }

    // --- IPv6 CIDR BLOCKLIST ---
    if is_module_enabled(CFG_THREAT_FEEDS) {
        let cidr_key = Key::new(
            128,
            LpmKeyIpv6 {
                prefix_len: 128,
                addr: src_addr,
            },
        );

        if let Some(_entry) = CIDR_BLOCKLIST_IPV6.get(&cidr_key) {
            stats_inc_ipv6_drop();
            stats_inc_block_cidr();
            return log_ipv6_drop(
                ctx,
                &src_addr,
                &dst_addr,
                src_port,
                dst_port,
                next_header,
                tcp_flags,
                REASON_CIDR_FEED,
                THREAT_BLOCKLIST,
                payload_len,
                ext_hdr_count,
            );
        }
    }

    // --- IPv6 EXACT BLOCKLIST ---
    let key_exact = FlowKeyIpv6 {
        src_ip: src_addr,
        dst_port,
        proto: next_header,
        _pad: 0,
    };

    if let Some(_) = unsafe { BLOCKLIST_IPV6.get(&key_exact) } {
        stats_inc_ipv6_drop();
        stats_inc_block_manual();
        return log_ipv6_drop(
            ctx,
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            next_header,
            tcp_flags,
            REASON_MANUAL_BLOCK,
            THREAT_BLOCKLIST,
            payload_len,
            ext_hdr_count,
        );
    }

    // Wildcard lookup
    let key_wild = FlowKeyIpv6 {
        src_ip: src_addr,
        dst_port: 0,
        proto: 0,
        _pad: 0,
    };

    if let Some(_) = unsafe { BLOCKLIST_IPV6.get(&key_wild) } {
        stats_inc_ipv6_drop();
        stats_inc_block_manual();
        return log_ipv6_drop(
            ctx,
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            next_header,
            tcp_flags,
            REASON_MANUAL_BLOCK,
            THREAT_BLOCKLIST,
            payload_len,
            ext_hdr_count,
        );
    }

    // XDP stays stateless for IPv6 as well; TC owns conntrack state.

    // --- TCP SCAN DETECTION for IPv6 ---
    if is_module_enabled(CFG_SCAN_DETECT) && next_header == NEXTHDR_TCP {
        let fin = tcp_flags & 0x01 != 0;
        let syn = tcp_flags & 0x02 != 0;
        let psh = tcp_flags & 0x08 != 0;
        let urg = tcp_flags & 0x20 != 0;

        // Xmas Tree
        if fin && urg && psh {
            stats_inc_ipv6_drop();
            return log_ipv6_drop(
                ctx,
                &src_addr,
                &dst_addr,
                src_port,
                dst_port,
                next_header,
                tcp_flags,
                REASON_TCP_ANOMALY,
                THREAT_SCAN_XMAS,
                payload_len,
                ext_hdr_count,
            );
        }

        // Null Scan
        if tcp_flags == 0 {
            stats_inc_ipv6_drop();
            return log_ipv6_drop(
                ctx,
                &src_addr,
                &dst_addr,
                src_port,
                dst_port,
                next_header,
                tcp_flags,
                REASON_TCP_ANOMALY,
                THREAT_SCAN_NULL,
                payload_len,
                ext_hdr_count,
            );
        }

        // SYN+FIN
        if syn && fin {
            stats_inc_ipv6_drop();
            return log_ipv6_drop(
                ctx,
                &src_addr,
                &dst_addr,
                src_port,
                dst_port,
                next_header,
                tcp_flags,
                REASON_TCP_ANOMALY,
                THREAT_SCAN_SYNFIN,
                payload_len,
                ext_hdr_count,
            );
        }
    }

    stats_inc_ipv6_pass();
    Ok(xdp_action::XDP_PASS)
}

/// Log IPv6 drop event and return XDP_DROP
#[inline(always)]
fn log_ipv6_drop(
    _ctx: &XdpContext,
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
    reason: u8,
    threat_type: u8,
    packet_len: u16,
    ext_hdr_count: u8,
) -> Result<u32, ()> {
    let log = PacketLogIpv6 {
        src_ip: *src_ip,
        dst_ip: *dst_ip,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        action: ACTION_DROP,
        reason,
        threat_type,
        hook: HOOK_XDP,
        packet_len,
        ext_hdr_count,
        _pad: [0u8; 3],
    };
    if EVENTS_IPV6.output(&log, 0).is_ok() {
        stats_inc_event_ok();
    } else {
        stats_inc_event_fail();
    }
    Ok(xdp_action::XDP_DROP)
}

// ============================================================
// LOGGING HELPERS
// ============================================================

#[inline(always)]
fn log_packet(
    _ctx: &XdpContext,
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
    if EVENTS.output(&log_entry, 0).is_ok() {
        stats_inc_event_ok();
    } else {
        stats_inc_event_fail();
    }
}

fn log_and_return(
    _ctx: &XdpContext,
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
    if EVENTS.output(&log_entry, 0).is_ok() {
        stats_inc_event_ok();
    } else {
        stats_inc_event_fail();
    }

    if action == ACTION_DROP {
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
