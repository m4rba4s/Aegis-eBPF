//! Deep Packet Inspection (DPI) Userspace Worker
//!
//! Reads suspect packets from the DPI_EVENTS perf buffer,
//! applies pattern matching heuristics, and optionally auto-blocks
//! high-confidence threats by inserting into the BLOCKLIST BPF map.
//!
//! This module is non-blocking: the XDP program passes the packet
//! regardless. DPI operates as an async observer.

use std::net::Ipv4Addr;
use aya::maps::perf::AsyncPerfEventArray;
use aya::Ebpf;
use aya::util::online_cpus;
use bytes::BytesMut;
use futures::stream::{FuturesUnordered, StreamExt};
use tracing::{info, warn};

use aegis_common::{
    DpiEvent,
    DPI_REASON_ENTROPY, DPI_REASON_RARE_PORT, DPI_REASON_DNS_TUNNEL,
    DPI_REASON_UNKNOWN_PROTO, DPI_REASON_C2_PATTERN,
};

// ── Known C2 / Malware payload signatures (first bytes) ─────────────
// These are simplified byte-prefix patterns for demonstration.
// A production system would use Aho-Corasick or YARA rules.

/// Cobalt Strike default HTTP beacon magic
const SIG_COBALT_STRIKE: &[u8] = &[0x4d, 0x5a, 0x90, 0x00];

/// Metasploit Meterpreter stage header
const SIG_METERPRETER: &[u8] = &[0xfc, 0x48, 0x83, 0xe4];

/// Common DNS tunnel exfil: TXT record with base64 (starts with long labels)
const DNS_TUNNEL_MIN_LEN: u16 = 128;

// ── DPI Reason Display ──────────────────────────────────────────────

fn reason_str(reason: u8) -> &'static str {
    match reason {
        DPI_REASON_ENTROPY => "high_entropy",
        DPI_REASON_RARE_PORT => "rare_port",
        DPI_REASON_DNS_TUNNEL => "dns_tunnel_suspect",
        DPI_REASON_UNKNOWN_PROTO => "unknown_protocol",
        DPI_REASON_C2_PATTERN => "c2_beacon_pattern",
        _ => "unknown",
    }
}

// ── Pattern Matching Engine ─────────────────────────────────────────

/// Analyze a DPI event and return a threat confidence score (0-100).
/// Scores >= 80 trigger auto-block.
fn analyze_payload(event: &DpiEvent) -> (u8, &'static str) {
    let snippet = &event.payload_snippet[..event.payload_len.min(16) as usize];

    if snippet.is_empty() {
        return (0, "empty_payload");
    }

    // Check for known C2 signatures
    if snippet.len() >= 4 {
        if snippet.starts_with(SIG_COBALT_STRIKE) {
            return (95, "cobalt_strike_beacon");
        }
        if snippet.starts_with(SIG_METERPRETER) {
            return (90, "meterpreter_stage");
        }
    }

    // DNS tunnel detection: large DNS response with high entropy
    if event.dpi_reason == DPI_REASON_DNS_TUNNEL && event.payload_len > DNS_TUNNEL_MIN_LEN {
        return (75, "dns_tunnel_large_response");
    }

    // Entropy-based detection: count unique bytes in snippet
    let mut seen = [false; 256];
    let mut unique = 0u16;
    for &b in snippet {
        if !seen[b as usize] {
            seen[b as usize] = true;
            unique += 1;
        }
    }

    // If most bytes are unique in a short snippet, likely encrypted
    let ratio = if !snippet.is_empty() {
        (unique as f32 / snippet.len() as f32 * 100.0) as u8
    } else {
        0
    };

    if ratio > 90 && event.payload_len > 100 {
        return (70, "high_entropy_payload");
    }

    // Rare port with non-HTTP content
    if event.dpi_reason == DPI_REASON_RARE_PORT {
        // Check if it looks like HTTP
        let looks_http = snippet.starts_with(b"HTTP")
            || snippet.starts_with(b"GET ")
            || snippet.starts_with(b"POST")
            || snippet.starts_with(b"SSH-");

        if !looks_http {
            return (40, "rare_port_non_standard_protocol");
        }
    }

    (10, "low_confidence")
}

// ── Auto-Block via BPF Map ──────────────────────────────────────────

fn auto_block_ip(ip: u32) -> bool {
    use aya::maps::HashMap;

    let path = "/sys/fs/bpf/aegis/BLOCKLIST";
    let md = match aya::maps::MapData::from_pin(path) {
        Ok(md) => md,
        Err(_) => return false,
    };
    let map = aya::maps::Map::HashMap(md);
    let mut hm = match HashMap::<_, u32, u32>::try_from(map) {
        Ok(hm) => hm,
        Err(_) => return false,
    };

    let key = ip.to_be();
    hm.insert(key, 1, 0).is_ok()
}

// ── Main DPI Worker ─────────────────────────────────────────────────

/// Spawn the DPI worker as a tokio task.
/// Reads DPI_EVENTS perf buffer and processes suspect packets.
pub fn spawn_dpi_worker(bpf: &mut Ebpf) -> anyhow::Result<()> {
    let dpi_map = bpf.take_map("DPI_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("DPI_EVENTS map not found — is DPI enabled in eBPF?"))?;

    let mut perf_array = AsyncPerfEventArray::try_from(dpi_map)?;

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("failed to get online CPUs: {:?}", e))?;

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, Some(256))?;

        tokio::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<DpiEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        warn!(cpu = cpu_id, error = %e, "DPI perf read error");
                        continue;
                    }
                };

                for i in 0..events.read {
                    let buf = &buffers[i];
                    if buf.len() < std::mem::size_of::<DpiEvent>() {
                        continue;
                    }

                    let event: DpiEvent = unsafe {
                        std::ptr::read_unaligned(buf.as_ptr() as *const DpiEvent)
                    };

                    let src = Ipv4Addr::from(u32::from_be(event.src_ip));
                    let dst = Ipv4Addr::from(u32::from_be(event.dst_ip));
                    let reason = reason_str(event.dpi_reason);

                    let (confidence, detection) = analyze_payload(&event);

                    if confidence >= 80 {
                        // High confidence — auto-block
                        let blocked = auto_block_ip(event.src_ip);
                        warn!(
                            src_ip = %src,
                            dst_ip = %dst,
                            src_port = event.src_port,
                            dst_port = event.dst_port,
                            proto = event.proto,
                            trigger = reason,
                            detection = detection,
                            confidence = confidence,
                            auto_blocked = blocked,
                            "🔴 DPI: HIGH CONFIDENCE THREAT — AUTO-BLOCKED"
                        );
                    } else if confidence >= 40 {
                        // Medium confidence — alert only
                        info!(
                            src_ip = %src,
                            dst_ip = %dst,
                            dst_port = event.dst_port,
                            trigger = reason,
                            detection = detection,
                            confidence = confidence,
                            "🟡 DPI: SUSPECT TRAFFIC"
                        );
                    }
                    // Low confidence (<40) — silently ignore
                }
            }
        });
    }

    info!("🔬 DPI worker started — monitoring suspect packet queue");
    Ok(())
}
