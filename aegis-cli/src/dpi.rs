//! Deep Packet Inspection (DPI) Userspace Worker
//!
//! Reads suspect packets from the DPI_EVENTS perf buffer,
//! applies pattern matching heuristics, and optionally auto-blocks
//! high-confidence threats by inserting into the BLOCKLIST BPF map.
//!
//! This module is non-blocking: the XDP program passes the packet
//! regardless. DPI operates as an async observer.

use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use aegis_common::{
    DpiEvent, DPI_REASON_C2_PATTERN, DPI_REASON_DNS_TUNNEL, DPI_REASON_ENTROPY,
    DPI_REASON_RARE_PORT, DPI_REASON_TLS_HELLO, DPI_REASON_UNKNOWN_PROTO,
};

use crate::config::AegisConfig;
use crate::fleet_client::fleet::{EventMsg, EventSeverity};
use crate::yara_engine::YaraEngine;

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
        DPI_REASON_TLS_HELLO => "tls_client_hello",
        _ => "unknown",
    }
}

// ── Pattern Matching Engine ─────────────────────────────────────────

/// Analyze a DPI event and return a threat confidence score (0-100).
/// Scores >= 80 trigger auto-block.
fn analyze_payload(event: &DpiEvent, yara_engine: Option<&YaraEngine>) -> (u8, String) {
    let actual_len = (event.payload_len as usize).min(event.payload_snippet.len());
    let snippet = &event.payload_snippet[..actual_len];
    let full_payload = snippet; // We only have snippet data (max 16 bytes)

    if full_payload.is_empty() {
        return (0, "empty_payload".to_string());
    }

    // 1. Scan with YARA if available
    if let Some(yara) = yara_engine {
        let matches = yara.scan_payload(full_payload);
        if !matches.is_empty() {
            let combined = matches.join(",");
            return (100, format!("yara_match:{}", combined));
        }
    }

    // DNS tunnel detection: large DNS response with high entropy
    if event.dpi_reason == DPI_REASON_DNS_TUNNEL && event.payload_len > DNS_TUNNEL_MIN_LEN {
        return (75, "dns_tunnel_large_response".to_string());
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
        return (70, "high_entropy_payload".to_string());
    }

    // Rare port with non-HTTP content
    if event.dpi_reason == DPI_REASON_RARE_PORT {
        // Check if it looks like HTTP
        let looks_http = snippet.starts_with(b"HTTP")
            || snippet.starts_with(b"GET ")
            || snippet.starts_with(b"POST")
            || snippet.starts_with(b"SSH-");

        if !looks_http {
            return (40, "rare_port_non_standard_protocol".to_string());
        }
    }

    (10, "low_confidence".to_string())
}

// ── Auto-Block via BPF Map ──────────────────────────────────────────

pub fn auto_block_ip(ip: u32) -> bool {
    use aya::maps::HashMap;
    use aegis_common::FlowKey;

    let path = "/sys/fs/bpf/aegis/BLOCKLIST";
    let md = match aya::maps::MapData::from_pin(path) {
        Ok(md) => md,
        Err(_) => return false,
    };
    let map = aya::maps::Map::HashMap(md);
    let mut hm = match HashMap::<_, FlowKey, u32>::try_from(map) {
        Ok(hm) => hm,
        Err(_) => return false,
    };

    // ip is already in network byte order from eBPF — no extra to_be()
    let key = FlowKey {
        src_ip: ip,
        dst_port: 0,
        proto: 0,
        _pad: 0,
    };
    hm.insert(key, 1, 0).is_ok()
}

// ── Main DPI Worker ─────────────────────────────────────────────────

/// Spawn the DPI worker as a tokio task.
/// Reads DPI_EVENTS perf buffer and processes suspect packets.
pub fn spawn_dpi_worker(
    bpf: &mut Ebpf,
    config: &AegisConfig,
    fleet_tx: Option<Sender<EventMsg>>,
) -> anyhow::Result<()> {
    let dpi_map = bpf
        .take_map("DPI_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("DPI_EVENTS map not found — is DPI enabled in eBPF?"))?;

    let mut perf_array = AsyncPerfEventArray::try_from(dpi_map)?;

    // Load YARA engine from configured path
    let yara_engine = YaraEngine::load_from_directory(&config.dpi.rules_path)?.map(Arc::new);

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("failed to get online CPUs: {:?}", e))?;

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, Some(256))?;
        let yara_engine = yara_engine.clone();
        let fleet_tx = fleet_tx.clone();
        let threshold = config.dpi.auto_block_threshold;

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

                for buf in buffers.iter().take(events.read) {
                    if buf.len() < std::mem::size_of::<DpiEvent>() {
                        continue;
                    }

                    let event: DpiEvent =
                        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const DpiEvent) };

                    let src = Ipv4Addr::from(u32::from_be(event.src_ip));
                    let dst = Ipv4Addr::from(u32::from_be(event.dst_ip));
                    let reason = reason_str(event.dpi_reason);

                    let (confidence, detection) = analyze_payload(&event, yara_engine.as_deref());

                    // TLS ClientHello: process through JA3 fingerprint engine
                    if event.dpi_reason == DPI_REASON_TLS_HELLO {
                        let actual_len =
                            (event.payload_len as usize).min(event.payload_snippet.len());
                        let _snippet = &event.payload_snippet[..actual_len];
                        // Decode TLS version from entropy_score field
                        let tls_major = (event.entropy_score >> 4) & 0x0F;
                        let tls_minor = event.entropy_score & 0x0F;
                        let tls_version = ((tls_major as u16) << 8) | (tls_minor as u16);

                        // Build minimal TlsClientHello for JA3 computation
                        let hello = crate::tls_fingerprint::TlsClientHello {
                            src_ip: event.src_ip,
                            tls_version,
                            cipher_suites: vec![], // Full extraction requires larger snippet
                            extensions: vec![],
                            elliptic_curves: vec![],
                            ec_point_formats: vec![],
                        };

                        if let Some(entry) = crate::tls_fingerprint::process_hello(&hello) {
                            if entry.match_name.is_some() {
                                // Known-bad JA3 match — high severity
                                warn!(
                                    src_ip = %src,
                                    ja3 = %entry.ja3_hash,
                                    match_name = ?entry.match_name,
                                    tls_version = %format!("0x{:04x}", tls_version),
                                    "🔒 TLS ClientHello: KNOWN-BAD JA3 fingerprint"
                                );
                                // Auto-block known-bad TLS fingerprint
                                let blocked = auto_block_ip(event.src_ip);
                                if blocked {
                                    warn!(src_ip = %src, "⛔ AUTO-BLOCKED (bad JA3 fingerprint)");
                                }
                            } else {
                                info!(
                                    src_ip = %src,
                                    ja3 = %entry.ja3_hash,
                                    tls_version = %format!("0x{:04x}", tls_version),
                                    "🔒 TLS ClientHello fingerprinted"
                                );
                            }
                        }
                        continue; // TLS events don't go through normal DPI pipeline
                    }

                    if confidence >= threshold {
                        // High confidence — auto-block
                        let blocked = auto_block_ip(event.src_ip);
                        warn!(
                            src_ip = %src,
                            dst_ip = %dst,
                            src_port = event.src_port,
                            dst_port = event.dst_port,
                            proto = event.proto,
                            trigger = reason,
                            detection = %detection,
                            confidence = confidence,
                            auto_blocked = blocked,
                            "🔴 DPI: HIGH CONFIDENCE THREAT — AUTO-BLOCKED"
                        );

                        // Broadcast to Fleet Controller
                        if let Some(tx) = &fleet_tx {
                            let msg = EventMsg {
                                node_id: sysinfo::System::host_name().unwrap_or_default(),
                                event_type: "DPI".to_string(),
                                src_ip: src.to_string(),
                                dst_ip: dst.to_string(),
                                message: format!(
                                    "Detection: {}, Reason: {}, Confidence: {}",
                                    detection, reason, confidence
                                ),
                                severity: EventSeverity::Critical.into(),
                            };
                            let _ = tx.try_send(msg);
                        }
                    } else if confidence >= 40 {
                        // Medium confidence — alert only
                        info!(
                            src_ip = %src,
                            dst_ip = %dst,
                            dst_port = event.dst_port,
                            trigger = reason,
                            detection = %detection,
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
