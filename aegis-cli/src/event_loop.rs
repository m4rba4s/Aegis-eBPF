use crate::alerts;
use crate::cef_export;
use crate::config::{LoggingConfig, WebhooksConfig};
use crate::format;
use crate::pcap;
use aegis_common::{
    FlowKey, PacketLog, PacketLogIpv6, REASON_CIDR_FEED, REASON_CONNTRACK, REASON_DEFAULT,
    REASON_EGRESS_BLOCK, REASON_IPV6_POLICY, REASON_MALFORMED, REASON_MANUAL_BLOCK,
    REASON_PORTSCAN, REASON_RATELIMIT, REASON_TCP_ANOMALY, REASON_WHITELIST, THREAT_BLOCKLIST,
    THREAT_EGRESS_BLOCKED, THREAT_FLOOD_SYN, THREAT_INCOMING_SYN, THREAT_IPV6_EXT_CHAIN,
    THREAT_IPV6_FRAGMENT, THREAT_IPV6_HOP_BY_HOP, THREAT_IPV6_ROUTING_TYPE0, THREAT_NONE,
    THREAT_SCAN_NULL, THREAT_SCAN_PORT, THREAT_SCAN_SYNFIN, THREAT_SCAN_XMAS,
};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::MapData;
use aya::util::online_cpus;
use bytes::BytesMut;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

pub struct EventLoopContext {
    pub logs_arc: Arc<Mutex<VecDeque<String>>>,
    pub blocklist_arc: Arc<Mutex<aya::maps::HashMap<MapData, FlowKey, u32>>>,
    pub remote_log_base: Option<String>,
    pub logging_cfg: LoggingConfig,
    pub webhooks_cfg: WebhooksConfig,
    pub pcap_on: bool,
}

pub fn spawn_event_loops(bpf: &mut aya::Ebpf, ctx: EventLoopContext) -> Result<(), anyhow::Error> {
    let logs_arc = ctx.logs_arc;
    let blocklist_arc = ctx.blocklist_arc;
    let remote_log_base = ctx.remote_log_base;
    let logging_cfg = ctx.logging_cfg;
    let webhooks_cfg = ctx.webhooks_cfg;
    let pcap_on = ctx.pcap_on;

    // Take ownership of EVENTS (IPv4)
    let events_map = bpf.take_map("EVENTS").expect("EVENTS map not found");
    let mut events = AsyncPerfEventArray::try_from(events_map)?;

    // Take ownership of EVENTS_IPV6
    let events_ipv6_map = bpf
        .take_map("EVENTS_IPV6")
        .expect("EVENTS_IPV6 map not found");
    let mut events_ipv6 = AsyncPerfEventArray::try_from(events_ipv6_map)?;

    // Channel for lock-free logging
    let (log_tx, mut log_rx) = tokio::sync::mpsc::channel::<String>(1024);

    // Bridge: channel -> shared VecDeque (for UI/CLI compatibility)
    let logs_for_bridge = logs_arc.clone();
    tokio::spawn(async move {
        while let Some(msg) = log_rx.recv().await {
            let mut logs = logs_for_bridge.lock().unwrap();
            if logs.len() >= 100 {
                logs.pop_front();
            }
            logs.push_back(msg);
        }
    });

    // Lifetime auto-ban counter. This is intentionally a monotonic high-water mark:
    // it's incremented on auto-ban but NEVER decremented on unblock. After 512
    // cumulative auto-bans, the OODA loop permanently disarms. This prevents
    // attackers from cycling ban/unban to exhaust the BLOCKLIST map (1024 entries).
    let ban_count_atomic = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Setup event logging futures
    let mut event_futures = FuturesUnordered::new();
    let cpus = online_cpus().map_err(|(_, e)| e)?;

    let blocklist_clone = blocklist_arc.clone(); // Clone for event loop

    // Pre-create a shared UDP socket for remote logging (avoid per-event socket creation)
    let remote_socket: Option<Arc<std::net::UdpSocket>> = remote_log_base
        .as_ref()
        .and_then(|_| std::net::UdpSocket::bind("0.0.0.0:0").ok().map(Arc::new));

    for cpu_id in cpus {
        let mut buf = events.open(cpu_id, None)?;
        let log_tx_inner = log_tx.clone();
        let remote_log = remote_log_base.clone();
        let remote_sock = remote_socket.clone();
        let _logging_cfg_inner = logging_cfg.clone();
        let webhooks_cfg_inner = webhooks_cfg.clone();
        let blocklist_inner = blocklist_clone.clone(); // Clone for this CPU task
        let ban_count_inner = ban_count_atomic.clone(); // Clone for this CPU task

        event_futures.push(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            while let Ok(events) = buf.read_events(&mut buffers).await {
                // Track perf buffer overflow (silent data loss)
                if events.lost > 0 {
                    let _ = log_tx_inner.try_send(format!(
                        "⚠️ PERF OVERFLOW: {} events lost on CPU {}",
                        events.lost, cpu_id
                    ));
                }
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let log = unsafe { ptr.read_unaligned() };
                    let src_ip = Ipv4Addr::from(u32::from_be(log.src_ip));
                    let dst_ip = Ipv4Addr::from(u32::from_be(log.dst_ip));

                    // Format threat type using constants from aegis_common
                    let threat_str = match log.threat_type {
                        THREAT_SCAN_XMAS => "XMAS_SCAN",
                        THREAT_SCAN_NULL => "NULL_SCAN",
                        THREAT_SCAN_SYNFIN => "SYNFIN_SCAN",
                        THREAT_SCAN_PORT => "PORT_SCAN",
                        THREAT_FLOOD_SYN => "SYN_FLOOD",
                        THREAT_BLOCKLIST => "BLOCKLIST",
                        THREAT_INCOMING_SYN => "INCOMING_SYN",
                        THREAT_EGRESS_BLOCKED => "EGRESS_BLOCKED",
                        _ => "NONE",
                    };

                    // Format reason (WHY this action)
                    let reason_str = match log.reason {
                        REASON_DEFAULT => "DEFAULT",
                        REASON_WHITELIST => "WHITELIST",
                        REASON_CONNTRACK => "CONNTRACK",
                        REASON_MANUAL_BLOCK => "MANUAL_BLOCK",
                        REASON_CIDR_FEED => "CIDR_FEED",
                        REASON_PORTSCAN => "PORTSCAN",
                        REASON_TCP_ANOMALY => "TCP_ANOMALY",
                        REASON_RATELIMIT => "RATELIMIT",
                        REASON_IPV6_POLICY => "IPV6_POLICY",
                        REASON_MALFORMED => "MALFORMED",
                        REASON_EGRESS_BLOCK => "EGRESS_BLOCK",
                        _ => "UNKNOWN",
                    };

                    // Format TCP flags
                    let flags_str = format::format_tcp_flags(log.tcp_flags);

                    let action_icon = if log.action == 1 { "❌" } else { "✅" };

                    let msg = match log.threat_type {
                        THREAT_SCAN_XMAS => format!(
                            "🎄 XMAS SCAN: {} -> {}:{} [{}]",
                            src_ip, dst_ip, log.dst_port, flags_str
                        ),
                        THREAT_SCAN_NULL => {
                            format!("⚫ NULL SCAN: {} -> {}:{}", src_ip, dst_ip, log.dst_port)
                        }
                        THREAT_SCAN_SYNFIN => format!(
                            "💀 SYNFIN: {} -> {}:{} [{}]",
                            src_ip, dst_ip, log.dst_port, flags_str
                        ),
                        THREAT_SCAN_PORT => {
                            format!("🔍 PORT SCAN: {} scanned port {}", src_ip, log.dst_port)
                        }
                        THREAT_FLOOD_SYN => {
                            format!("🔥 SYN FLOOD: {} -> {}:{}", src_ip, dst_ip, log.dst_port)
                        }
                        THREAT_BLOCKLIST => format!("🚫 BLOCKED: {} ({})", src_ip, reason_str),
                        THREAT_INCOMING_SYN => {
                            format!("🛡️ DROP SYN: {} -> {}:{}", src_ip, dst_ip, log.dst_port)
                        }
                        THREAT_EGRESS_BLOCKED => format!(
                            "🚫 EGRESS BLOCKED: {} -> {} ({})",
                            src_ip, dst_ip, reason_str
                        ),
                        _ => format!(
                            "{} {} -> {}:{} [{}] reason={}",
                            action_icon, src_ip, dst_ip, log.dst_port, flags_str, reason_str
                        ),
                    };

                    // Remote Logging (JSON) — UDP with shared socket
                    if let (Some(ref remote), Some(ref sock)) = (&remote_log, &remote_sock) {
                        let json_log = serde_json::json!({
                            "src_ip": src_ip.to_string(),
                            "dst_ip": dst_ip.to_string(),
                            "src_port": log.src_port,
                            "dst_port": log.dst_port,
                            "proto": log.proto,
                            "tcp_flags": log.tcp_flags,
                            "action": log.action,
                            "reason": reason_str,
                            "threat_type": threat_str,
                            "packet_len": log.packet_len,
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        });
                        let _ = sock.send_to(json_log.to_string().as_bytes(), remote.as_str());
                    }
                    // Push to shared log deque (TUI reads this, REPL printer prints this)
                    let full_msg = format!(
                        "{} | Reason: {} | Action: {}",
                        msg,
                        reason_str,
                        if log.action == 1 { "DROP" } else { "PASS" }
                    );
                    let _ = log_tx_inner.try_send(full_msg);

                    // --- DYNAMIC AUTO-BAN (OODA Loop) ---
                    // Auto-ban on SYN FLOOD or PORT SCAN (with cap + dedup)
                    if log.threat_type == THREAT_FLOOD_SYN || log.threat_type == THREAT_SCAN_PORT {
                        let mut blocklist = blocklist_inner.lock().unwrap();
                        let key = FlowKey {
                            src_ip: log.src_ip, // Already Network Byte Order from eBPF
                            dst_port: 0,        // Wildcard port
                            proto: 0,           // Wildcard proto
                            _pad: 0,
                        };
                        // Skip if already banned (dedup)
                        if blocklist.get(&key, 0).is_ok() {
                            // Already banned, skip
                        } else {
                            // Cap: don't auto-ban beyond 512 entries to prevent map exhaustion
                            const AUTO_BAN_MAX: usize = 512;
                            let current_bans =
                                ban_count_inner.load(std::sync::atomic::Ordering::Relaxed);
                            if current_bans >= AUTO_BAN_MAX {
                                let _ = log_tx_inner.try_send(format!(
                                    "⚠️ AUTO-BAN LIMIT ({}) reached, skipping {}",
                                    AUTO_BAN_MAX, src_ip
                                ));
                            } else if let Err(e) = blocklist.insert(key, 2, 0) {
                                let _ = log_tx_inner
                                    .try_send(format!("❌ AUTO-BAN FAILED for {}: {}", src_ip, e));
                            } else {
                                ban_count_inner.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let _ = log_tx_inner
                                    .try_send(format!("⛔ AUTO-BANNED {} (OODA Trigger)", src_ip));
                            }
                        }
                    }
                    // ------------------------------------

                    // --- CEF / PCAP Export on DROP ---
                    if log.action == 1 {
                        let proto_name = match log.proto {
                            6 => "tcp",
                            17 => "udp",
                            1 => "icmp",
                            _ => "ip",
                        };
                        cef_export::report_block(
                            &src_ip.to_string(),
                            &dst_ip.to_string(),
                            log.src_port,
                            log.dst_port,
                            proto_name,
                            reason_str,
                        );
                        if pcap_on {
                            pcap::write_packet(
                                log.src_ip,
                                log.dst_ip,
                                log.src_port,
                                log.dst_port,
                                log.proto,
                                &[],
                                0,
                            );
                        }
                    }
                    // ---------------------------------

                    // --- ALERTS DISPATCH ---
                    if log.threat_type != THREAT_NONE {
                        alerts::dispatch(
                            &webhooks_cfg_inner,
                            alerts::Alert {
                                severity: match log.threat_type {
                                    THREAT_FLOOD_SYN | THREAT_SCAN_PORT => alerts::Severity::High,
                                    THREAT_SCAN_XMAS | THREAT_SCAN_NULL | THREAT_SCAN_SYNFIN => {
                                        alerts::Severity::Medium
                                    }
                                    _ => alerts::Severity::Low,
                                },
                                title: format!("Aegis: {}", threat_str),
                                message: msg.clone(),
                                source_ip: src_ip.to_string(),
                                details: format!(
                                    "Port: {}, Proto: {}, Reason: {}",
                                    log.dst_port, log.proto, reason_str
                                ),
                            },
                        );
                    }
                    // -----------------------
                }
            }
        });
    }

    // --- IPv6 EVENT LOOP ---
    let logging_cfg_v6 = logging_cfg.clone(); // Config for IPv6 loop
    let cpus_v6 = online_cpus().map_err(|(_, e)| e)?;

    for cpu_id in cpus_v6 {
        let mut buf = events_ipv6.open(cpu_id, None)?;
        let log_tx_v6 = log_tx.clone();
        let _logging_cfg_inner = logging_cfg_v6.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            while let Ok(events) = buf.read_events(&mut buffers).await {
                // Track perf buffer overflow (silent data loss)
                if events.lost > 0 {
                    let _ = log_tx_v6.try_send(format!(
                        "⚠️ IPv6 PERF OVERFLOW: {} events lost on CPU {}",
                        events.lost, cpu_id
                    ));
                }
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLogIpv6;
                    let log = unsafe { ptr.read_unaligned() };

                    // Convert IPv6 bytes to Ipv6Addr for display
                    let src_ip = Ipv6Addr::from(log.src_ip);
                    let dst_ip = Ipv6Addr::from(log.dst_ip);

                    // Format IPv6 threat type
                    let threat_str = match log.threat_type {
                        THREAT_IPV6_EXT_CHAIN => "IPv6_EXT_CHAIN",
                        THREAT_IPV6_ROUTING_TYPE0 => "IPv6_ROUTING_TYPE0",
                        THREAT_IPV6_FRAGMENT => "IPv6_FRAGMENT",
                        THREAT_IPV6_HOP_BY_HOP => "IPv6_HOP_BY_HOP",
                        THREAT_SCAN_XMAS => "XMAS_SCAN",
                        THREAT_SCAN_NULL => "NULL_SCAN",
                        THREAT_SCAN_SYNFIN => "SYNFIN_SCAN",
                        THREAT_BLOCKLIST => "BLOCKLIST",
                        _ => "NONE",
                    };

                    let msg = match log.threat_type {
                        THREAT_IPV6_EXT_CHAIN => format!(
                            "⛓️ IPv6 EXT CHAIN ATTACK: {} ({} hdrs)",
                            src_ip, log.ext_hdr_count
                        ),
                        THREAT_IPV6_ROUTING_TYPE0 => {
                            format!("🚨 IPv6 TYPE0 ROUTING (deprecated): {}", src_ip)
                        }
                        THREAT_IPV6_FRAGMENT => {
                            format!("💥 IPv6 FRAGMENT ATTACK: {} -> {}", src_ip, dst_ip)
                        }
                        THREAT_IPV6_HOP_BY_HOP => format!("🔗 IPv6 HOP-BY-HOP MISUSE: {}", src_ip),
                        THREAT_SCAN_XMAS => format!(
                            "🎄 IPv6 XMAS SCAN: {} -> {}:{}",
                            src_ip, dst_ip, log.dst_port
                        ),
                        THREAT_SCAN_NULL => format!(
                            "⚫ IPv6 NULL SCAN: {} -> {}:{}",
                            src_ip, dst_ip, log.dst_port
                        ),
                        THREAT_SCAN_SYNFIN => {
                            format!("💀 IPv6 SYNFIN: {} -> {}:{}", src_ip, dst_ip, log.dst_port)
                        }
                        THREAT_BLOCKLIST => format!("🚫 IPv6 BLOCKED: {} ({})", src_ip, threat_str),
                        _ => format!(
                            "🌐 IPv6: {} -> {}:{} [{}]",
                            src_ip, dst_ip, log.dst_port, threat_str
                        ),
                    };

                    // Push to shared log deque only — no stdout
                    let _ = log_tx_v6.try_send(msg);
                }
            }
        });
    }

    // Spawn event poller globally
    tokio::spawn(async move {
        loop {
            event_futures.next().await;
        }
    });

    Ok(())
}
