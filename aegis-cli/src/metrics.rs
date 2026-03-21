//! Prometheus metrics endpoint for Aegis eBPF Firewall
//!
//! Serves `/metrics` on localhost:9100 (configurable) in Prometheus text exposition format.
//! Reads stats directly from pinned BPF maps — zero-copy, no shared state needed.
//!
//! Usage:
//!   Start alongside daemon: spawned automatically in daemon mode
//!   Scrape: curl http://127.0.0.1:9100/metrics

use std::io::Write;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;

/// Default bind address (localhost only — security)
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

use aegis_common::Stats;

/// Read aggregated stats from pinned BPF STATS map
fn read_bpf_stats() -> Option<Stats> {
    use aya::maps::PerCpuArray;

    let map_path = "/sys/fs/bpf/aegis/STATS";
    let md = aya::maps::MapData::from_pin(map_path).ok()?;
    let map = aya::maps::Map::PerCpuArray(md);
    let array = PerCpuArray::<_, Stats>::try_from(map).ok()?;

    let values = array.get(&0, 0).ok()?;
    let mut total = Stats::default();
    for stat in values.iter() {
        total.pkts_seen += stat.pkts_seen;
        total.pkts_drop += stat.pkts_drop;
        total.pkts_pass += stat.pkts_pass;
        total.events_ok += stat.events_ok;
        total.events_fail += stat.events_fail;
        total.block_manual += stat.block_manual;
        total.block_cidr += stat.block_cidr;
        total.portscan_hits += stat.portscan_hits;
        total.conntrack_hits += stat.conntrack_hits;
    }
    Some(total)
}

/// Read blocklist entry count from pinned BPF map
fn read_blocklist_count() -> u64 {
    use aya::maps::HashMap;

    let path = "/sys/fs/bpf/aegis/BLOCKLIST";
    let md = match aya::maps::MapData::from_pin(path) {
        Ok(md) => md,
        Err(_) => return 0,
    };
    let map = aya::maps::Map::HashMap(md);
    match HashMap::<_, u32, u32>::try_from(map) {
        Ok(hm) => hm.keys().count() as u64,
        Err(_) => 0,
    }
}

/// Generate Prometheus text exposition format
fn render_metrics() -> String {
    let mut buf = Vec::with_capacity(2048);

    if let Some(s) = read_bpf_stats() {
        writeln!(buf, "# HELP aegis_packets_total Total packets processed by category").ok();
        writeln!(buf, "# TYPE aegis_packets_total counter").ok();
        writeln!(buf, "aegis_packets_total{{action=\"seen\"}} {}", s.pkts_seen).ok();
        writeln!(buf, "aegis_packets_total{{action=\"drop\"}} {}", s.pkts_drop).ok();
        writeln!(buf, "aegis_packets_total{{action=\"pass\"}} {}", s.pkts_pass).ok();

        writeln!(buf, "# HELP aegis_blocks_total Blocks by source").ok();
        writeln!(buf, "# TYPE aegis_blocks_total counter").ok();
        writeln!(buf, "aegis_blocks_total{{source=\"manual\"}} {}", s.block_manual).ok();
        writeln!(buf, "aegis_blocks_total{{source=\"cidr_feed\"}} {}", s.block_cidr).ok();

        writeln!(buf, "# HELP aegis_portscan_hits_total Port scan detections").ok();
        writeln!(buf, "# TYPE aegis_portscan_hits_total counter").ok();
        writeln!(buf, "aegis_portscan_hits_total {}", s.portscan_hits).ok();

        writeln!(buf, "# HELP aegis_conntrack_hits_total Connection tracking cache hits").ok();
        writeln!(buf, "# TYPE aegis_conntrack_hits_total counter").ok();
        writeln!(buf, "aegis_conntrack_hits_total {}", s.conntrack_hits).ok();

        writeln!(buf, "# HELP aegis_events_total eBPF perf events").ok();
        writeln!(buf, "# TYPE aegis_events_total counter").ok();
        writeln!(buf, "aegis_events_total{{status=\"ok\"}} {}", s.events_ok).ok();
        writeln!(buf, "aegis_events_total{{status=\"fail\"}} {}", s.events_fail).ok();
    } else {
        writeln!(buf, "# aegis: BPF maps not available (is aegis running?)").ok();
    }

    let blocklist = read_blocklist_count();
    writeln!(buf, "# HELP aegis_blocklist_entries Current blocklist size").ok();
    writeln!(buf, "# TYPE aegis_blocklist_entries gauge").ok();
    writeln!(buf, "aegis_blocklist_entries {}", blocklist).ok();

    writeln!(buf, "# HELP aegis_up Aegis firewall running (1 = up)").ok();
    writeln!(buf, "# TYPE aegis_up gauge").ok();
    writeln!(buf, "aegis_up {}", if read_bpf_stats().is_some() { 1 } else { 0 }).ok();

    String::from_utf8(buf).unwrap_or_default()
}

/// Spawn the metrics HTTP server as a background tokio task.
/// Returns the actual bound address for logging.
pub async fn spawn_metrics_server(addr: Option<&str>) -> anyhow::Result<SocketAddr> {
    let bind_addr: SocketAddr = addr
        .unwrap_or(DEFAULT_ADDR)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid metrics bind address: {}", e))?;

    let listener = TcpListener::bind(bind_addr).await?;
    let actual_addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };

            // Minimal HTTP: read request, serve /metrics, reject everything else
            let mut req_buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut req_buf).await;
            let req = String::from_utf8_lossy(&req_buf);

            if req.starts_with("GET /metrics") {
                let body = render_metrics();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else if req.starts_with("GET /health") || req.starts_with("GET /") {
                let body = "ok\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n").await;
            }
        }
    });

    Ok(actual_addr)
}
