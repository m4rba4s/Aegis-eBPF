//! Aegis REST API + Prometheus Metrics Server
//!
//! Unified HTTP server on localhost:9100 serving:
//!   - GET  /metrics         — Prometheus text exposition
//!   - GET  /health          — health check
//!   - GET  /api/stats       — JSON firewall statistics
//!   - GET  /api/blocklist   — JSON blocked IPs
//!   - GET  /api/config      — current YAML config
//!   - GET  /api/feeds       — feed cache metadata
//!   - GET  /api/geo/:ip     — GeoIP lookup
//!   - POST /api/block       — add IP to blocklist
//!   - POST /api/unblock     — remove IP from blocklist
//!   - GET  /                — embedded web dashboard

use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use aegis_common::Stats;

use crate::dashboard;

/// Default bind address (localhost only — security)
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

// ── Pre-opened BPF Map Handles (passed before privdrop) ─────────────────

use aegis_common::FlowKey;
use aya::maps::{MapData, PerCpuArray};

/// Shared handles to BPF maps opened before privilege drop.
/// Without these, metrics/API cannot read maps after setresuid(1000).
pub struct SharedHandles {
    pub stats: Arc<std::sync::Mutex<PerCpuArray<MapData, Stats>>>,
    pub blocklist: Arc<std::sync::Mutex<aya::maps::HashMap<MapData, FlowKey, u32>>>,
}

// ── Cached Stats (1s TTL) ───────────────────────────────────────────────

struct CachedStats {
    stats: Option<Stats>,
    blocklist_count: u64,
    updated_at: Instant,
}

impl CachedStats {
    fn new() -> Self {
        Self {
            stats: None,
            blocklist_count: 0,
            updated_at: Instant::now() - Duration::from_secs(10),
        }
    }

    fn is_stale(&self) -> bool {
        self.updated_at.elapsed() > Duration::from_secs(1)
    }

    fn refresh(&mut self, handles: &SharedHandles) {
        self.stats = read_bpf_stats_shared(handles);
        self.blocklist_count = read_blocklist_count_shared(handles);
        self.updated_at = Instant::now();
    }
}

// ── BPF Map Readers (via pre-opened handles) ───────────────────────────

fn read_bpf_stats_shared(handles: &SharedHandles) -> Option<Stats> {
    let array = handles.stats.lock().ok()?;
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

fn read_blocklist_count_shared(handles: &SharedHandles) -> u64 {
    match handles.blocklist.lock() {
        Ok(hm) => hm.keys().count() as u64,
        Err(_) => 0,
    }
}

fn read_blocklist_ips_shared(handles: &SharedHandles) -> Vec<String> {
    use std::net::Ipv4Addr;

    match handles.blocklist.lock() {
        Ok(hm) => hm
            .keys()
            .filter_map(|k| k.ok())
            .map(|k| Ipv4Addr::from(u32::from_be(k.src_ip)).to_string())
            .collect(),
        Err(_) => vec![],
    }
}

// ── Softnet / NAPI Stats Reader ─────────────────────────────────────────

struct SoftnetStats {
    processed: u64,
    dropped: u64,
    time_squeeze: u64,
    backlog_len: u64,
}

/// Parse /proc/net/softnet_stat — kernel NAPI counters (hex, per-CPU)
/// Format: each line = one CPU, columns are hex counters separated by spaces
/// Col 0: total frames processed  Col 1: dropped  Col 2: time_squeeze
fn read_softnet_stats() -> Option<SoftnetStats> {
    let content = std::fs::read_to_string("/proc/net/softnet_stat").ok()?;
    let mut total = SoftnetStats {
        processed: 0,
        dropped: 0,
        time_squeeze: 0,
        backlog_len: 0,
    };

    for line in content.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 {
            total.processed += u64::from_str_radix(cols[0], 16).unwrap_or(0);
            total.dropped += u64::from_str_radix(cols[1], 16).unwrap_or(0);
            total.time_squeeze += u64::from_str_radix(cols[2], 16).unwrap_or(0);
        }
        // Column 11 (0-indexed) is backlog_len on kernels >= 4.x
        if cols.len() > 11 {
            total.backlog_len += u64::from_str_radix(cols[11], 16).unwrap_or(0);
        }
    }

    Some(total)
}

/// Count current CONN_TRACK entries (LRU map utilization)
fn read_conntrack_count() -> u64 {
    let path = "/sys/fs/bpf/aegis/CONN_TRACK";
    let md = match aya::maps::MapData::from_pin(path) {
        Ok(md) => md,
        Err(_) => return 0,
    };
    let map = aya::maps::Map::LruHashMap(md);
    match aya::maps::HashMap::<_, aegis_common::ConnTrackKey, aegis_common::ConnTrackState>::try_from(map) {
        Ok(hm) => hm.keys().count() as u64,
        Err(_) => 0,
    }
}

// ── Prometheus Renderer ─────────────────────────────────────────────────

fn render_prometheus(stats: &Option<Stats>, blocklist_count: u64) -> String {
    let mut buf = String::with_capacity(2048);

    if let Some(s) = stats {
        let _ = writeln!(buf, "# HELP aegis_packets_seen_total Total packets seen");
        let _ = writeln!(buf, "# TYPE aegis_packets_seen_total counter");
        let _ = writeln!(buf, "aegis_packets_seen_total {}", s.pkts_seen);

        let _ = writeln!(buf, "# HELP aegis_packets_drop_total Total packets dropped");
        let _ = writeln!(buf, "# TYPE aegis_packets_drop_total counter");
        let _ = writeln!(buf, "aegis_packets_drop_total {}", s.pkts_drop);

        let _ = writeln!(buf, "# HELP aegis_packets_pass_total Total packets passed");
        let _ = writeln!(buf, "# TYPE aegis_packets_pass_total counter");
        let _ = writeln!(buf, "aegis_packets_pass_total {}", s.pkts_pass);

        let _ = writeln!(buf, "# HELP aegis_block_manual_total Manual block hits");
        let _ = writeln!(buf, "# TYPE aegis_block_manual_total counter");
        let _ = writeln!(buf, "aegis_block_manual_total {}", s.block_manual);

        let _ = writeln!(buf, "# HELP aegis_block_cidr_total CIDR feed block hits");
        let _ = writeln!(buf, "# TYPE aegis_block_cidr_total counter");
        let _ = writeln!(buf, "aegis_block_cidr_total {}", s.block_cidr);

        let _ = writeln!(buf, "# HELP aegis_portscan_hits_total Port scan detections");
        let _ = writeln!(buf, "# TYPE aegis_portscan_hits_total counter");
        let _ = writeln!(buf, "aegis_portscan_hits_total {}", s.portscan_hits);

        let _ = writeln!(
            buf,
            "# HELP aegis_conntrack_hits_total Conntrack fast-path hits"
        );
        let _ = writeln!(buf, "# TYPE aegis_conntrack_hits_total counter");
        let _ = writeln!(buf, "aegis_conntrack_hits_total {}", s.conntrack_hits);
    } else {
        let _ = writeln!(buf, "# aegis: BPF maps not available (is aegis running?)");
    }

    let _ = writeln!(buf, "# HELP aegis_blocklist_entries Current blocklist size");
    let _ = writeln!(buf, "# TYPE aegis_blocklist_entries gauge");
    let _ = writeln!(buf, "aegis_blocklist_entries {}", blocklist_count);

    let _ = writeln!(buf, "# HELP aegis_up Aegis firewall running (1 = up)");
    let _ = writeln!(buf, "# TYPE aegis_up gauge");
    let _ = writeln!(buf, "aegis_up {}", if stats.is_some() { 1 } else { 0 });

    if let Some(softnet) = read_softnet_stats() {
        let _ = writeln!(
            buf,
            "# HELP aegis_softnet_processed_total Packets processed via NAPI"
        );
        let _ = writeln!(buf, "# TYPE aegis_softnet_processed_total counter");
        let _ = writeln!(buf, "aegis_softnet_processed_total {}", softnet.processed);

        let _ = writeln!(
            buf,
            "# HELP aegis_softnet_dropped_total Packets dropped (full backlog)"
        );
        let _ = writeln!(buf, "# TYPE aegis_softnet_dropped_total counter");
        let _ = writeln!(buf, "aegis_softnet_dropped_total {}", softnet.dropped);
    }

    let ct_count = read_conntrack_count();
    if ct_count > 0 {
        let _ = writeln!(
            buf,
            "# HELP aegis_conntrack_entries Current conntrack map entries"
        );
        let _ = writeln!(buf, "# TYPE aegis_conntrack_entries gauge");
        let _ = writeln!(buf, "aegis_conntrack_entries {}", ct_count);
    }

    buf
}

// ── JSON Renderers ──────────────────────────────────────────────────────

fn json_stats(stats: &Option<Stats>, blocklist_count: u64) -> String {
    match stats {
        Some(s) => format!(
            r#"{{"up":true,"packets":{{"seen":{},"drop":{},"pass":{}}},"blocks":{{"manual":{},"cidr_feed":{}}},"portscan_hits":{},"conntrack_hits":{},"events":{{"ok":{},"fail":{}}},"blocklist_entries":{}}}"#,
            s.pkts_seen,
            s.pkts_drop,
            s.pkts_pass,
            s.block_manual,
            s.block_cidr,
            s.portscan_hits,
            s.conntrack_hits,
            s.events_ok,
            s.events_fail,
            blocklist_count
        ),
        None => r#"{"up":false,"error":"BPF maps not available"}"#.to_string(),
    }
}

fn json_blocklist(handles: &SharedHandles) -> String {
    let ips = read_blocklist_ips_shared(handles);
    let entries: Vec<String> = ips.iter().map(|ip| format!(r#""{}""#, ip)).collect();
    format!(
        r#"{{"count":{},"ips":[{}]}}"#,
        entries.len(),
        entries.join(",")
    )
}

fn json_config() -> String {
    let path = "aegis.yaml";
    match std::fs::read_to_string(path) {
        Ok(content) => {
            // Escape for JSON string
            let escaped = content
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t");
            format!(r#"{{"path":"{}","content":"{}"}}"#, path, escaped)
        }
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    }
}

fn json_feeds() -> String {
    let cache_dir = crate::feeds::cache_dir();
    let mut feeds = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&cache_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let modified = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                feeds.push(format!(
                    r#"{{"name":"{}","size_bytes":{},"age_secs":{}}}"#,
                    name, size, modified
                ));
            }
        }
    }

    format!(
        r#"{{"cache_dir":"{}","feeds":[{}]}}"#,
        cache_dir.display(),
        feeds.join(",")
    )
}

fn json_geo(ip_str: &str) -> String {
    use std::net::IpAddr;

    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return format!(r#"{{"error":"invalid IP: {}"}}"#, ip_str),
    };

    let geo = crate::geo::GeoLookup::open();
    match geo {
        Some(g) => match g.lookup(ip) {
            Some(result) => format!(
                r#"{{"ip":"{}","country":"{}","city":"{}"}}"#,
                ip_str, result.country_code, result.city
            ),
            None => format!(
                r#"{{"ip":"{}","error":"not found in GeoIP database"}}"#,
                ip_str
            ),
        },
        None => r#"{"error":"GeoIP database not available"}"#.to_string(),
    }
}

// ── Block / Unblock via BPF Map ─────────────────────────────────────────

fn block_ip(handles: &SharedHandles, ip_str: &str) -> String {
    use aegis_common::FlowKey;
    use std::net::Ipv4Addr;

    let ip: Ipv4Addr = match ip_str.trim().parse() {
        Ok(ip) => ip,
        Err(_) => return format!(r#"{{"error":"invalid IPv4: {}"}}"#, ip_str),
    };

    match handles.blocklist.lock() {
        Ok(mut hm) => {
            let key = FlowKey {
                src_ip: u32::from(ip).to_be(),
                dst_port: 0,
                proto: 0,
                _pad: 0,
            };
            match hm.insert(key, 1, 0) {
                Ok(()) => format!(r#"{{"ok":true,"blocked":"{}"}}"#, ip),
                Err(e) => format!(r#"{{"error":"insert failed: {}"}}"#, e),
            }
        }
        Err(e) => format!(r#"{{"error":"BLOCKLIST lock error: {}"}}"#, e),
    }
}

fn unblock_ip(handles: &SharedHandles, ip_str: &str) -> String {
    use aegis_common::FlowKey;
    use std::net::Ipv4Addr;

    let ip: Ipv4Addr = match ip_str.trim().parse() {
        Ok(ip) => ip,
        Err(_) => return format!(r#"{{"error":"invalid IPv4: {}"}}"#, ip_str),
    };

    match handles.blocklist.lock() {
        Ok(mut hm) => {
            let key = FlowKey {
                src_ip: u32::from(ip).to_be(),
                dst_port: 0,
                proto: 0,
                _pad: 0,
            };
            match hm.remove(&key) {
                Ok(()) => format!(r#"{{"ok":true,"unblocked":"{}"}}"#, ip),
                Err(e) => format!(r#"{{"error":"remove failed: {}"}}"#, e),
            }
        }
        Err(e) => format!(r#"{{"error":"BLOCKLIST lock error: {}"}}"#, e),
    }
}

// ── Auth Check ──────────────────────────────────────────────────────────

fn check_auth(req: &str) -> bool {
    // Read token from env or /etc/aegis/api_token
    let token = std::env::var("AEGIS_API_TOKEN")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/aegis/api_token").ok())
        .map(|t| t.trim().to_string());

    match token {
        Some(expected) if !expected.is_empty() => {
            // Look for X-Aegis-Token header in raw request
            for line in req.lines() {
                if let Some(val) = line
                    .strip_prefix("X-Aegis-Token:")
                    .or_else(|| line.strip_prefix("x-aegis-token:"))
                {
                    let provided = val.trim().as_bytes();
                    let expected_b = expected.as_bytes();
                    // Constant-time comparison
                    if provided.len() != expected_b.len() {
                        return false;
                    }
                    let mut diff = 0u8;
                    for (a, b) in provided.iter().zip(expected_b.iter()) {
                        diff |= a ^ b;
                    }
                    return diff == 0;
                }
            }
            false
        }
        _ => true, // No token configured = open (localhost only anyway)
    }
}

// ── Request Body Extraction ─────────────────────────────────────────────

fn extract_json_field<'a>(body: &'a str, field: &str) -> Option<&'a str> {
    let pattern = format!(r#""{}":""#, field);
    let start = body.find(&pattern)? + pattern.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

// ── HTTP Response Helpers ───────────────────────────────────────────────

fn http_json(status: u16, body: &str) -> Vec<u8> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: 127.0.0.1\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{}",
        status, status_text, body.len(), body
    )
    .into_bytes()
}

fn http_html(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )
    .into_bytes()
}

fn http_text(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )
    .into_bytes()
}

// ── Main Server ─────────────────────────────────────────────────────────

pub async fn spawn_metrics_server(
    addr: Option<&str>,
    handles: Arc<SharedHandles>,
) -> anyhow::Result<SocketAddr> {
    let bind_addr: SocketAddr = addr
        .unwrap_or(DEFAULT_ADDR)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid metrics bind address: {}", e))?;

    let listener = TcpListener::bind(bind_addr).await?;
    let actual_addr = listener.local_addr()?;

    let cache = Arc::new(RwLock::new(CachedStats::new()));

    tokio::spawn(async move {
        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };

            let cache = cache.clone();
            let handles = handles.clone();

            tokio::spawn(async move {
                // API Rate Limiting (per-IP token bucket)
                if !crate::api_ratelimit::check_rate_limit(peer.ip()) {
                    let body = crate::api_ratelimit::rate_limit_response();
                    let resp = http_json(429, &body);
                    let _ = stream.write_all(&resp).await;
                    return;
                }

                // C-3: Robust HTTP reading with Content-Length and Payload limits
                let read_result = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut buffer = Vec::with_capacity(2048);
                    let mut header_end = None;
                    let mut content_length = 0;

                    loop {
                        let mut chunk = [0u8; 1024];
                        match stream.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(n) => {
                                buffer.extend_from_slice(&chunk[..n]);
                                if buffer.len() > 8192 {
                                    // Payload too large
                                    let resp = http_json(413, r#"{"error":"payload too large"}"#);
                                    let _ = stream.write_all(&resp).await;
                                    return None;
                                }

                                // Check if we have complete headers
                                if header_end.is_none() {
                                    let req_str = String::from_utf8_lossy(&buffer);
                                    if let Some(pos) = req_str.find("\r\n\r\n") {
                                        header_end = Some(pos);
                                        // For POST, parse Content-Length
                                        if req_str.starts_with("POST") {
                                            for line in req_str[..pos].lines() {
                                                let lower = line.to_ascii_lowercase();
                                                if let Some(value) =
                                                    lower.strip_prefix("content-length:")
                                                {
                                                    content_length =
                                                        value.trim().parse().unwrap_or(0);
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some(pos) = header_end {
                                    // We have headers, check if we have enough body
                                    if buffer.len() >= pos + 4 + content_length {
                                        break;
                                    }
                                }
                            }
                            Err(_) => return None,
                        }
                    }
                    if buffer.is_empty() {
                        return None;
                    }
                    Some(String::from_utf8_lossy(&buffer).to_string())
                })
                .await;

                let req_str = match read_result {
                    Ok(Some(s)) => s,
                    _ => return, // timeout, overflow, or empty
                };

                let response = route_request(&req_str, &cache, &handles).await;
                let _ = stream.write_all(&response).await;
            });
        }
    });

    Ok(actual_addr)
}

async fn route_request(
    full_req: &str,
    cache: &Arc<RwLock<CachedStats>>,
    handles: &SharedHandles,
) -> Vec<u8> {
    let first_line = full_req.lines().next().unwrap_or("");
    // Parse method and path
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let (method, path) = match parts.as_slice() {
        [m, p, ..] => (*m, *p),
        _ => return http_json(400, r#"{"error":"malformed request"}"#),
    };

    match (method, path) {
        // ── Dashboard ───────────────────────────────────
        ("GET", "/") => http_html(dashboard::DASHBOARD_HTML),

        // ── Prometheus ──────────────────────────────────
        ("GET", "/metrics") => {
            let mut c = cache.write().await;
            if c.is_stale() {
                c.refresh(handles);
            }
            let body = render_prometheus(&c.stats, c.blocklist_count);
            http_text(&body)
        }

        // ── Health ──────────────────────────────────────
        ("GET", "/health") => http_json(200, r#"{"status":"ok"}"#),

        // ── API: Stats ──────────────────────────────────
        ("GET", "/api/stats") => {
            let mut c = cache.write().await;
            if c.is_stale() {
                c.refresh(handles);
            }
            let body = json_stats(&c.stats, c.blocklist_count);
            http_json(200, &body)
        }

        // ── API: Blocklist ──────────────────────────────
        ("GET", "/api/blocklist") => http_json(200, &json_blocklist(handles)),

        // ── API: Config ─────────────────────────────────
        ("GET", "/api/config") => http_json(200, &json_config()),

        // ── API: Feeds ──────────────────────────────────
        ("GET", "/api/feeds") => http_json(200, &json_feeds()),

        // ── API: GeoIP ──────────────────────────────────
        ("GET", p) if p.starts_with("/api/geo/") => {
            let ip = &p["/api/geo/".len()..];
            http_json(200, &json_geo(ip))
        }

        // ── API: Block (POST, auth required) ────────────
        ("POST", "/api/block") => {
            if !check_auth(full_req) {
                return http_json(401, r#"{"error":"unauthorized"}"#);
            }
            // Extract body after \r\n\r\n
            let body = full_req.split("\r\n\r\n").nth(1).unwrap_or("");
            match extract_json_field(body, "ip") {
                Some(ip) => http_json(200, &block_ip(handles, ip)),
                None => http_json(400, r#"{"error":"missing 'ip' field in JSON body"}"#),
            }
        }

        // ── API: Unblock (POST, auth required) ──────────
        ("POST", "/api/unblock") => {
            if !check_auth(full_req) {
                return http_json(401, r#"{"error":"unauthorized"}"#);
            }
            let body = full_req.split("\r\n\r\n").nth(1).unwrap_or("");
            match extract_json_field(body, "ip") {
                Some(ip) => http_json(200, &unblock_ip(handles, ip)),
                None => http_json(400, r#"{"error":"missing 'ip' field in JSON body"}"#),
            }
        }
        // ── API: IP Reputation Score ──────────────────
        ("GET", p) if p.starts_with("/api/reputation/") => {
            let ip = &p["/api/reputation/".len()..];
            let score = crate::reputation::lookup(ip, None);
            http_json(200, &serde_json::to_string(&score).unwrap_or_default())
        }

        // ── API: JA3 TLS Fingerprint Cache ──────────
        ("GET", "/api/ja3") => http_json(200, &crate::tls_fingerprint::get_ja3_cache_json()),

        // ── API: Stats History (time-series) ────────
        ("GET", "/api/history") => http_json(200, &crate::stats_history::get_history_json(None)),

        // ── 404 ─────────────────────────────────────────
        _ => http_json(404, r#"{"error":"not found"}"#),
    }
}
