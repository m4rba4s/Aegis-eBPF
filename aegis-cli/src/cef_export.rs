//! CEF/Syslog Event Export for Aegis eBPF Firewall
//!
//! Converts Aegis security events to Common Event Format (CEF)
//! for direct ingestion by SIEM platforms:
//!   - ArcSight (CEF native)
//!   - Splunk (via syslog input)
//!   - QRadar (LEEF variant)
//!   - ELK Stack (via Logstash syslog input)
//!
//! Events are written to syslog via UDP (configurable destination).

use std::net::UdpSocket;
use std::sync::OnceLock;
use tracing::{info, warn};

/// Global syslog UDP socket
static SYSLOG_SOCKET: OnceLock<UdpSocket> = OnceLock::new();

/// CEF version header
const CEF_VERSION: &str = "CEF:0";
const VENDOR: &str = "Aegis";
const PRODUCT: &str = "eBPF-Firewall";
const PRODUCT_VERSION: &str = "3.0";

/// Initialize syslog export with a destination address (e.g., "10.0.0.5:514")
pub fn init_syslog(dest: &str) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(dest)?;
    SYSLOG_SOCKET.set(socket).map_err(|_| anyhow::anyhow!("syslog already initialized"))?;
    info!(dest = dest, "📡 CEF syslog export initialized");
    Ok(())
}

/// CEF severity levels (0-10)
#[derive(Debug, Clone, Copy)]
pub enum CefSeverity {
    Low = 3,
    Medium = 5,
    High = 7,
    Critical = 9,
}

impl CefSeverity {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Send a CEF-formatted event to syslog
pub fn send_cef_event(
    event_name: &str,
    event_id: u32,
    severity: CefSeverity,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    proto: &str,
    message: &str,
) {
    let socket = match SYSLOG_SOCKET.get() {
        Some(s) => s,
        None => return, // syslog not configured
    };

    // CEF format: CEF:Version|Vendor|Product|Version|EventID|Name|Severity|Extensions
    let cef = format!(
        "{}|{}|{}|{}|{}|{}|{}|src={} dst={} spt={} dpt={} proto={} msg={}",
        CEF_VERSION, VENDOR, PRODUCT, PRODUCT_VERSION,
        event_id, event_name, severity.as_u8(),
        src_ip, dst_ip, src_port, dst_port, proto, message,
    );

    // Wrap in syslog format (RFC 5424 simplified)
    let syslog_msg = format!(
        "<134>1 {} aegis - - - {}",
        chrono::Utc::now().to_rfc3339(),
        cef,
    );

    if let Err(e) = socket.send(syslog_msg.as_bytes()) {
        warn!(error = %e, "syslog send failed");
    }
}

// ── Convenience Functions ───────────────────────────────────────────

/// Report a blocked packet via CEF
pub fn report_block(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16, proto: &str, reason: &str) {
    send_cef_event(
        "PacketBlocked", 100, CefSeverity::Medium,
        src_ip, dst_ip, src_port, dst_port, proto,
        &format!("Blocked: {}", reason),
    );
}

/// Report a DPI detection via CEF
pub fn report_dpi_detection(src_ip: &str, dst_ip: &str, dst_port: u16, detection: &str, confidence: u8) {
    let severity = if confidence >= 80 {
        CefSeverity::Critical
    } else if confidence >= 50 {
        CefSeverity::High
    } else {
        CefSeverity::Medium
    };

    send_cef_event(
        "DPIDetection", 200, severity,
        src_ip, dst_ip, 0, dst_port, "tcp",
        &format!("DPI: {} (confidence={}%)", detection, confidence),
    );
}

/// Report a JA3 match via CEF
pub fn report_ja3_match(src_ip: &str, ja3_hash: &str, threat_name: &str) {
    send_cef_event(
        "TLSFingerprintMatch", 300, CefSeverity::Critical,
        src_ip, "0.0.0.0", 0, 443, "tcp",
        &format!("JA3={} threat={}", ja3_hash, threat_name),
    );
}

/// Report an auto-block via CEF
pub fn report_auto_block(src_ip: &str, reason: &str) {
    send_cef_event(
        "AutoBlock", 400, CefSeverity::High,
        src_ip, "0.0.0.0", 0, 0, "ip",
        &format!("Auto-blocked: {}", reason),
    );
}
