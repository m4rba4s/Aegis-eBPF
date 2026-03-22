//! PCAP Forensics Capture for Aegis eBPF Firewall
//!
//! Writes suspect packets (from DPI queue) to standard .pcap files
//! for post-mortem forensic analysis with Wireshark/tcpdump.
//!
//! Features:
//!   - Standard libpcap file format (no external dependencies)
//!   - Configurable max file size with automatic rotation
//!   - Raw Ethernet frame reconstruction from DPI metadata

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

/// Max PCAP file size before rotation (default: 50 MB)
const DEFAULT_MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Max number of rotated files to keep
const MAX_ROTATED_FILES: u32 = 10;

/// PCAP output directory
const PCAP_DIR: &str = "/var/log/aegis/pcap";

/// Libpcap magic number (microsecond precision)
const PCAP_MAGIC: u32 = 0xa1b2c3d4;

/// Current file size tracker
static CURRENT_SIZE: AtomicU64 = AtomicU64::new(0);

/// PCAP Global Header (24 bytes)
#[repr(C, packed)]
struct PcapGlobalHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,  // LINKTYPE_RAW_IPV4 = 228
}

/// PCAP Record Header (16 bytes)
#[repr(C, packed)]
struct PcapRecordHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

/// Initialize PCAP capture directory and first file
pub fn init_pcap() -> std::io::Result<PathBuf> {
    fs::create_dir_all(PCAP_DIR)?;
    let path = current_pcap_path();
    let mut file = File::create(&path)?;
    write_global_header(&mut file)?;
    CURRENT_SIZE.store(24, Ordering::Relaxed);
    info!(path = %path.display(), "PCAP capture initialized");
    Ok(path)
}

/// Write a suspect packet to the PCAP file.
/// `src_ip`, `dst_ip` in network byte order. `payload` is the L4 payload snippet.
pub fn write_packet(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    payload: &[u8],
    timestamp_ns: u64,
) {
    let max_size = DEFAULT_MAX_FILE_SIZE;

    // Check if rotation needed
    if CURRENT_SIZE.load(Ordering::Relaxed) >= max_size {
        if let Err(e) = rotate_pcap() {
            warn!(error = %e, "PCAP rotation failed");
            return;
        }
    }

    // Build a minimal IPv4 packet (20-byte IP header + L4 header + payload)
    let ip_total_len: u16 = 20 + if proto == 6 { 20 } else { 8 } + payload.len() as u16;
    let mut pkt = Vec::with_capacity(ip_total_len as usize);

    // IPv4 header (20 bytes, no options)
    pkt.push(0x45); // version=4, ihl=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment=0
    pkt.push(64); // TTL
    pkt.push(proto);
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = not computed)
    pkt.extend_from_slice(&src_ip.to_ne_bytes());
    pkt.extend_from_slice(&dst_ip.to_ne_bytes());

    // L4 header (minimal)
    if proto == 6 {
        // TCP: src_port, dst_port, seq=0, ack=0, data_offset=5, flags=0
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 8]); // seq + ack
        pkt.push(0x50); // data offset = 5 words
        pkt.push(0x00); // flags
        pkt.extend_from_slice(&[0xff, 0xff]); // window
        pkt.extend_from_slice(&[0x00; 4]); // checksum + urgent
    } else {
        // UDP: src_port, dst_port, length, checksum
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    }

    // Payload
    pkt.extend_from_slice(payload);

    // Write PCAP record
    let ts_sec = (timestamp_ns / 1_000_000_000) as u32;
    let ts_usec = ((timestamp_ns % 1_000_000_000) / 1000) as u32;

    let record = PcapRecordHeader {
        ts_sec,
        ts_usec,
        incl_len: pkt.len() as u32,
        orig_len: pkt.len() as u32,
    };

    let path = current_pcap_path();
    let mut file = match OpenOptions::new().append(true).create(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, "cannot open PCAP file");
            return;
        }
    };

    let record_bytes = unsafe {
        std::slice::from_raw_parts(
            &record as *const PcapRecordHeader as *const u8,
            std::mem::size_of::<PcapRecordHeader>(),
        )
    };

    if file.write_all(record_bytes).is_ok() && file.write_all(&pkt).is_ok() {
        let written = 16 + pkt.len() as u64;
        CURRENT_SIZE.fetch_add(written, Ordering::Relaxed);
    }
}

// ── Internal Helpers ────────────────────────────────────────────────

fn current_pcap_path() -> PathBuf {
    Path::new(PCAP_DIR).join("aegis_suspect.pcap")
}

fn write_global_header(file: &mut File) -> std::io::Result<()> {
    let header = PcapGlobalHeader {
        magic_number: PCAP_MAGIC,
        version_major: 2,
        version_minor: 4,
        thiszone: 0,
        sigfigs: 0,
        snaplen: 65535,
        network: 228, // LINKTYPE_IPV4
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const PcapGlobalHeader as *const u8,
            std::mem::size_of::<PcapGlobalHeader>(),
        )
    };

    file.write_all(bytes)
}

fn rotate_pcap() -> std::io::Result<()> {
    let base = current_pcap_path();

    // Shift existing rotated files
    for i in (1..MAX_ROTATED_FILES).rev() {
        let from = base.with_extension(format!("pcap.{}", i));
        let to = base.with_extension(format!("pcap.{}", i + 1));
        if from.exists() {
            fs::rename(&from, &to)?;
        }
    }

    // Rotate current file
    if base.exists() {
        let rotated = base.with_extension("pcap.1");
        fs::rename(&base, &rotated)?;
    }

    // Create fresh file
    let mut file = File::create(&base)?;
    write_global_header(&mut file)?;
    CURRENT_SIZE.store(24, Ordering::Relaxed);

    info!("PCAP rotated — new capture file created");
    Ok(())
}
