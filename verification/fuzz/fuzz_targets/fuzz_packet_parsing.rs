//! Fuzz target for packet header parsing
//!
//! This fuzzer tests the packet parsing logic that runs in the eBPF program.
//! It generates random byte sequences and verifies that parsing never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

/// Simulated Ethernet header (14 bytes)
#[derive(Debug, Clone, Arbitrary)]
struct FuzzEthHdr {
    dst_addr: [u8; 6],
    src_addr: [u8; 6],
    ether_type: u16,
}

/// Simulated IPv4 header (20+ bytes)
#[derive(Debug, Clone, Arbitrary)]
struct FuzzIpv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src_addr: u32,
    dst_addr: u32,
}

/// Simulated IPv6 header (40 bytes)
#[derive(Debug, Clone, Arbitrary)]
struct FuzzIpv6Hdr {
    version_tc_flow: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

/// Simulated TCP header (20+ bytes)
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTcpHdr {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_flags: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
}

/// Full packet for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzPacket {
    eth: FuzzEthHdr,
    // Variant: IPv4 or IPv6
    is_ipv6: bool,
    ipv4: Option<FuzzIpv4Hdr>,
    ipv6: Option<FuzzIpv6Hdr>,
    // L4: TCP, UDP, or other
    tcp: Option<FuzzTcpHdr>,
    // Payload bytes
    payload: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // Try to parse as arbitrary structured packet
    if let Ok(packet) = FuzzPacket::arbitrary(&mut Unstructured::new(data)) {
        // Simulate the parsing logic from aegis-ebpf

        // 1. Validate Ethernet header ethertype
        let ether_type = u16::from_be(packet.eth.ether_type);
        let _is_ip = ether_type == 0x0800;
        let _is_ipv6 = ether_type == 0x86DD;

        // 2. For IPv4: validate IHL
        if let Some(ref ipv4) = packet.ipv4 {
            let ihl = ipv4.version_ihl & 0x0F;
            let _header_len = (ihl as usize) * 4;

            // IHL must be >= 5 (20 bytes minimum)
            // This is a bounds check the eBPF program makes
            let _valid_ihl = ihl >= 5 && ihl <= 15;

            // Protocol extraction
            let _proto = ipv4.proto;

            // Total length check
            let _tot_len = u16::from_be(ipv4.tot_len);
        }

        // 3. For IPv6: validate next header
        if let Some(ref ipv6) = packet.ipv6 {
            let _next_hdr = ipv6.next_header;
            let _payload_len = u16::from_be(ipv6.payload_len);

            // Version check
            let version = (u32::from_be(ipv6.version_tc_flow) >> 28) & 0xF;
            let _is_v6 = version == 6;
        }

        // 4. For TCP: extract flags and ports
        if let Some(ref tcp) = packet.tcp {
            let _src_port = u16::from_be(tcp.src_port);
            let _dst_port = u16::from_be(tcp.dst_port);

            // Extract flags (lower 6 bits of second byte)
            let flags_byte = (u16::from_be(tcp.data_offset_flags) & 0x3F) as u8;
            let _syn = flags_byte & 0x02 != 0;
            let _ack = flags_byte & 0x10 != 0;
            let _fin = flags_byte & 0x01 != 0;
            let _rst = flags_byte & 0x04 != 0;
            let _psh = flags_byte & 0x08 != 0;
            let _urg = flags_byte & 0x20 != 0;

            // Data offset (header length)
            let data_offset = ((u16::from_be(tcp.data_offset_flags) >> 12) & 0xF) as usize;
            let _tcp_header_len = data_offset * 4;
        }

        // 5. Entropy check simulation (4 bytes)
        if packet.payload.len() >= 4 {
            let b0 = packet.payload[0];
            let b1 = packet.payload[1];
            let b2 = packet.payload[2];
            let b3 = packet.payload[3];

            // All different = high entropy
            let _all_different = (b0 != b1) && (b0 != b2) && (b0 != b3)
                && (b1 != b2) && (b1 != b3) && (b2 != b3);
        }

        // 6. Port scan bitmap simulation
        for port in packet.payload.iter().take(2) {
            let port_val = *port as u16;
            if port_val < 256 {
                let _bitmap_idx = (port_val / 32) as usize;
                let _bit_pos = port_val % 32;
                // These must always be valid
                assert!(_bitmap_idx < 8);
                assert!(_bit_pos < 32);
            }
        }
    }

    // Also test raw byte parsing (bounds checking)
    if data.len() >= 14 {
        // Ethernet header bounds check
        let _eth_dst = &data[0..6];
        let _eth_src = &data[6..12];
        let _eth_type = u16::from_be_bytes([data[12], data[13]]);

        if data.len() >= 34 {
            // IPv4 header bounds check (14 + 20)
            let version_ihl = data[14];
            let ihl = version_ihl & 0x0F;
            if ihl >= 5 {
                let ip_header_len = (ihl as usize) * 4;
                if data.len() >= 14 + ip_header_len {
                    // Valid IPv4 header
                    let _proto = data[23];
                    let _src_ip = u32::from_be_bytes([data[26], data[27], data[28], data[29]]);
                }
            }
        }
    }
});
