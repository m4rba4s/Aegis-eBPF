/// Format TCP flags byte into human-readable string
pub fn format_tcp_flags(flags: u8) -> String {
    let mut result = String::new();
    if flags & 0x01 != 0 {
        result.push_str("FIN ");
    }
    if flags & 0x02 != 0 {
        result.push_str("SYN ");
    }
    if flags & 0x04 != 0 {
        result.push_str("RST ");
    }
    if flags & 0x08 != 0 {
        result.push_str("PSH ");
    }
    if flags & 0x10 != 0 {
        result.push_str("ACK ");
    }
    if flags & 0x20 != 0 {
        result.push_str("URG ");
    }
    if result.is_empty() {
        format!("0x{:02x}", flags)
    } else {
        result.trim().to_string()
    }
}
