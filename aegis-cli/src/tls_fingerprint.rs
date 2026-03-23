//! JA3/JA4 TLS Fingerprinting for Aegis eBPF Firewall
//!
//! Computes JA3 fingerprints from TLS ClientHello metadata.
//! The eBPF program extracts TLS version + cipher suite count + extension IDs
//! from the ClientHello (first ~100 bytes after TCP), sends them via perf buffer.
//! This module hashes them into JA3 strings and checks against known-bad signatures.
//!
//! JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//! We compute a simplified version from the eBPF-extracted fields.

use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{info, warn};

/// Known-bad JA3 fingerprints (Cobalt Strike, Metasploit, common RATs)
/// Source: ja3er.com + internal threat intel
static KNOWN_BAD_JA3: std::sync::LazyLock<HashMap<&str, &str>> =
    std::sync::LazyLock::new(|| {
        let mut m = HashMap::new();
        // Cobalt Strike default HTTPS beacon
        m.insert("72a589da586844d7f0818ce684948eea", "CobaltStrike_HTTPS");
        m.insert("a0e9f5d64349fb13191bc781f81f42e1", "CobaltStrike_4.0");
        m.insert("6734f37431670b3ab4292b8f60f29984", "CobaltStrike_3.x");
        // Metasploit / Meterpreter
        m.insert("b386946a5a44d1ddcc843bc75336dfce", "Metasploit_Meterpreter");
        m.insert("e35df3e00ca4ef31d42b34bebaa2f86e", "Metasploit_HTTPS");
        // Empire
        m.insert("d0ec4b50a944b182fc10ff51f883ccae", "Empire_C2");
        // Trickbot
        m.insert("6734f37431670b3ab4292b8f60f29984", "Trickbot");
        // PoshC2
        m.insert("2c14bfb3f8a2e2e33a6773cd933a1e27", "PoshC2");
        // Sliver C2
        m.insert("cd08e31494f9531f560d64c695473da9", "Sliver_C2");
        // Havoc C2
        m.insert("3b5074b1b5d032e5620f69f9f700ff0e", "Havoc_C2");
        // Generic suspicious (empty extensions = old/custom TLS)
        m.insert("e7d705a3286e19ea42f587b344ee6865", "Empty_Extensions");
        m
    });

/// Recent JA3 sightings cache (IP → last seen JA3)
static JA3_CACHE: std::sync::LazyLock<RwLock<HashMap<u32, JA3Entry>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::with_capacity(2048)));

#[derive(Debug, Clone, serde::Serialize)]
pub struct JA3Entry {
    pub ja3_hash: String,
    pub ja3_string: String,
    pub match_name: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub count: u32,
}

/// TLS ClientHello fields extracted by eBPF
#[derive(Debug, Clone)]
pub struct TlsClientHello {
    pub src_ip: u32,
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

// ── JA3 Computation ─────────────────────────────────────────────────

/// Compute JA3 string and MD5 hash from TLS ClientHello fields
pub fn compute_ja3(hello: &TlsClientHello) -> (String, String) {
    // Build JA3 string: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    let ciphers = hello.cipher_suites
        .iter()
        .filter(|&&c| !is_grease(c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let extensions = hello.extensions
        .iter()
        .filter(|&&e| !is_grease(e))
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let curves = hello.elliptic_curves
        .iter()
        .filter(|&&c| !is_grease(c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let formats = hello.ec_point_formats
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ja3_string = format!("{},{},{},{},{}",
        hello.tls_version, ciphers, extensions, curves, formats
    );

    let ja3_hash = format!("{:x}", md5_simple(ja3_string.as_bytes()));

    (ja3_string, ja3_hash)
}

/// Check if a JA3 hash matches a known-bad fingerprint
pub fn check_known_bad(ja3_hash: &str) -> Option<&'static str> {
    KNOWN_BAD_JA3.get(ja3_hash).copied()
}

/// Process a TLS ClientHello: compute JA3, cache, and check against known-bad
pub fn process_hello(hello: &TlsClientHello) -> Option<JA3Entry> {
    let (ja3_string, ja3_hash) = compute_ja3(hello);
    let match_name = check_known_bad(&ja3_hash).map(|s| s.to_string());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entry = JA3Entry {
        ja3_hash: ja3_hash.clone(),
        ja3_string,
        match_name: match_name.clone(),
        first_seen: now,
        last_seen: now,
        count: 1,
    };

    // Update cache
    if let Ok(mut cache) = JA3_CACHE.write() {
        if let Some(existing) = cache.get_mut(&hello.src_ip) {
            existing.last_seen = now;
            existing.count += 1;
            existing.ja3_hash = entry.ja3_hash.clone();
            existing.ja3_string = entry.ja3_string.clone();
            existing.match_name = entry.match_name.clone();
        } else {
            // Evict old entries if at capacity
            if cache.len() >= 2048 {
                let oldest_key = cache.iter()
                    .min_by_key(|(_, v)| v.last_seen)
                    .map(|(&k, _)| k);
                if let Some(key) = oldest_key {
                    cache.remove(&key);
                }
            }
            cache.insert(hello.src_ip, entry.clone());
        }
    }

    if match_name.is_some() {
        warn!(
            src_ip = %std::net::Ipv4Addr::from(u32::from_be(hello.src_ip)),
            ja3 = %ja3_hash,
            threat = ?match_name,
            "🔒 JA3 MATCH: known-bad TLS fingerprint detected"
        );
        Some(entry)
    } else {
        None
    }
}

/// Get all cached JA3 entries as JSON
pub fn get_ja3_cache_json() -> String {
    let entries: Vec<_> = if let Ok(cache) = JA3_CACHE.read() {
        cache.iter().map(|(&ip, entry)| {
            serde_json::json!({
                "ip": std::net::Ipv4Addr::from(u32::from_be(ip)).to_string(),
                "ja3_hash": entry.ja3_hash,
                "ja3_string": entry.ja3_string,
                "match": entry.match_name,
                "first_seen": entry.first_seen,
                "last_seen": entry.last_seen,
                "count": entry.count,
            })
        }).collect()
    } else {
        Vec::new()
    };

    serde_json::json!({
        "count": entries.len(),
        "entries": entries,
    })
    .to_string()
}

// ── GREASE detection ────────────────────────────────────────────────

/// Check if a value is a TLS GREASE value (RFC 8701)
/// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a
}

// ── Simple MD5 (no external dep) ────────────────────────────────────

struct Md5Hash([u8; 16]);

impl std::fmt::LowerHex for Md5Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Minimal MD5 implementation for JA3 hashing (no external crate needed)
/// This is only for fingerprint comparison, NOT for security.
fn md5_simple(data: &[u8]) -> Md5Hash {
    // MD5 constants
    const S: [u32; 64] = [
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
    ];

    const K: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Process each 512-bit chunk
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]))
                    .rotate_left(S[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut hash = [0u8; 16];
    hash[0..4].copy_from_slice(&a0.to_le_bytes());
    hash[4..8].copy_from_slice(&b0.to_le_bytes());
    hash[8..12].copy_from_slice(&c0.to_le_bytes());
    hash[12..16].copy_from_slice(&d0.to_le_bytes());

    Md5Hash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_empty() {
        let hash = format!("{:x}", md5_simple(b""));
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_hello() {
        let hash = format!("{:x}", md5_simple(b"hello"));
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0035));
        assert!(!is_grease(0xc02c));
    }

    #[test]
    fn test_ja3_computation() {
        let hello = TlsClientHello {
            src_ip: 0,
            tls_version: 0x0303,
            cipher_suites: vec![0xc02c, 0xc02b, 0x0035],
            extensions: vec![0x0000, 0x000b, 0x000a],
            elliptic_curves: vec![0x001d, 0x0017],
            ec_point_formats: vec![0],
        };
        let (ja3_str, _hash) = compute_ja3(&hello);
        assert!(ja3_str.starts_with("771,"));
    }
}
