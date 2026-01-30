//! Kernel Compatibility Detection Module
//!
//! Probes the running kernel for features required by Aegis.
//! Provides clear error messages when requirements aren't met.

#![allow(dead_code)]

use std::fs;
use std::path::Path;

/// Minimum supported kernel version
pub const MIN_KERNEL_VERSION: (u32, u32) = (5, 4);

/// Kernel capabilities detected at runtime
#[derive(Debug, Clone)]
pub struct KernelCaps {
    /// Parsed kernel version (major, minor, patch)
    pub version: (u32, u32, u32),
    /// Raw kernel version string
    pub version_string: String,
    /// BPF filesystem available at /sys/fs/bpf
    pub has_bpf_fs: bool,
    /// XDP support (kernel >= 4.8)
    pub has_xdp: bool,
    /// XDP driver mode (kernel >= 4.12)
    pub has_xdp_driver: bool,
    /// LPM Trie maps (kernel >= 4.11)
    pub has_lpm_trie: bool,
    /// Per-CPU arrays (kernel >= 4.6)
    pub has_percpu_array: bool,
    /// TC classifier (kernel >= 4.1)
    pub has_tc_clsact: bool,
    /// Memory lock unlimited or kernel >= 5.11
    pub memlock_ok: bool,
}

impl KernelCaps {
    /// Detect kernel capabilities
    pub fn detect() -> Self {
        let version_string = Self::read_kernel_version();
        let version = Self::parse_version(&version_string);

        KernelCaps {
            version,
            version_string: version_string.clone(),
            has_bpf_fs: Path::new("/sys/fs/bpf").exists(),
            has_xdp: version >= (4, 8, 0),
            has_xdp_driver: version >= (4, 12, 0),
            has_lpm_trie: version >= (4, 11, 0),
            has_percpu_array: version >= (4, 6, 0),
            has_tc_clsact: version >= (4, 1, 0),
            memlock_ok: version >= (5, 11, 0) || Self::check_memlock(),
        }
    }

    /// Validate that all required features are available
    pub fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::new();

        // Check minimum kernel version
        if (self.version.0, self.version.1) < MIN_KERNEL_VERSION {
            errors.push(format!(
                "Kernel {}.{}.{} is too old. Aegis requires >= {}.{}",
                self.version.0, self.version.1, self.version.2,
                MIN_KERNEL_VERSION.0, MIN_KERNEL_VERSION.1
            ));
        }

        // Check BPF filesystem
        if !self.has_bpf_fs {
            errors.push("BPF filesystem not mounted at /sys/fs/bpf".to_string());
        }

        // Check XDP support
        if !self.has_xdp {
            errors.push("XDP not supported (requires kernel >= 4.8)".to_string());
        }

        // Check LPM Trie (needed for CIDR blocklists)
        if !self.has_lpm_trie {
            errors.push("LPM Trie maps not supported (requires kernel >= 4.11)".to_string());
        }

        // Check memlock
        if !self.memlock_ok {
            errors.push(
                "Insufficient locked memory. Run with: ulimit -l unlimited".to_string()
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("\n"))
        }
    }

    /// Print detected capabilities
    pub fn print_summary(&self) {
        println!("🔍 Kernel: {} ({}.{}.{})",
            self.version_string,
            self.version.0, self.version.1, self.version.2
        );

        let check = |ok: bool| if ok { "✅" } else { "❌" };

        println!("   {} BPF filesystem", check(self.has_bpf_fs));
        println!("   {} XDP support", check(self.has_xdp));
        println!("   {} XDP driver mode", check(self.has_xdp_driver));
        println!("   {} LPM Trie maps", check(self.has_lpm_trie));
        println!("   {} TC clsact qdisc", check(self.has_tc_clsact));
        println!("   {} Memory lock", check(self.memlock_ok));
    }

    /// Read kernel version from /proc/version or uname
    fn read_kernel_version() -> String {
        // Try /proc/version first
        if let Ok(content) = fs::read_to_string("/proc/version") {
            // Format: "Linux version X.Y.Z-..."
            if let Some(ver) = content.split_whitespace().nth(2) {
                return ver.to_string();
            }
        }

        // Fallback to uname -r via /proc/sys/kernel/osrelease
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Parse version string like "5.15.0-generic" into (5, 15, 0)
    fn parse_version(version_str: &str) -> (u32, u32, u32) {
        let parts: Vec<&str> = version_str
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .take(3)
            .collect();

        let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        (major, minor, patch)
    }

    /// Check if memlock rlimit is sufficient
    fn check_memlock() -> bool {
        // Try to read current limits
        // If unlimited or >= 64MB, we're good
        unsafe {
            let mut rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) == 0 {
                // RLIM_INFINITY or at least 64MB
                rlim.rlim_cur == libc::RLIM_INFINITY || rlim.rlim_cur >= 64 * 1024 * 1024
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(KernelCaps::parse_version("5.15.0-generic"), (5, 15, 0));
        assert_eq!(KernelCaps::parse_version("6.1.0"), (6, 1, 0));
        assert_eq!(KernelCaps::parse_version("4.18.0-372.el8.x86_64"), (4, 18, 0));
        assert_eq!(KernelCaps::parse_version("5.4"), (5, 4, 0));
    }

    #[test]
    fn test_detect() {
        let caps = KernelCaps::detect();
        // Should at least parse something
        assert!(caps.version.0 > 0);
    }
}
