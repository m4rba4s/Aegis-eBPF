use aya::{Ebpf, EbpfLoader};
use std::path::Path;

/// Load XDP eBPF program - uses embedded bytecode if available and path is default
///
/// AEGIS-SEC-006: Validates that pinned maps at `pin_root` match the current
/// MAP_ABI_VERSION before loading. Stale pins from a previous version with
/// different struct layouts would cause silent memory corruption.
pub fn load_xdp_program(path: &str, pin_root: &str) -> Result<Ebpf, anyhow::Error> {
    validate_pin_root_abi(pin_root)?;
    // If embedded and using default path, use embedded bytecode
    #[cfg(embedded_xdp)]
    if path == crate::DEFAULT_XDP_PATH {
        log::debug!(
            "Loading embedded XDP program ({} bytes)",
            crate::EMBEDDED_XDP.len()
        );
        println!("📦 Loading embedded XDP program");
        return Ok(EbpfLoader::new()
            .map_pin_path(pin_root)
            .load(crate::EMBEDDED_XDP)?);
    }

    // Otherwise load from file
    if Path::new(path).exists() {
        println!("📁 Loading XDP program from: {}", path);
        Ok(EbpfLoader::new().map_pin_path(pin_root).load_file(path)?)
    } else {
        #[cfg(embedded_xdp)]
        {
            println!("⚠️  File {} not found, using embedded XDP", path);
            return Ok(EbpfLoader::new()
                .map_pin_path(pin_root)
                .load(crate::EMBEDDED_XDP)?);
        }
        #[cfg(not(embedded_xdp))]
        {
            anyhow::bail!(
                "XDP program not found at {} and no embedded bytecode available",
                path
            );
        }
    }
}

/// Load TC eBPF program - uses embedded bytecode if available and path is default.
/// Uses map_pin_path to reuse pinned maps/ring buffers such as CONFIG and EVENTS.
pub fn load_tc_program(path: &str, pin_root: &str) -> Result<Ebpf, anyhow::Error> {
    validate_pin_root_abi(pin_root)?;
    // If embedded and using default path, use embedded bytecode
    #[cfg(embedded_tc)]
    if path == crate::DEFAULT_TC_PATH {
        println!(
            "📦 Loading embedded TC program ({} bytes)",
            crate::EMBEDDED_TC.len()
        );
        // Reuse pinned maps so TC shares CONFIG/EVENTS and owns its conntrack maps.
        return Ok(EbpfLoader::new()
            .map_pin_path(pin_root)
            .load(crate::EMBEDDED_TC)?);
    }

    // Otherwise load from file
    if Path::new(path).exists() {
        println!("📁 Loading TC program from: {}", path);
        Ok(EbpfLoader::new().map_pin_path(pin_root).load_file(path)?)
    } else {
        #[cfg(embedded_tc)]
        {
            println!("⚠️  File {} not found, using embedded TC", path);
            return Ok(EbpfLoader::new()
                .map_pin_path(pin_root)
                .load(crate::EMBEDDED_TC)?);
        }
        #[cfg(not(embedded_tc))]
        {
            anyhow::bail!(
                "TC program not found at {} and no embedded bytecode available",
                path
            );
        }
    }
}

// ============================================================
// ABI VALIDATION (AEGIS-SEC-006)
// ============================================================

/// Validate that any existing ownership marker in the pin directory
/// matches the current MAP_ABI_VERSION. Prevents loading programs
/// against stale pinned maps with incompatible struct layouts.
fn validate_pin_root_abi(pin_root: &str) -> Result<(), anyhow::Error> {
    use aegis_common::MAP_ABI_VERSION;

    let pin_path = Path::new(pin_root);
    if !pin_path.exists() {
        return Ok(()); // Fresh start, no stale maps
    }

    // Check if the pin_root path contains the expected ABI version segment.
    // The instance pin dir format is: /sys/fs/bpf/aegis/<iface>/abi-v<N>
    // If we find an abi-v<M> segment where M != current, bail.
    let expected_segment = format!("abi-v{}", MAP_ABI_VERSION);
    let pin_str = pin_path.to_string_lossy();

    // Look for any abi-v* segment in the path
    for component in pin_path.components() {
        let comp = component.as_os_str().to_string_lossy();
        if comp.starts_with("abi-v") && comp != expected_segment {
            anyhow::bail!(
                "AEGIS-SEC-006: Pin root {} contains stale ABI version '{}' \
                 (expected '{}'). Clean up stale pins with: \
                 rm -rf {} && restart Aegis.",
                pin_str,
                comp,
                expected_segment,
                pin_str
            );
        }
    }

    Ok(())
}
