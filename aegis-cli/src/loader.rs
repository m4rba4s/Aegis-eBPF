use aya::{Ebpf, EbpfLoader};
use std::path::Path;

/// Load XDP eBPF program - uses embedded bytecode if available and path is default
pub fn load_xdp_program(path: &str) -> Result<Ebpf, anyhow::Error> {
    // If embedded and using default path, use embedded bytecode
    #[cfg(embedded_xdp)]
    if path == crate::DEFAULT_XDP_PATH {
        log::debug!(
            "Loading embedded XDP program ({} bytes)",
            crate::EMBEDDED_XDP.len()
        );
        println!("📦 Loading embedded XDP program");
        return Ok(EbpfLoader::new().load(crate::EMBEDDED_XDP)?);
    }

    // Otherwise load from file
    if Path::new(path).exists() {
        println!("📁 Loading XDP program from: {}", path);
        Ok(Ebpf::load_file(path)?)
    } else {
        #[cfg(embedded_xdp)]
        {
            println!("⚠️  File {} not found, using embedded XDP", path);
            return Ok(EbpfLoader::new().load(crate::EMBEDDED_XDP)?);
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

/// Load TC eBPF program - uses embedded bytecode if available and path is default
pub fn load_tc_program(path: &str) -> Result<Ebpf, anyhow::Error> {
    // If embedded and using default path, use embedded bytecode
    #[cfg(embedded_tc)]
    if path == crate::DEFAULT_TC_PATH {
        println!(
            "📦 Loading embedded TC program ({} bytes)",
            crate::EMBEDDED_TC.len()
        );
        return Ok(EbpfLoader::new().load(crate::EMBEDDED_TC)?);
    }

    // Otherwise load from file
    if Path::new(path).exists() {
        println!("📁 Loading TC program from: {}", path);
        Ok(Ebpf::load_file(path)?)
    } else {
        #[cfg(embedded_tc)]
        {
            println!("⚠️  File {} not found, using embedded TC", path);
            return Ok(EbpfLoader::new().load(crate::EMBEDDED_TC)?);
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
