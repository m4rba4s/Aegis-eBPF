#[cfg(unix)]
pub fn freeze_map(path: &str) {
    #[repr(C, align(8))]
    struct BpfAttrObjGet {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    #[repr(C, align(8))]
    struct BpfAttrMapFreeze {
        map_fd: u32,
    }

    let bpf_path = match std::ffi::CString::new(path) {
        Ok(p) => p,
        Err(_) => return,
    };

    let mut attr_obj_get: BpfAttrObjGet = unsafe { std::mem::zeroed() };
    attr_obj_get.pathname = bpf_path.as_ptr() as u64;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            7, /* BPF_OBJ_GET */
            &attr_obj_get,
            std::mem::size_of::<BpfAttrObjGet>(),
        )
    };

    if fd < 0 {
        return; // Map probably doesn't exist, ignore
    }

    let mut attr_freeze: BpfAttrMapFreeze = unsafe { std::mem::zeroed() };
    attr_freeze.map_fd = fd as u32;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            22, /* BPF_MAP_FREEZE */
            &attr_freeze,
            std::mem::size_of::<BpfAttrMapFreeze>(),
        )
    };

    if ret == 0 {
        tracing::info!("🔒 eBPF Map {} frozen (read-only from userspace)", path);
    }
    unsafe {
        libc::close(fd as i32);
    }
}

#[cfg(unix)]
pub fn drop_privileges() -> anyhow::Result<()> {
    use caps::{CapSet, Capability, CapsHashSet};

    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(65534);
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(65534);

    // NOTE: Do NOT chown BPF maps to non-root — writable BPF maps allow
    // unprivileged modification of firewall state. Maps remain root-owned.

    caps::securebits::set_keepcaps(true)?;

    let mut keep = CapsHashSet::new();
    keep.insert(Capability::CAP_BPF);
    keep.insert(Capability::CAP_NET_ADMIN);
    keep.insert(Capability::CAP_PERFMON);

    // Reduce bounding set BEFORE uid change (requires CAP_SETPCAP as root)
    // Keep CAP_SETPCAP temporarily so we can modify caps after setresuid
    for cap in caps::all() {
        if !keep.contains(&cap) && cap != Capability::CAP_SETPCAP {
            let _ = caps::drop(None, CapSet::Bounding, cap);
        }
    }

    // Clear supplementary groups (prevents group-based access leaks)
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            tracing::warn!("setgroups(0) failed — supplementary groups may persist");
        }
        if libc::setresgid(gid, gid, gid) != 0 {
            anyhow::bail!("Failed to drop to GID {}", gid);
        }
        if libc::setresuid(uid, uid, uid) != 0 {
            anyhow::bail!("Failed to drop to UID {}", uid);
        }
    }

    // Set effective + permitted to minimum needed
    caps::set(None, CapSet::Effective, &keep)?;
    caps::set(None, CapSet::Permitted, &keep)?;

    // Clear inheritable (no caps pass to child processes)
    caps::set(None, CapSet::Inheritable, &CapsHashSet::new())?;

    // Now drop CAP_SETPCAP from bounding set (no longer needed)
    let _ = caps::drop(None, CapSet::Bounding, Capability::CAP_SETPCAP);

    // Prevent regaining caps via execve
    caps::securebits::set_keepcaps(false).unwrap_or(());

    tracing::info!(
        uid = uid,
        gid = gid,
        "🛡️ Privileges dropped. Retained CAP_BPF & CAP_NET_ADMIN."
    );
    Ok(())
}
