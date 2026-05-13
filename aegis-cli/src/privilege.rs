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

    if let Ok(entries) = std::fs::read_dir("/sys/fs/bpf/aegis") {
        for entry in entries.flatten() {
            unsafe {
                use std::os::unix::ffi::OsStrExt;
                let c_path = std::ffi::CString::new(entry.path().as_os_str().as_bytes()).unwrap();
                libc::chown(c_path.as_ptr(), uid, gid);
            }
        }
        unsafe {
            let c_dir = std::ffi::CString::new("/sys/fs/bpf/aegis").unwrap();
            libc::chown(c_dir.as_ptr(), uid, gid);
        }
    }

    caps::securebits::set_keepcaps(true)?;

    unsafe {
        if libc::setresgid(gid, gid, gid) != 0 {
            anyhow::bail!("Failed to drop to GID {}", gid);
        }
        if libc::setresuid(uid, uid, uid) != 0 {
            anyhow::bail!("Failed to drop to UID {}", uid);
        }
    }

    let mut keep = CapsHashSet::new();
    keep.insert(Capability::CAP_BPF);
    keep.insert(Capability::CAP_NET_ADMIN);
    keep.insert(Capability::CAP_PERFMON);

    caps::set(None, CapSet::Effective, &keep)?;
    caps::set(None, CapSet::Permitted, &keep)?;
    caps::securebits::set_keepcaps(false).unwrap_or(());

    tracing::info!(
        uid = uid,
        gid = gid,
        "🛡️ Privileges dropped. Retained CAP_BPF & CAP_NET_ADMIN."
    );
    Ok(())
}
