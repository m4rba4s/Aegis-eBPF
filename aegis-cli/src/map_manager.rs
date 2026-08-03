use aegis_common::{CidrBlockEntry, LpmKeyIpv4, LpmKeyIpv6, CAT_MANUAL, MAP_ABI_VERSION};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Type alias to reduce type complexity (clippy::type_complexity)
pub type ConfigMap = Arc<Mutex<HashMap<MapData, u32, u32>>>;

pub const PIN_ROOT: &str = "/sys/fs/bpf/aegis";
pub const RUNTIME_ROOT: &str = "/run/aegis";
pub const INSTANCE_ENV: &str = "AEGIS_INSTANCE_ID";
const PROJECT_ID: &str = "Aegis-eBPF";
const OWNERSHIP_FILE: &str = "ownership.json";

const OWNED_PIN_NAMES: &[&str] = &[
    "ALLOWLIST",
    "ALLOWLIST_IPV6",
    "BLOCKLIST",
    "BLOCKLIST_IPV6",
    "CIDR_BLOCKLIST",
    "CIDR_BLOCKLIST_IPV6",
    "CONFIG",
    "CONN_TRACK",
    "CONN_TRACK_IPV6",
    "DPI_EVENTS",
    "EGRESS_BLOCKLIST",
    "EGRESS_BLOCKLIST_IPV6",
    "EGRESS_CIDR_BLOCKLIST",
    "EGRESS_CIDR_BLOCKLIST_IPV6",
    "EVENTS",
    "EVENTS_IPV6",
    "GLOBAL_SYN_CTR",
    "PORT_SCAN",
    "RATE_LIMIT",
    "STATS",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwnershipMarker {
    project: String,
    instance_id: String,
    map_abi_version: u32,
    created_by_version: String,
    interface: String,
}

pub fn instance_id_for_interface(iface: &str) -> String {
    iface.to_string()
}

pub fn current_instance_id() -> anyhow::Result<String> {
    env::var(INSTANCE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "missing {} environment variable for Aegis instance identity",
            INSTANCE_ENV
        )
    })
}

pub fn instance_pin_dir(instance_id: &str) -> PathBuf {
    instance_pin_dir_at(Path::new(PIN_ROOT), instance_id)
}

fn instance_pin_dir_at(pin_root: &Path, instance_id: &str) -> PathBuf {
    pin_root
        .join(instance_id)
        .join(format!("abi-v{}", MAP_ABI_VERSION))
}

fn ownership_marker_path_at(runtime_root: &Path, instance_id: &str) -> PathBuf {
    runtime_root
        .join("instances")
        .join(instance_id)
        .join(format!("abi-v{}", MAP_ABI_VERSION))
        .join(OWNERSHIP_FILE)
}

fn expected_marker(iface: &str) -> OwnershipMarker {
    OwnershipMarker {
        project: PROJECT_ID.to_string(),
        instance_id: instance_id_for_interface(iface),
        map_abi_version: MAP_ABI_VERSION,
        created_by_version: env!("CARGO_PKG_VERSION").to_string(),
        interface: iface.to_string(),
    }
}

/// Resolve the pin directory for the current instance identity.
///
/// The hot path uses this to keep map pins scoped to a single interface
/// instance and map ABI version.
pub fn current_pin_dir() -> anyhow::Result<PathBuf> {
    Ok(instance_pin_dir(&current_instance_id()?))
}

/// Resolve a pinned map path under the current instance directory.
pub fn current_map_path(name: &str) -> anyhow::Result<PathBuf> {
    Ok(current_pin_dir()?.join(name))
}

/// Best-effort compatibility shim for legacy call sites that still expect a
/// direct `PathBuf`. If the instance identity is not available, fall back to
/// the historical shared root path instead of panicking.
pub fn map_path(name: &str) -> PathBuf {
    current_map_path(name).unwrap_or_else(|_| Path::new(PIN_ROOT).join(name))
}

pub fn ensure_instance_pin_dir(iface: &str) -> anyhow::Result<PathBuf> {
    let pin_dir = ensure_instance_pin_dir_at(Path::new(PIN_ROOT), Path::new(RUNTIME_ROOT), iface)?;
    assign_runtime_path_ownership(&pin_dir, iface)?;
    Ok(pin_dir)
}

fn ensure_instance_pin_dir_at(
    pin_root: &Path,
    runtime_root: &Path,
    iface: &str,
) -> anyhow::Result<PathBuf> {
    let instance_id = instance_id_for_interface(iface);
    let pin_dir = instance_pin_dir_at(pin_root, &instance_id);
    let marker_path = ownership_marker_path_at(runtime_root, &instance_id);

    if marker_path.exists() {
        verify_instance_marker_at(&pin_dir, pin_root, runtime_root, iface)?;
        fs::create_dir_all(&pin_dir)?;
        return Ok(pin_dir);
    }

    if pin_dir.exists() && fs::read_dir(&pin_dir)?.next().transpose()?.is_some() {
        anyhow::bail!(
            "refusing to claim non-empty bpffs directory without ownership marker: {}",
            pin_dir.display()
        );
    }

    fs::create_dir_all(&pin_dir)?;
    write_ownership_marker(&marker_path, &expected_marker(iface))?;
    Ok(pin_dir)
}

fn write_ownership_marker(path: &Path, marker: &OwnershipMarker) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("ownership marker has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to create ownership marker {}: {}",
                path.display(),
                e
            )
        })?;
    let body = serde_json::to_vec_pretty(marker)?;
    file.write_all(&body)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn runtime_identity() -> (u32, u32) {
    let uid = env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(65534);
    let gid = env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(65534);
    (uid, gid)
}

fn assign_runtime_path_ownership(pin_dir: &Path, iface: &str) -> anyhow::Result<()> {
    let (uid, gid) = runtime_identity();
    let instance_id = instance_id_for_interface(iface);
    let marker_path = ownership_marker_path_at(Path::new(RUNTIME_ROOT), &instance_id);
    let shared_paths = [
        PathBuf::from(PIN_ROOT),
        PathBuf::from(RUNTIME_ROOT),
        Path::new(RUNTIME_ROOT).join("instances"),
    ];
    let instance_paths = [
        pin_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("pin directory has no instance parent"))?
            .to_path_buf(),
        pin_dir.to_path_buf(),
        Path::new(RUNTIME_ROOT).join("instances").join(&instance_id),
        marker_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("marker has no ABI directory"))?
            .to_path_buf(),
    ];

    for path in shared_paths {
        set_shared_directory(&path)?;
    }
    for path in instance_paths {
        set_owned_directory(&path, uid, gid)?;
    }
    set_path_owner(&marker_path, uid, gid)?;
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn set_shared_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!(
            "shared Aegis path is not a real directory: {}",
            path.display()
        );
    }
    set_path_owner(path, 0, 0)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o711))?;
    Ok(())
}

fn set_owned_directory(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!(
            "managed Aegis path is not a real directory: {}",
            path.display()
        );
    }
    set_path_owner(path, uid, gid)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn set_path_owner(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        anyhow::anyhow!(
            "managed Aegis path contains an interior NUL: {}",
            path.display()
        )
    })?;
    // SAFETY: `c_path` is a live, NUL-terminated CString for the duration of
    // the call, and `chown` does not retain the pointer.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "failed to chown {} to {}:{}: {}",
            path.display(),
            uid,
            gid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub fn verify_instance_marker(pin_dir: &Path, iface: &str) -> anyhow::Result<()> {
    verify_instance_marker_at(pin_dir, Path::new(PIN_ROOT), Path::new(RUNTIME_ROOT), iface)
}

fn verify_instance_marker_at(
    pin_dir: &Path,
    pin_root: &Path,
    runtime_root: &Path,
    iface: &str,
) -> anyhow::Result<()> {
    let expected = expected_marker(iface);
    let expected_pin_dir = instance_pin_dir_at(pin_root, &expected.instance_id);
    if pin_dir != expected_pin_dir {
        anyhow::bail!(
            "pin directory {} does not match instance {} expected path {}",
            pin_dir.display(),
            expected.instance_id,
            expected_pin_dir.display()
        );
    }

    let marker_path = ownership_marker_path_at(runtime_root, &expected.instance_id);
    let body = fs::read(&marker_path).map_err(|e| {
        anyhow::anyhow!(
            "missing or unreadable ownership marker {}: {}",
            marker_path.display(),
            e
        )
    })?;
    let actual: OwnershipMarker = serde_json::from_slice(&body).map_err(|e| {
        anyhow::anyhow!("invalid ownership marker {}: {}", marker_path.display(), e)
    })?;

    if actual.project != expected.project
        || actual.instance_id != expected.instance_id
        || actual.interface != expected.interface
    {
        anyhow::bail!(
            "ownership marker {} does not belong to Aegis instance {}",
            marker_path.display(),
            expected.instance_id
        );
    }
    if actual.map_abi_version != MAP_ABI_VERSION {
        anyhow::bail!(
            "incompatible map ABI in {}: found {}, expected {}",
            marker_path.display(),
            actual.map_abi_version,
            MAP_ABI_VERSION
        );
    }
    Ok(())
}

/// Remove only pins from the current instance after verifying ownership.
pub fn cleanup_instance_pin_dir(pin_dir: &Path, iface: &str) -> anyhow::Result<()> {
    cleanup_instance_pin_dir_at(
        pin_dir,
        Path::new(PIN_ROOT),
        Path::new(RUNTIME_ROOT),
        iface,
        false,
    )
}

/// Explicit operator recovery for stale state whose runtime marker was lost.
///
/// The force path still removes only known Aegis pin names and refuses unknown
/// entries, so it cannot recursively erase arbitrary bpffs contents.
pub fn cleanup_orphaned_instance_pin_dir(iface: &str) -> anyhow::Result<()> {
    let pin_dir = instance_pin_dir(&instance_id_for_interface(iface));
    cleanup_instance_pin_dir_at(
        &pin_dir,
        Path::new(PIN_ROOT),
        Path::new(RUNTIME_ROOT),
        iface,
        true,
    )
}

fn cleanup_instance_pin_dir_at(
    pin_dir: &Path,
    pin_root: &Path,
    runtime_root: &Path,
    iface: &str,
    allow_missing_marker: bool,
) -> anyhow::Result<()> {
    let instance_id = instance_id_for_interface(iface);
    let marker_path = ownership_marker_path_at(runtime_root, &instance_id);

    if marker_path.exists() || !allow_missing_marker {
        verify_instance_marker_at(pin_dir, pin_root, runtime_root, iface)?;
    }

    if pin_dir.exists() {
        let mut owned_entries = Vec::new();
        for entry in fs::read_dir(pin_dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| {
                anyhow::anyhow!(
                    "refusing to clean {} because a non-UTF-8 entry remains",
                    pin_dir.display()
                )
            })?;
            if !OWNED_PIN_NAMES.contains(&name.as_str()) {
                anyhow::bail!(
                    "refusing to clean {} because unknown entry remains: {}",
                    pin_dir.display(),
                    entry.path().display()
                );
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || metadata.file_type().is_dir() {
                anyhow::bail!(
                    "refusing to remove non-pin entry from {}: {}",
                    pin_dir.display(),
                    entry.path().display()
                );
            }
            owned_entries.push(entry.path());
        }

        for path in owned_entries {
            fs::remove_file(&path).map_err(|e| {
                anyhow::anyhow!("failed to remove owned pin {}: {}", path.display(), e)
            })?;
        }
        fs::remove_dir(pin_dir)?;
    }

    if let Some(parent) = pin_dir.parent() {
        remove_dir_if_empty(parent)?;
    }

    if marker_path.exists() {
        fs::remove_file(&marker_path)?;
        if let Some(abi_dir) = marker_path.parent() {
            remove_dir_if_empty(abi_dir)?;
            if let Some(instance_dir) = abi_dir.parent() {
                remove_dir_if_empty(instance_dir)?;
                if let Some(instances_dir) = instance_dir.parent() {
                    remove_dir_if_empty(instances_dir)?;
                }
            }
        }
    }
    Ok(())
}

fn remove_dir_if_empty(path: &Path) -> anyhow::Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::DirectoryNotEmpty =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

pub fn setup_config_map(
    bpf: &mut Ebpf,
    iface: &str,
    sys_cfg: &crate::config::AegisConfig,
) -> Result<ConfigMap, anyhow::Error> {
    let config_map = bpf
        .take_map("CONFIG")
        .ok_or_else(|| anyhow::anyhow!("CONFIG map not found"))?;
    let mut config: HashMap<_, u32, u32> = HashMap::try_from(config_map)?;

    // Key 0: Interface mode (L3 for WireGuard/tun, L2 for Ethernet)
    let mode: u32 = if iface.starts_with("wg") || iface.starts_with("tun") {
        println!("ℹ️  Setting L3 mode (raw IP) for interface: {}", iface);
        1
    } else {
        0
    };
    config.insert(0u32, mode, 0)?;

    // Keys 1-7: Defense modules (from config.toml)
    config.insert(
        aegis_common::CFG_PORT_SCAN,
        sys_cfg.modules.port_scan as u32,
        0,
    )?;
    config.insert(
        aegis_common::CFG_RATE_LIMIT,
        sys_cfg.modules.rate_limit as u32,
        0,
    )?;
    config.insert(
        aegis_common::CFG_THREAT_FEEDS,
        sys_cfg.modules.threat_feeds as u32,
        0,
    )?;
    // NOTE: CFG_CONN_TRACK is written here for config-map completeness, but no
    // BPF program reads it in v4.3.0-rc.1 — conntrack is telemetry-only (the
    // handshake state machine in aegis-common is aspirational and the
    // conntrack_hits counter is never incremented). Retained rather than
    // removed so existing config files keep parsing; see
    // docs/release/v4.3.0-rc.1-hardening.md.
    config.insert(
        aegis_common::CFG_CONN_TRACK,
        sys_cfg.modules.conn_track as u32,
        0,
    )?;
    config.insert(
        aegis_common::CFG_SCAN_DETECT,
        sys_cfg.modules.scan_detect as u32,
        0,
    )?;

    // Logging and Entropy
    config.insert(aegis_common::CFG_VERBOSE, sys_cfg.modules.verbose as u32, 0)?;
    config.insert(aegis_common::CFG_ENTROPY, sys_cfg.modules.entropy as u32, 0)?;

    // DPI (Deep Packet Inspection) — TLS fingerprinting, YARA, entropy analysis
    config.insert(aegis_common::CFG_DPI_ENABLED, sys_cfg.dpi.enabled as u32, 0)?;

    // Skip RFC1918/loopback whitelist on public-facing interfaces.
    // On non-loopback/non-virtual interfaces, RFC1918 sources are spoofed.
    let is_virtual = iface == "lo"
        || iface.starts_with("tun")
        || iface.starts_with("docker")
        || iface.starts_with("veth")
        || iface.starts_with("br-");
    let skip_wl: u32 = if !is_virtual { 1 } else { 0 };
    config.insert(aegis_common::CFG_SKIP_WHITELIST, skip_wl, 0)?;
    if skip_wl == 1 {
        tracing::info!(
            iface = iface,
            "RFC1918 whitelist DISABLED (public interface)"
        );
    }

    Ok(Arc::new(Mutex::new(config)))
}

pub fn setup_allowlists(
    bpf: &mut Ebpf,
    sys_cfg: &crate::config::AegisConfig,
) -> Result<(), anyhow::Error> {
    if let Some(map) = bpf.take_map("ALLOWLIST") {
        let mut allowlist: HashMap<_, u32, u32> = HashMap::try_from(map)?;
        for ip_str in &sys_cfg.allowlist.ips {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                let key = u32::from(ip).to_be();
                let _ = allowlist.insert(key, 0, 0);
                println!("✅ Allowed IPv4: {}", ip);
            }
        }
    }

    if let Some(map) = bpf.take_map("ALLOWLIST_IPV6") {
        let mut allowlist6: HashMap<_, [u8; 16], u32> = HashMap::try_from(map)?;
        for ip_str in &sys_cfg.allowlist.ips {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                let key = ip.octets();
                let _ = allowlist6.insert(key, 0, 0);
                println!("✅ Allowed IPv6: {}", ip);
            }
        }
    }
    Ok(())
}

pub fn load_threat_feeds(bpf: &mut Ebpf, cfg: &crate::config::Config) -> Result<(), anyhow::Error> {
    println!("📡 Loading threat feeds into CIDR blocklist...");
    let cidr_map = bpf
        .take_map("CIDR_BLOCKLIST")
        .ok_or_else(|| anyhow::anyhow!("CIDR_BLOCKLIST not found"))?;
    let mut cidr: aya::maps::LpmTrie<_, aegis_common::LpmKeyIpv4, aegis_common::CidrBlockEntry> =
        aya::maps::LpmTrie::try_from(cidr_map)?;
    let configs = crate::feeds::FeedConfig::from_config(cfg);
    match crate::feeds::load_feeds_to_map(&mut cidr, &configs) {
        Ok(count) => println!("✅ Loaded {} IPs from threat feeds", count),
        Err(e) => println!("⚠️  Feed loading error: {}", e),
    }
    Ok(())
}

enum ParsedCidr {
    V4 { addr: Ipv4Addr, prefix: u32 },
    V6 { addr: Ipv6Addr, prefix: u32 },
}

fn normalize_ipv4_cidr(addr: Ipv4Addr, prefix: u32) -> Ipv4Addr {
    let addr = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(addr & mask)
}

fn normalize_ipv6_cidr(addr: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    let mut bytes = addr.octets();
    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = (prefix % 8) as u8;

    if full_bytes < bytes.len() {
        if remaining_bits == 0 {
            bytes[full_bytes] = 0;
        } else {
            bytes[full_bytes] &= u8::MAX << (8 - remaining_bits);
        }
        let mut i = full_bytes + 1;
        while i < bytes.len() {
            bytes[i] = 0;
            i += 1;
        }
    }

    Ipv6Addr::from(bytes)
}

fn parse_egress_cidr(cidr: &str) -> Result<ParsedCidr, anyhow::Error> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("egress CIDR '{cidr}' is missing '/' prefix length"))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid egress CIDR prefix in '{cidr}': {e}"))?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid egress CIDR address in '{cidr}': {e}"))?;

    match ip {
        IpAddr::V4(addr) if prefix <= 32 => Ok(ParsedCidr::V4 {
            addr: normalize_ipv4_cidr(addr, prefix),
            prefix,
        }),
        IpAddr::V6(addr) if prefix <= 128 => Ok(ParsedCidr::V6 {
            addr: normalize_ipv6_cidr(addr, prefix),
            prefix,
        }),
        IpAddr::V4(_) => Err(anyhow::anyhow!(
            "invalid IPv4 egress CIDR prefix in '{cidr}': {prefix}"
        )),
        IpAddr::V6(_) => Err(anyhow::anyhow!(
            "invalid IPv6 egress CIDR prefix in '{cidr}': {prefix}"
        )),
    }
}

pub fn setup_egress_blocklists(
    tc_bpf: &mut Ebpf,
    cfg: &crate::config::Config,
) -> Result<(), anyhow::Error> {
    let drop_exact: Vec<IpAddr> = cfg
        .egress_rules
        .iter()
        .filter(|rule| rule.action.eq_ignore_ascii_case("drop"))
        .map(|rule| rule.ip)
        .collect();
    let drop_cidrs: Vec<ParsedCidr> = cfg
        .egress_cidrs
        .iter()
        .filter(|rule| rule.action.eq_ignore_ascii_case("drop"))
        .map(|rule| parse_egress_cidr(&rule.cidr))
        .collect::<Result<_, _>>()?;

    let has_v4_exact = drop_exact.iter().any(|ip| matches!(ip, IpAddr::V4(_)));
    let has_v6_exact = drop_exact.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
    let has_v4_cidr = drop_cidrs
        .iter()
        .any(|cidr| matches!(cidr, ParsedCidr::V4 { .. }));
    let has_v6_cidr = drop_cidrs
        .iter()
        .any(|cidr| matches!(cidr, ParsedCidr::V6 { .. }));

    if has_v4_exact {
        let map = tc_bpf
            .take_map("EGRESS_BLOCKLIST")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_BLOCKLIST map not found"))?;
        let mut egress: HashMap<_, u32, u32> = HashMap::try_from(map)?;
        for ip in &drop_exact {
            if let IpAddr::V4(ipv4) = ip {
                egress.insert(u32::from(*ipv4).to_be(), 1, 0)?;
            }
        }
    }

    if has_v6_exact {
        let map = tc_bpf
            .take_map("EGRESS_BLOCKLIST_IPV6")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_BLOCKLIST_IPV6 map not found"))?;
        let mut egress6: HashMap<_, [u8; 16], u32> = HashMap::try_from(map)?;
        for ip in &drop_exact {
            if let IpAddr::V6(ipv6) = ip {
                egress6.insert(ipv6.octets(), 1, 0)?;
            }
        }
    }

    let entry = CidrBlockEntry {
        category: CAT_MANUAL,
        _pad: [0u8; 3],
    };

    if has_v4_cidr {
        let map = tc_bpf
            .take_map("EGRESS_CIDR_BLOCKLIST")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR_BLOCKLIST map not found"))?;
        let mut cidr: LpmTrie<_, LpmKeyIpv4, CidrBlockEntry> = LpmTrie::try_from(map)?;
        for cidr_rule in &drop_cidrs {
            if let ParsedCidr::V4 { addr, prefix } = cidr_rule {
                let key = Key::new(
                    *prefix,
                    LpmKeyIpv4 {
                        addr: u32::from(*addr).to_be(),
                    },
                );
                cidr.insert(&key, entry, 0)?;
            }
        }
    }

    if has_v6_cidr {
        let map = tc_bpf
            .take_map("EGRESS_CIDR_BLOCKLIST_IPV6")
            .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR_BLOCKLIST_IPV6 map not found"))?;
        let mut cidr6: LpmTrie<_, LpmKeyIpv6, CidrBlockEntry> = LpmTrie::try_from(map)?;
        for cidr_rule in &drop_cidrs {
            if let ParsedCidr::V6 { addr, prefix } = cidr_rule {
                let key = Key::new(
                    *prefix,
                    LpmKeyIpv6 {
                        addr: addr.octets(),
                    },
                );
                cidr6.insert(&key, entry, 0)?;
            }
        }
    }

    let loaded = drop_exact.len() + drop_cidrs.len();
    if loaded > 0 {
        tracing::info!(rules = loaded, "loaded TC egress blocklist policy");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_instance_pin_dir_at, ensure_instance_pin_dir_at, instance_pin_dir,
        instance_pin_dir_at, ownership_marker_path_at, parse_egress_cidr,
        verify_instance_marker_at, OwnershipMarker, ParsedCidr, OWNED_PIN_NAMES,
    };
    use crate::map_manager::MAP_ABI_VERSION;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_roots(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let unique = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aegis-map-manager-{}-{}-{}",
            name,
            std::process::id(),
            unique
        ));
        let pin_root = root.join("bpffs");
        let runtime_root = root.join("run");
        fs::create_dir_all(&pin_root).unwrap();
        fs::create_dir_all(&runtime_root).unwrap();
        (root, pin_root, runtime_root)
    }

    fn write_marker(path: &Path, marker: &OwnershipMarker) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(marker).unwrap()).unwrap();
    }

    #[test]
    fn test_parse_egress_cidr_ipv4() {
        match parse_egress_cidr("203.0.113.0/24").unwrap() {
            ParsedCidr::V4 { addr, prefix } => {
                assert_eq!(addr, Ipv4Addr::new(203, 0, 113, 0));
                assert_eq!(prefix, 24);
            }
            ParsedCidr::V6 { .. } => panic!("expected IPv4 CIDR"),
        }
    }

    #[test]
    fn test_parse_egress_cidr_ipv6() {
        match parse_egress_cidr("2001:db8::/32").unwrap() {
            ParsedCidr::V6 { addr, prefix } => {
                assert_eq!(addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(prefix, 32);
            }
            ParsedCidr::V4 { .. } => panic!("expected IPv6 CIDR"),
        }
    }

    #[test]
    fn test_instance_pin_dir_is_scoped_by_interface_and_abi() {
        let pin_dir = instance_pin_dir("eth0");
        let pin_dir_text = pin_dir.to_string_lossy();
        assert!(pin_dir_text.ends_with("/sys/fs/bpf/aegis/eth0/abi-v1"));
        assert!(pin_dir_text.contains("/aegis/eth0/"));
        assert_eq!(MAP_ABI_VERSION, 1);
    }

    #[test]
    fn matching_marker_allows_owned_cleanup() {
        let (root, pin_root, runtime_root) = test_roots("owned-cleanup");
        let pin_dir = ensure_instance_pin_dir_at(&pin_root, &runtime_root, "eth0").unwrap();
        fs::write(pin_dir.join(OWNED_PIN_NAMES[0]), b"pin").unwrap();

        cleanup_instance_pin_dir_at(&pin_dir, &pin_root, &runtime_root, "eth0", false).unwrap();

        assert!(!pin_dir.exists());
        assert!(!ownership_marker_path_at(&runtime_root, "eth0").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_marker_prevents_destructive_cleanup() {
        let (root, pin_root, runtime_root) = test_roots("missing-marker");
        let pin_dir = instance_pin_dir_at(&pin_root, "eth0");
        fs::create_dir_all(&pin_dir).unwrap();
        let pin = pin_dir.join(OWNED_PIN_NAMES[0]);
        fs::write(&pin, b"pin").unwrap();

        let result = cleanup_instance_pin_dir_at(&pin_dir, &pin_root, &runtime_root, "eth0", false);

        assert!(result.is_err());
        assert!(pin.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_orphan_cleanup_removes_only_known_pins() {
        let (root, pin_root, runtime_root) = test_roots("orphan-cleanup");
        let pin_dir = instance_pin_dir_at(&pin_root, "eth0");
        fs::create_dir_all(&pin_dir).unwrap();
        fs::write(pin_dir.join(OWNED_PIN_NAMES[0]), b"pin").unwrap();

        cleanup_instance_pin_dir_at(&pin_dir, &pin_root, &runtime_root, "eth0", true).unwrap();

        assert!(!pin_dir.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_entry_prevents_recursive_cleanup() {
        let (root, pin_root, runtime_root) = test_roots("unknown-entry");
        let pin_dir = ensure_instance_pin_dir_at(&pin_root, &runtime_root, "eth0").unwrap();
        let known = pin_dir.join(OWNED_PIN_NAMES[0]);
        let unknown = pin_dir.join("NOT_OWNED");
        fs::write(&known, b"preserve-until-preflight-passes").unwrap();
        fs::write(&unknown, b"preserve").unwrap();

        let result = cleanup_instance_pin_dir_at(&pin_dir, &pin_root, &runtime_root, "eth0", false);

        assert!(result.is_err());
        assert!(known.exists());
        assert!(unknown.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn instance_cleanup_cannot_remove_sibling_instance() {
        let (root, pin_root, runtime_root) = test_roots("sibling-instance");
        let pin_a = ensure_instance_pin_dir_at(&pin_root, &runtime_root, "eth0").unwrap();
        let pin_b = ensure_instance_pin_dir_at(&pin_root, &runtime_root, "eth1").unwrap();
        fs::write(pin_a.join(OWNED_PIN_NAMES[0]), b"a").unwrap();
        let sibling_pin = pin_b.join(OWNED_PIN_NAMES[0]);
        fs::write(&sibling_pin, b"b").unwrap();

        cleanup_instance_pin_dir_at(&pin_a, &pin_root, &runtime_root, "eth0", false).unwrap();

        assert!(sibling_pin.exists());
        assert!(ownership_marker_path_at(&runtime_root, "eth1").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incompatible_map_abi_is_rejected() {
        let (root, pin_root, runtime_root) = test_roots("abi-mismatch");
        let pin_dir = instance_pin_dir_at(&pin_root, "eth0");
        fs::create_dir_all(&pin_dir).unwrap();
        let marker_path = ownership_marker_path_at(&runtime_root, "eth0");
        write_marker(
            &marker_path,
            &OwnershipMarker {
                project: "Aegis-eBPF".to_string(),
                instance_id: "eth0".to_string(),
                map_abi_version: MAP_ABI_VERSION + 1,
                created_by_version: "older-release".to_string(),
                interface: "eth0".to_string(),
            },
        );

        let result = verify_instance_marker_at(&pin_dir, &pin_root, &runtime_root, "eth0");

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("incompatible map ABI"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_abi_marker_survives_userspace_upgrade() {
        let (root, pin_root, runtime_root) = test_roots("version-upgrade");
        let pin_dir = instance_pin_dir_at(&pin_root, "eth0");
        fs::create_dir_all(&pin_dir).unwrap();
        let marker_path = ownership_marker_path_at(&runtime_root, "eth0");
        write_marker(
            &marker_path,
            &OwnershipMarker {
                project: "Aegis-eBPF".to_string(),
                instance_id: "eth0".to_string(),
                map_abi_version: MAP_ABI_VERSION,
                created_by_version: "4.2.0".to_string(),
                interface: "eth0".to_string(),
            },
        );

        verify_instance_marker_at(&pin_dir, &pin_root, &runtime_root, "eth0").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_parse_egress_cidr_rejects_bad_prefix() {
        assert!(parse_egress_cidr("203.0.113.0/33").is_err());
        assert!(parse_egress_cidr("2001:db8::/129").is_err());
    }

    #[test]
    fn test_parse_egress_cidr_normalizes_host_bits() {
        match parse_egress_cidr("198.51.100.20/24").unwrap() {
            ParsedCidr::V4 { addr, prefix } => {
                assert_eq!(addr, Ipv4Addr::new(198, 51, 100, 0));
                assert_eq!(prefix, 24);
            }
            ParsedCidr::V6 { .. } => panic!("expected IPv4 CIDR"),
        }

        match parse_egress_cidr("2001:db8:dead:beef::20/48").unwrap() {
            ParsedCidr::V6 { addr, prefix } => {
                assert_eq!(addr, "2001:db8:dead::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(prefix, 48);
            }
            ParsedCidr::V4 { .. } => panic!("expected IPv6 CIDR"),
        }
    }
}
