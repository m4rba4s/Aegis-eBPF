//! CNI specification types and command handlers
//!
//! Implements CNI v0.4.0 / v1.0.0 compatible responses.
//! As a chain plugin, ADD returns the prevResult unchanged,
//! while attaching XDP to the pod's veth interface.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;

// ── CNI Specification Types ─────────────────────────────────────────

/// CNI network configuration (from stdin)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniConfig {
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
    /// Previous result from upstream plugin (chain mode)
    pub prev_result: Option<serde_json::Value>,
    /// Aegis-specific: path to XDP program binary
    #[serde(default = "default_xdp_path")]
    pub xdp_program: String,
    /// Aegis-specific: path to policy config
    #[serde(default)]
    pub policy_path: String,
}

fn default_xdp_path() -> String {
    "/opt/aegis/aegis-ebpf".to_string()
}

/// CNI success result (chain plugin returns prevResult or empty)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CniResult {
    pub cni_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interfaces: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<serde_json::Value>,
}

/// CNI error response
#[derive(Debug, Serialize)]
pub struct CniError {
    pub code: u32,
    pub msg: String,
}

/// CNI VERSION response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CniVersion {
    pub cni_version: String,
    pub supported_versions: Vec<String>,
}

// ── Error Helper ────────────────────────────────────────────────────

pub fn cni_error(code: u32, msg: &str) -> String {
    serde_json::to_string(&CniError {
        code,
        msg: msg.to_string(),
    })
    .unwrap_or_else(|_| format!(r#"{{"code":{},"msg":"{}"}}"#, code, msg))
}

// ── XDP Attachment via ip link ──────────────────────────────────────

/// Attach XDP program to an interface inside a network namespace
fn attach_xdp(netns: &str, ifname: &str, xdp_path: &str) -> Result<()> {
    // Use `ip netns exec` or `nsenter` to run inside the pod's netns
    let status = Command::new("nsenter")
        .args([
            &format!("--net={}", netns),
            "--",
            "ip",
            "link",
            "set",
            "dev",
            ifname,
            "xdpgeneric",
            "obj",
            xdp_path,
            "sec",
            "xdp",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!(
            "failed to attach XDP to {}:{} (exit: {:?})",
            netns,
            ifname,
            status.code()
        );
    }

    Ok(())
}

/// Detach XDP program from an interface inside a network namespace
fn detach_xdp(netns: &str, ifname: &str) -> Result<()> {
    let status = Command::new("nsenter")
        .args([
            &format!("--net={}", netns),
            "--",
            "ip",
            "link",
            "set",
            "dev",
            ifname,
            "xdp",
            "off",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!(
            "failed to detach XDP from {}:{} (exit: {:?})",
            netns,
            ifname,
            status.code()
        );
    }

    Ok(())
}

/// Check if XDP is attached to an interface
fn check_xdp(netns: &str, ifname: &str) -> Result<bool> {
    let output = Command::new("nsenter")
        .args([
            &format!("--net={}", netns),
            "--",
            "ip",
            "link",
            "show",
            "dev",
            ifname,
        ])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("xdp"))
}

// ── CNI Command Handlers ────────────────────────────────────────────

/// CNI ADD — attach XDP firewall to pod veth
pub fn handle_add(
    _container_id: &str,
    netns: &str,
    ifname: &str,
    stdin_config: &str,
) -> Result<String> {
    let config: CniConfig = serde_json::from_str(stdin_config)?;

    // Attach XDP to the pod's interface
    attach_xdp(netns, ifname, &config.xdp_program)?;

    // As a chain plugin, return the prevResult from upstream
    if let Some(prev) = config.prev_result {
        Ok(serde_json::to_string(&prev)?)
    } else {
        // No upstream result — return minimal success
        let result = CniResult {
            cni_version: config.cni_version,
            interfaces: None,
            ips: None,
            routes: None,
            dns: None,
        };
        Ok(serde_json::to_string(&result)?)
    }
}

/// CNI DEL — detach XDP firewall from pod veth
pub fn handle_del(
    _container_id: &str,
    netns: &str,
    ifname: &str,
) -> Result<String> {
    // Best-effort detach — don't fail if netns is already gone
    let _ = detach_xdp(netns, ifname);
    Ok(String::new())
}

/// CNI CHECK — verify XDP attachment is healthy
pub fn handle_check(
    _container_id: &str,
    netns: &str,
    ifname: &str,
) -> Result<String> {
    if check_xdp(netns, ifname)? {
        Ok(String::new())
    } else {
        anyhow::bail!("XDP not attached to {} in {}", ifname, netns)
    }
}

/// CNI VERSION — report supported CNI versions
pub fn handle_version() -> Result<String> {
    let version = CniVersion {
        cni_version: "1.0.0".to_string(),
        supported_versions: vec![
            "0.3.0".to_string(),
            "0.3.1".to_string(),
            "0.4.0".to_string(),
            "1.0.0".to_string(),
        ],
    };
    Ok(serde_json::to_string(&version)?)
}
