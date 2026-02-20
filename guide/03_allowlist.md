# Guide 03: IP Allowlist (Whitelist)

> **Priority: HIGH** — No mechanism to exempt trusted IPs from blocking.
> VPN endpoints, monitoring probes, and known-good IPs can get auto-banned.

## Problem

Current auto-ban logic (`aegis-cli/src/main.rs`, ~line 541) bans ANY IP that triggers
SYN flood or port scan detection. There is no way to exempt:
- Your own VPN server
- Monitoring/health-check probes (Nagios, Uptime Robot)
- Load balancer health checks
- Known partner IPs

## Solution

Add an `ALLOWLIST` BPF HashMap checked BEFORE the blocklist in the eBPF program.
IPs in the allowlist are always passed, regardless of other detection.

## Architecture

```
Packet arrives → ALLOWLIST check → if match → XDP_PASS (skip all checks)
                                 → if no match → normal pipeline (blocklist, rate limit, etc.)
```

### Step 1: Add ALLOWLIST map in aegis-common

In `aegis-common/src/lib.rs`, add a constant:
```rust
// Map key for allowlist — same FlowKey structure, src_ip only
// Value: u32 = 1 (ALLOW)
```

### Step 2: Add ALLOWLIST map in aegis-ebpf

In `aegis-ebpf/src/main.rs`:
```rust
#[map]
static ALLOWLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
```

### Step 3: Check allowlist FIRST in packet processing

In `try_xdp_ipv4()`, BEFORE the blocklist check:
```rust
// Allowlist check — always pass trusted IPs
let src_ip_be = u32::from_be_bytes(src_ip);
if unsafe { ALLOWLIST.get(&src_ip_be) }.is_some() {
    stats_inc_ipv4_pass();
    return Ok(xdp_action::XDP_PASS);
}
```

Same for `try_xdp_ipv6()` (use first 4 bytes of src for v6, or add v6 allowlist map).

### Step 4: CLI commands for allowlist management

In `aegis-cli/src/main.rs`, add to the CLI commands:
```rust
/// Allowlist management
#[clap(subcommand)]
Allow(AllowCommands),

#[derive(Subcommand)]
enum AllowCommands {
    /// Add IP to allowlist
    Add { ip: String },
    /// Remove IP from allowlist
    Remove { ip: String },
    /// List all allowlisted IPs
    List,
}
```

### Step 5: Prevent auto-ban of allowlisted IPs

In the auto-ban logic (main.rs ~line 541), add check:
```rust
// Check allowlist before auto-banning
let allow_key = log.src_ip; // already network byte order
if unsafe { allowlist_map.get(&allow_key, 0) }.is_ok() {
    // IP is allowlisted, skip auto-ban
    let mut logs = logs_inner.lock().unwrap();
    logs.push_back(format!("⚪ SKIP auto-ban for allowlisted {}", src_ip));
    continue;  // or skip the ban block
}
```

### Step 6: Config file integration

In `config.toml` (from Guide 02):
```toml
[allowlist]
ips = [
    "10.0.0.0/8",       # Internal network
    "192.168.1.1",       # Gateway
    "203.0.113.50",      # Monitoring probe
]
```

Load at startup and populate the BPF map.

### Step 7: TUI indicator

In the connection list, show allowlisted IPs with a special indicator:
```rust
let style = if c.is_allowlisted {
    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
} else if c.is_blocked {
    Style::default().fg(Color::Red)
// ...
```

## Testing

1. Add your gateway IP to allowlist
2. Trigger port scan from that IP → verify NOT banned
3. Trigger port scan from non-allowlisted IP → verify banned
4. Restart service → verify allowlist persists via config
5. `aegis-cli allow list` → verify IP shown

## Acceptance Criteria

- [ ] Allowlisted IPs bypass ALL detection
- [ ] Auto-ban skips allowlisted IPs
- [ ] CLI: `allow add/remove/list` commands
- [ ] Config file: `[allowlist]` section loaded at startup
- [ ] TUI shows allowlist status

## Files Changed

| File | Action |
|------|--------|
| `aegis-common/src/lib.rs` | **MODIFY** — allowlist constants |
| `aegis-ebpf/src/main.rs` | **MODIFY** — add ALLOWLIST map, check before blocklist |
| `aegis-cli/src/main.rs` | **MODIFY** — CLI commands, auto-ban skip, load from config |
| `aegis-cli/src/tui/mod.rs` | **MODIFY** — show allowlist indicator |
