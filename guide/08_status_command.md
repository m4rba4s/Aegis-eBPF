# Guide 08: Status Command (aegis-cli status)

> **Priority: MEDIUM** — Operators need a quick check: "is Aegis running? how many rules loaded?"

## Problem

No way to query runtime state without entering TUI.
Operators need:
- Is eBPF loaded?
- Which interface?
- How many blocklist entries?
- Packets processed / dropped?
- Uptime?

## Solution

Add `aegis-cli status` subcommand that reads BPF maps and prints a summary.

## Step-by-Step Implementation

### Step 1: Add Status subcommand

In `aegis-cli/src/main.rs`, add to `Commands` enum:

```rust
#[derive(Subcommand)]
enum Commands {
    Tui,
    Daemon,
    Load,
    Completions { shell: Shell },
    /// Show firewall status
    Status,
}
```

### Step 2: Implement status handler

Create `aegis-cli/src/status.rs`:

```rust
use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use std::net::Ipv4Addr;

pub fn show_status() -> anyhow::Result<()> {
    // Check if BPF programs are loaded
    let bpf_dir = std::path::Path::new("/sys/fs/bpf/aegis");

    if !bpf_dir.exists() {
        println!("⚫ Aegis is NOT running (no pinned BPF maps found)");
        return Ok(());
    }

    println!("🟢 Aegis is RUNNING");
    println!();

    // Read pinned maps
    // Stats map
    let stats_path = bpf_dir.join("STATS");
    if stats_path.exists() {
        println!("📊 Statistics:");
        // Try to open and read stats map
        // Keys: 0=ipv4_pass, 1=ipv4_drop, 2=ipv6_pass, 3=ipv6_drop, etc.
        match aya::maps::HashMap::<_, u32, u64>::try_from(
            aya::maps::MapData::from_pin(&stats_path)?
        ) {
            Ok(map) => {
                let ipv4_pass = map.get(&0, 0).unwrap_or(0);
                let ipv4_drop = map.get(&1, 0).unwrap_or(0);
                let ipv6_pass = map.get(&2, 0).unwrap_or(0);
                let ipv6_drop = map.get(&3, 0).unwrap_or(0);

                let total = ipv4_pass + ipv4_drop + ipv6_pass + ipv6_drop;
                let dropped = ipv4_drop + ipv6_drop;
                let drop_pct = if total > 0 {
                    (dropped as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                println!("  Packets processed: {}", total);
                println!("  Packets dropped:   {} ({:.1}%)", dropped, drop_pct);
                println!("  IPv4: {} pass / {} drop", ipv4_pass, ipv4_drop);
                println!("  IPv6: {} pass / {} drop", ipv6_pass, ipv6_drop);
            }
            Err(e) => println!("  (could not read stats: {})", e),
        }
    }

    // Blocklist
    let blocklist_path = bpf_dir.join("BLOCKLIST");
    if blocklist_path.exists() {
        match aya::maps::HashMap::<_, u32, u32>::try_from(
            aya::maps::MapData::from_pin(&blocklist_path)?
        ) {
            Ok(map) => {
                let count = map.keys().count();
                println!("\n🚫 Blocklist: {} entries", count);
            }
            Err(e) => println!("\n🚫 Blocklist: (error: {})", e),
        }
    }

    // CIDR blocklist
    let cidr_path = bpf_dir.join("CIDR_BLOCKLIST");
    if cidr_path.exists() {
        println!("📋 CIDR feeds: loaded");
    }

    // Config map — read module states
    let config_path = bpf_dir.join("CONFIG");
    if config_path.exists() {
        match aya::maps::HashMap::<_, u32, u32>::try_from(
            aya::maps::MapData::from_pin(&config_path)?
        ) {
            Ok(map) => {
                println!("\n⚙️  Modules:");
                let modules = [
                    (1, "Port Scan"),
                    (2, "Rate Limit"),
                    (3, "Threat Feeds"),
                    (4, "Conn Track"),
                    (5, "Scan Detect"),
                    (6, "Verbose"),
                    (7, "Entropy"),
                ];
                for (key, name) in modules {
                    let val = map.get(&key, 0).unwrap_or(0);
                    let icon = if val == 1 { "🟢" } else { "⚫" };
                    println!("  {} {}", icon, name);
                }
            }
            Err(e) => println!("\n⚙️  Modules: (error: {})", e),
        }
    }

    // Kernel info
    println!("\n🖥️  System:");
    if let Ok(output) = std::process::Command::new("uname").arg("-r").output() {
        println!("  Kernel: {}", String::from_utf8_lossy(&output.stdout).trim());
    }

    // Service status
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["is-active", "aegis@*"])
        .output()
    {
        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("  Service: {}", if status == "active" { "running" } else { &status });
    }

    Ok(())
}
```

### Step 3: Wire into main.rs

```rust
mod status;

// In command match:
Commands::Status => {
    status::show_status()?;
    return Ok(());
}
```

### Step 4: Register mod

```rust
mod status;
```

## Expected Output

```
$ sudo aegis-cli status
🟢 Aegis is RUNNING

📊 Statistics:
  Packets processed: 1,234,567
  Packets dropped:   12,345 (1.0%)
  IPv4: 1,100,000 pass / 10,000 drop
  IPv6: 134,567 pass / 2,345 drop

🚫 Blocklist: 42 entries
📋 CIDR feeds: loaded

⚙️  Modules:
  🟢 Port Scan
  🟢 Rate Limit
  🟢 Threat Feeds
  🟢 Conn Track
  🟢 Scan Detect
  ⚫ Verbose
  ⚫ Entropy

🖥️  System:
  Kernel: 6.7.4-200.fc39.x86_64
  Service: running
```

## Testing

1. Start Aegis: `sudo aegis-cli -i eth0 daemon &`
2. Run `sudo aegis-cli status` → verify output
3. Stop Aegis → run `sudo aegis-cli status` → "NOT running"
4. Generate traffic → verify counters increment

## Acceptance Criteria

- [ ] Shows running/not-running state
- [ ] Displays packet counters
- [ ] Shows blocklist entry count
- [ ] Shows module on/off states
- [ ] Works without entering TUI
- [ ] Requires root (reads BPF maps)

## Files Changed

| File | Action |
|------|--------|
| `aegis-cli/src/status.rs` | **NEW** |
| `aegis-cli/src/main.rs` | **MODIFY** — add Status command + handler |
