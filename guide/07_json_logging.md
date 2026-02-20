# Guide 07: Structured JSON Logging

> **Priority: MEDIUM** — Plain-text logs are unparseable by SIEM/ELK/Loki/Splunk.
> Production environments require structured output.

## Problem

Current logging in `aegis-cli` uses:
- `log::info!()` / `log::warn!()` → `env_logger` → plain text to stderr
- TUI log panel → `VecDeque<String>` → unstructured strings

Example current output:
```
[2025-02-19T10:30:00Z INFO  aegis_cli] XDP attached to eth0 (driver mode)
[2025-02-19T10:30:01Z WARN  aegis_cli] SYN flood from 1.2.3.4 — auto-banned
```

This cannot be parsed reliably. Timestamp formats vary, no fields.

## Solution

Add JSON logging mode (toggle via config or `--log-json` flag).
Use `tracing` + `tracing-subscriber` with JSON formatter.

### Why tracing over env_logger?

- Structured fields (IP, action, module, reason)
- JSON and text formatters built-in
- Zero-cost when disabled
- Industry standard for Rust async apps

## Dependencies

Replace or supplement `env_logger`:
```toml
# aegis-cli/Cargo.toml — ADD
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }

# KEEP: log = "0.4" (aya and other deps use it)
# ADD bridge:
tracing-log = "0.2"  # bridges `log` crate → tracing
```

## Step-by-Step Implementation

### Step 1: Initialize tracing subscriber

In `main()`, replace `env_logger::init()` with:

```rust
use tracing_subscriber::{fmt, EnvFilter, prelude::*};

fn init_logging(json: bool, level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_target(true))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true))
            .init();
    }

    // Bridge log crate → tracing (for aya etc.)
    tracing_log::LogTracer::init().ok();
}
```

### Step 2: Structured events for security actions

Replace `log::warn!("SYN flood from {} — auto-banned", ip)` with:

```rust
use tracing::{info, warn, error, instrument};

// Auto-ban
warn!(
    target: "aegis::security",
    event = "auto_ban",
    src_ip = %src_ip,
    reason = "syn_flood",
    module = "rate_limit",
    action = "blocked",
    "SYN flood detected — IP auto-banned"
);

// Packet drop
info!(
    target: "aegis::packet",
    event = "drop",
    src_ip = %src_ip,
    dst_port = dst_port,
    reason = "blocklist",
    "Packet dropped"
);

// Module toggle
info!(
    target: "aegis::config",
    event = "module_toggle",
    module = name,
    enabled = enabled,
    "Module toggled"
);
```

### Step 3: JSON output format

When `--log-json` or `config.logging.json = true`:

```json
{
  "timestamp": "2025-02-19T10:30:01.123Z",
  "level": "WARN",
  "target": "aegis::security",
  "fields": {
    "event": "auto_ban",
    "src_ip": "1.2.3.4",
    "reason": "syn_flood",
    "module": "rate_limit",
    "action": "blocked",
    "message": "SYN flood detected — IP auto-banned"
  }
}
```

### Step 4: File output (optional)

If `config.logging.file` is set:

```rust
use tracing_subscriber::fmt::writer::MakeWriterExt;
use std::fs::OpenOptions;

let file = OpenOptions::new()
    .create(true)
    .append(true)
    .open(log_path)?;

// Use file writer instead of stdout
fmt::layer().with_writer(file)
```

### Step 5: CLI flag

```rust
#[derive(Parser)]
struct Opt {
    /// Output logs as JSON (for SIEM/ELK integration)
    #[clap(long)]
    log_json: bool,

    /// Log level: debug, info, warn, error
    #[clap(long, default_value = "info")]
    log_level: String,
}
```

### Step 6: Migrate log calls

Find and replace all `log::info!`, `log::warn!`, `log::error!` calls
in `aegis-cli/src/main.rs` and `aegis-cli/src/tui/mod.rs` with
structured `tracing::` equivalents.

Key locations:
- `main.rs` line ~190: XDP attach
- `main.rs` line ~540: auto-ban
- `main.rs` line ~410: config init
- `tui/mod.rs` line ~170: geo lookup

## Testing

```bash
# Text mode (default)
sudo aegis-cli -i eth0 daemon
# Output: [2025-02-19T10:30:00Z INFO aegis_cli] ...

# JSON mode
sudo aegis-cli -i eth0 --log-json daemon 2>&1 | jq .
# Output: {"timestamp":"...","level":"INFO","fields":{...}}

# Parse with jq
sudo aegis-cli -i eth0 --log-json daemon 2>&1 | \
  jq 'select(.fields.event == "auto_ban")'
```

## Acceptance Criteria

- [ ] `--log-json` produces valid JSON lines
- [ ] Security events have structured fields: event, src_ip, reason, action
- [ ] Default text output unchanged (no regression)
- [ ] `log` crate calls (from aya) bridged to tracing
- [ ] Config file `logging.json = true` works

## Files Changed

| File | Action |
|------|--------|
| `aegis-cli/Cargo.toml` | **MODIFY** — add tracing deps |
| `aegis-cli/src/main.rs` | **MODIFY** — replace env_logger, migrate log calls |
| `aegis-cli/src/tui/mod.rs` | **MODIFY** — migrate log calls |
