# Guide 02: Configuration File (/etc/aegis/config.toml)

> **Priority: HIGH** — All settings are CLI-only. No persistence, no reproducibility.

## Problem

Current state: every setting is a CLI flag or compile-time constant.
- Rate limit thresholds: hardcoded in eBPF
- Module toggles: set at runtime, lost on restart
- Feed URLs: hardcoded in `feeds/mod.rs`
- Auto-ban limit: hardcoded constant (512)
- Interface: CLI flag only

Production users need a config file that persists across restarts.

## Solution

TOML config file at `/etc/aegis/config.toml`, parsed at startup, with CLI flags as overrides.

## Dependencies

Already have `serde` and `serde_yaml`. Add:
```toml
# aegis-cli/Cargo.toml
toml = "0.8"
```

## Step-by-Step Implementation

### Step 1: Define config structure

Create `aegis-cli/src/config.rs`:

```rust
use serde::Deserialize;
use std::path::Path;

const DEFAULT_CONFIG_PATH: &str = "/etc/aegis/config.toml";

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct AegisConfig {
    pub interface: String,
    pub mode: RunMode,
    pub modules: ModuleConfig,
    pub autoban: AutoBanConfig,
    pub feeds: FeedConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub enum RunMode {
    #[serde(rename = "tui")]
    Tui,
    #[serde(rename = "daemon")]
    Daemon,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct ModuleConfig {
    pub port_scan: bool,
    pub rate_limit: bool,
    pub threat_feeds: bool,
    pub conn_track: bool,
    pub scan_detect: bool,
    pub verbose: bool,
    pub entropy: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct AutoBanConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub ttl_seconds: u64,       // 0 = permanent
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct FeedConfig {
    pub enabled: bool,
    pub urls: Vec<String>,
    pub max_download_bytes: u64,
    pub refresh_interval_hours: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,             // Guide 07
    pub file: Option<String>,
}

// Defaults
impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".into(),
            mode: RunMode::Tui,
            modules: ModuleConfig::default(),
            autoban: AutoBanConfig::default(),
            feeds: FeedConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            port_scan: true,
            rate_limit: true,
            threat_feeds: true,
            conn_track: true,
            scan_detect: true,
            verbose: false,
            entropy: false,  // Off by default — breaks TLS/SSH
        }
    }
}

impl Default for AutoBanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 512,
            ttl_seconds: 0,
        }
    }
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            urls: vec![
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt".into(),
            ],
            max_download_bytes: 10 * 1024 * 1024,
            refresh_interval_hours: 24,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
            file: None,
        }
    }
}

impl AegisConfig {
    /// Load config: file → defaults, CLI flags override
    pub fn load(path: Option<&str>) -> Self {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);

        if Path::new(config_path).exists() {
            match std::fs::read_to_string(config_path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(config) => {
                        log::info!("Config loaded: {}", config_path);
                        return config;
                    }
                    Err(e) => {
                        log::error!("Config parse error: {} — using defaults", e);
                    }
                },
                Err(e) => {
                    log::error!("Config read error: {} — using defaults", e);
                }
            }
        }

        Self::default()
    }
}
```

### Step 2: Create default config file

Add to `install.sh` in the install section:

```bash
install_default_config() {
    local config_dir="/etc/aegis"
    local config_file="$config_dir/config.toml"

    mkdir -p "$config_dir"

    if [[ ! -f "$config_file" ]]; then
        cat > "$config_file" << 'CONFIGEOF'
# Aegis eBPF Firewall Configuration
# Docs: https://github.com/m4rba4s/Aegis-Portable-Demo

# Network interface to protect
interface = "eth0"

# Run mode: "tui" or "daemon"
mode = "daemon"

[modules]
port_scan = true
rate_limit = true
threat_feeds = true
conn_track = true
scan_detect = true
verbose = false
entropy = false          # WARNING: blocks TLS/SSH when enabled

[autoban]
enabled = true
max_entries = 512
ttl_seconds = 0          # 0 = permanent, 3600 = 1 hour

[feeds]
enabled = true
max_download_bytes = 10485760  # 10 MB
refresh_interval_hours = 24
urls = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
]

[logging]
level = "info"           # debug, info, warn, error
json = false             # true for SIEM integration
# file = "/var/log/aegis/aegis.log"
CONFIGEOF
        log_ok "Default config created: $config_file"
    else
        log_ok "Config exists: $config_file"
    fi
}
```

### Step 3: Integrate into main.rs

In `main()`, after CLI parsing:

```rust
mod config;
use config::AegisConfig;

// In main():
let cfg = AegisConfig::load(opt.config.as_deref());

// CLI flags override config file
let iface = if opt.iface != "eth0" { &opt.iface } else { &cfg.interface };
```

### Step 4: Add --config CLI flag

In the `Opt` struct (clap):
```rust
/// Path to config file
#[clap(long, default_value = "/etc/aegis/config.toml")]
config: String,
```

### Step 5: Wire module toggles from config

Replace the hardcoded config map init (lines ~404-412) to use `cfg.modules.*`:

```rust
config.insert(CFG_PORT_SCAN, cfg.modules.port_scan as u32, 0)?;
config.insert(CFG_RATE_LIMIT, cfg.modules.rate_limit as u32, 0)?;
// ... etc
```

## Testing

1. Create `/etc/aegis/config.toml` with custom settings
2. Run `sudo aegis-cli -i eth0 tui` — verify config is loaded
3. Run with `--config /tmp/test.toml` — verify override works
4. Delete config file — verify defaults are used
5. Write invalid TOML — verify error message, graceful fallback

## Acceptance Criteria

- [ ] Config file parsed at startup
- [ ] CLI flags override config values
- [ ] Missing config file → defaults (no crash)
- [ ] Invalid TOML → error log + defaults
- [ ] `install.sh` creates default config
- [ ] All current hardcoded values are configurable

## Files Changed

| File | Action |
|------|--------|
| `aegis-cli/src/config.rs` | **NEW** |
| `aegis-cli/src/main.rs` | **MODIFY** — load config, wire to modules |
| `aegis-cli/Cargo.toml` | **MODIFY** — add `toml = "0.8"` |
| `install.sh` | **MODIFY** — add default config creation |
