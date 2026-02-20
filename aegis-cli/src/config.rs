use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::fs::File;
use std::io::BufReader;
use anyhow::{Context, Result, bail};

/// Maximum config file size (1 MB) to prevent YAML bomb attacks
const MAX_CONFIG_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub remote_log: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub proto: String, // "tcp", "udp", "icmp" or numeric
    #[serde(default = "default_action")]
    pub action: String,
}

fn default_action() -> String {
    "drop".to_string()
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("Failed to open config file: {}", path))?;

        // SECURITY: Check file size to prevent YAML bomb attacks
        let metadata = file.metadata().context("Failed to read file metadata")?;
        if metadata.len() > MAX_CONFIG_SIZE {
            bail!(
                "Config file too large ({} bytes, max {} bytes). Possible YAML bomb attack.",
                metadata.len(),
                MAX_CONFIG_SIZE
            );
        }

        let reader = BufReader::new(file);
        let config: Config = serde_yaml::from_reader(reader).context("Failed to parse YAML config")?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let file = File::create(path).with_context(|| format!("Failed to create config file: {}", path))?;
        serde_yaml::to_writer(file, self).context("Failed to write YAML config")?;
        Ok(())
    }
}

pub fn parse_proto(proto: &str) -> u8 {
    match proto.to_lowercase().as_str() {
        "icmp" => 1,
        "tcp" => 6,
        "udp" => 17,
        p => p.parse().unwrap_or(0),
    }
}

pub fn proto_to_str(proto: u8) -> String {
    match proto {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        _ => proto.to_string(),
    }
}

// =============================================================================
// SYSTEM CONFIG (TOML) — /etc/aegis/config.toml
// =============================================================================

const DEFAULT_SYSTEM_CONFIG: &str = "/etc/aegis/config.toml";

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AegisConfig {
    pub interface: String,
    pub modules: ModulesConfig,
    pub autoban: AutoBanConfig,
    pub feeds: FeedsConfig,
    pub logging: LoggingConfig,
    pub allowlist: AllowlistConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct ModulesConfig {
    pub port_scan: bool,
    pub rate_limit: bool,
    pub threat_feeds: bool,
    pub conn_track: bool,
    pub scan_detect: bool,
    pub verbose: bool,
    pub entropy: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AutoBanConfig {
    pub enabled: bool,
    pub max_entries: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct FeedsConfig {
    pub enabled: bool,
    pub max_download_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AllowlistConfig {
    pub ips: Vec<String>,
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".into(),
            modules: ModulesConfig::default(),
            autoban: AutoBanConfig::default(),
            feeds: FeedsConfig::default(),
            logging: LoggingConfig::default(),
            allowlist: AllowlistConfig::default(),
        }
    }
}

impl Default for ModulesConfig {
    fn default() -> Self {
        Self {
            port_scan: true,
            rate_limit: true,
            threat_feeds: true,
            conn_track: true,
            scan_detect: true,
            verbose: false,
            entropy: false,
        }
    }
}

impl Default for AutoBanConfig {
    fn default() -> Self {
        Self { enabled: true, max_entries: 512 }
    }
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self { enabled: true, max_download_bytes: 10 * 1024 * 1024 }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { level: "info".into(), json: false }
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self { ips: Vec::new() }
    }
}

impl AegisConfig {
    pub fn load(path: Option<&str>) -> Self {
        let config_path = path.unwrap_or(DEFAULT_SYSTEM_CONFIG);

        if std::path::Path::new(config_path).exists() {
            match std::fs::read_to_string(config_path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(cfg) => {
                        log::info!("System config loaded: {}", config_path);
                        return cfg;
                    }
                    Err(e) => {
                        log::error!("Config parse error in {}: {} — using defaults", config_path, e);
                    }
                },
                Err(e) => {
                    log::error!("Cannot read {}: {} — using defaults", config_path, e);
                }
            }
        }

        Self::default()
    }

    pub fn save(&self, path: Option<&str>) -> anyhow::Result<()> {
        let config_path = path.unwrap_or(DEFAULT_SYSTEM_CONFIG);
        let content = toml::to_string_pretty(self)?;
        std::fs::write(config_path, content)?;
        Ok(())
    }
}
