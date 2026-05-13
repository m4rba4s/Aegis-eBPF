use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;

/// Maximum config file size (1 MB) to prevent YAML bomb attacks
const MAX_CONFIG_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub remote_log: Option<String>,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub proto: String, // "tcp", "udp", "icmp" or numeric
    #[serde(default)]
    pub advanced: AdvancedConfig,
    #[serde(default)]
    pub webhooks: WebhooksConfig,
    #[serde(default = "default_action")]
    pub action: String,
}

fn default_action() -> String {
    "drop".to_string()
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("Failed to open config file: {}", path))?;

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
        let config: Config =
            serde_yaml::from_reader(reader).context("Failed to parse YAML config")?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create config file: {}", path))?;
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
    pub webhooks: WebhooksConfig,
    pub dpi: DpiModuleConfig,
    pub fleet: FleetControllerConfig,
    pub pcap: PcapConfig,
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
    /// Syslog destination for CEF export (e.g. "10.0.0.5:514")
    pub syslog_dest: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[derive(Default)]
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
            webhooks: WebhooksConfig::default(),
            dpi: DpiModuleConfig::default(),
            fleet: FleetControllerConfig::default(),
            pcap: PcapConfig::default(),
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
        Self {
            enabled: true,
            max_entries: 512,
        }
    }
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_download_bytes: 10 * 1024 * 1024,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
            syslog_dest: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct PcapConfig {
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct WebhooksConfig {
    pub enabled: bool,
    pub slack_url: String,
    pub pagerduty_key: String,
    pub generic_url: String,
    /// Minimum severity to trigger alert: "low", "medium", "high", "critical"
    pub min_severity: String,
}

impl Default for WebhooksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            slack_url: String::new(),
            pagerduty_key: String::new(),
            generic_url: String::new(),
            min_severity: "high".into(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct DpiModuleConfig {
    pub enabled: bool,
    pub auto_block_threshold: u8,
    #[serde(default = "default_yara_rules_path")]
    pub rules_path: String,
}

fn default_yara_rules_path() -> String {
    "/etc/aegis/rules".to_string()
}

impl Default for DpiModuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_block_threshold: 80,
            rules_path: default_yara_rules_path(),
        }
    }
}

impl AegisConfig {
    pub fn load(path: Option<&str>) -> Self {
        let config_path = path.unwrap_or(DEFAULT_SYSTEM_CONFIG);

        if std::path::Path::new(config_path).exists() {
            // SECURITY: Check file size to prevent TOML bomb attacks
            if let Ok(metadata) = std::fs::metadata(config_path) {
                if metadata.len() > MAX_CONFIG_SIZE {
                    log::error!(
                        "Config file too large ({} bytes, max {}). Possible attack — using defaults",
                        metadata.len(), MAX_CONFIG_SIZE
                    );
                    return Self::default();
                }
            }

            match std::fs::read_to_string(config_path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(cfg) => {
                        log::info!("System config loaded: {}", config_path);
                        return cfg;
                    }
                    Err(e) => {
                        log::error!(
                            "Config parse error in {}: {} — using defaults",
                            config_path,
                            e
                        );
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

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct AdvancedConfig {
    pub allow_all: bool,
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct FleetControllerConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub token: String,
}

impl Default for FleetControllerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:50051".to_string(),
            token: "secret-tower-token-auth".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proto() {
        assert_eq!(parse_proto("tcp"), 6);
        assert_eq!(parse_proto("udp"), 17);
        assert_eq!(parse_proto(""), 0);
        assert_eq!(parse_proto("TCP"), 6);
    }

    #[test]
    fn test_proto_to_str() {
        assert_eq!(proto_to_str(6), "tcp");
        assert_eq!(proto_to_str(17), "udp");
        assert_eq!(proto_to_str(0), "0");
    }

    fn write_temp_file(content: &[u8], name: &str) -> String {
        let path = std::env::temp_dir().join(format!("{}_{}", name, std::process::id()));
        let path_str = path.to_str().unwrap().to_string();
        std::fs::write(&path_str, content).unwrap();
        path_str
    }

    #[test]
    fn test_config_load_valid_yaml() {
        let yaml = r#"
rules:
  - ip: 192.168.1.1
    port: 80
    proto: tcp
    action: drop
remote_log: "http://10.0.0.1:8080"
blocked_countries: ["RU", "CN"]
"#;
        let path = write_temp_file(yaml.as_bytes(), "test_valid_yaml.yaml");
        let config = Config::load(&path).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(
            config.rules[0].ip,
            "192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(config.remote_log.unwrap(), "http://10.0.0.1:8080");
        assert_eq!(config.blocked_countries.len(), 2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_config_load_invalid_yaml() {
        let yaml = r#"
rules:
  - ip: "not an ip"
"#;
        let path = write_temp_file(yaml.as_bytes(), "test_invalid_yaml.yaml");
        let res = Config::load(&path);
        assert!(res.is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_aegis_config_valid_toml() {
        let toml = r#"
interface = "eth1"

[modules]
port_scan = false

[logging]
level = "debug"
"#;
        let path = write_temp_file(toml.as_bytes(), "test_valid_toml.toml");
        let config = AegisConfig::load(Some(&path));
        assert_eq!(config.interface, "eth1");
        assert_eq!(config.modules.port_scan, false);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.modules.rate_limit, true); // default
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_aegis_config_missing_file() {
        let config = AegisConfig::load(Some("/tmp/definitely_does_not_exist_config.toml"));
        assert_eq!(config.interface, "eth0"); // default
    }

    #[test]
    fn test_config_size_limit() {
        let large_content = vec![b' '; (MAX_CONFIG_SIZE + 10) as usize];
        let path = write_temp_file(&large_content, "test_large.yaml");

        let res = Config::load(&path);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("too large"));

        let aegis_res = AegisConfig::load(Some(&path));
        // AegisConfig::load returns default on error
        assert_eq!(aegis_res.interface, "eth0");

        std::fs::remove_file(path).unwrap();
    }
}
