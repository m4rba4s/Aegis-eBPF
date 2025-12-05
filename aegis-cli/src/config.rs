use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::fs::File;
use std::io::BufReader;
use anyhow::{Context, Result};

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
