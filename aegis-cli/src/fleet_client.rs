use crate::config::AegisConfig;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::Request;
use tracing::{error, info, warn};

pub mod fleet {
    tonic::include_proto!("aegis.fleet");
}

use fleet::fleet_control_client::FleetControlClient;
use fleet::{EventMsg, NodeInfo};

#[allow(dead_code)] // Fields used via FleetHandle indirection
pub struct FleetClient {
    config: AegisConfig,
    event_tx: mpsc::Sender<EventMsg>,
}

pub struct FleetHandle {
    pub event_tx: mpsc::Sender<EventMsg>,
}

impl FleetClient {
    pub fn spawn(config: AegisConfig) -> Option<FleetHandle> {
        if !config.fleet.enabled {
            return None;
        }

        // W-5: Security validation of fleet defaults
        if config.fleet.token == "secret-tower-token-auth" {
            error!("FleetClient: Refusing to start with default hardcoded token! Update fleet.token in config.");
            return None;
        }
        if !config.fleet.endpoint.starts_with("https://") && !config.fleet.endpoint.contains("localhost") && !config.fleet.endpoint.contains("127.0.0.1") {
            warn!("FleetClient: Using plaintext gRPC for remote endpoint! TLS is highly recommended.");
        }

        let (tx, rx) = mpsc::channel(100);
        let client = Self {
            config,
            event_tx: tx.clone(),
        };

        // Spawn background task to manage connection
        tokio::spawn(async move {
            client.run_loop(rx).await;
        });

        Some(FleetHandle { event_tx: tx })
    }

    async fn run_loop(self, mut event_rx: mpsc::Receiver<EventMsg>) {
        info!(
            "FleetClient: Connecting to Tower at {}",
            self.config.fleet.endpoint
        );

        loop {
            match FleetControlClient::connect(self.config.fleet.endpoint.clone()).await {
                Ok(mut client) => {
                    info!("FleetClient: Connected to Tower.");

                    let token = format!("Bearer {}", self.config.fleet.token);

                    // Create NodeInfo
                    let hostname =
                        sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
                    let node_info = NodeInfo {
                        node_id: hostname.clone(),
                        hostname,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    };

                    let mut req = Request::new(node_info);
                    let Ok(auth_val) = token.parse() else {
                        error!("FleetClient: invalid auth token (non-ASCII?)");
                        break;
                    };
                    req.metadata_mut().insert("authorization", auth_val);

                    // Start streaming
                    match client.subscribe_blocklist(req).await {
                        Ok(response) => {
                            let mut stream = response.into_inner();
                            info!("FleetClient: Subscribed to Global Blocklist Stream.");

                            loop {
                                tokio::select! {
                                    // 1. Process incoming Global BlockRules from Tower
                                    msg = stream.next() => {
                                        match msg {
                                            Some(Ok(rule)) => {
                                                self.handle_block_rule(&rule);
                                            }
                                            Some(Err(e)) => {
                                                error!("FleetClient: Stream error: {}", e);
                                                break;
                                            }
                                            None => {
                                                warn!("FleetClient: Stream closed by Server.");
                                                break;
                                            }
                                        }
                                    }
                                    // 2. Process outgoing Events to send to Tower
                                    out_event = event_rx.recv() => {
                                        if let Some(event) = out_event {
                                            let mut req = Request::new(event);
                                            if let Ok(auth_val) = token.parse() {
                                                req.metadata_mut().insert("authorization", auth_val);
                                            }
                                            if let Err(e) = client.report_event(req).await {
                                                error!("FleetClient: Failed to report event to Tower: {}", e);
                                            }
                                        } else {
                                            return; // Rx dropped, exit entirely
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("FleetClient: Subscribe failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("FleetClient: Connection error: {}. Retrying in 5s...", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    fn handle_block_rule(&self, rule: &fleet::BlockRule) {
        info!(
            ip = %rule.ip,
            reason = %rule.reason,
            src_node = %rule.source_node,
            "Received Global BlockRule from Fleet Tower"
        );

        if let Ok(ip) = rule.ip.parse::<std::net::Ipv4Addr>() {
            // Convert to Network Byte Order for BPF map consistency
            let ip_nbo = u32::from(ip).to_be();

            // Write to local eBPF Map
            if crate::dpi::auto_block_ip(ip_nbo) {
                crate::alerts::dispatch(
                    &self.config.webhooks,
                    crate::alerts::Alert {
                        severity: crate::alerts::Severity::High,
                        title: "Fleet Block".to_string(),
                        message: format!("Tower blocked {}", ip),
                        source_ip: ip.to_string(),
                        details: rule.reason.clone(),
                    },
                );
            } else {
                error!("FleetClient: Failed to inject BPF block rule for {}", ip);
            }
        } else {
            warn!("FleetClient: Invalid IP from Tower: {}", rule.ip);
        }
    }
}
