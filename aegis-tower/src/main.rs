use clap::Parser;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

pub mod fleet {
    tonic::include_proto!("aegis.fleet");
}

use fleet::fleet_control_server::{FleetControl, FleetControlServer};
use fleet::{Ack, BlockRule, EventMsg, EventSeverity, NodeInfo};

/// Aegis Tower: gRPC Central Fleet Controller
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Bind address (default: 0.0.0.0:50051)
    #[arg(short, long, default_value = "0.0.0.0:50051")]
    bind: String,

    /// Static Bearer token for Agent auth. Required via --token or AEGIS_TOWER_TOKEN.
    #[arg(short, long, env = "AEGIS_TOWER_TOKEN")]
    token: String,
}

#[derive(Clone)]
struct TowerState {
    // Channel for broadcasting BlockRules to all connected Agents
    tx: broadcast::Sender<BlockRule>,
    // Connected nodes catalog (in-memory)
    nodes: Arc<Mutex<HashMap<String, NodeInfo>>>,
    // Global lock for token auth
    auth_token: String,
}

impl TowerState {
    fn new(auth_token: String) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            tx,
            nodes: Arc::new(Mutex::new(HashMap::new())),
            auth_token,
        }
    }

    fn check_auth<T>(&self, req: &Request<T>) -> bool {
        let Some(token) = req
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
        else {
            warn!("Unauthorized gRPC connection attempt");
            return false;
        };

        let expected = format!("Bearer {}", self.auth_token);
        if token == expected {
            true
        } else {
            warn!("Unauthorized gRPC connection attempt");
            false
        }
    }
}

#[tonic::async_trait]
impl FleetControl for TowerState {
    type SubscribeBlocklistStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<BlockRule, Status>> + Send + 'static>,
    >;

    async fn subscribe_blocklist(
        &self,
        request: Request<NodeInfo>,
    ) -> Result<Response<Self::SubscribeBlocklistStream>, Status> {
        if !self.check_auth(&request) {
            return Err(Status::unauthenticated("Invalid or missing Bearer token"));
        }

        let node_info = request.into_inner();
        let client_id = node_info.node_id.clone();
        info!(
            node_id = %client_id,
            hostname = %node_info.hostname,
            "Agent connected to Fleet stream"
        );

        // Register node
        {
            let mut nodes = self.nodes.lock().unwrap();
            nodes.insert(client_id.clone(), node_info);
        }

        let rx = self.tx.subscribe();

        // Wrap broadcast receiver in a tokio Stream
        let output_stream = BroadcastStream::new(rx).filter_map(move |res| match res {
            Ok(rule) => Some(Ok(rule)),
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                warn!(node_id = %client_id, lagged = n, "Agent is lagging behind stream");
                None
            }
        });

        Ok(Response::new(
            Box::pin(output_stream) as Self::SubscribeBlocklistStream
        ))
    }

    async fn report_event(&self, request: Request<EventMsg>) -> Result<Response<Ack>, Status> {
        if !self.check_auth(&request) {
            return Err(Status::unauthenticated("Invalid or missing Bearer token"));
        }

        let event = request.into_inner();

        info!(
            node_id = %event.node_id,
            type_ = %event.event_type,
            src = %event.src_ip,
            severity = ?EventSeverity::from_i32(event.severity).unwrap_or(EventSeverity::Info),
            "Received Agent Event: {}", event.message
        );

        // --- CENTRAL THREAT INTELLIGENCE LOGIC ---
        // If the event is Critical (e.g., DPI threat >= 80% or confirmed JA3 hit),
        // we instantly broadcast the attacker's IP to the entire fleet!
        if event.severity == EventSeverity::Critical as i32 {
            let rule = BlockRule {
                ip: event.src_ip.clone(),
                duration_secs: 0, // Permanent fleet block
                reason: format!(
                    "Tower Auto-Ban (Detected by {}, type: {})",
                    event.node_id, event.event_type
                ),
                source_node: event.node_id.clone(),
            };

            info!(
                ip = %rule.ip,
                reason = %rule.reason,
                "🚨 Critical Event -> Broadcasting BlockRule to Fleet!"
            );

            // Send to all connected agents.
            if let Err(e) = self.tx.send(rule) {
                warn!("Fleet broadcast failed (no connected agents?): {}", e);
            }
        }

        Ok(Response::new(Ack { success: true }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let token = args.token.trim();
    if token.is_empty() || token == "secret-tower-token-auth" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AEGIS_TOWER_TOKEN/--token must be set to a non-default secret",
        )
        .into());
    }

    let addr = args.bind.parse()?;
    info!(
        "🏰 Starting Aegis Tower (gRPC Fleet Controller) on {}",
        addr
    );
    info!("Auth token configuration loaded.");

    let state = TowerState::new(token.to_string());

    Server::builder()
        .add_service(FleetControlServer::new(state))
        .serve(addr)
        .await?;

    Ok(())
}
