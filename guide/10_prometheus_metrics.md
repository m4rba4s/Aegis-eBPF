# Guide 10: Prometheus Metrics Endpoint

> **Priority: LOW** — Production monitoring standard, but requires infra (Prometheus + Grafana).
> Implement after Guides 01-09 are done.

## Problem

No way to monitor Aegis remotely. Operators need:
- Packets/sec (pass, drop, by protocol)
- Active connections count
- Blocklist size
- Auto-ban rate
- CPU/memory usage of aegis-cli process
- Alert on anomalies (sudden spike in drops)

## Solution

Expose a Prometheus HTTP metrics endpoint at `http://localhost:9100/metrics`.
Scrape with Prometheus → visualize in Grafana.

Port 9100 is the node_exporter default. Use `9190` to avoid conflict:
`http://localhost:9190/metrics`

## Dependencies

```toml
# aegis-cli/Cargo.toml
prometheus = "0.13"
hyper = { version = "1.0", features = ["http1", "server"] }
hyper-util = { version = "0.1", features = ["tokio"] }
```

Alternative (lighter): `prometheus-client = "0.22"` (official Rust client, no hyper needed).

## Step-by-Step Implementation

### Step 1: Define metrics

Create `aegis-cli/src/metrics.rs`:

```rust
use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec,
    CounterVec, Gauge, GaugeVec, Encoder, TextEncoder,
};
use std::sync::LazyLock;

// Packet counters
pub static PACKETS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "aegis_packets_total",
        "Total packets processed by Aegis",
        &["protocol", "action"]  // protocol: ipv4/ipv6, action: pass/drop
    ).unwrap()
});

// Active connections
pub static CONNECTIONS_ACTIVE: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "aegis_connections_active",
        "Number of active tracked connections"
    ).unwrap()
});

// Blocklist size
pub static BLOCKLIST_SIZE: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "aegis_blocklist_entries",
        "Number of IPs in the blocklist"
    ).unwrap()
});

// Auto-ban counter
pub static AUTOBAN_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "aegis_autoban_total",
        "Total auto-ban actions",
        &["reason"]  // syn_flood, port_scan
    ).unwrap()
});

// Module states
pub static MODULE_ENABLED: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        "aegis_module_enabled",
        "Module enabled state (1=on, 0=off)",
        &["module"]
    ).unwrap()
});

// Drops by reason
pub static DROPS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "aegis_drops_total",
        "Dropped packets by reason",
        &["reason"]  // blocklist, cidr, syn_flood, port_scan, entropy, tcp_anomaly
    ).unwrap()
});

pub fn encode_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
```

### Step 2: HTTP server

Create `aegis-cli/src/metrics_server.rs`:

```rust
use hyper::{Request, Response, body::Bytes};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use crate::metrics;

async fn handle_request(req: Request<hyper::body::Incoming>) -> Result<Response<String>, hyper::Error> {
    match req.uri().path() {
        "/metrics" => {
            let body = metrics::encode_metrics();
            Ok(Response::builder()
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(body)
                .unwrap())
        }
        "/health" => {
            Ok(Response::new("ok".to_string()))
        }
        _ => {
            Ok(Response::builder()
                .status(404)
                .body("Not Found".to_string())
                .unwrap())
        }
    }
}

pub async fn start_metrics_server(port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    log::info!("Prometheus metrics server listening on http://{}/metrics", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let service = service_fn(handle_request);
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                log::error!("Metrics server error: {}", err);
            }
        });
    }
}
```

### Step 3: Feed metrics from event loop

In `main.rs`, after processing each packet log:

```rust
// In the event loop where PacketLog is processed:
match log.action {
    0 => { // PASS
        metrics::PACKETS_TOTAL
            .with_label_values(&["ipv4", "pass"])
            .inc();
    }
    1 => { // DROP
        metrics::PACKETS_TOTAL
            .with_label_values(&["ipv4", "drop"])
            .inc();

        // Reason-specific counter
        let reason = match log.reason {
            1 => "blocklist",
            2 => "cidr",
            3 => "syn_flood",
            4 => "port_scan",
            5 => "entropy",
            6 => "tcp_anomaly",
            _ => "other",
        };
        metrics::DROPS_TOTAL
            .with_label_values(&[reason])
            .inc();
    }
    _ => {}
}

// Auto-ban
if auto_banned {
    metrics::AUTOBAN_TOTAL
        .with_label_values(&[ban_reason])
        .inc();
    metrics::BLOCKLIST_SIZE.inc();
}
```

### Step 4: Periodic stats sync

Add a timer task (every 10s) that reads BPF stats maps and updates gauges:

```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;

        // Read blocklist map size
        if let Ok(map) = /* open pinned blocklist */ {
            metrics::BLOCKLIST_SIZE.set(map.keys().count() as f64);
        }

        // Read connection tracking size
        if let Ok(map) = /* open pinned conntrack */ {
            metrics::CONNECTIONS_ACTIVE.set(map.keys().count() as f64);
        }
    }
});
```

### Step 5: Start metrics server in daemon mode

In `main()`:

```rust
Commands::Daemon => {
    // Start metrics server (background task)
    if cfg.metrics.enabled {
        let port = cfg.metrics.port; // default: 9190
        tokio::spawn(async move {
            if let Err(e) = metrics_server::start_metrics_server(port).await {
                log::error!("Metrics server failed: {}", e);
            }
        });
    }

    // ... existing daemon code ...
}
```

### Step 6: Config integration (Guide 02)

```toml
[metrics]
enabled = false          # Enable Prometheus endpoint
port = 9190
bind = "127.0.0.1"       # Bind to localhost only (security)
```

### Step 7: CLI flag

```rust
/// Enable Prometheus metrics endpoint
#[clap(long)]
metrics: bool,

/// Metrics port
#[clap(long, default_value = "9190")]
metrics_port: u16,
```

## Prometheus scrape config

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'aegis'
    static_configs:
      - targets: ['localhost:9190']
    scrape_interval: 10s
```

## Grafana dashboard (bonus)

Export a JSON dashboard to `deploy/grafana-aegis.json` with panels for:
- Packets/sec (pass vs drop)
- Drop reasons pie chart
- Blocklist size over time
- Auto-ban rate
- Active connections

## Expected /metrics output

```
# HELP aegis_packets_total Total packets processed by Aegis
# TYPE aegis_packets_total counter
aegis_packets_total{protocol="ipv4",action="pass"} 1234567
aegis_packets_total{protocol="ipv4",action="drop"} 12345
aegis_packets_total{protocol="ipv6",action="pass"} 56789
aegis_packets_total{protocol="ipv6",action="drop"} 234

# HELP aegis_blocklist_entries Number of IPs in the blocklist
# TYPE aegis_blocklist_entries gauge
aegis_blocklist_entries 42

# HELP aegis_drops_total Dropped packets by reason
# TYPE aegis_drops_total counter
aegis_drops_total{reason="blocklist"} 5000
aegis_drops_total{reason="syn_flood"} 3000
aegis_drops_total{reason="port_scan"} 2000
aegis_drops_total{reason="cidr"} 1000
```

## Testing

```bash
# Start with metrics
sudo aegis-cli -i eth0 --metrics daemon

# Check endpoint
curl http://localhost:9190/metrics

# Health check
curl http://localhost:9190/health

# Verify Prometheus scrapes
# Check Prometheus UI: http://prometheus:9090/targets
```

## Security Note

> [!WARNING]
> - Bind metrics to `127.0.0.1` only (default). Never expose to `0.0.0.0`.
> - Metrics can reveal internal network topology (IP addresses, connection patterns).
> - If exposing externally, put behind reverse proxy with auth.

## Acceptance Criteria

- [ ] `/metrics` returns valid Prometheus text format
- [ ] `/health` returns 200 OK
- [ ] Packet counters increment in real time
- [ ] Blocklist gauge reflects actual map size
- [ ] Configurable via config file and CLI flag
- [ ] Bound to localhost only by default

## Files Changed

| File | Action |
|------|--------|
| `aegis-cli/src/metrics.rs` | **NEW** — metric definitions |
| `aegis-cli/src/metrics_server.rs` | **NEW** — HTTP endpoint |
| `aegis-cli/src/main.rs` | **MODIFY** — feed metrics, start server |
| `aegis-cli/Cargo.toml` | **MODIFY** — add prometheus, hyper deps |
| `deploy/grafana-aegis.json` | **NEW** (bonus) — Grafana dashboard |
