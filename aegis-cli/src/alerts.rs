//! Alert Webhook Dispatcher for Aegis eBPF Firewall
//!
//! Sends security alerts to external services:
//!   - Slack (incoming webhook)
//!   - PagerDuty (Events API v2)
//!   - Generic HTTP POST (SIEM/ELK/Splunk HEC)
//!
//! Non-blocking: all webhook calls are fire-and-forget tokio tasks.

use crate::config::WebhooksConfig;
use tracing::{info, warn};

/// Severity levels for alert filtering
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::High,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// An alert event to dispatch
#[derive(Debug, Clone)]
pub struct Alert {
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub source_ip: String,
    pub details: String,
}

/// Dispatch an alert to all configured webhooks.
/// Non-blocking — spawns tokio tasks for each webhook.
pub fn dispatch(config: &WebhooksConfig, alert: Alert) {
    if !config.enabled {
        return;
    }

    let min_severity = Severity::from_str(&config.min_severity);
    if alert.severity < min_severity {
        return;
    }

    // Slack
    if !config.slack_url.is_empty() {
        let url = config.slack_url.clone();
        let alert = alert.clone();
        tokio::spawn(async move {
            send_slack(&url, &alert).await;
        });
    }

    // PagerDuty
    if !config.pagerduty_key.is_empty() {
        let key = config.pagerduty_key.clone();
        let alert = alert.clone();
        tokio::spawn(async move {
            send_pagerduty(&key, &alert).await;
        });
    }

    // Generic HTTP POST
    if !config.generic_url.is_empty() {
        let url = config.generic_url.clone();
        let alert = alert.clone();
        tokio::spawn(async move {
            send_generic(&url, &alert).await;
        });
    }
}

// ── Slack ────────────────────────────────────────────────────────────

async fn send_slack(url: &str, alert: &Alert) {
    let emoji = match alert.severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
    };

    let payload = format!(
        r#"{{"text":"{} *Aegis Alert [{}]*\n*{}*\n{}\nSource: `{}`\n{}"}}"#,
        emoji,
        alert.severity.as_str().to_uppercase(),
        alert.title,
        alert.message,
        alert.source_ip,
        alert.details,
    );

    match reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
    {
        Ok(r) => info!(status = %r.status(), "Slack webhook sent"),
        Err(e) => warn!(error = %e, "Slack webhook failed"),
    }
}

// ── PagerDuty Events API v2 ─────────────────────────────────────────

async fn send_pagerduty(routing_key: &str, alert: &Alert) {
    let pd_severity = match alert.severity {
        Severity::Critical => "critical",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "info",
    };

    let payload = serde_json::json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": alert.title,
            "severity": pd_severity,
            "source": "aegis-ebpf",
            "component": "firewall",
            "custom_details": {
                "message": alert.message,
                "source_ip": alert.source_ip,
                "details": alert.details
            }
        }
    })
    .to_string();

    match reqwest::Client::new()
        .post("https://events.pagerduty.com/v2/enqueue")
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
    {
        Ok(r) => info!(status = %r.status(), "PagerDuty event sent"),
        Err(e) => warn!(error = %e, "PagerDuty webhook failed"),
    }
}

// ── Generic HTTP POST (Splunk HEC / ELK / custom SIEM) ──────────────

async fn send_generic(url: &str, alert: &Alert) {
    let payload = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "severity": alert.severity.as_str(),
        "title": alert.title,
        "message": alert.message,
        "source_ip": alert.source_ip,
        "details": alert.details,
        "product": "aegis-ebpf"
    })
    .to_string();

    match reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
    {
        Ok(r) => info!(status = %r.status(), "Generic webhook sent"),
        Err(e) => warn!(error = %e, "Generic webhook failed"),
    }
}
