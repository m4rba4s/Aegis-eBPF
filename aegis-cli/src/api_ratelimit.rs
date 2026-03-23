//! API Rate Limiter Middleware for Aegis REST Server
//!
//! Protects the :9100 API from brute-force and abuse.
//! Token bucket per client IP with configurable limits.
//!
//! - Default: 60 requests/minute per IP
//! - Block IPs that exceed limit for 5 minutes

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Max requests per minute per IP
const DEFAULT_RATE: u32 = 60;

/// Block duration after exceeding rate
const BLOCK_DURATION: Duration = Duration::from_secs(300);

/// Bucket refill interval
const REFILL_INTERVAL: Duration = Duration::from_secs(60);

/// Global rate limiter state
static LIMITER: std::sync::LazyLock<RwLock<RateLimiter>> =
    std::sync::LazyLock::new(|| RwLock::new(RateLimiter::new()));

struct ClientBucket {
    tokens: u32,
    last_refill: Instant,
    blocked_until: Option<Instant>,
}

struct RateLimiter {
    buckets: HashMap<IpAddr, ClientBucket>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            buckets: HashMap::with_capacity(256),
        }
    }
}

/// Check if a request from the given IP is allowed.
/// Returns `true` if allowed, `false` if rate-limited.
pub fn check_rate_limit(ip: IpAddr) -> bool {
    let mut limiter = match LIMITER.write() {
        Ok(l) => l,
        Err(_) => return true, // poisoned lock — don't block
    };

    let now = Instant::now();

    // Evict old entries periodically (every 1000 entries)
    if limiter.buckets.len() > 1000 {
        limiter.buckets.retain(|_, bucket| {
            match bucket.blocked_until {
                Some(until) if until < now => false,
                _ => now.duration_since(bucket.last_refill) < Duration::from_secs(600),
            }
        });
    }

    let bucket = limiter.buckets.entry(ip).or_insert(ClientBucket {
        tokens: DEFAULT_RATE,
        last_refill: now,
        blocked_until: None,
    });

    // Check if currently blocked
    if let Some(until) = bucket.blocked_until {
        if now < until {
            return false;
        }
        // Unblock
        bucket.blocked_until = None;
        bucket.tokens = DEFAULT_RATE;
        bucket.last_refill = now;
    }

    // Refill tokens
    if now.duration_since(bucket.last_refill) >= REFILL_INTERVAL {
        bucket.tokens = DEFAULT_RATE;
        bucket.last_refill = now;
    }

    // Consume token
    if bucket.tokens > 0 {
        bucket.tokens -= 1;
        true
    } else {
        // Rate exceeded — block
        bucket.blocked_until = Some(now + BLOCK_DURATION);
        tracing::warn!(
            client_ip = %ip,
            block_mins = BLOCK_DURATION.as_secs() / 60,
            "🚫 API rate limit exceeded — IP blocked"
        );
        false
    }
}

/// Generate HTTP 429 response body
pub fn rate_limit_response() -> String {
    r#"{"error":"rate_limit_exceeded","retry_after_secs":300}"#.to_string()
}
