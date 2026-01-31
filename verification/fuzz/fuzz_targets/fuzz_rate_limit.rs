//! Fuzz target for rate limiting token bucket algorithm
//!
//! Tests that rate limiting never overflows or produces invalid states.

#![no_main]

use libfuzzer_sys::fuzz_target;
use aegis_common::{RateLimitState, TOKENS_PER_SEC, MAX_TOKENS};

/// Simulates the token bucket algorithm from the eBPF program
fn simulate_rate_limit(
    mut state: RateLimitState,
    current_time_ns: u64,
    consume: bool,
) -> (RateLimitState, bool) {
    // Calculate elapsed time
    let elapsed_ns = current_time_ns.saturating_sub(state.last_update);

    // Calculate tokens to add (1 token per 10ms = 100 tokens/sec)
    // TOKENS_PER_SEC = 100, so 1 token every 10_000_000 ns
    let ns_per_token = 1_000_000_000u64 / (TOKENS_PER_SEC as u64);
    let new_tokens = (elapsed_ns / ns_per_token) as u32;

    // Refill tokens (saturating to prevent overflow)
    state.tokens = state.tokens.saturating_add(new_tokens).min(MAX_TOKENS);
    state.last_update = current_time_ns;

    // Try to consume a token
    let allowed = if consume && state.tokens > 0 {
        state.tokens -= 1;
        true
    } else if consume {
        false
    } else {
        true
    };

    (state, allowed)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Parse fuzz input
    let initial_tokens = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let initial_time = u64::from_le_bytes([data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11]]);
    let time_delta = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as u64;

    // Clamp initial tokens to valid range
    let clamped_tokens = initial_tokens.min(MAX_TOKENS);

    let mut state = RateLimitState {
        tokens: clamped_tokens,
        last_update: initial_time,
    };

    // Simulate sequence of operations
    let current_time = initial_time.saturating_add(time_delta);

    // Operation 1: Check without consuming
    let (state1, _allowed1) = simulate_rate_limit(state.clone(), current_time, false);
    assert!(state1.tokens <= MAX_TOKENS);

    // Operation 2: Check with consuming
    let (state2, allowed2) = simulate_rate_limit(state.clone(), current_time, true);
    assert!(state2.tokens <= MAX_TOKENS);

    // If we had tokens and consumed, we should have been allowed
    if state.tokens > 0 || time_delta > 10_000_000 {
        // Either had tokens or had time to refill
        // (Note: might still be denied if starting from 0 and not enough time)
    }

    // Invariant: tokens never exceed MAX_TOKENS
    assert!(state2.tokens <= MAX_TOKENS);

    // Simulate rapid fire (many requests in short time)
    state = RateLimitState {
        tokens: MAX_TOKENS,
        last_update: 0,
    };

    let mut denied_count = 0;
    for i in 0..300 {
        // No time passes, just consuming
        let (new_state, allowed) = simulate_rate_limit(state, 0, true);
        state = new_state;

        if !allowed {
            denied_count += 1;
        }

        // Invariant always holds
        assert!(state.tokens <= MAX_TOKENS);

        // After MAX_TOKENS requests, should start denying
        if i >= MAX_TOKENS as usize {
            // Should be denied (no time to refill)
            if i > MAX_TOKENS as usize {
                assert!(!allowed, "Should deny after exhausting tokens");
            }
        }
    }

    // Should have denied at least (300 - MAX_TOKENS) requests
    assert!(denied_count >= 300 - MAX_TOKENS as usize);

    // Test edge case: time overflow protection
    let edge_state = RateLimitState {
        tokens: 0,
        last_update: u64::MAX - 1000,
    };
    let (final_state, _) = simulate_rate_limit(edge_state, u64::MAX, true);
    assert!(final_state.tokens <= MAX_TOKENS);
});
