//! Usage tracking handlers.
//!
//! Manages usage statistics, cost tracking, and quota monitoring.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::*;

/// Global usage state
static USAGE_STATE: LazyLock<RwLock<UsageState>> =
    LazyLock::new(|| RwLock::new(UsageState::default()));

/// Usage tracking state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageState {
    /// Whether usage tracking is enabled
    pub enabled: bool,
    /// Per-session usage data
    pub sessions: HashMap<String, SessionUsage>,
    /// Per-provider usage data
    pub providers: HashMap<String, ProviderUsage>,
    /// Daily usage summaries
    pub daily_summaries: Vec<DailySummary>,
}

/// Usage data for a session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionUsage {
    /// Session key
    pub session_key: String,
    /// Input tokens consumed
    pub input_tokens: u64,
    /// Output tokens generated
    pub output_tokens: u64,
    /// Number of requests
    pub requests: u64,
    /// Estimated cost in USD
    pub cost_usd: f64,
    /// First usage timestamp (ms)
    pub first_used_at: u64,
    /// Last usage timestamp (ms)
    pub last_used_at: u64,
}

/// Usage data for a provider
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderUsage {
    /// Provider ID
    pub provider: String,
    /// Input tokens consumed
    pub input_tokens: u64,
    /// Output tokens generated
    pub output_tokens: u64,
    /// Number of requests
    pub requests: u64,
    /// Estimated cost in USD
    pub cost_usd: f64,
}

/// Daily usage summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySummary {
    /// Date (YYYY-MM-DD)
    pub date: String,
    /// Input tokens consumed
    pub input_tokens: u64,
    /// Output tokens generated
    pub output_tokens: u64,
    /// Number of requests
    pub requests: u64,
    /// Estimated cost in USD
    pub cost_usd: f64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

/// Get usage status
pub(super) fn handle_usage_status() -> Result<Value, ErrorShape> {
    let state = USAGE_STATE.read();

    let total_input: u64 = state.sessions.values().map(|s| s.input_tokens).sum();
    let total_output: u64 = state.sessions.values().map(|s| s.output_tokens).sum();
    let total_requests: u64 = state.sessions.values().map(|s| s.requests).sum();
    let total_cost: f64 = state.sessions.values().map(|s| s.cost_usd).sum();

    // Also check config for tracking setting
    let tracking = config::load_config()
        .ok()
        .and_then(|cfg| cfg.get("usage")?.get("enabled")?.as_bool())
        .unwrap_or(true);

    Ok(json!({
        "enabled": state.enabled || tracking,
        "tracking": tracking,
        "summary": {
            "inputTokens": total_input,
            "outputTokens": total_output,
            "totalTokens": total_input + total_output,
            "requests": total_requests,
            "totalCost": total_cost
        },
        "sessionCount": state.sessions.len(),
        "providerCount": state.providers.len()
    }))
}

/// Enable usage tracking
pub(super) fn handle_usage_enable() -> Result<Value, ErrorShape> {
    let mut state = USAGE_STATE.write();
    state.enabled = true;

    Ok(json!({
        "ok": true,
        "enabled": true
    }))
}

/// Disable usage tracking
pub(super) fn handle_usage_disable() -> Result<Value, ErrorShape> {
    let mut state = USAGE_STATE.write();
    state.enabled = false;

    Ok(json!({
        "ok": true,
        "enabled": false
    }))
}

/// Get usage cost for a time period
pub(super) fn handle_usage_cost(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let days = params
        .and_then(|v| v.get("days"))
        .and_then(|v| v.as_i64())
        .unwrap_or(30)
        .max(1);

    let provider = params
        .and_then(|v| v.get("provider"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let state = USAGE_STATE.read();

    let now = now_ms();
    let cutoff = now - (days as u64 * 24 * 60 * 60 * 1000);

    // Filter sessions based on criteria
    let filtered: Vec<&SessionUsage> = state
        .sessions
        .values()
        .filter(|s| {
            if let Some(ref key) = session_key {
                if &s.session_key != key {
                    return false;
                }
            }
            s.last_used_at >= cutoff
        })
        .collect();

    let input_tokens: u64 = filtered.iter().map(|s| s.input_tokens).sum();
    let output_tokens: u64 = filtered.iter().map(|s| s.output_tokens).sum();
    let requests: u64 = filtered.iter().map(|s| s.requests).sum();
    let total_cost: f64 = filtered.iter().map(|s| s.cost_usd).sum();

    Ok(json!({
        "days": days,
        "sessionKey": session_key,
        "provider": provider,
        "inputTokens": input_tokens,
        "outputTokens": output_tokens,
        "totalTokens": input_tokens + output_tokens,
        "requests": requests,
        "totalCost": total_cost,
        "sessionCount": filtered.len()
    }))
}

/// Get detailed usage for a specific session
pub(super) fn handle_usage_session(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;

    let state = USAGE_STATE.read();

    match state.sessions.get(session_key) {
        Some(usage) => Ok(json!({
            "sessionKey": usage.session_key,
            "inputTokens": usage.input_tokens,
            "outputTokens": usage.output_tokens,
            "totalTokens": usage.input_tokens + usage.output_tokens,
            "requests": usage.requests,
            "cost": usage.cost_usd,
            "firstUsedAt": usage.first_used_at,
            "lastUsedAt": usage.last_used_at
        })),
        None => Ok(json!({
            "sessionKey": session_key,
            "inputTokens": 0,
            "outputTokens": 0,
            "totalTokens": 0,
            "requests": 0,
            "cost": 0.0,
            "firstUsedAt": null,
            "lastUsedAt": null
        })),
    }
}

/// Get usage by provider
pub(super) fn handle_usage_providers() -> Result<Value, ErrorShape> {
    let state = USAGE_STATE.read();

    let providers: Vec<Value> = state
        .providers
        .values()
        .map(|p| {
            json!({
                "provider": p.provider,
                "inputTokens": p.input_tokens,
                "outputTokens": p.output_tokens,
                "totalTokens": p.input_tokens + p.output_tokens,
                "requests": p.requests,
                "cost": p.cost_usd
            })
        })
        .collect();

    Ok(json!({
        "providers": providers
    }))
}

/// Get daily usage summaries
pub(super) fn handle_usage_daily(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let days = params
        .and_then(|v| v.get("days"))
        .and_then(|v| v.as_i64())
        .unwrap_or(30)
        .max(1)
        .min(365) as usize;

    let state = USAGE_STATE.read();

    // Return last N days of summaries
    let summaries: Vec<Value> = state
        .daily_summaries
        .iter()
        .rev()
        .take(days)
        .map(|s| {
            json!({
                "date": s.date,
                "inputTokens": s.input_tokens,
                "outputTokens": s.output_tokens,
                "totalTokens": s.input_tokens + s.output_tokens,
                "requests": s.requests,
                "cost": s.cost_usd
            })
        })
        .collect();

    Ok(json!({
        "days": days,
        "summaries": summaries
    }))
}

/// Reset usage statistics
pub(super) fn handle_usage_reset(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut state = USAGE_STATE.write();

    if let Some(key) = session_key {
        // Reset specific session
        if state.sessions.remove(&key).is_some() {
            return Ok(json!({
                "ok": true,
                "reset": "session",
                "sessionKey": key
            }));
        } else {
            return Ok(json!({
                "ok": true,
                "reset": "none",
                "reason": "session not found"
            }));
        }
    }

    // Reset all usage
    let session_count = state.sessions.len();
    state.sessions.clear();
    state.providers.clear();
    state.daily_summaries.clear();

    Ok(json!({
        "ok": true,
        "reset": "all",
        "clearedSessions": session_count
    }))
}

/// Record usage (internal helper, would be called by agent execution)
pub fn record_usage(
    session_key: &str,
    provider: &str,
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
) {
    let mut state = USAGE_STATE.write();

    if !state.enabled {
        return;
    }

    let now = now_ms();

    // Update session usage
    let session = state
        .sessions
        .entry(session_key.to_string())
        .or_insert_with(|| SessionUsage {
            session_key: session_key.to_string(),
            first_used_at: now,
            ..Default::default()
        });
    session.input_tokens += input_tokens;
    session.output_tokens += output_tokens;
    session.requests += 1;
    session.cost_usd += cost;
    session.last_used_at = now;

    // Update provider usage
    let provider_usage = state
        .providers
        .entry(provider.to_string())
        .or_insert_with(|| ProviderUsage {
            provider: provider.to_string(),
            ..Default::default()
        });
    provider_usage.input_tokens += input_tokens;
    provider_usage.output_tokens += output_tokens;
    provider_usage.requests += 1;
    provider_usage.cost_usd += cost;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let mut state = USAGE_STATE.write();
        *state = UsageState::default();
        state.enabled = true;
    }

    #[test]
    fn test_usage_status_default() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_usage_status().unwrap();
        assert_eq!(result["summary"]["inputTokens"], 0);
        assert_eq!(result["summary"]["requests"], 0);
    }

    #[test]
    fn test_usage_enable_disable() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let result = handle_usage_disable().unwrap();
        assert_eq!(result["enabled"], false);

        let result = handle_usage_enable().unwrap();
        assert_eq!(result["enabled"], true);
    }

    #[test]
    fn test_usage_cost() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({ "days": 7 });
        let result = handle_usage_cost(Some(&params)).unwrap();
        assert_eq!(result["days"], 7);
        assert_eq!(result["inputTokens"], 0);
    }

    #[test]
    fn test_record_usage() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        record_usage("test-session", "anthropic", 100, 50, 0.01);

        let result = handle_usage_status().unwrap();
        assert_eq!(result["summary"]["inputTokens"], 100);
        assert_eq!(result["summary"]["outputTokens"], 50);
        assert_eq!(result["summary"]["requests"], 1);
    }

    #[test]
    fn test_usage_session() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        record_usage("test-session", "anthropic", 100, 50, 0.01);

        let params = json!({ "sessionKey": "test-session" });
        let result = handle_usage_session(Some(&params)).unwrap();
        assert_eq!(result["sessionKey"], "test-session");
        assert_eq!(result["inputTokens"], 100);
        assert_eq!(result["requests"], 1);
    }

    #[test]
    fn test_usage_providers() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        record_usage("session1", "anthropic", 100, 50, 0.01);
        record_usage("session2", "openai", 200, 100, 0.02);

        let result = handle_usage_providers().unwrap();
        let providers = result["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn test_usage_reset() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        record_usage("test-session", "anthropic", 100, 50, 0.01);

        // Reset all
        let result = handle_usage_reset(None).unwrap();
        assert_eq!(result["reset"], "all");
        assert_eq!(result["clearedSessions"], 1);

        let status = handle_usage_status().unwrap();
        assert_eq!(status["sessionCount"], 0);
    }

    #[test]
    fn test_usage_reset_session() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        record_usage("session1", "anthropic", 100, 50, 0.01);
        record_usage("session2", "anthropic", 100, 50, 0.01);

        let params = json!({ "sessionKey": "session1" });
        let result = handle_usage_reset(Some(&params)).unwrap();
        assert_eq!(result["reset"], "session");
        assert_eq!(result["sessionKey"], "session1");

        let status = handle_usage_status().unwrap();
        assert_eq!(status["sessionCount"], 1);
    }
}
