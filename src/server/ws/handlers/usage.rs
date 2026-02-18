//! Usage tracking handlers.
//!
//! Manages usage statistics, cost tracking, and quota monitoring.

use serde_json::{json, Value};
use std::collections::HashMap;

use super::super::*;
use crate::usage;
use crate::usage::{DailyCost, DailySummary, ModelUsage, MonthlySummary, ProviderUsage};

fn provider_usage_to_value(usage: &ProviderUsage) -> Value {
    json!({
        "provider": usage.provider,
        "inputTokens": usage.input_tokens,
        "outputTokens": usage.output_tokens,
        "totalTokens": usage.input_tokens + usage.output_tokens,
        "requests": usage.requests,
        "cost": usage.cost_usd
    })
}

fn model_usage_to_value(usage: &ModelUsage) -> Value {
    json!({
        "provider": usage.provider,
        "model": usage.model,
        "inputTokens": usage.input_tokens,
        "outputTokens": usage.output_tokens,
        "totalTokens": usage.input_tokens + usage.output_tokens,
        "requests": usage.requests,
        "cost": usage.cost_usd
    })
}

fn daily_cost_to_value(cost: &DailyCost) -> Value {
    json!({
        "date": cost.date,
        "cost": cost.cost_usd,
        "requests": cost.requests
    })
}

fn map_provider_breakdown(map: &HashMap<String, ProviderUsage>) -> Vec<Value> {
    let mut providers: Vec<&ProviderUsage> = map.values().collect();
    providers.sort_by(|a, b| a.provider.cmp(&b.provider));
    providers.into_iter().map(provider_usage_to_value).collect()
}

fn map_model_breakdown(map: &HashMap<String, ModelUsage>) -> Vec<Value> {
    let mut models: Vec<&ModelUsage> = map.values().collect();
    models.sort_by(|a, b| a.model.cmp(&b.model));
    models.into_iter().map(model_usage_to_value).collect()
}

fn daily_summary_to_value(summary: &DailySummary) -> Value {
    json!({
        "date": summary.date,
        "inputTokens": summary.input_tokens,
        "outputTokens": summary.output_tokens,
        "totalTokens": summary.input_tokens + summary.output_tokens,
        "requests": summary.requests,
        "cost": summary.cost_usd,
        "byProvider": map_provider_breakdown(&summary.by_provider),
        "byModel": map_model_breakdown(&summary.by_model)
    })
}

fn monthly_summary_to_value(summary: &MonthlySummary) -> Value {
    json!({
        "month": summary.month,
        "inputTokens": summary.input_tokens,
        "outputTokens": summary.output_tokens,
        "totalTokens": summary.input_tokens + summary.output_tokens,
        "requests": summary.requests,
        "cost": summary.cost_usd,
        "byProvider": map_provider_breakdown(&summary.by_provider),
        "byModel": map_model_breakdown(&summary.by_model)
    })
}

fn totals_from_providers(providers: &[ProviderUsage]) -> (u64, u64, u64, f64) {
    let mut input_tokens = 0;
    let mut output_tokens = 0;
    let mut requests = 0;
    let mut cost_usd = 0.0;

    for usage in providers {
        input_tokens += usage.input_tokens;
        output_tokens += usage.output_tokens;
        requests += usage.requests;
        cost_usd += usage.cost_usd;
    }

    (input_tokens, output_tokens, requests, cost_usd)
}

fn provider_daily_costs(provider: &str, summaries: &[DailySummary]) -> Vec<DailyCost> {
    let mut daily = Vec::new();
    for summary in summaries {
        if let Some(usage) = summary.by_provider.get(provider) {
            daily.push(DailyCost {
                date: summary.date.clone(),
                cost_usd: usage.cost_usd,
                requests: usage.requests,
            });
        }
    }
    daily.sort_by(|a, b| a.date.cmp(&b.date));
    daily
}

/// Get usage status
pub(super) fn handle_usage_status() -> Result<Value, ErrorShape> {
    let status = usage::get_status();
    let providers = usage::get_providers();
    let (input_tokens, output_tokens, requests, total_cost) = totals_from_providers(&providers);

    Ok(json!({
        "enabled": status.enabled,
        "tracking": status.enabled,
        "summary": {
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "totalTokens": input_tokens + output_tokens,
            "requests": requests,
            "totalCost": total_cost
        },
        "sessionCount": status.session_count,
        "providerCount": providers.len()
    }))
}

/// Enable usage tracking
pub(super) fn handle_usage_enable() -> Result<Value, ErrorShape> {
    usage::enable_tracking();
    Ok(json!({
        "ok": true,
        "enabled": true
    }))
}

/// Disable usage tracking
pub(super) fn handle_usage_disable() -> Result<Value, ErrorShape> {
    usage::disable_tracking();
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

    let cutoff = now_ms().saturating_sub(days as u64 * 24 * 60 * 60 * 1000);

    if let Some(ref session_key) = session_key {
        let usage = usage::get_session_usage(session_key);
        let (input_tokens, output_tokens, requests, total_cost, session_count) = match usage {
            Some(u) if u.last_used_at >= cutoff => {
                (u.input_tokens, u.output_tokens, u.requests, u.cost_usd, 1)
            }
            _ => (0, 0, 0, 0.0, 0),
        };

        return Ok(json!({
            "days": days,
            "sessionKey": session_key,
            "provider": provider,
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "totalTokens": input_tokens + output_tokens,
            "requests": requests,
            "totalCost": total_cost,
            "sessionCount": session_count,
            "byProvider": [],
            "byModel": [],
            "daily": []
        }));
    }

    let breakdown = usage::get_cost_breakdown(days as u64);
    let mut by_provider = breakdown.by_provider;
    let mut by_model = breakdown.by_model;
    let mut daily = breakdown.daily;

    if let Some(ref provider) = provider {
        by_provider.retain(|entry| entry.provider == *provider);
        by_model.retain(|entry| entry.provider == *provider);
        let (input_tokens, output_tokens, requests, total_cost) =
            totals_from_providers(&by_provider);
        let summaries = usage::get_daily_summaries(days as usize);
        daily = provider_daily_costs(provider, &summaries);

        let session_count = usage::get_sessions()
            .into_iter()
            .filter(|session| session.last_used_at >= cutoff)
            .count();

        return Ok(json!({
            "days": days,
            "sessionKey": session_key,
            "provider": provider,
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "totalTokens": input_tokens + output_tokens,
            "requests": requests,
            "totalCost": total_cost,
            "sessionCount": session_count,
            "byProvider": by_provider.iter().map(provider_usage_to_value).collect::<Vec<_>>(),
            "byModel": by_model.iter().map(model_usage_to_value).collect::<Vec<_>>(),
            "daily": daily.iter().map(daily_cost_to_value).collect::<Vec<_>>()
        }));
    }

    let session_count = usage::get_sessions()
        .into_iter()
        .filter(|session| session.last_used_at >= cutoff)
        .count();

    Ok(json!({
        "days": days,
        "sessionKey": session_key,
        "provider": provider,
        "inputTokens": breakdown.total_input_tokens,
        "outputTokens": breakdown.total_output_tokens,
        "totalTokens": breakdown.total_input_tokens + breakdown.total_output_tokens,
        "requests": breakdown.total_requests,
        "totalCost": breakdown.total_cost,
        "sessionCount": session_count,
        "byProvider": by_provider.iter().map(provider_usage_to_value).collect::<Vec<_>>(),
        "byModel": by_model.iter().map(model_usage_to_value).collect::<Vec<_>>(),
        "daily": daily.iter().map(daily_cost_to_value).collect::<Vec<_>>()
    }))
}

/// Get detailed usage for a specific session
pub(super) fn handle_usage_session(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;

    match usage::get_session_usage(session_key) {
        Some(usage) => Ok(json!({
            "sessionKey": session_key,
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
    let providers = usage::get_providers();
    Ok(json!({
        "providers": providers.iter().map(provider_usage_to_value).collect::<Vec<_>>()
    }))
}

/// Get daily usage summaries
pub(super) fn handle_usage_daily(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let days = params
        .and_then(|v| v.get("days"))
        .and_then(|v| v.as_i64())
        .unwrap_or(30)
        .clamp(1, 365) as usize;

    let summaries = usage::get_daily_summaries(days);

    Ok(json!({
        "days": days,
        "summaries": summaries.iter().map(daily_summary_to_value).collect::<Vec<_>>()
    }))
}

/// Get monthly usage summaries
pub(super) fn handle_usage_monthly(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let months = params
        .and_then(|v| v.get("months"))
        .and_then(|v| v.as_i64())
        .unwrap_or(12)
        .clamp(1, 120) as usize;

    let summaries = usage::get_monthly_summaries(months);

    Ok(json!({
        "months": months,
        "summaries": summaries.iter().map(monthly_summary_to_value).collect::<Vec<_>>()
    }))
}

/// Reset usage statistics
pub(super) fn handle_usage_reset(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(key) = session_key {
        if usage::reset_session(&key) {
            return Ok(json!({
                "ok": true,
                "reset": "session",
                "sessionKey": key
            }));
        }
        return Ok(json!({
            "ok": true,
            "reset": "none",
            "reason": "session not found"
        }));
    }

    let session_count = usage::get_sessions().len();
    usage::reset_all();

    Ok(json!({
        "ok": true,
        "reset": "all",
        "clearedSessions": session_count
    }))
}

/// Record usage (internal helper, called by agent execution)
pub fn record_usage(
    session_key: &str,
    provider: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
) {
    usage::record_usage(
        provider,
        model,
        Some(session_key),
        input_tokens,
        output_tokens,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let path =
            std::env::temp_dir().join(format!("usage_ws_test_{}.json", uuid::Uuid::new_v4()));
        usage::reset_global_for_tests(path);
        usage::enable_tracking();
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
        record_usage(
            "test-session",
            "anthropic",
            "claude-sonnet-4-20250514",
            100,
            50,
        );

        let result = handle_usage_status().unwrap();
        assert_eq!(result["summary"]["inputTokens"], 100);
        assert_eq!(result["summary"]["outputTokens"], 50);
        assert_eq!(result["summary"]["requests"], 1);
    }

    #[test]
    fn test_usage_session() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        record_usage(
            "test-session",
            "anthropic",
            "claude-sonnet-4-20250514",
            100,
            50,
        );

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
        record_usage("session1", "anthropic", "claude-sonnet-4-20250514", 100, 50);
        record_usage("session2", "openai", "gpt-4o", 200, 100);

        let result = handle_usage_providers().unwrap();
        let providers = result["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn test_usage_reset() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        record_usage(
            "test-session",
            "anthropic",
            "claude-sonnet-4-20250514",
            100,
            50,
        );

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
        record_usage("session1", "anthropic", "claude-sonnet-4-20250514", 100, 50);
        record_usage("session2", "anthropic", "claude-sonnet-4-20250514", 100, 50);

        let params = json!({ "sessionKey": "session1" });
        let result = handle_usage_reset(Some(&params)).unwrap();
        assert_eq!(result["reset"], "session");
        assert_eq!(result["sessionKey"], "session1");

        let status = handle_usage_status().unwrap();
        assert_eq!(status["sessionCount"], 1);
    }
}
