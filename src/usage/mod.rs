//! Usage tracking module
//!
//! Tracks API usage by provider, token counts, and costs.
//! Supports daily/monthly aggregation with persistent JSON storage.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default path for usage data storage
fn default_usage_path() -> PathBuf {
    if let Ok(dir) = std::env::var("CARAPACE_STATE_DIR") {
        return PathBuf::from(dir).join("usage.json");
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
        .join("usage.json")
}

/// Global usage tracker instance
static USAGE_TRACKER: LazyLock<RwLock<UsageTracker>> = LazyLock::new(|| {
    let tracker = UsageTracker::load_or_default(default_usage_path());
    RwLock::new(tracker)
});

static PRICING_CONFIG: LazyLock<RwLock<PricingConfig>> =
    LazyLock::new(|| RwLock::new(PricingConfig::default()));

const DAY_MS: u64 = 86_400_000;
const USAGE_DAILY_RETENTION_DAYS: u64 = 365;
const USAGE_MONTHLY_RETENTION_MONTHS: u64 = 24;
const USAGE_SESSION_RETENTION_DAYS: u64 = 90;
const USAGE_MAX_DAILY_ENTRIES: usize = 400;
const USAGE_MAX_MONTHLY_ENTRIES: usize = 36;
const USAGE_MAX_SESSIONS: usize = 1000;

#[derive(Clone, Copy)]
struct UsageRetention {
    daily_retention_days: u64,
    monthly_retention_months: u64,
    session_retention_days: u64,
    max_daily_entries: usize,
    max_monthly_entries: usize,
    max_sessions: usize,
}

const DEFAULT_USAGE_RETENTION: UsageRetention = UsageRetention {
    daily_retention_days: USAGE_DAILY_RETENTION_DAYS,
    monthly_retention_months: USAGE_MONTHLY_RETENTION_MONTHS,
    session_retention_days: USAGE_SESSION_RETENTION_DAYS,
    max_daily_entries: USAGE_MAX_DAILY_ENTRIES,
    max_monthly_entries: USAGE_MAX_MONTHLY_ENTRIES,
    max_sessions: USAGE_MAX_SESSIONS,
};

#[derive(Debug, Clone, Default)]
struct PricingConfig {
    default: Option<ModelPricing>,
    overrides: Vec<PricingOverride>,
}

#[derive(Debug, Clone)]
struct PricingOverride {
    pattern: String,
    match_type: MatchType,
    pricing: ModelPricing,
}

#[derive(Debug, Clone, Copy)]
enum MatchType {
    Contains,
    Exact,
}

impl MatchType {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "contains" => Some(MatchType::Contains),
            "exact" => Some(MatchType::Exact),
            _ => None,
        }
    }
}

/// Model pricing information (cost per million tokens)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    /// Cost per million input tokens (USD)
    pub input_cost_per_mtok: f64,
    /// Cost per million output tokens (USD)
    pub output_cost_per_mtok: f64,
}

impl ModelPricing {
    /// Calculate cost for given token counts
    pub fn calculate_cost(&self, input_tokens: u64, output_tokens: u64) -> f64 {
        let input_cost = (input_tokens as f64 / 1_000_000.0) * self.input_cost_per_mtok;
        let output_cost = (output_tokens as f64 / 1_000_000.0) * self.output_cost_per_mtok;
        input_cost + output_cost
    }
}

/// Default pricing table for known models
pub fn get_model_pricing(model: &str) -> Option<ModelPricing> {
    let model_lower = model.to_lowercase();
    let config = PRICING_CONFIG.read();
    lookup_pricing(model, &model_lower, &config)
}

fn lookup_pricing(model: &str, model_lower: &str, config: &PricingConfig) -> Option<ModelPricing> {
    if let Some(pricing) = pricing_override(model, model_lower, &config.overrides) {
        return Some(pricing);
    }

    if let Some(pricing) = builtin_pricing(model_lower) {
        return Some(pricing);
    }

    if let Some(default) = config.default.clone() {
        return Some(default);
    }

    None
}

fn pricing_override(
    model: &str,
    model_lower: &str,
    overrides: &[PricingOverride],
) -> Option<ModelPricing> {
    for override_entry in overrides {
        let matches = match override_entry.match_type {
            MatchType::Contains => model_lower.contains(&override_entry.pattern),
            MatchType::Exact => model.eq_ignore_ascii_case(&override_entry.pattern),
        };

        if matches {
            return Some(override_entry.pricing.clone());
        }
    }

    None
}

fn builtin_pricing(model_lower: &str) -> Option<ModelPricing> {
    // Claude models
    if model_lower.contains("claude-3-5-sonnet") || model_lower.contains("claude-3.5-sonnet") {
        return Some(ModelPricing {
            input_cost_per_mtok: 3.0,
            output_cost_per_mtok: 15.0,
        });
    }
    if model_lower.contains("claude-3-opus") || model_lower.contains("claude-3.0-opus") {
        return Some(ModelPricing {
            input_cost_per_mtok: 15.0,
            output_cost_per_mtok: 75.0,
        });
    }
    if model_lower.contains("claude-3-sonnet") || model_lower.contains("claude-3.0-sonnet") {
        return Some(ModelPricing {
            input_cost_per_mtok: 3.0,
            output_cost_per_mtok: 15.0,
        });
    }
    if model_lower.contains("claude-3-haiku")
        || model_lower.contains("claude-3.0-haiku")
        || model_lower.contains("claude-haiku-3")
    {
        return Some(ModelPricing {
            input_cost_per_mtok: 0.25,
            output_cost_per_mtok: 1.25,
        });
    }
    // Claude 4 / claude-sonnet-4 / claude-haiku-4 models
    if model_lower.contains("claude-sonnet-4") {
        return Some(ModelPricing {
            input_cost_per_mtok: 3.0,
            output_cost_per_mtok: 15.0,
        });
    }
    if model_lower.contains("claude-haiku-4") {
        return Some(ModelPricing {
            input_cost_per_mtok: 0.25,
            output_cost_per_mtok: 1.25,
        });
    }
    if model_lower.contains("claude-opus-4")
        || model_lower.contains("claude-4-opus")
        || model_lower.contains("claude-4.0-opus")
    {
        return Some(ModelPricing {
            input_cost_per_mtok: 15.0,
            output_cost_per_mtok: 75.0,
        });
    }

    // OpenAI GPT-4 models
    if model_lower.contains("gpt-4-turbo") || model_lower.contains("gpt-4-1106") {
        return Some(ModelPricing {
            input_cost_per_mtok: 10.0,
            output_cost_per_mtok: 30.0,
        });
    }
    if model_lower.contains("gpt-4o") {
        return Some(ModelPricing {
            input_cost_per_mtok: 5.0,
            output_cost_per_mtok: 15.0,
        });
    }
    if model_lower.starts_with("gpt-4") && !model_lower.contains("turbo") {
        return Some(ModelPricing {
            input_cost_per_mtok: 30.0,
            output_cost_per_mtok: 60.0,
        });
    }

    // GPT-3.5
    if model_lower.contains("gpt-3.5") {
        return Some(ModelPricing {
            input_cost_per_mtok: 0.5,
            output_cost_per_mtok: 1.5,
        });
    }

    None
}

fn default_pricing() -> ModelPricing {
    ModelPricing {
        input_cost_per_mtok: 3.0,
        output_cost_per_mtok: 15.0,
    }
}

fn parse_pricing_config(config: &serde_json::Value) -> PricingConfig {
    let usage = match config.get("usage").and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => return PricingConfig::default(),
    };

    let pricing = match usage.get("pricing").and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => return PricingConfig::default(),
    };

    let default = pricing
        .get("default")
        .and_then(|v| v.as_object())
        .and_then(parse_pricing_object);

    let mut overrides = Vec::new();
    if let Some(entries) = pricing.get("overrides").and_then(|v| v.as_array()) {
        for entry in entries {
            if let Some(override_entry) = parse_pricing_override(entry) {
                overrides.push(override_entry);
            }
        }
    }

    PricingConfig { default, overrides }
}

fn parse_pricing_override(value: &serde_json::Value) -> Option<PricingOverride> {
    let obj = value.as_object()?;
    let pattern = obj.get("match").and_then(|v| v.as_str())?.to_string();
    let pattern = pattern.trim().to_string();
    if pattern.is_empty() {
        return None;
    }

    let match_type = obj
        .get("matchType")
        .and_then(|v| v.as_str())
        .and_then(MatchType::parse)
        .unwrap_or(MatchType::Contains);

    let pricing = parse_pricing_object(obj)?;
    Some(PricingOverride {
        pattern: pattern.to_lowercase(),
        match_type,
        pricing,
    })
}

fn parse_pricing_object(obj: &serde_json::Map<String, serde_json::Value>) -> Option<ModelPricing> {
    let input = obj.get("inputCostPerMTok").and_then(parse_number);
    let output = obj.get("outputCostPerMTok").and_then(parse_number);

    match (input, output) {
        (Some(input_cost_per_mtok), Some(output_cost_per_mtok)) => Some(ModelPricing {
            input_cost_per_mtok,
            output_cost_per_mtok,
        }),
        _ => None,
    }
}

fn parse_number(value: &serde_json::Value) -> Option<f64> {
    value.as_f64().or_else(|| value.as_u64().map(|v| v as f64))
}

/// Get current timestamp in milliseconds
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

/// Get current date as YYYY-MM-DD string
fn today_date() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let secs = now.as_secs();
    // Simple date calculation (doesn't handle leap seconds, but good enough for usage tracking)
    let days_since_epoch = secs / 86400;
    let mut year = 1970;
    let mut remaining_days = days_since_epoch;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let mut month = 1;
    loop {
        let days_in_month = days_in_month(year, month);
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;
    format!("{:04}-{:02}-{:02}", year, month, day)
}

/// Get current month as YYYY-MM string
fn current_month() -> String {
    let date = today_date();
    date[..7].to_string()
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 => 31,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 30,
    }
}

/// Usage record for a single API call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// Timestamp of the API call (Unix ms)
    pub timestamp: u64,
    /// Provider name (e.g., "anthropic", "openai")
    pub provider: String,
    /// Model name
    pub model: String,
    /// Session key (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// Input tokens consumed
    pub input_tokens: u64,
    /// Output tokens generated
    pub output_tokens: u64,
    /// Calculated cost in USD
    pub cost_usd: f64,
}

/// Aggregated usage for a provider
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderUsage {
    /// Provider name
    pub provider: String,
    /// Total input tokens
    pub input_tokens: u64,
    /// Total output tokens
    pub output_tokens: u64,
    /// Total requests
    pub requests: u64,
    /// Total cost in USD
    pub cost_usd: f64,
}

/// Aggregated usage for a model
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelUsage {
    /// Model name
    pub model: String,
    /// Provider name
    pub provider: String,
    /// Total input tokens
    pub input_tokens: u64,
    /// Total output tokens
    pub output_tokens: u64,
    /// Total requests
    pub requests: u64,
    /// Total cost in USD
    pub cost_usd: f64,
}

/// Daily usage summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySummary {
    /// Date (YYYY-MM-DD)
    pub date: String,
    /// Total input tokens
    pub input_tokens: u64,
    /// Total output tokens
    pub output_tokens: u64,
    /// Total requests
    pub requests: u64,
    /// Total cost in USD
    pub cost_usd: f64,
    /// Breakdown by provider
    #[serde(default)]
    pub by_provider: HashMap<String, ProviderUsage>,
    /// Breakdown by model
    #[serde(default)]
    pub by_model: HashMap<String, ModelUsage>,
}

impl DailySummary {
    fn new(date: String) -> Self {
        Self {
            date,
            input_tokens: 0,
            output_tokens: 0,
            requests: 0,
            cost_usd: 0.0,
            by_provider: HashMap::new(),
            by_model: HashMap::new(),
        }
    }

    fn add_record(&mut self, record: &UsageRecord) {
        self.input_tokens += record.input_tokens;
        self.output_tokens += record.output_tokens;
        self.requests += 1;
        self.cost_usd += record.cost_usd;

        // Update provider breakdown
        let provider = self
            .by_provider
            .entry(record.provider.clone())
            .or_insert_with(|| ProviderUsage {
                provider: record.provider.clone(),
                ..Default::default()
            });
        provider.input_tokens += record.input_tokens;
        provider.output_tokens += record.output_tokens;
        provider.requests += 1;
        provider.cost_usd += record.cost_usd;

        // Update model breakdown
        let model_key = format!("{}:{}", record.provider, record.model);
        let model = self
            .by_model
            .entry(model_key)
            .or_insert_with(|| ModelUsage {
                model: record.model.clone(),
                provider: record.provider.clone(),
                ..Default::default()
            });
        model.input_tokens += record.input_tokens;
        model.output_tokens += record.output_tokens;
        model.requests += 1;
        model.cost_usd += record.cost_usd;
    }
}

/// Monthly usage summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlySummary {
    /// Month (YYYY-MM)
    pub month: String,
    /// Total input tokens
    pub input_tokens: u64,
    /// Total output tokens
    pub output_tokens: u64,
    /// Total requests
    pub requests: u64,
    /// Total cost in USD
    pub cost_usd: f64,
    /// Breakdown by provider
    #[serde(default)]
    pub by_provider: HashMap<String, ProviderUsage>,
    /// Breakdown by model
    #[serde(default)]
    pub by_model: HashMap<String, ModelUsage>,
}

impl MonthlySummary {
    fn new(month: String) -> Self {
        Self {
            month,
            input_tokens: 0,
            output_tokens: 0,
            requests: 0,
            cost_usd: 0.0,
            by_provider: HashMap::new(),
            by_model: HashMap::new(),
        }
    }

    fn add_record(&mut self, record: &UsageRecord) {
        self.input_tokens += record.input_tokens;
        self.output_tokens += record.output_tokens;
        self.requests += 1;
        self.cost_usd += record.cost_usd;

        // Update provider breakdown
        let provider = self
            .by_provider
            .entry(record.provider.clone())
            .or_insert_with(|| ProviderUsage {
                provider: record.provider.clone(),
                ..Default::default()
            });
        provider.input_tokens += record.input_tokens;
        provider.output_tokens += record.output_tokens;
        provider.requests += 1;
        provider.cost_usd += record.cost_usd;

        // Update model breakdown
        let model_key = format!("{}:{}", record.provider, record.model);
        let model = self
            .by_model
            .entry(model_key)
            .or_insert_with(|| ModelUsage {
                model: record.model.clone(),
                provider: record.provider.clone(),
                ..Default::default()
            });
        model.input_tokens += record.input_tokens;
        model.output_tokens += record.output_tokens;
        model.requests += 1;
        model.cost_usd += record.cost_usd;
    }
}

/// Persistent usage data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageData {
    /// Whether tracking is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Daily summaries (keyed by date YYYY-MM-DD)
    #[serde(default)]
    pub daily: HashMap<String, DailySummary>,
    /// Monthly summaries (keyed by month YYYY-MM)
    #[serde(default)]
    pub monthly: HashMap<String, MonthlySummary>,
    /// Per-session usage (keyed by session key)
    #[serde(default)]
    pub sessions: HashMap<String, SessionUsage>,
    /// Last updated timestamp
    #[serde(default)]
    pub last_updated: u64,
}

fn default_enabled() -> bool {
    true
}

/// Session-level usage tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionUsage {
    /// Session key
    pub session_key: String,
    /// Total input tokens
    pub input_tokens: u64,
    /// Total output tokens
    pub output_tokens: u64,
    /// Total requests
    pub requests: u64,
    /// Total cost in USD
    pub cost_usd: f64,
    /// First usage timestamp
    pub first_used_at: u64,
    /// Last usage timestamp
    pub last_used_at: u64,
}

/// Usage tracker with persistence
#[derive(Debug)]
pub struct UsageTracker {
    /// Path to the usage data file
    path: PathBuf,
    /// In-memory usage data
    data: UsageData,
    /// Whether there are unsaved changes
    dirty: bool,
    /// Last time usage data was saved
    last_save: Option<Instant>,
    /// Minimum interval between saves
    save_interval: Duration,
}

impl UsageTracker {
    /// Create a new usage tracker with the given path
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            data: UsageData {
                enabled: true,
                ..Default::default()
            },
            dirty: false,
            last_save: None,
            save_interval: Duration::from_secs(5),
        }
    }

    /// Load usage data from disk or create default
    pub fn load_or_default(path: PathBuf) -> Self {
        if path.exists() {
            match File::open(&path) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    match serde_json::from_reader(reader) {
                        Ok(data) => {
                            let mut tracker = Self {
                                path,
                                data,
                                dirty: false,
                                last_save: None,
                                save_interval: Duration::from_secs(5),
                            };
                            if tracker.prune_data() {
                                let _ = tracker.save();
                            }
                            return tracker;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse usage data: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to open usage file: {}", e);
                }
            }
        }

        Self::new(path)
    }

    /// Save usage data to disk
    pub fn save(&mut self) -> Result<(), std::io::Error> {
        if !self.dirty {
            return Ok(());
        }

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(&self.path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.data)?;
        self.dirty = false;
        self.last_save = Some(Instant::now());
        Ok(())
    }

    /// Save usage data if enough time has elapsed since the last flush.
    fn maybe_save(&mut self) {
        if !self.dirty {
            return;
        }
        let should_flush = match self.last_save {
            Some(ts) => ts.elapsed() >= self.save_interval,
            None => true,
        };
        if should_flush {
            let _ = self.save();
        }
    }

    /// Check if tracking is enabled
    pub fn is_enabled(&self) -> bool {
        self.data.enabled
    }

    /// Enable tracking
    pub fn enable(&mut self) {
        self.data.enabled = true;
        self.dirty = true;
    }

    /// Disable tracking
    pub fn disable(&mut self) {
        self.data.enabled = false;
        self.dirty = true;
    }

    /// Record API usage
    pub fn record(
        &mut self,
        provider: &str,
        model: &str,
        session_key: Option<&str>,
        input_tokens: u64,
        output_tokens: u64,
    ) {
        if !self.data.enabled {
            return;
        }

        let now = now_ms();
        let date = today_date();
        let month = current_month();

        // Calculate cost
        let pricing = get_model_pricing(model).unwrap_or_else(default_pricing);
        let cost = pricing.calculate_cost(input_tokens, output_tokens);

        let record = UsageRecord {
            timestamp: now,
            provider: provider.to_string(),
            model: model.to_string(),
            session_key: session_key.map(|s| s.to_string()),
            input_tokens,
            output_tokens,
            cost_usd: cost,
        };

        // Update daily summary
        let daily = self
            .data
            .daily
            .entry(date.clone())
            .or_insert_with(|| DailySummary::new(date));
        daily.add_record(&record);

        // Update monthly summary
        let monthly = self
            .data
            .monthly
            .entry(month.clone())
            .or_insert_with(|| MonthlySummary::new(month));
        monthly.add_record(&record);

        // Update session usage if session key provided
        if let Some(key) = session_key {
            let session = self
                .data
                .sessions
                .entry(key.to_string())
                .or_insert_with(|| SessionUsage {
                    session_key: key.to_string(),
                    first_used_at: now,
                    ..Default::default()
                });
            session.input_tokens += input_tokens;
            session.output_tokens += output_tokens;
            session.requests += 1;
            session.cost_usd += cost;
            session.last_used_at = now;
        }

        self.data.last_updated = now;
        self.dirty = true;
        self.prune_data();
    }

    fn prune_data(&mut self) -> bool {
        self.prune_data_with_limits(&DEFAULT_USAGE_RETENTION)
    }

    fn prune_data_with_limits(&mut self, limits: &UsageRetention) -> bool {
        let mut pruned = false;
        let now = now_ms();

        if limits.daily_retention_days > 0 {
            let cutoff = now.saturating_sub(limits.daily_retention_days.saturating_mul(DAY_MS));
            let before = self.data.daily.len();
            self.data
                .daily
                .retain(|date, _| date_within_range(date, cutoff));
            if self.data.daily.len() != before {
                pruned = true;
            }
        }

        if limits.max_daily_entries > 0 && self.data.daily.len() > limits.max_daily_entries {
            let mut keys: Vec<String> = self.data.daily.keys().cloned().collect();
            keys.sort();
            let remove_count = self.data.daily.len() - limits.max_daily_entries;
            for key in keys.into_iter().take(remove_count) {
                self.data.daily.remove(&key);
            }
            pruned = true;
        }

        if limits.monthly_retention_months > 0 {
            if let Some((year, month)) = parse_month(&current_month()) {
                let current_index = month_to_index(year, month);
                let cutoff = current_index - limits.monthly_retention_months as i64 + 1;
                let before = self.data.monthly.len();
                self.data.monthly.retain(|month_key, _| {
                    parse_month(month_key)
                        .map(|(y, m)| month_to_index(y, m) >= cutoff)
                        .unwrap_or(false)
                });
                if self.data.monthly.len() != before {
                    pruned = true;
                }
            }
        }

        if limits.max_monthly_entries > 0 && self.data.monthly.len() > limits.max_monthly_entries {
            let mut keys: Vec<String> = self.data.monthly.keys().cloned().collect();
            keys.sort();
            let remove_count = self.data.monthly.len() - limits.max_monthly_entries;
            for key in keys.into_iter().take(remove_count) {
                self.data.monthly.remove(&key);
            }
            pruned = true;
        }

        if limits.session_retention_days > 0 {
            let cutoff = now.saturating_sub(limits.session_retention_days.saturating_mul(DAY_MS));
            let before = self.data.sessions.len();
            self.data
                .sessions
                .retain(|_, usage| usage.last_used_at >= cutoff);
            if self.data.sessions.len() != before {
                pruned = true;
            }
        }

        if limits.max_sessions > 0 && self.data.sessions.len() > limits.max_sessions {
            let mut sessions: Vec<(String, u64)> = self
                .data
                .sessions
                .iter()
                .map(|(key, usage)| (key.clone(), usage.last_used_at))
                .collect();
            sessions.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            let remove_count = self.data.sessions.len() - limits.max_sessions;
            for (key, _) in sessions.into_iter().take(remove_count) {
                self.data.sessions.remove(&key);
            }
            pruned = true;
        }

        if pruned {
            self.dirty = true;
        }

        pruned
    }

    /// Get current period status
    pub fn status(&self) -> UsageStatus {
        let today = today_date();
        let month = current_month();

        let daily = self.data.daily.get(&today).cloned();
        let monthly = self.data.monthly.get(&month).cloned();

        UsageStatus {
            enabled: self.data.enabled,
            today: daily,
            current_month: monthly,
            session_count: self.data.sessions.len(),
            last_updated: self.data.last_updated,
        }
    }

    /// Get cost breakdown for a time period
    pub fn cost_breakdown(&self, days: u64) -> CostBreakdown {
        let now = now_ms();
        let cutoff_ms = now.saturating_sub(days * 24 * 60 * 60 * 1000);

        // Collect all relevant daily summaries
        let mut total_input_tokens: u64 = 0;
        let mut total_output_tokens: u64 = 0;
        let mut total_requests: u64 = 0;
        let mut total_cost: f64 = 0.0;
        let mut by_provider: HashMap<String, ProviderUsage> = HashMap::new();
        let mut by_model: HashMap<String, ModelUsage> = HashMap::new();
        let mut daily_costs: Vec<DailyCost> = Vec::new();

        for (date, summary) in &self.data.daily {
            // Parse date to check if it's within range
            // Simple check: compare string dates (works for YYYY-MM-DD format)
            if date_within_range(date, cutoff_ms) {
                total_input_tokens += summary.input_tokens;
                total_output_tokens += summary.output_tokens;
                total_requests += summary.requests;
                total_cost += summary.cost_usd;

                // Merge provider breakdown
                for (provider, usage) in &summary.by_provider {
                    let entry =
                        by_provider
                            .entry(provider.clone())
                            .or_insert_with(|| ProviderUsage {
                                provider: provider.clone(),
                                ..Default::default()
                            });
                    entry.input_tokens += usage.input_tokens;
                    entry.output_tokens += usage.output_tokens;
                    entry.requests += usage.requests;
                    entry.cost_usd += usage.cost_usd;
                }

                // Merge model breakdown
                for (model_key, usage) in &summary.by_model {
                    let entry = by_model
                        .entry(model_key.clone())
                        .or_insert_with(|| ModelUsage {
                            model: usage.model.clone(),
                            provider: usage.provider.clone(),
                            ..Default::default()
                        });
                    entry.input_tokens += usage.input_tokens;
                    entry.output_tokens += usage.output_tokens;
                    entry.requests += usage.requests;
                    entry.cost_usd += usage.cost_usd;
                }

                daily_costs.push(DailyCost {
                    date: date.clone(),
                    cost_usd: summary.cost_usd,
                    requests: summary.requests,
                });
            }
        }

        // Sort daily costs by date
        daily_costs.sort_by(|a, b| a.date.cmp(&b.date));

        CostBreakdown {
            days,
            total_input_tokens,
            total_output_tokens,
            total_requests,
            total_cost,
            by_provider: by_provider.into_values().collect(),
            by_model: by_model.into_values().collect(),
            daily: daily_costs,
        }
    }

    /// Get session usage
    pub fn get_session_usage(&self, session_key: &str) -> Option<&SessionUsage> {
        self.data.sessions.get(session_key)
    }

    /// Get all session usage entries
    pub fn get_sessions(&self) -> Vec<SessionUsage> {
        self.data.sessions.values().cloned().collect()
    }

    /// Get all providers with usage
    pub fn get_providers(&self) -> Vec<ProviderUsage> {
        let mut providers: HashMap<String, ProviderUsage> = HashMap::new();

        for summary in self.data.daily.values() {
            for (provider, usage) in &summary.by_provider {
                let entry = providers
                    .entry(provider.clone())
                    .or_insert_with(|| ProviderUsage {
                        provider: provider.clone(),
                        ..Default::default()
                    });
                entry.input_tokens += usage.input_tokens;
                entry.output_tokens += usage.output_tokens;
                entry.requests += usage.requests;
                entry.cost_usd += usage.cost_usd;
            }
        }

        providers.into_values().collect()
    }

    /// Get daily summaries for the last N days
    pub fn get_daily_summaries(&self, days: usize) -> Vec<DailySummary> {
        let mut summaries: Vec<DailySummary> = self.data.daily.values().cloned().collect();
        summaries.sort_by(|a, b| b.date.cmp(&a.date));
        summaries.truncate(days);
        summaries
    }

    /// Get monthly summaries for the last N months
    pub fn get_monthly_summaries(&self, months: usize) -> Vec<MonthlySummary> {
        let mut summaries: Vec<MonthlySummary> = self.data.monthly.values().cloned().collect();
        summaries.sort_by(|a, b| b.month.cmp(&a.month));
        summaries.truncate(months);
        summaries
    }

    /// Reset all usage data
    pub fn reset(&mut self) {
        let enabled = self.data.enabled;
        self.data = UsageData {
            enabled,
            ..Default::default()
        };
        self.dirty = true;
    }

    /// Reset usage for a specific session
    pub fn reset_session(&mut self, session_key: &str) -> bool {
        if self.data.sessions.remove(session_key).is_some() {
            self.dirty = true;
            true
        } else {
            false
        }
    }
}

fn parse_date(date_str: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year = parts[0].parse().ok()?;
    let month = parts[1].parse().ok()?;
    let day = parts[2].parse().ok()?;
    Some((year, month, day))
}

fn date_within_range(date_str: &str, cutoff_ms: u64) -> bool {
    // Parse YYYY-MM-DD and convert to approximate ms timestamp.
    if let Some((year, month, day)) = parse_date(date_str) {
        let date_ms = date_to_ms(year, month, day);
        return date_ms >= cutoff_ms;
    }
    false
}

fn parse_month(month_str: &str) -> Option<(i64, i64)> {
    let parts: Vec<&str> = month_str.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    Some((year, month))
}

fn month_to_index(year: i64, month: i64) -> i64 {
    year.saturating_mul(12).saturating_add(month - 1)
}

fn date_to_ms(year: u64, month: u64, day: u64) -> u64 {
    // Approximate conversion (doesn't need to be exact for range filtering)
    let mut days: u64 = 0;

    // Years since 1970
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Months in current year
    for m in 1..month {
        days += days_in_month(year, m);
    }

    // Days in current month
    days += day - 1;

    days * 86400 * 1000
}

/// Current usage status
#[derive(Debug, Clone, Serialize)]
pub struct UsageStatus {
    /// Whether tracking is enabled
    pub enabled: bool,
    /// Today's usage (if any)
    pub today: Option<DailySummary>,
    /// Current month's usage (if any)
    pub current_month: Option<MonthlySummary>,
    /// Number of tracked sessions
    pub session_count: usize,
    /// Last update timestamp
    pub last_updated: u64,
}

/// Daily cost entry
#[derive(Debug, Clone, Serialize)]
pub struct DailyCost {
    /// Date (YYYY-MM-DD)
    pub date: String,
    /// Cost in USD
    pub cost_usd: f64,
    /// Number of requests
    pub requests: u64,
}

/// Cost breakdown for a time period
#[derive(Debug, Clone, Serialize)]
pub struct CostBreakdown {
    /// Number of days in the period
    pub days: u64,
    /// Total input tokens
    pub total_input_tokens: u64,
    /// Total output tokens
    pub total_output_tokens: u64,
    /// Total requests
    pub total_requests: u64,
    /// Total cost in USD
    pub total_cost: f64,
    /// Breakdown by provider
    pub by_provider: Vec<ProviderUsage>,
    /// Breakdown by model
    pub by_model: Vec<ModelUsage>,
    /// Daily cost breakdown
    pub daily: Vec<DailyCost>,
}

// ============== Public API for global usage tracker ==============

/// Record API usage (global tracker)
pub fn record_usage(
    provider: &str,
    model: &str,
    session_key: Option<&str>,
    input_tokens: u64,
    output_tokens: u64,
) {
    let mut tracker = USAGE_TRACKER.write();
    tracker.record(provider, model, session_key, input_tokens, output_tokens);
    // Attempt to save (ignore errors for now, will retry on next write)
    tracker.maybe_save();
}

/// Update model pricing overrides from config (global tracker).
pub fn update_pricing_from_config(config: &serde_json::Value) {
    let mut pricing = PRICING_CONFIG.write();
    *pricing = parse_pricing_config(config);
}

/// Get current usage status (global tracker)
pub fn get_status() -> UsageStatus {
    let tracker = USAGE_TRACKER.read();
    tracker.status()
}

/// Get cost breakdown (global tracker)
pub fn get_cost_breakdown(days: u64) -> CostBreakdown {
    let tracker = USAGE_TRACKER.read();
    tracker.cost_breakdown(days)
}

/// Enable usage tracking (global tracker)
pub fn enable_tracking() {
    let mut tracker = USAGE_TRACKER.write();
    tracker.enable();
    let _ = tracker.save();
}

/// Disable usage tracking (global tracker)
pub fn disable_tracking() {
    let mut tracker = USAGE_TRACKER.write();
    tracker.disable();
    let _ = tracker.save();
}

/// Check if tracking is enabled (global tracker)
pub fn is_tracking_enabled() -> bool {
    let tracker = USAGE_TRACKER.read();
    tracker.is_enabled()
}

/// Get session usage (global tracker)
pub fn get_session_usage(session_key: &str) -> Option<SessionUsage> {
    let tracker = USAGE_TRACKER.read();
    tracker.get_session_usage(session_key).cloned()
}

/// Get all session usage entries (global tracker)
pub fn get_sessions() -> Vec<SessionUsage> {
    let tracker = USAGE_TRACKER.read();
    tracker.get_sessions()
}

/// Get all providers (global tracker)
pub fn get_providers() -> Vec<ProviderUsage> {
    let tracker = USAGE_TRACKER.read();
    tracker.get_providers()
}

/// Get daily summaries (global tracker)
pub fn get_daily_summaries(days: usize) -> Vec<DailySummary> {
    let tracker = USAGE_TRACKER.read();
    tracker.get_daily_summaries(days)
}

/// Get monthly summaries (global tracker)
pub fn get_monthly_summaries(months: usize) -> Vec<MonthlySummary> {
    let tracker = USAGE_TRACKER.read();
    tracker.get_monthly_summaries(months)
}

/// Reset all usage data (global tracker)
pub fn reset_all() {
    let mut tracker = USAGE_TRACKER.write();
    tracker.reset();
    let _ = tracker.save();
}

/// Reset session usage (global tracker)
pub fn reset_session(session_key: &str) -> bool {
    let mut tracker = USAGE_TRACKER.write();
    let result = tracker.reset_session(session_key);
    let _ = tracker.save();
    result
}

#[cfg(test)]
pub fn reset_global_for_tests(path: PathBuf) {
    let mut tracker = USAGE_TRACKER.write();
    *tracker = UsageTracker::new(path);
}

// ============== Tests ==============

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tracker() -> UsageTracker {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("usage_test_{}.json", uuid::Uuid::new_v4()));
        UsageTracker::new(path)
    }

    #[test]
    fn test_model_pricing_claude_sonnet() {
        let pricing = get_model_pricing("claude-3-5-sonnet-20241022").unwrap();
        assert!((pricing.input_cost_per_mtok - 3.0).abs() < 0.001);
        assert!((pricing.output_cost_per_mtok - 15.0).abs() < 0.001);
    }

    #[test]
    fn test_model_pricing_claude_opus() {
        let pricing = get_model_pricing("claude-3-opus-20240229").unwrap();
        assert!((pricing.input_cost_per_mtok - 15.0).abs() < 0.001);
        assert!((pricing.output_cost_per_mtok - 75.0).abs() < 0.001);
    }

    #[test]
    fn test_model_pricing_gpt4() {
        let pricing = get_model_pricing("gpt-4").unwrap();
        assert!((pricing.input_cost_per_mtok - 30.0).abs() < 0.001);
        assert!((pricing.output_cost_per_mtok - 60.0).abs() < 0.001);
    }

    #[test]
    fn test_model_pricing_unknown() {
        let pricing = get_model_pricing("unknown-model");
        assert!(pricing.is_none());
    }

    #[test]
    fn test_calculate_cost() {
        let pricing = ModelPricing {
            input_cost_per_mtok: 3.0,
            output_cost_per_mtok: 15.0,
        };

        // 1M input tokens + 1M output tokens = $3 + $15 = $18
        let cost = pricing.calculate_cost(1_000_000, 1_000_000);
        assert!((cost - 18.0).abs() < 0.001);

        // 1000 input + 500 output at Claude Sonnet rates
        // (1000/1M) * 3 + (500/1M) * 15 = 0.003 + 0.0075 = 0.0105
        let cost = pricing.calculate_cost(1000, 500);
        assert!((cost - 0.0105).abs() < 0.0001);
    }

    #[test]
    fn test_tracker_record_and_status() {
        let mut tracker = create_test_tracker();

        // Record some usage
        tracker.record(
            "anthropic",
            "claude-3-5-sonnet-20241022",
            Some("test-session"),
            1000,
            500,
        );

        let status = tracker.status();
        assert!(status.enabled);
        assert!(status.today.is_some());

        let today = status.today.unwrap();
        assert_eq!(today.input_tokens, 1000);
        assert_eq!(today.output_tokens, 500);
        assert_eq!(today.requests, 1);
        assert!(today.cost_usd > 0.0);
    }

    #[test]
    fn test_tracker_multiple_records() {
        let mut tracker = create_test_tracker();

        tracker.record(
            "anthropic",
            "claude-3-5-sonnet-20241022",
            Some("session-1"),
            1000,
            500,
        );
        tracker.record("openai", "gpt-4", Some("session-2"), 2000, 1000);

        let status = tracker.status();
        let today = status.today.unwrap();

        assert_eq!(today.input_tokens, 3000);
        assert_eq!(today.output_tokens, 1500);
        assert_eq!(today.requests, 2);
        assert_eq!(today.by_provider.len(), 2);
    }

    #[test]
    fn test_tracker_session_usage() {
        let mut tracker = create_test_tracker();

        tracker.record(
            "anthropic",
            "claude-3-5-sonnet-20241022",
            Some("my-session"),
            1000,
            500,
        );
        tracker.record(
            "anthropic",
            "claude-3-5-sonnet-20241022",
            Some("my-session"),
            2000,
            1000,
        );

        let session = tracker.get_session_usage("my-session").unwrap();
        assert_eq!(session.input_tokens, 3000);
        assert_eq!(session.output_tokens, 1500);
        assert_eq!(session.requests, 2);
    }

    #[test]
    fn test_tracker_enable_disable() {
        let mut tracker = create_test_tracker();

        assert!(tracker.is_enabled());

        tracker.disable();
        assert!(!tracker.is_enabled());

        // Recording should be ignored when disabled
        tracker.record("anthropic", "claude-3-5-sonnet-20241022", None, 1000, 500);
        let status = tracker.status();
        assert!(status.today.is_none());

        tracker.enable();
        tracker.record("anthropic", "claude-3-5-sonnet-20241022", None, 1000, 500);
        let status = tracker.status();
        assert!(status.today.is_some());
    }

    #[test]
    fn test_tracker_cost_breakdown() {
        let mut tracker = create_test_tracker();

        tracker.record("anthropic", "claude-3-5-sonnet-20241022", None, 1000, 500);
        tracker.record("openai", "gpt-4", None, 2000, 1000);

        let breakdown = tracker.cost_breakdown(30);

        assert_eq!(breakdown.total_input_tokens, 3000);
        assert_eq!(breakdown.total_output_tokens, 1500);
        assert_eq!(breakdown.total_requests, 2);
        assert!(breakdown.total_cost > 0.0);
        assert_eq!(breakdown.by_provider.len(), 2);
        assert_eq!(breakdown.by_model.len(), 2);
    }

    #[test]
    fn test_tracker_reset() {
        let mut tracker = create_test_tracker();

        tracker.record(
            "anthropic",
            "claude-3-5-sonnet-20241022",
            Some("session"),
            1000,
            500,
        );

        let status = tracker.status();
        assert!(status.today.is_some());
        assert_eq!(status.session_count, 1);

        tracker.reset();

        let status = tracker.status();
        assert!(status.today.is_none());
        assert_eq!(status.session_count, 0);
    }

    #[test]
    fn test_tracker_reset_session() {
        let mut tracker = create_test_tracker();

        tracker.record(
            "anthropic",
            "claude-3-5-sonnet-20241022",
            Some("session-1"),
            1000,
            500,
        );
        tracker.record(
            "anthropic",
            "claude-3-5-sonnet-20241022",
            Some("session-2"),
            1000,
            500,
        );

        assert!(tracker.get_session_usage("session-1").is_some());
        assert!(tracker.get_session_usage("session-2").is_some());

        let removed = tracker.reset_session("session-1");
        assert!(removed);

        assert!(tracker.get_session_usage("session-1").is_none());
        assert!(tracker.get_session_usage("session-2").is_some());
    }

    #[test]
    fn test_tracker_persistence() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("usage_persist_test_{}.json", uuid::Uuid::new_v4()));

        // Create tracker and add data
        {
            let mut tracker = UsageTracker::new(path.clone());
            tracker.record("anthropic", "claude-3-5-sonnet-20241022", None, 1000, 500);
            tracker.save().unwrap();
        }

        // Load tracker and verify data persisted
        {
            let tracker = UsageTracker::load_or_default(path.clone());
            let status = tracker.status();
            assert!(status.today.is_some());
            assert_eq!(status.today.unwrap().input_tokens, 1000);
        }

        // Clean up
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_usage_prune_by_retention() {
        let mut tracker = create_test_tracker();
        let today = today_date();
        let month = current_month();

        tracker.data.daily.insert(
            "1999-01-01".to_string(),
            DailySummary::new("1999-01-01".to_string()),
        );
        tracker
            .data
            .daily
            .insert(today.clone(), DailySummary::new(today.clone()));
        tracker.data.monthly.insert(
            "1999-01".to_string(),
            MonthlySummary::new("1999-01".to_string()),
        );
        tracker
            .data
            .monthly
            .insert(month.clone(), MonthlySummary::new(month.clone()));

        let now = now_ms();
        tracker.data.sessions.insert(
            "old".to_string(),
            SessionUsage {
                session_key: "old".to_string(),
                ..Default::default()
            },
        );
        tracker.data.sessions.insert(
            "recent".to_string(),
            SessionUsage {
                session_key: "recent".to_string(),
                first_used_at: now,
                last_used_at: now,
                ..Default::default()
            },
        );

        let pruned = tracker.prune_data_with_limits(&UsageRetention {
            daily_retention_days: 1,
            monthly_retention_months: 1,
            session_retention_days: 1,
            max_daily_entries: 10,
            max_monthly_entries: 10,
            max_sessions: 10,
        });

        assert!(pruned);
        assert!(tracker.data.daily.contains_key(&today));
        assert!(!tracker.data.daily.contains_key("1999-01-01"));
        assert!(tracker.data.monthly.contains_key(&month));
        assert!(!tracker.data.monthly.contains_key("1999-01"));
        assert!(tracker.data.sessions.contains_key("recent"));
        assert!(!tracker.data.sessions.contains_key("old"));
    }

    #[test]
    fn test_usage_prune_by_max_entries() {
        let mut tracker = create_test_tracker();
        let today = today_date();
        let month = current_month();

        tracker.data.daily.insert(
            "1999-01-01".to_string(),
            DailySummary::new("1999-01-01".to_string()),
        );
        tracker
            .data
            .daily
            .insert(today.clone(), DailySummary::new(today.clone()));
        tracker.data.monthly.insert(
            "1999-01".to_string(),
            MonthlySummary::new("1999-01".to_string()),
        );
        tracker
            .data
            .monthly
            .insert(month.clone(), MonthlySummary::new(month.clone()));

        let now = now_ms();
        tracker.data.sessions.insert(
            "older".to_string(),
            SessionUsage {
                session_key: "older".to_string(),
                first_used_at: now.saturating_sub(1_000),
                last_used_at: now.saturating_sub(1_000),
                ..Default::default()
            },
        );
        tracker.data.sessions.insert(
            "newer".to_string(),
            SessionUsage {
                session_key: "newer".to_string(),
                first_used_at: now,
                last_used_at: now,
                ..Default::default()
            },
        );

        let pruned = tracker.prune_data_with_limits(&UsageRetention {
            daily_retention_days: 100_000,
            monthly_retention_months: 2400,
            session_retention_days: 100_000,
            max_daily_entries: 1,
            max_monthly_entries: 1,
            max_sessions: 1,
        });

        assert!(pruned);
        assert_eq!(tracker.data.daily.len(), 1);
        assert!(tracker.data.daily.contains_key(&today));
        assert_eq!(tracker.data.monthly.len(), 1);
        assert!(tracker.data.monthly.contains_key(&month));
        assert_eq!(tracker.data.sessions.len(), 1);
        assert!(tracker.data.sessions.contains_key("newer"));
    }

    #[test]
    fn test_pricing_override_precedence() {
        let config = serde_json::json!({
            "usage": {
                "pricing": {
                    "default": { "inputCostPerMTok": 1.0, "outputCostPerMTok": 2.0 },
                    "overrides": [
                        { "match": "gpt-4", "matchType": "contains", "inputCostPerMTok": 30.0, "outputCostPerMTok": 60.0 },
                        { "match": "gpt-4o", "matchType": "exact", "inputCostPerMTok": 5.0, "outputCostPerMTok": 15.0 }
                    ]
                }
            }
        });

        let pricing = parse_pricing_config(&config);
        let model = "gpt-4o";
        let model_lower = model.to_lowercase();
        let matched = lookup_pricing(model, &model_lower, &pricing).unwrap();
        assert!((matched.input_cost_per_mtok - 5.0).abs() < 0.001);
        assert!((matched.output_cost_per_mtok - 15.0).abs() < 0.001);
    }

    #[test]
    fn test_pricing_default_fallback() {
        let config = serde_json::json!({
            "usage": {
                "pricing": {
                    "default": { "inputCostPerMTok": 4.0, "outputCostPerMTok": 8.0 }
                }
            }
        });

        let pricing = parse_pricing_config(&config);
        let model = "custom-model";
        let model_lower = model.to_lowercase();
        let matched = lookup_pricing(model, &model_lower, &pricing).unwrap();
        assert!((matched.input_cost_per_mtok - 4.0).abs() < 0.001);
        assert!((matched.output_cost_per_mtok - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_date_parsing() {
        let (year, month, day) = parse_date("2025-01-27").unwrap();
        assert_eq!(year, 2025);
        assert_eq!(month, 1);
        assert_eq!(day, 27);

        assert!(parse_date("invalid").is_none());
        assert!(parse_date("2025-01").is_none());
    }

    #[test]
    fn test_today_date_format() {
        let date = today_date();
        assert_eq!(date.len(), 10);
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
    }

    #[test]
    fn test_daily_summary_add_record() {
        let mut summary = DailySummary::new("2025-01-27".to_string());

        let record = UsageRecord {
            timestamp: now_ms(),
            provider: "anthropic".to_string(),
            model: "claude-3-5-sonnet".to_string(),
            session_key: None,
            input_tokens: 1000,
            output_tokens: 500,
            cost_usd: 0.01,
        };

        summary.add_record(&record);

        assert_eq!(summary.input_tokens, 1000);
        assert_eq!(summary.output_tokens, 500);
        assert_eq!(summary.requests, 1);
        assert!((summary.cost_usd - 0.01).abs() < 0.0001);
        assert!(summary.by_provider.contains_key("anthropic"));
    }

    #[test]
    fn test_get_providers() {
        let mut tracker = create_test_tracker();

        tracker.record("anthropic", "claude-3-5-sonnet", None, 1000, 500);
        tracker.record("anthropic", "claude-3-5-sonnet", None, 1000, 500);
        tracker.record("openai", "gpt-4", None, 2000, 1000);

        let providers = tracker.get_providers();
        assert_eq!(providers.len(), 2);

        let anthropic = providers
            .iter()
            .find(|p| p.provider == "anthropic")
            .unwrap();
        assert_eq!(anthropic.requests, 2);
        assert_eq!(anthropic.input_tokens, 2000);

        let openai = providers.iter().find(|p| p.provider == "openai").unwrap();
        assert_eq!(openai.requests, 1);
    }

    #[test]
    fn test_get_daily_summaries() {
        let mut tracker = create_test_tracker();

        // Record usage (will go to today's summary)
        tracker.record("anthropic", "claude-3-5-sonnet", None, 1000, 500);

        let summaries = tracker.get_daily_summaries(7);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].input_tokens, 1000);
    }
}
