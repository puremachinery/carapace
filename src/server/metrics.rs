//! Prometheus metrics endpoint
//!
//! Zero-dependency Prometheus text format exporter using only `std::sync::atomic`,
//! `parking_lot`, and `axum`. Provides counters, gauges, histograms, and
//! label-vector variants with a global singleton registry.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Atomic helpers
// ---------------------------------------------------------------------------

/// A simple atomic counter backed by `AtomicU64`.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.inc_by(1);
    }

    pub fn inc_by(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A gauge that stores an `f64` via bit-casting into `AtomicU64`.
#[derive(Debug, Default)]
pub struct Gauge(AtomicU64);

impl Gauge {
    pub fn set(&self, val: f64) {
        self.0.store(val.to_bits(), Ordering::Relaxed);
    }

    pub fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }

    pub fn inc(&self) {
        self.add(1.0);
    }

    pub fn dec(&self) {
        self.add(-1.0);
    }

    fn add(&self, delta: f64) {
        loop {
            let current = self.0.load(Ordering::Relaxed);
            let new_val = f64::from_bits(current) + delta;
            if self
                .0
                .compare_exchange_weak(
                    current,
                    new_val.to_bits(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }
}
/// A histogram that observes values into pre-defined buckets.
#[derive(Debug)]
pub struct Histogram {
    /// Upper-bound for each bucket (sorted ascending, last = +Inf implied).
    buckets: Vec<f64>,
    /// Count per bucket (index-aligned with `buckets`, plus one for +Inf).
    counts: Vec<AtomicU64>,
    /// Running sum of all observed values (bit-cast f64).
    sum: AtomicU64,
    /// Total observation count.
    count: AtomicU64,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let num = buckets.len();
        let mut counts = Vec::with_capacity(num + 1);
        for _ in 0..=num {
            counts.push(AtomicU64::new(0));
        }
        Self {
            buckets,
            counts,
            sum: AtomicU64::new(0.0_f64.to_bits()),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, val: f64) {
        // Increment all buckets whose bound >= val (cumulative).
        for (i, bound) in self.buckets.iter().enumerate() {
            if val <= *bound {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf bucket always incremented.
        self.counts[self.buckets.len()].fetch_add(1, Ordering::Relaxed);

        // Add to sum via CAS loop.
        loop {
            let current = self.sum.load(Ordering::Relaxed);
            let new_val = f64::from_bits(current) + val;
            if self
                .sum
                .compare_exchange_weak(
                    current,
                    new_val.to_bits(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }

        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn get_sum(&self) -> f64 {
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }
}

// ---------------------------------------------------------------------------
// Metric descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

impl MetricType {
    fn as_str(&self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Histogram => "histogram",
        }
    }
}

#[derive(Debug)]
enum MetricData {
    Counter(Arc<Counter>),
    Gauge(Arc<Gauge>),
    Histogram(Arc<Histogram>),
    CounterVec {
        label_names: Vec<String>,
        entries: RwLock<HashMap<Vec<String>, Arc<Counter>>>,
    },
    GaugeVec {
        label_names: Vec<String>,
        entries: RwLock<HashMap<Vec<String>, Arc<Gauge>>>,
    },
}

#[derive(Debug)]
struct MetricDescriptor {
    name: String,
    help: String,
    metric_type: MetricType,
    data: MetricData,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Global metrics registry.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    metrics: RwLock<Vec<MetricDescriptor>>,
}

/// The global singleton metrics registry.
pub static METRICS: LazyLock<MetricsRegistry> = LazyLock::new(MetricsRegistry::default);

impl MetricsRegistry {
    // -- Counter --

    pub fn register_counter(&self, name: &str, help: &str) -> Arc<Counter> {
        let counter = Arc::new(Counter::default());
        let desc = MetricDescriptor {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Counter,
            data: MetricData::Counter(Arc::clone(&counter)),
        };
        self.metrics.write().push(desc);
        counter
    }

    pub fn register_counter_vec(
        &self,
        name: &str,
        help: &str,
        label_names: &[&str],
    ) -> CounterVecHandle {
        let handle = CounterVecHandle {
            name: name.to_string(),
        };
        let desc = MetricDescriptor {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Counter,
            data: MetricData::CounterVec {
                label_names: label_names.iter().map(|s| s.to_string()).collect(),
                entries: RwLock::new(HashMap::new()),
            },
        };
        self.metrics.write().push(desc);
        handle
    }

    // -- Gauge --

    pub fn register_gauge(&self, name: &str, help: &str) -> Arc<Gauge> {
        let gauge = Arc::new(Gauge::default());
        let desc = MetricDescriptor {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Gauge,
            data: MetricData::Gauge(Arc::clone(&gauge)),
        };
        self.metrics.write().push(desc);
        gauge
    }

    pub fn register_gauge_vec(
        &self,
        name: &str,
        help: &str,
        label_names: &[&str],
    ) -> GaugeVecHandle {
        let handle = GaugeVecHandle {
            name: name.to_string(),
        };
        let desc = MetricDescriptor {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Gauge,
            data: MetricData::GaugeVec {
                label_names: label_names.iter().map(|s| s.to_string()).collect(),
                entries: RwLock::new(HashMap::new()),
            },
        };
        self.metrics.write().push(desc);
        handle
    }

    // -- Histogram --

    pub fn register_histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<Histogram> {
        let histogram = Arc::new(Histogram::new(buckets));
        let desc = MetricDescriptor {
            name: name.to_string(),
            help: help.to_string(),
            metric_type: MetricType::Histogram,
            data: MetricData::Histogram(Arc::clone(&histogram)),
        };
        self.metrics.write().push(desc);
        histogram
    }

    // -- Counter vec helpers --

    /// Get or create a counter for the given label values in a counter_vec.
    pub fn counter_vec_inc(&self, name: &str, label_values: &[&str]) {
        self.with_counter_vec(name, label_values, |c| c.inc());
    }

    pub fn counter_vec_inc_by(&self, name: &str, label_values: &[&str], n: u64) {
        self.with_counter_vec(name, label_values, |c| c.inc_by(n));
    }

    fn with_counter_vec(&self, name: &str, label_values: &[&str], f: impl FnOnce(&Counter)) {
        let metrics = self.metrics.read();
        for desc in metrics.iter() {
            if desc.name == name {
                if let MetricData::CounterVec { entries, .. } = &desc.data {
                    let key: Vec<String> = label_values.iter().map(|s| s.to_string()).collect();
                    // Fast path: read lock
                    {
                        let map = entries.read();
                        if let Some(counter) = map.get(&key) {
                            f(counter);
                            return;
                        }
                    }
                    // Slow path: write lock to insert
                    let mut map = entries.write();
                    let counter = map
                        .entry(key)
                        .or_insert_with(|| Arc::new(Counter::default()));
                    f(counter);
                }
                return;
            }
        }
    }

    /// Get or create a gauge for the given label values in a gauge_vec.
    pub fn gauge_vec_set(&self, name: &str, label_values: &[&str], val: f64) {
        self.with_gauge_vec(name, label_values, |g| g.set(val));
    }

    fn with_gauge_vec(&self, name: &str, label_values: &[&str], f: impl FnOnce(&Gauge)) {
        let metrics = self.metrics.read();
        for desc in metrics.iter() {
            if desc.name == name {
                if let MetricData::GaugeVec { entries, .. } = &desc.data {
                    let key: Vec<String> = label_values.iter().map(|s| s.to_string()).collect();
                    {
                        let map = entries.read();
                        if let Some(gauge) = map.get(&key) {
                            f(gauge);
                            return;
                        }
                    }
                    let mut map = entries.write();
                    let gauge = map.entry(key).or_insert_with(|| Arc::new(Gauge::default()));
                    f(gauge);
                }
                return;
            }
        }
    }
    // -- Render --

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let metrics = self.metrics.read();
        let mut out = String::with_capacity(4096);

        for desc in metrics.iter() {
            // HELP line
            let _ = writeln!(out, "# HELP {} {}", desc.name, desc.help);
            // TYPE line
            let _ = writeln!(out, "# TYPE {} {}", desc.name, desc.metric_type.as_str());

            match &desc.data {
                MetricData::Counter(counter) => {
                    let _ = writeln!(out, "{} {}", desc.name, counter.get());
                }
                MetricData::Gauge(gauge) => {
                    let _ = write_f64(&mut out, &desc.name, None, gauge.get());
                }
                MetricData::Histogram(histogram) => {
                    render_histogram(&mut out, &desc.name, histogram);
                }
                MetricData::CounterVec {
                    label_names,
                    entries,
                } => {
                    let map = entries.read();
                    let mut sorted: Vec<_> = map.iter().collect();
                    sorted.sort_by(|a, b| a.0.cmp(b.0));
                    for (label_values, counter) in sorted {
                        let labels = format_labels(label_names, label_values);
                        let _ = writeln!(out, "{}{} {}", desc.name, labels, counter.get());
                    }
                }
                MetricData::GaugeVec {
                    label_names,
                    entries,
                } => {
                    let map = entries.read();
                    let mut sorted: Vec<_> = map.iter().collect();
                    sorted.sort_by(|a, b| a.0.cmp(b.0));
                    for (label_values, gauge) in sorted {
                        let labels = format_labels(label_names, label_values);
                        let _ = write_f64(&mut out, &desc.name, Some(&labels), gauge.get());
                    }
                }
            }
        }

        out
    }
}

/// Format a gauge/f64 value, rendering integers without decimal.
fn write_f64(out: &mut String, name: &str, labels: Option<&str>, val: f64) -> std::fmt::Result {
    if val == val.floor() && val.is_finite() {
        writeln!(out, "{}{} {}", name, labels.unwrap_or(""), val as i64)
    } else {
        writeln!(out, "{}{} {}", name, labels.unwrap_or(""), val)
    }
}

fn format_labels(names: &[String], values: &[String]) -> String {
    let mut buf = String::from("{");
    for (i, (name, value)) in names.iter().zip(values.iter()).enumerate() {
        if i > 0 {
            buf.push(',');
        }
        let _ = write!(buf, "{}=\"{}\"", name, escape_label_value(value));
    }
    buf.push('}');
    buf
}

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn render_histogram(out: &mut String, name: &str, h: &Histogram) {
    // Bucket counts are already cumulative (observe increments all buckets >= val).
    for (i, bound) in h.buckets.iter().enumerate() {
        let count = h.counts[i].load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{}_bucket{{le=\"{}\"}} {}",
            name,
            format_bound(*bound),
            count
        );
    }
    let inf_count = h.counts[h.buckets.len()].load(Ordering::Relaxed);
    let _ = writeln!(out, "{}_bucket{{le=\"+Inf\"}} {}", name, inf_count);

    let sum = h.get_sum();
    if sum == sum.floor() && sum.is_finite() {
        let _ = writeln!(out, "{}_sum {}", name, sum as i64);
    } else {
        let _ = writeln!(out, "{}_sum {}", name, sum);
    }
    let _ = writeln!(out, "{}_count {}", name, h.get_count());
}

fn format_bound(v: f64) -> String {
    if v == v.floor() && v.is_finite() {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

// ---------------------------------------------------------------------------
// Vec handles (convenience wrappers)
// ---------------------------------------------------------------------------

/// Handle for a counter_vec metric, allowing labeled increments.
#[derive(Debug, Clone)]
pub struct CounterVecHandle {
    name: String,
}

impl CounterVecHandle {
    pub fn inc(&self, label_values: &[&str]) {
        METRICS.counter_vec_inc(&self.name, label_values);
    }

    pub fn inc_by(&self, label_values: &[&str], n: u64) {
        METRICS.counter_vec_inc_by(&self.name, label_values, n);
    }
}

/// Handle for a gauge_vec metric.
#[derive(Debug, Clone)]
pub struct GaugeVecHandle {
    name: String,
}

impl GaugeVecHandle {
    pub fn set(&self, label_values: &[&str], val: f64) {
        METRICS.gauge_vec_set(&self.name, label_values, val);
    }
}

// ---------------------------------------------------------------------------
// Standard metrics
// ---------------------------------------------------------------------------

/// Standard metric handles for use across the application.
pub struct StandardMetrics {
    pub http_requests_total: CounterVecHandle,
    pub ws_connections_active: Arc<Gauge>,
    pub ws_messages_total: CounterVecHandle,
    pub agent_runs_total: CounterVecHandle,
    pub agent_tokens_total: CounterVecHandle,
    pub sessions_active: Arc<Gauge>,
    pub cron_executions_total: CounterVecHandle,
    pub rate_limit_hits_total: CounterVecHandle,
    pub ws_broadcast_drops_total: Arc<Counter>,
    pub matrix_verification_rate_limit_drops_total: Arc<Counter>,
    pub matrix_inbound_dispatch_failures_total: CounterVecHandle,
    pub matrix_inbound_dlq_lost_event_ids_total: Arc<Counter>,
    pub matrix_sync_failures_total: CounterVecHandle,
    pub matrix_unsupported_inbound_total: CounterVecHandle,
    pub matrix_pending_verifications: Arc<Gauge>,
    pub matrix_dlq_records: Arc<Gauge>,
    pub matrix_outbound_send_duration_seconds: Arc<Histogram>,
    pub matrix_sync_cycle_seconds: Arc<Histogram>,
    pub build_info: GaugeVecHandle,
    pub uptime_seconds: Arc<Gauge>,
}

/// Global standard metrics, lazily initialized.
pub static STD_METRICS: LazyLock<StandardMetrics> = LazyLock::new(init_standard_metrics);

/// Register all standard application metrics.
pub fn init_standard_metrics() -> StandardMetrics {
    register_standard_metrics(&METRICS)
}

fn register_standard_metrics(registry: &MetricsRegistry) -> StandardMetrics {
    let http_requests_total = registry.register_counter_vec(
        "carapace_http_requests_total",
        "Total HTTP requests processed",
        &["method", "path", "status"],
    );

    let ws_connections_active = registry.register_gauge(
        "carapace_ws_connections_active",
        "Number of active WebSocket connections",
    );

    let ws_messages_total = registry.register_counter_vec(
        "carapace_ws_messages_total",
        "Total WebSocket messages processed",
        &["method"],
    );

    let agent_runs_total = registry.register_counter_vec(
        "carapace_agent_runs_total",
        "Total agent runs",
        &["provider", "model"],
    );

    let agent_tokens_total = registry.register_counter_vec(
        "carapace_agent_tokens_total",
        "Total agent tokens consumed",
        &["direction"],
    );

    let sessions_active =
        registry.register_gauge("carapace_sessions_active", "Number of active sessions");

    let cron_executions_total = registry.register_counter_vec(
        "carapace_cron_executions_total",
        "Total cron job executions",
        &["status"],
    );

    let rate_limit_hits_total = registry.register_counter_vec(
        "carapace_rate_limit_hits_total",
        "Total rate limit hits",
        &["endpoint"],
    );

    let ws_broadcast_drops_total = registry.register_counter(
        "carapace_ws_broadcast_drops_total",
        "Total WebSocket broadcast frames dropped due to backpressure or closed clients",
    );

    let matrix_verification_rate_limit_drops_total = registry.register_counter(
        "carapace_matrix_verification_rate_limit_drops_total",
        "Total Matrix verification broadcast notifications dropped by rate limiting",
    );

    let matrix_inbound_dispatch_failures_total = registry.register_counter_vec(
        "carapace_matrix_inbound_dispatch_failures_total",
        "Total Matrix inbound dispatch failures by failure stage",
        &["failure_stage"],
    );

    let matrix_inbound_dlq_lost_event_ids_total = registry.register_counter(
        "carapace_matrix_inbound_dlq_lost_event_ids_total",
        "Total Matrix inbound event ids lost during DLQ replay cleanup",
    );

    let matrix_sync_failures_total = registry.register_counter_vec(
        "carapace_matrix_sync_failures_total",
        "Total Matrix sync failures classified by retry decision",
        &["class"],
    );

    let matrix_unsupported_inbound_total = registry.register_counter_vec(
        "carapace_matrix_unsupported_inbound_total",
        "Total unsupported Matrix inbound events by kind",
        &["kind"],
    );

    let matrix_pending_verifications = registry.register_gauge(
        "carapace_matrix_pending_verifications",
        "Current Matrix verification records pending in daemon memory",
    );

    let matrix_dlq_records = registry.register_gauge(
        "carapace_matrix_dlq_records",
        "Matrix inbound DLQ records observed during maintenance sampling",
    );

    let matrix_outbound_send_duration_seconds = registry.register_histogram(
        "carapace_matrix_outbound_send_duration_seconds",
        "Matrix outbound send duration in seconds",
        vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
    );

    let matrix_sync_cycle_seconds = registry.register_histogram(
        "carapace_matrix_sync_cycle_seconds",
        "Matrix sync cycle duration in seconds, including Matrix long-poll wait",
        vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
    );

    let build_info =
        registry.register_gauge_vec("carapace_build_info", "Build information", &["version"]);
    registry.gauge_vec_set("carapace_build_info", &[env!("CARGO_PKG_VERSION")], 1.0);

    let uptime_seconds =
        registry.register_gauge("carapace_uptime_seconds", "Gateway uptime in seconds");

    StandardMetrics {
        http_requests_total,
        ws_connections_active,
        ws_messages_total,
        agent_runs_total,
        agent_tokens_total,
        sessions_active,
        cron_executions_total,
        rate_limit_hits_total,
        ws_broadcast_drops_total,
        matrix_verification_rate_limit_drops_total,
        matrix_inbound_dispatch_failures_total,
        matrix_inbound_dlq_lost_event_ids_total,
        matrix_sync_failures_total,
        matrix_unsupported_inbound_total,
        matrix_pending_verifications,
        matrix_dlq_records,
        matrix_outbound_send_duration_seconds,
        matrix_sync_cycle_seconds,
        build_info,
        uptime_seconds,
    }
}

// ---------------------------------------------------------------------------
// Axum handler
// ---------------------------------------------------------------------------

/// Axum handler that returns all metrics in Prometheus text exposition format.
pub async fn metrics_handler() -> impl IntoResponse {
    let body = METRICS.render();
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(body)
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a fresh isolated registry for testing.
    fn new_registry() -> MetricsRegistry {
        MetricsRegistry::default()
    }

    #[test]
    fn test_counter_default_zero() {
        let c = Counter::default();
        assert_eq!(c.get(), 0);
    }

    #[test]
    fn test_counter_inc() {
        let c = Counter::default();
        c.inc();
        assert_eq!(c.get(), 1);
        c.inc();
        assert_eq!(c.get(), 2);
    }

    #[test]
    fn test_counter_inc_by() {
        let c = Counter::default();
        c.inc_by(10);
        assert_eq!(c.get(), 10);
        c.inc_by(5);
        assert_eq!(c.get(), 15);
    }

    #[test]
    fn test_gauge_default_zero() {
        let g = Gauge::default();
        assert_eq!(g.get(), 0.0);
    }

    #[test]
    fn test_gauge_set() {
        let g = Gauge::default();
        g.set(42.5);
        assert!((g.get() - 42.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_gauge_inc_dec() {
        let g = Gauge::default();
        g.inc();
        assert!((g.get() - 1.0).abs() < f64::EPSILON);
        g.inc();
        assert!((g.get() - 2.0).abs() < f64::EPSILON);
        g.dec();
        assert!((g.get() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_gauge_negative() {
        let g = Gauge::default();
        g.set(-2.75);
        assert!((g.get() - (-2.75)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_observe() {
        let h = Histogram::new(vec![1.0, 5.0, 10.0]);
        h.observe(0.5);
        h.observe(3.0);
        h.observe(7.0);
        h.observe(15.0);

        assert_eq!(h.get_count(), 4);
        assert!((h.get_sum() - 25.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_empty() {
        let h = Histogram::new(vec![1.0, 5.0, 10.0]);
        assert_eq!(h.get_count(), 0);
        assert!((h.get_sum()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_registry_counter() {
        let reg = new_registry();
        let c = reg.register_counter("test_counter", "A test counter");
        c.inc();
        c.inc_by(4);

        let output = reg.render();
        assert!(output.contains("# HELP test_counter A test counter"));
        assert!(output.contains("# TYPE test_counter counter"));
        assert!(output.contains("test_counter 5"));
    }

    #[test]
    fn test_registry_gauge() {
        let reg = new_registry();
        let g = reg.register_gauge("test_gauge", "A test gauge");
        g.set(99.0);

        let output = reg.render();
        assert!(output.contains("# HELP test_gauge A test gauge"));
        assert!(output.contains("# TYPE test_gauge gauge"));
        assert!(output.contains("test_gauge 99"));
    }

    #[test]
    fn test_registry_gauge_float() {
        let reg = new_registry();
        let g = reg.register_gauge("test_gauge_f", "Float gauge");
        g.set(2.75);

        let output = reg.render();
        assert!(output.contains("test_gauge_f 2.75"));
    }

    #[test]
    fn test_registry_counter_vec() {
        let reg = new_registry();
        let _handle =
            reg.register_counter_vec("http_total", "HTTP requests", &["method", "status"]);

        reg.counter_vec_inc("http_total", &["GET", "200"]);
        reg.counter_vec_inc("http_total", &["GET", "200"]);
        reg.counter_vec_inc("http_total", &["POST", "201"]);

        let output = reg.render();
        assert!(output.contains("# TYPE http_total counter"));
        assert!(output.contains("http_total{method=\"GET\",status=\"200\"} 2"));
        assert!(output.contains("http_total{method=\"POST\",status=\"201\"} 1"));
    }

    #[test]
    fn test_registry_counter_vec_inc_by() {
        let reg = new_registry();
        let _handle = reg.register_counter_vec("bytes_total", "Bytes", &["dir"]);

        reg.counter_vec_inc_by("bytes_total", &["in"], 100);
        reg.counter_vec_inc_by("bytes_total", &["out"], 200);
        reg.counter_vec_inc_by("bytes_total", &["in"], 50);

        let output = reg.render();
        assert!(output.contains("bytes_total{dir=\"in\"} 150"));
        assert!(output.contains("bytes_total{dir=\"out\"} 200"));
    }

    #[test]
    fn test_registry_histogram_render() {
        let reg = new_registry();
        let h = reg.register_histogram("req_duration", "Request duration", vec![0.1, 0.5, 1.0]);

        h.observe(0.05);
        h.observe(0.3);
        h.observe(0.8);
        h.observe(2.0);

        let output = reg.render();
        assert!(output.contains("# TYPE req_duration histogram"));
        assert!(output.contains("req_duration_bucket{le=\"0.1\"} 1"));
        assert!(output.contains("req_duration_bucket{le=\"0.5\"} 2"));
        assert!(output.contains("req_duration_bucket{le=\"1\"} 3"));
        assert!(output.contains("req_duration_bucket{le=\"+Inf\"} 4"));
        assert!(output.contains("req_duration_count 4"));
    }

    #[test]
    fn test_registry_histogram_buckets_cumulative() {
        let reg = new_registry();
        let h = reg.register_histogram("lat", "Latency", vec![1.0, 5.0, 10.0]);

        h.observe(0.5);
        h.observe(3.0);
        h.observe(7.0);

        let output = reg.render();
        assert!(output.contains("lat_bucket{le=\"1\"} 1"));
        assert!(output.contains("lat_bucket{le=\"5\"} 2"));
        assert!(output.contains("lat_bucket{le=\"10\"} 3"));
        assert!(output.contains("lat_bucket{le=\"+Inf\"} 3"));
        assert!(output.contains("lat_count 3"));
    }

    #[test]
    fn test_escape_label_value_quotes() {
        let escaped = escape_label_value("say \"hello\"");
        assert_eq!(escaped, "say \\\"hello\\\"");
    }

    #[test]
    fn test_escape_label_value_backslash() {
        let escaped = escape_label_value("path\\to\\thing");
        assert_eq!(escaped, "path\\\\to\\\\thing");
    }

    #[test]
    fn test_escape_label_value_newline() {
        let escaped = escape_label_value("line1\nline2");
        assert_eq!(escaped, "line1\\nline2");
    }

    #[test]
    fn test_format_labels() {
        let names = vec!["method".to_string(), "status".to_string()];
        let values = vec!["GET".to_string(), "200".to_string()];
        let result = format_labels(&names, &values);
        assert_eq!(result, "{method=\"GET\",status=\"200\"}");
    }

    #[test]
    fn test_render_empty_registry() {
        let reg = new_registry();
        let output = reg.render();
        assert!(output.is_empty());
    }

    #[test]
    fn test_render_multiple_metrics() {
        let reg = new_registry();
        let c = reg.register_counter("m_counter", "A counter");
        let g = reg.register_gauge("m_gauge", "A gauge");

        c.inc_by(10);
        g.set(42.0);

        let output = reg.render();
        assert!(output.contains("# HELP m_counter A counter"));
        assert!(output.contains("m_counter 10"));
        assert!(output.contains("# HELP m_gauge A gauge"));
        assert!(output.contains("m_gauge 42"));
    }

    #[test]
    fn test_counter_vec_handle_inc() {
        let reg = new_registry();
        let _handle = reg.register_counter_vec("handle_test", "Test", &["key"]);
        reg.counter_vec_inc("handle_test", &["val"]);
        let output = reg.render();
        assert!(output.contains("handle_test{key=\"val\"} 1"));
    }

    #[test]
    fn test_gauge_vec() {
        let reg = new_registry();
        let _handle = reg.register_gauge_vec("build_info", "Build", &["version"]);
        reg.gauge_vec_set("build_info", &["1.0.0"], 1.0);

        let output = reg.render();
        assert!(output.contains("# TYPE build_info gauge"));
        assert!(output.contains("build_info{version=\"1.0.0\"} 1"));
    }

    #[test]
    fn test_standard_metrics_registered() {
        let _ = &*STD_METRICS;

        let output = METRICS.render();
        assert!(output.contains("carapace_http_requests_total"));
        assert!(output.contains("carapace_ws_connections_active"));
        assert!(output.contains("carapace_ws_messages_total"));
        assert!(output.contains("carapace_agent_runs_total"));
        assert!(output.contains("carapace_agent_tokens_total"));
        assert!(output.contains("carapace_sessions_active"));
        assert!(output.contains("carapace_cron_executions_total"));
        assert!(output.contains("carapace_rate_limit_hits_total"));
        assert!(output.contains("carapace_build_info"));
        assert!(output.contains("carapace_uptime_seconds"));
        assert!(output.contains("carapace_matrix_inbound_dispatch_failures_total"));
        assert!(output.contains("carapace_matrix_inbound_dlq_lost_event_ids_total"));
        assert!(output.contains("carapace_matrix_sync_failures_total"));
        assert!(output.contains("carapace_matrix_unsupported_inbound_total"));
        assert!(output.contains("carapace_matrix_pending_verifications"));
        assert!(output.contains("carapace_matrix_dlq_records"));
        assert!(output.contains("carapace_matrix_outbound_send_duration_seconds"));
        assert!(output.contains("carapace_matrix_sync_cycle_seconds"));
    }

    #[test]
    fn test_matrix_standard_metrics_render_labels_and_buckets() {
        let reg = new_registry();
        let metrics = register_standard_metrics(&reg);

        reg.counter_vec_inc(
            "carapace_matrix_inbound_dispatch_failures_total",
            &["dispatch"],
        );
        reg.counter_vec_inc(
            "carapace_matrix_inbound_dispatch_failures_total",
            &["dlq_append"],
        );
        metrics.matrix_inbound_dlq_lost_event_ids_total.inc_by(3);
        reg.counter_vec_inc("carapace_matrix_sync_failures_total", &["transient"]);
        reg.counter_vec_inc("carapace_matrix_sync_failures_total", &["permanent"]);
        reg.counter_vec_inc(
            "carapace_matrix_unsupported_inbound_total",
            &["encrypted_room"],
        );
        reg.counter_vec_inc("carapace_matrix_unsupported_inbound_total", &["msgtype"]);
        reg.counter_vec_inc("carapace_matrix_unsupported_inbound_total", &["oversize"]);
        metrics.matrix_pending_verifications.set(2.0);
        metrics.matrix_dlq_records.set(7.0);
        metrics.matrix_outbound_send_duration_seconds.observe(0.25);
        metrics.matrix_sync_cycle_seconds.observe(30.0);

        let output = reg.render();
        assert!(output.contains(
            "carapace_matrix_inbound_dispatch_failures_total{failure_stage=\"dispatch\"} 1"
        ));
        assert!(output.contains(
            "carapace_matrix_inbound_dispatch_failures_total{failure_stage=\"dlq_append\"} 1"
        ));
        assert!(output.contains("carapace_matrix_inbound_dlq_lost_event_ids_total 3"));
        assert!(output.contains("carapace_matrix_sync_failures_total{class=\"transient\"} 1"));
        assert!(output.contains("carapace_matrix_sync_failures_total{class=\"permanent\"} 1"));
        assert!(
            output.contains("carapace_matrix_unsupported_inbound_total{kind=\"encrypted_room\"} 1")
        );
        assert!(output.contains("carapace_matrix_unsupported_inbound_total{kind=\"msgtype\"} 1"));
        assert!(output.contains("carapace_matrix_unsupported_inbound_total{kind=\"oversize\"} 1"));
        assert!(output.contains("carapace_matrix_pending_verifications 2"));
        assert!(output.contains("carapace_matrix_dlq_records 7"));
        for bucket in ["0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "30"] {
            assert!(output.contains(&format!(
                "carapace_matrix_outbound_send_duration_seconds_bucket{{le=\"{bucket}\"}}"
            )));
        }
        for bucket in ["1", "5", "10", "30", "60", "120", "300"] {
            assert!(output.contains(&format!(
                "carapace_matrix_sync_cycle_seconds_bucket{{le=\"{bucket}\"}}"
            )));
        }
        assert!(output.contains("carapace_matrix_outbound_send_duration_seconds_count 1"));
        assert!(output.contains("carapace_matrix_sync_cycle_seconds_count 1"));
    }

    #[tokio::test]
    async fn test_metrics_handler_response() {
        let response = metrics_handler().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");
    }

    #[test]
    fn test_histogram_boundary_value() {
        let h = Histogram::new(vec![1.0, 5.0]);
        h.observe(1.0);
        h.observe(5.0);

        assert_eq!(h.get_count(), 2);
        assert_eq!(h.counts[0].load(Ordering::Relaxed), 1);
        assert_eq!(h.counts[1].load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_gauge_set_overwrite() {
        let g = Gauge::default();
        g.set(1.0);
        g.set(2.0);
        g.set(3.0);
        assert!((g.get() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_format_bound_integer() {
        assert_eq!(format_bound(1.0), "1");
        assert_eq!(format_bound(10.0), "10");
    }

    #[test]
    fn test_format_bound_float() {
        assert_eq!(format_bound(0.5), "0.5");
        assert_eq!(format_bound(2.5), "2.5");
    }

    #[test]
    fn test_metric_type_as_str() {
        assert_eq!(MetricType::Counter.as_str(), "counter");
        assert_eq!(MetricType::Gauge.as_str(), "gauge");
        assert_eq!(MetricType::Histogram.as_str(), "histogram");
    }
}
