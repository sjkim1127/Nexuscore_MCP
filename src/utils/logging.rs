use tracing::{info, warn, error, debug, instrument, Level};
use std::time::Instant;
use serde_json::Value;

/// Log tool execution with timing
#[instrument(skip(result), fields(duration_ms))]
pub fn log_tool_execution(tool_name: &str, args: &Value, result: &Value, start: Instant) {
    let duration = start.elapsed().as_millis();
    
    let status = result["status"].as_str().unwrap_or("unknown");
    let cached = result["metadata"]["cached"].as_bool().unwrap_or(false);
    
    if status == "success" {
        if cached {
            info!(
                tool = tool_name,
                duration_ms = duration,
                cached = true,
                "Tool execution (cached)"
            );
        } else {
            info!(
                tool = tool_name,
                duration_ms = duration,
                "Tool execution complete"
            );
        }
    } else if status == "error" {
        let err_msg = result["error"].as_str().unwrap_or("Unknown error");
        error!(
            tool = tool_name,
            error = err_msg,
            duration_ms = duration,
            "Tool execution failed"
        );
    } else {
        warn!(
            tool = tool_name,
            status = status,
            duration_ms = duration,
            "Tool execution partial"
        );
    }
}

/// Log Frida session events
pub fn log_frida_event(event_type: &str, session_id: &str, details: &str) {
    info!(
        event = event_type,
        session = session_id,
        details = details,
        "Frida event"
    );
}

/// Log cache operations
pub fn log_cache_event(operation: &str, key: &str, hit: bool) {
    debug!(
        op = operation,
        key = key,
        hit = hit,
        "Cache event"
    );
}

/// Log external tool execution
pub fn log_external_tool(tool: &str, file: &str, exit_code: i32, duration_ms: u64) {
    if exit_code == 0 {
        info!(
            tool = tool,
            file = file,
            exit_code = exit_code,
            duration_ms = duration_ms,
            "External tool completed"
        );
    } else {
        warn!(
            tool = tool,
            file = file,
            exit_code = exit_code,
            duration_ms = duration_ms,
            "External tool failed"
        );
    }
}

/// Log session lifecycle
pub fn log_session_lifecycle(action: &str, session_id: &str, pid: Option<u32>) {
    info!(
        action = action,
        session = session_id,
        pid = pid,
        "Session lifecycle"
    );
}

/// Performance metrics tracker
pub struct PerfMetrics {
    pub tool_calls: std::sync::atomic::AtomicU64,
    pub cache_hits: std::sync::atomic::AtomicU64,
    pub cache_misses: std::sync::atomic::AtomicU64,
    pub total_duration_ms: std::sync::atomic::AtomicU64,
}

impl PerfMetrics {
    pub fn new() -> Self {
        Self {
            tool_calls: std::sync::atomic::AtomicU64::new(0),
            cache_hits: std::sync::atomic::AtomicU64::new(0),
            cache_misses: std::sync::atomic::AtomicU64::new(0),
            total_duration_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_call(&self, duration_ms: u64, cached: bool) {
        use std::sync::atomic::Ordering;
        self.tool_calls.fetch_add(1, Ordering::Relaxed);
        self.total_duration_ms.fetch_add(duration_ms, Ordering::Relaxed);
        if cached {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get_stats(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering;
        serde_json::json!({
            "total_calls": self.tool_calls.load(Ordering::Relaxed),
            "cache_hits": self.cache_hits.load(Ordering::Relaxed),
            "cache_misses": self.cache_misses.load(Ordering::Relaxed),
            "total_duration_ms": self.total_duration_ms.load(Ordering::Relaxed),
            "cache_hit_rate": {
                let hits = self.cache_hits.load(Ordering::Relaxed) as f64;
                let total = (self.cache_hits.load(Ordering::Relaxed) + self.cache_misses.load(Ordering::Relaxed)) as f64;
                if total > 0.0 { hits / total * 100.0 } else { 0.0 }
            }
        })
    }
}

/// Global metrics instance
static METRICS: std::sync::OnceLock<PerfMetrics> = std::sync::OnceLock::new();

pub fn get_metrics() -> &'static PerfMetrics {
    METRICS.get_or_init(|| PerfMetrics::new())
}

/// Initialize logging with appropriate level
pub fn init_logging(level: Level) {
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}
