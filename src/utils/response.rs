use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH, Instant};

/// Status of tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseStatus {
    Success,
    Error,
    Partial,
}

/// Metadata about the response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached: Option<bool>,
    pub version: String,
}

impl Default for ResponseMetadata {
    fn default() -> Self {
        Self {
            duration_ms: 0,
            cached: None,
            version: "1.0".to_string(),
        }
    }
}

/// Standardized response format for all NexusCore tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardResponse {
    pub tool: String,
    pub status: ResponseStatus,
    pub timestamp: u64,
    pub data: Value,
    pub metadata: ResponseMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl StandardResponse {
    /// Create a success response
    pub fn success(tool: &str, data: Value) -> Value {
        let response = Self {
            tool: tool.to_string(),
            status: ResponseStatus::Success,
            timestamp: current_timestamp(),
            data,
            metadata: ResponseMetadata::default(),
            error: None,
        };
        serde_json::to_value(response).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    /// Create a success response with timing
    pub fn success_timed(tool: &str, data: Value, start: Instant) -> Value {
        let duration = start.elapsed().as_millis() as u64;
        let response = Self {
            tool: tool.to_string(),
            status: ResponseStatus::Success,
            timestamp: current_timestamp(),
            data,
            metadata: ResponseMetadata {
                duration_ms: duration,
                cached: None,
                version: "1.0".to_string(),
            },
            error: None,
        };
        serde_json::to_value(response).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    /// Create a success response with cache info
    pub fn success_cached(tool: &str, data: Value, cached: bool) -> Value {
        let response = Self {
            tool: tool.to_string(),
            status: ResponseStatus::Success,
            timestamp: current_timestamp(),
            data,
            metadata: ResponseMetadata {
                duration_ms: 0,
                cached: Some(cached),
                version: "1.0".to_string(),
            },
            error: None,
        };
        serde_json::to_value(response).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    /// Create an error response
    pub fn error(tool: &str, message: &str) -> Value {
        let response = Self {
            tool: tool.to_string(),
            status: ResponseStatus::Error,
            timestamp: current_timestamp(),
            data: Value::Null,
            metadata: ResponseMetadata::default(),
            error: Some(message.to_string()),
        };
        serde_json::to_value(response).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    /// Create a partial success response (some data but with warnings)
    pub fn partial(tool: &str, data: Value, warning: &str) -> Value {
        let response = Self {
            tool: tool.to_string(),
            status: ResponseStatus::Partial,
            timestamp: current_timestamp(),
            data,
            metadata: ResponseMetadata::default(),
            error: Some(warning.to_string()),
        };
        serde_json::to_value(response).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convenience macro for creating success responses
#[macro_export]
macro_rules! respond_ok {
    ($tool:expr, $data:expr) => {
        Ok($crate::utils::response::StandardResponse::success($tool, serde_json::json!($data)))
    };
}

/// Convenience macro for creating timed success responses
#[macro_export]
macro_rules! respond_ok_timed {
    ($tool:expr, $data:expr, $start:expr) => {
        Ok($crate::utils::response::StandardResponse::success_timed($tool, serde_json::json!($data), $start))
    };
}

/// Convenience macro for creating error responses
#[macro_export]
macro_rules! respond_err {
    ($tool:expr, $msg:expr) => {
        Ok($crate::utils::response::StandardResponse::error($tool, $msg))
    };
}
