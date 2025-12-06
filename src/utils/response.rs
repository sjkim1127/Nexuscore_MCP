use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseStatus { Success, Error, Partial }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached: Option<bool>,
    pub version: String,
}

impl Default for ResponseMetadata {
    fn default() -> Self { Self { duration_ms: 0, cached: None, version: "1.0".to_string() } }
}

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

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl StandardResponse {
    pub fn success(tool: &str, data: Value) -> Value {
        serde_json::to_value(Self {
            tool: tool.to_string(), status: ResponseStatus::Success, timestamp: current_timestamp(),
            data, metadata: ResponseMetadata::default(), error: None,
        }).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    pub fn success_timed(tool: &str, data: Value, start: Instant) -> Value {
        serde_json::to_value(Self {
            tool: tool.to_string(), status: ResponseStatus::Success, timestamp: current_timestamp(),
            data, metadata: ResponseMetadata { duration_ms: start.elapsed().as_millis() as u64, cached: None, version: "1.0".to_string() }, error: None,
        }).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    pub fn success_cached(tool: &str, data: Value) -> Value {
        serde_json::to_value(Self {
            tool: tool.to_string(), status: ResponseStatus::Success, timestamp: current_timestamp(),
            data, metadata: ResponseMetadata { duration_ms: 0, cached: Some(true), version: "1.0".to_string() }, error: None,
        }).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    pub fn error(tool: &str, message: &str) -> Value {
        serde_json::to_value(Self {
            tool: tool.to_string(), status: ResponseStatus::Error, timestamp: current_timestamp(),
            data: Value::Null, metadata: ResponseMetadata::default(), error: Some(message.to_string()),
        }).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }

    pub fn partial(tool: &str, data: Value, warning: &str) -> Value {
        serde_json::to_value(Self {
            tool: tool.to_string(), status: ResponseStatus::Partial, timestamp: current_timestamp(),
            data, metadata: ResponseMetadata::default(), error: Some(warning.to_string()),
        }).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))
    }
}
