//! Tests for the StandardResponse module

use nexuscore_mcp::utils::response::StandardResponse;
use serde_json::json;
use std::time::Instant;

#[test]
fn test_success_response() {
    let result = StandardResponse::success("test_tool", json!({"key": "value"}));

    assert_eq!(result["tool"], "test_tool");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["key"], "value");
    assert!(result["timestamp"].as_u64().is_some());
    assert!(result["error"].is_null());
}

#[test]
fn test_success_timed_response() {
    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(10));

    let result = StandardResponse::success_timed("timed_tool", json!({"data": 123}), start);

    assert_eq!(result["tool"], "timed_tool");
    assert_eq!(result["status"], "success");
    assert!(result["metadata"]["duration_ms"].as_u64().unwrap() >= 10);
}

#[test]
fn test_success_cached_response() {
    let result = StandardResponse::success_cached("cached_tool", json!({"cached": true}));

    assert_eq!(result["tool"], "cached_tool");
    assert_eq!(result["status"], "success");
    assert_eq!(result["metadata"]["cached"], true);
}

#[test]
fn test_error_response() {
    let result = StandardResponse::error("error_tool", "Something went wrong");

    assert_eq!(result["tool"], "error_tool");
    assert_eq!(result["status"], "error");
    assert_eq!(result["error"], "Something went wrong");
    assert!(result["data"].is_null());
}

#[test]
fn test_partial_response() {
    let result = StandardResponse::partial(
        "partial_tool",
        json!({"partial_data": [1, 2, 3]}),
        "Some items could not be processed",
    );

    assert_eq!(result["tool"], "partial_tool");
    assert_eq!(result["status"], "partial");
    assert_eq!(result["error"], "Some items could not be processed");
    assert!(!result["data"].is_null());
}

#[test]
fn test_response_has_valid_timestamp() {
    let result = StandardResponse::success("timestamp_test", json!({}));

    let timestamp = result["timestamp"].as_u64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Timestamp should be within 1 second of now
    assert!(timestamp <= now);
    assert!(timestamp >= now - 1);
}

#[test]
fn test_response_version() {
    let result = StandardResponse::success("version_test", json!({}));

    assert_eq!(result["metadata"]["version"], "1.0");
}
