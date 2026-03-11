#![cfg(feature = "dynamic-analysis")]
use nexuscore_mcp::tools::common::process::{AttachProcess, SpawnProcess};
use nexuscore_mcp::tools::Tool;
use serde_json::json;

#[tokio::test]
async fn test_spawn_process_metadata() {
    let tool = SpawnProcess;
    assert_eq!(tool.name(), "spawn_process");
    assert!(!tool.description().is_empty());
}

#[tokio::test]
async fn test_spawn_process_missing_args() {
    let tool = SpawnProcess;
    let result = tool.execute(json!({})).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["status"], "error");
    assert!(response["error"].as_str().unwrap().contains("Missing path"));
}

#[tokio::test]
async fn test_attach_process_metadata() {
    let tool = AttachProcess;
    assert_eq!(tool.name(), "attach_process");
}
