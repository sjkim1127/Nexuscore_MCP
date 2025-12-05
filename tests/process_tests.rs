use nexuscore_mcp::tools::process::{SpawnProcess, AttachProcess, ResumeProcess};
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
    assert!(result.is_err());
}

#[tokio::test]
async fn test_attach_process_metadata() {
    let tool = AttachProcess;
    assert_eq!(tool.name(), "attach_process");
}
