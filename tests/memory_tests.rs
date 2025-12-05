use nexuscore_mcp::tools::memory::{ReadMemory, SearchMemory};
use nexuscore_mcp::tools::hook::InstallHook;
use nexuscore_mcp::tools::Tool;
use serde_json::json;

#[tokio::test]
async fn test_read_memory_metadata() {
    let tool = ReadMemory;
    assert_eq!(tool.name(), "read_memory");
}

#[tokio::test]
async fn test_read_memory_missing_pid() {
    let tool = ReadMemory;
    let result = tool.execute(json!({"address": "0x1234"})).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_install_hook_metadata() {
    let tool = InstallHook;
    assert_eq!(tool.name(), "install_hook");
}
