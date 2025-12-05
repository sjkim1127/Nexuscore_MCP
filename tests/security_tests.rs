use nexuscore_mcp::tools::etw::EtwMonitor;
use nexuscore_mcp::tools::yara::YaraScanner;
use nexuscore_mcp::tools::defender::DefenderBot;
use nexuscore_mcp::tools::Tool;
use serde_json::json;

#[tokio::test]
async fn test_etw_monitor_metadata() {
    let tool = EtwMonitor;
    assert_eq!(tool.name(), "etw_monitor");
}

#[tokio::test]
async fn test_yara_scanner_metadata() {
    let tool = YaraScanner;
    assert_eq!(tool.name(), "yara_scan");
}

#[tokio::test]
async fn test_yara_scanner_missing_rule() {
    let tool = YaraScanner;
    let result = tool.execute(json!({"target_pid": 1234})).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_defender_bot_metadata() {
    let tool = DefenderBot;
    assert_eq!(tool.name(), "defender_bot");
}
