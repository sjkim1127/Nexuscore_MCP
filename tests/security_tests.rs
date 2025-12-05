use nexuscore_mcp::tools::malware::etw::EtwMonitor;
use nexuscore_mcp::tools::malware::yara::YaraScanner;
use nexuscore_mcp::tools::malware::defender::DefenderBot;
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
async fn test_yara_rule_compilation() {
    let tool = YaraScanner;
    
    // Valid Rule
    let valid_rule = r#"
        rule TestRule {
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    
    // We pass a dummy file path just to trigger compilation check logic inside execute if possible,
    // or we assume execute compiles rules first. The current impl compiles immediately.
    // We pass file_path as "Cargo.toml" which exists, so it should run.
    let result = tool.execute(json!({
        "rule": valid_rule, 
        "file_path": "Cargo.toml"
    })).await;
    
    assert!(result.is_ok(), "Valid Yara rule failed to compile/scan");
    
    // Invalid Rule (Syntax Error)
    let invalid_rule = "rule Broken { strings: $a = condition: }";
    let result = tool.execute(json!({
        "rule": invalid_rule,
        "file_path": "Cargo.toml"
    })).await;
    
    assert!(result.is_err(), "Invalid Yara rule should return error");
}
