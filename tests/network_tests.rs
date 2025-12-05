use nexuscore_mcp::tools::common::network::NetworkCapture;
use nexuscore_mcp::tools::malware::proxy::HttpsProxy;
use nexuscore_mcp::tools::Tool;
use serde_json::json;

#[tokio::test]
async fn test_network_capture_metadata() {
    let tool = NetworkCapture;
    assert_eq!(tool.name(), "network_capture");
}

#[tokio::test]
async fn test_network_capture_invalid_action() {
    let tool = NetworkCapture;
    let result = tool.execute(json!({"action": "invalid"})).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_https_proxy_metadata() {
    let tool = HttpsProxy;
    assert_eq!(tool.name(), "https_proxy");
}
