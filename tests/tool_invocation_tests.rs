use nexuscore_mcp::tools::ToolRegistration;
use serde_json::json;

#[tokio::test]
async fn test_metrics_tool_invocation() {
    // 1. Find the get_metrics tool in the registry
    let metrics_tool = inventory::iter::<ToolRegistration>()
        .find(|reg| (reg.create)().name() == "get_metrics")
        .expect("Metrics tool NOT found in registry!");

    let tool = (metrics_tool.create)();

    // 2. Execute it
    let result = tool.execute(json!({})).await;

    // 3. Validate response
    assert!(result.is_ok(), "Tool execution failed: {:?}", result.err());
    let response = result.unwrap();

    assert_eq!(response["tool"], "get_metrics");
    assert_eq!(response["status"], "success");
    assert!(response["data"].get("total_calls").is_some());
    assert!(!response["timestamp"].is_null());
}

#[tokio::test]
async fn test_shellcode_emu_invocation() {
    let registration = inventory::iter::<ToolRegistration>()
        .find(|reg| (reg.create)().name() == "emulate_shellcode");

    if let Some(reg) = registration {
        let tool = (reg.create)();
        let result = tool
            .execute(json!({
                "code": "90C3", // NOP; RET
                "arch": "x64"
            }))
            .await;

        assert!(
            result.is_ok(),
            "Shellcode emulation failed: {:?}",
            result.err()
        );
        let response = result.unwrap();
        // It might be "success" or "partial" depending on the environment,
        // but it should return a valid StandardResponse.
        assert!(response["status"] == "success" || response["status"] == "partial");
        assert_eq!(response["tool"], "emulate_shellcode");
    }
}
