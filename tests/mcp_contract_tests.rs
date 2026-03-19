//! MCP Contract Tests for NexusCore
//! Verifies that the server strictly follows the MCP protocol response format.

#[cfg(test)]
mod contract_tests {
    use nexuscore_mcp::server::NexusCoreServer;
    use serde_json::json;

    #[tokio::test]
    async fn test_sr_02_success_response_structure() {
        let server = NexusCoreServer::new();
        // Use a simple tool that doesn't need external dependencies (e.g., get_metrics)
        let result = server.call_tool_internal("get_metrics".into(), json!({})).await.unwrap();

        // 1. Verify MCP Protocol compliance
        assert!(result.is_error.is_some());
        assert_eq!(result.is_error.unwrap(), false, "Success tool should have is_error: false");
        assert!(result.structured_content.is_some(), "Success tool should have structured_content");

        // 2. Verify StandardResponse structure in structured_content
        let sc = result.structured_content.unwrap();
        assert_eq!(sc["status"], "success");
        assert!(sc["data"].is_object(), "data should be an object");
        assert!(sc["metadata"]["duration_ms"].is_number(), "should have duration_ms");
        assert!(sc["timestamp"].is_number(), "should have timestamp");
    }

    #[tokio::test]
    async fn test_v1_critical_tools_registered() {
        let server = NexusCoreServer::new();

        // Tool exists independent of OS/tools installation.
        let result = server
            .call_tool_internal("check_reputation".into(), json!({ "type": "hash" }))
            .await
            .unwrap();
        assert!(result.is_error.unwrap_or(false));

        // Health check should exist on Windows builds.
        #[cfg(windows)]
        {
            let hc = server
                .call_tool_internal("health_check".into(), json!({}))
                .await
                .unwrap();
            assert!(hc.is_error.is_some());
            assert!(hc.structured_content.is_some());
            assert_eq!(hc.structured_content.as_ref().unwrap()["status"], "success");
        }
    }

    #[tokio::test]
    async fn test_sr_01_error_mapping_unknown_tool() {
        let server = NexusCoreServer::new();
        let result = server.call_tool_internal("non_existent_tool".into(), json!({})).await.unwrap();

        // 1. Verify MCP error signaling
        assert!(result.is_error.unwrap_or(false), "Unknown tool should have is_error: true");
        
        // 2. Check content for error message
        let text = result.content[0].as_text().map(|t| t.text.clone()).unwrap_or_default();
        assert!(text.contains("Unknown tool"), "Error message should mention 'Unknown tool'");
    }

    #[tokio::test]
    async fn test_error_propagation_from_tool() {
        let server = NexusCoreServer::new();
        // Call a tool with invalid arguments to trigger an internal error.
        // Use a tool that exists in the default feature set (static-analysis).
        let result = server.call_tool_internal(
            "check_reputation".into(),
            json!({ "type": "hash" })
        ).await.unwrap();

        // 1. Internal tool error should propagate to MCP is_error
        assert!(result.is_error.unwrap_or(false), "Tool failure should have is_error: true");

        // 2. Verify structured_content contains the error status
        let sc = result.structured_content.as_ref().expect("Failed tool should have structured_content");
        assert_eq!(sc["status"], "error");
        assert!(sc["error"].is_string(), "Error message should be a string");
        assert!(sc["error"].as_str().unwrap().contains("Missing value"), "Error should mention missing argument");
    }

    #[tokio::test]
    async fn test_large_result_summary_structure() {
        use nexuscore_mcp::utils::response::StandardResponse;
        
        // StandardResponse::success_large should have the correct structure
        let tool_name = "test_large";
        let summary = json!({"count": 100});
        let dump_id = "mem_dump_abc";
        
        let res = StandardResponse::success_large(tool_name, summary, dump_id);

        assert_eq!(res["status"], "partial");
        assert!(res["data"]["dump_id"].is_string());
        assert!(res["data"]["resource_uri"].as_str().unwrap().contains("mcp://dumps/"));
        assert!(res["error"].is_string(), "Should have a notice in the error field for LLM");
    }
}
