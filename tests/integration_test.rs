//! Integration tests for NexusCore MCP

use nexuscore_mcp::tools::Tool;
use nexuscore_mcp::utils::response::StandardResponse;
use serde_json::json;

/// Helper to run async tests
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(f)
}

/// Test that all tools return valid StandardResponse format
#[cfg(test)]
mod response_format_tests {
    use super::*;

    fn validate_response(result: serde_json::Value) {
        // Must have these fields
        assert!(result.get("tool").is_some(), "Missing 'tool' field");
        assert!(result.get("status").is_some(), "Missing 'status' field");
        assert!(
            result.get("timestamp").is_some(),
            "Missing 'timestamp' field"
        );

        // Status must be one of: success, error, partial
        let status = result["status"].as_str().unwrap();
        assert!(
            ["success", "error", "partial"].contains(&status),
            "Invalid status: {}",
            status
        );

        // If error, must have error field
        if status == "error" {
            assert!(
                result.get("error").is_some(),
                "Error response missing 'error' field"
            );
        }
    }

    #[test]
    fn test_success_response_format() {
        let result = StandardResponse::success("test", json!({"data": 1}));
        validate_response(result.clone());
        assert_eq!(result["status"], "success");
    }

    #[test]
    fn test_error_response_format() {
        let result = StandardResponse::error("test", "fail");
        validate_response(result.clone());
        assert_eq!(result["status"], "error");
    }

    #[test]
    fn test_cached_response_format() {
        let result = StandardResponse::success_cached("test", json!({}));
        validate_response(result.clone());
        assert_eq!(result["metadata"]["cached"], true);
    }
}

/// Schema validation tests
#[cfg(test)]
mod schema_validation_tests {
    use nexuscore_mcp::tools::{ParamDef, ToolSchema};

    fn validate_json_schema(schema: serde_json::Value) {
        assert_eq!(schema["type"], "object");
        assert!(schema.get("properties").is_some());
        assert!(schema.get("required").is_some());
    }

    #[test]
    fn test_empty_schema_valid() {
        let schema = ToolSchema::empty();
        validate_json_schema(schema.to_json());
    }

    #[test]
    fn test_schema_with_required_params() {
        let schema = ToolSchema::new(vec![
            ParamDef::new("pid", "number", true, "PID"),
            ParamDef::new("path", "string", true, "Path"),
        ]);

        let json = schema.to_json();
        validate_json_schema(json.clone());

        let required = json["required"].as_array().unwrap();
        assert_eq!(required.len(), 2);
    }
}

/// Tool naming convention tests
#[cfg(test)]
mod naming_convention_tests {
    use super::*;
    use nexuscore_mcp::tools::common::metrics::MetricsTool;

    #[test]
    fn test_tool_name_snake_case() {
        let tool = MetricsTool;
        let name = tool.name();

        // Name should be snake_case
        assert!(name
            .chars()
            .all(|c| c.is_lowercase() || c == '_' || c.is_numeric()));
        assert!(!name.contains('-'));
        assert!(!name.contains(' '));
    }

    #[test]
    fn test_tool_has_description() {
        let tool = MetricsTool;
        let desc = tool.description();

        assert!(!desc.is_empty());
        assert!(desc.len() > 10); // Should be meaningful
    }
}

/// Metrics tool integration test
#[cfg(test)]
mod metrics_integration_tests {
    use super::*;
    use nexuscore_mcp::tools::common::metrics::MetricsTool;

    #[test]
    fn test_metrics_tool_execution() {
        let tool = MetricsTool;

        let result = block_on(tool.execute(json!({})));
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response["status"], "success");
        assert!(response["data"].get("total_calls").is_some());
        assert!(response["data"].get("cache_hit_rate").is_some());
    }
}
