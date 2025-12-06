use anyhow::Result;
use serde_json::Value;
use crate::tools::{Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use crate::utils::logging::get_metrics;
use async_trait::async_trait;

/// Get system metrics
pub struct MetricsTool;

#[async_trait]
impl Tool for MetricsTool {
    fn name(&self) -> &str { "get_metrics" }
    fn description(&self) -> &str { "Returns NexusCore performance metrics (tool calls, cache stats, timings)" }
    fn schema(&self) -> ToolSchema { ToolSchema::empty() }

    async fn execute(&self, _args: Value) -> Result<Value> {
        let tool_name = self.name();
        let stats = get_metrics().get_stats();
        Ok(StandardResponse::success(tool_name, stats))
    }
}
