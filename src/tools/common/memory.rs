#![cfg(feature = "dynamic-analysis")]
use crate::engine::frida_handler;
use crate::tools::Tool;
use crate::utils::response::StandardResponse;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

pub struct ReadMemory;
#[async_trait]
impl Tool for ReadMemory {
    fn name(&self) -> &str {
        "read_memory"
    }
    fn description(&self) -> &str {
        "Reads memory from a process. Args: pid (number), address (string), size (number, optional)"
    }
    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();
        let pid = match args["pid"].as_u64() {
            Some(p) => p as u32,
            None => return Ok(StandardResponse::error(tool_name, "Missing pid")),
        };
        let address = match args["address"].as_str() {
            Some(a) => a,
            None => return Ok(StandardResponse::error(tool_name, "Missing address")),
        };
        let size = args["size"].as_u64().unwrap_or(256);

        // Frida script to read memory
        let script = format!(
            r#"
            var ptr = ptr("{}");
            var buf = Memory.readByteArray(ptr, {});
            send({{ "type": "memory_read", "data": buf }});
        "#,
            address, size
        );

        frida_handler::execute_script(pid, &script).await?;
        Ok(serde_json::json!({ "status": "reading", "pid": pid, "address": address }))
    }
}

pub struct SearchMemory;
#[async_trait]
impl Tool for SearchMemory {
    fn name(&self) -> &str {
        "search_memory"
    }
    fn description(&self) -> &str {
        "Searches memory for a pattern. Args: pid (number), pattern (string)"
    }
    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();
        let pid = match args["pid"].as_u64() {
            Some(p) => p as u32,
            None => return Ok(StandardResponse::error(tool_name, "Missing pid")),
        };
        let pattern = match args["pattern"].as_str() {
            Some(p) => p,
            None => return Ok(StandardResponse::error(tool_name, "Missing pattern")),
        };

        let script = format!(
            r#"
            var ranges = Process.enumerateRanges('rw-');
            var results = [];
            ranges.forEach(function(range) {{
                try {{
                    var matches = Memory.scanSync(range.base, range.size, "{}");
                    matches.forEach(function(match) {{
                        results.push(match.address);
                    }});
                }} catch (e) {{}}
            }});
            send({{ "type": "scan_result", "matches": results }});
        "#,
            pattern
        );

        frida_handler::execute_script(pid, &script).await?;

        Ok(serde_json::json!({ "status": "scanning", "pid": pid }))
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(ReadMemory))
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(SearchMemory))
}
