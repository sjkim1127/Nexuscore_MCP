use anyhow::Result;
use serde_json::Value;
use crate::engine::frida_handler;
use crate::tools::Tool;
use async_trait::async_trait;

pub struct ReadMemory;
#[async_trait]
impl Tool for ReadMemory {
    fn name(&self) -> &str { "read_memory" }
    fn description(&self) -> &str { "Reads memory from a process. Args: pid (number), address (string), size (number, optional)" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))? as u32;
        let address = args["address"].as_str().ok_or(anyhow::anyhow!("Missing address"))?;
        let size = args["size"].as_u64().unwrap_or(256);

        // Frida script to read memory
        let script = format!(r#"
            var ptr = ptr("{}");
            var buf = Memory.readByteArray(ptr, {});
            send({{ "type": "memory_read", "data": buf }});
        "#, address, size);

        frida_handler::execute_script(pid, &script)?;
        Ok(serde_json::json!({ "status": "reading", "pid": pid, "address": address }))
    }
}

pub struct SearchMemory;
#[async_trait]
impl Tool for SearchMemory {
    fn name(&self) -> &str { "search_memory" }
    fn description(&self) -> &str { "Searches memory for a pattern. Args: pid (number), pattern (string)" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))? as u32;
        let pattern = args["pattern"].as_str().ok_or(anyhow::anyhow!("Missing pattern"))?;
        
        let script = format!(r#"
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
        "#, pattern);

        frida_handler::execute_script(pid, &script)?;
        
        Ok(serde_json::json!({ "status": "scanning", "pid": pid }))
    }
}
