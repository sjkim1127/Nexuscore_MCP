use anyhow::Result;
use serde_json::Value;
use crate::engine::frida_handler;
use crate::tools::Tool;
use async_trait::async_trait;

pub struct SpawnProcess;
#[async_trait]
impl Tool for SpawnProcess {
    fn name(&self) -> &str { "spawn_process" }
    fn description(&self) -> &str { "Spawns a process in suspended state. Args: path (string), args (array of strings)" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let path = args["path"].as_str().ok_or(anyhow::anyhow!("Missing path"))?;
        let argv = args["args"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or(vec![]);

        let pid = frida_handler::spawn(path, &argv)?;
        
        Ok(serde_json::json!({
            "status": "spawned",
            "pid": pid,
            "state": "suspended"
        }))
    }
}

pub struct AttachProcess;
#[async_trait]
impl Tool for AttachProcess {
    fn name(&self) -> &str { "attach_process" }
    fn description(&self) -> &str { "Attaches to a running process. Args: pid (number)" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))? as u32;
        frida_handler::attach(pid)?;
        Ok(serde_json::json!({ "status": "attached", "pid": pid }))
    }
}

pub struct ResumeProcess;
#[async_trait]
impl Tool for ResumeProcess {
    fn name(&self) -> &str { "resume_process" }
    fn description(&self) -> &str { "Resumes a suspended process. Args: pid (number)" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))? as u32;
        frida_handler::resume(pid)?;
        Ok(serde_json::json!({ "status": "resumed", "pid": pid }))
    }
}
