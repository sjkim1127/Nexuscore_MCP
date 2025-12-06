use anyhow::Result;
use serde_json::Value;
use crate::tools::{Tool, ToolSchema, ParamDef};
use crate::utils::response::StandardResponse;
use async_trait::async_trait;
use crate::engine::frida_handler::FridaHandler;
use std::time::Instant;

pub struct InjectFridaScript;

#[async_trait]
impl Tool for InjectFridaScript {
    fn name(&self) -> &str { "inject_frida_script" }
    fn description(&self) -> &str { "Injects a custom Frida script (JavaScript) into a running process. Args: pid (number), script (string)" }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("pid", "number", true, "Target process ID"),
            ParamDef::new("script", "string", true, "JavaScript code to inject"),
        ])
    }
    
    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        
        let pid = match args["pid"].as_u64() {
            Some(p) => p as u32,
            None => return Ok(StandardResponse::error(tool_name, "Missing pid")),
        };
        let script = match args["script"].as_str() {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Missing script content")),
        };
        
        let engine = FridaHandler::new();
        if let Err(e) = engine.inject_script(pid, script).await {
            return Ok(StandardResponse::error(tool_name, &e.to_string()));
        }
        
        Ok(StandardResponse::success_timed(tool_name, serde_json::json!({ 
            "pid": pid,
            "script_length": script.len()
        }), start))
    }
}

pub struct SpawnProcess;

#[async_trait]
impl Tool for SpawnProcess {
    fn name(&self) -> &str { "spawn_process" }
    fn description(&self) -> &str { "Spawns a process in suspended state (Frida) & injects stealth hooks. Args: path, stealth (bool, default true)" }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("path", "string", true, "Path to executable"),
            ParamDef::new("stealth", "boolean", false, "Enable stealth mode (default: true)"),
        ])
    }
    
    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        
        let path = match args["path"].as_str() {
            Some(p) => p,
            None => return Ok(StandardResponse::error(tool_name, "Missing path")),
        };
        let stealth = args["stealth"].as_bool().unwrap_or(true);
        
        let engine = FridaHandler::new();
        let mut script_content = String::new();
        if stealth {
            script_content = include_str!("../../resources/scripts/stealth_unpacker.js").to_string();
        }

        match engine.spawn_and_instrument(path, &script_content).await {
            Ok(pid) => Ok(StandardResponse::success_timed(tool_name, serde_json::json!({ 
                "pid": pid, 
                "path": path,
                "stealth_mode": stealth
            }), start)),
            Err(e) => Ok(StandardResponse::error(tool_name, &e.to_string())),
        }
    }
}

pub struct AttachProcess;

#[async_trait]
impl Tool for AttachProcess {
    fn name(&self) -> &str { "attach_process" }
    fn description(&self) -> &str { "Attaches to a running process. Args: pid (number)" }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ ParamDef::new("pid", "number", true, "Target process ID") ])
    }
    
    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        
        let pid = match args["pid"].as_u64() {
            Some(p) => p as u32,
            None => return Ok(StandardResponse::error(tool_name, "Missing pid")),
        };
        
        let engine = FridaHandler::new();
        match engine.attach_process(pid).await {
            Ok(_) => Ok(StandardResponse::success_timed(tool_name, serde_json::json!({ "pid": pid }), start)),
            Err(e) => Ok(StandardResponse::error(tool_name, &e.to_string())),
        }
    }
}

pub struct ResumeProcess;

#[async_trait]
impl Tool for ResumeProcess {
    fn name(&self) -> &str { "resume_process" }
    fn description(&self) -> &str { "Resumes a suspended process. Args: pid (number)" }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ ParamDef::new("pid", "number", true, "Target process ID") ])
    }
    
    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        
        let pid = match args["pid"].as_u64() {
            Some(p) => p as u32,
            None => return Ok(StandardResponse::error(tool_name, "Missing pid")),
        };
        
        let engine = FridaHandler::new();
        match engine.resume_process(pid).await {
            Ok(_) => Ok(StandardResponse::success_timed(tool_name, serde_json::json!({ "pid": pid }), start)),
            Err(e) => Ok(StandardResponse::error(tool_name, &e.to_string())),
        }
    }
}
