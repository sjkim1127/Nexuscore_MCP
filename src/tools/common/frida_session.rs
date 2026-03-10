#![cfg(feature = "dynamic-analysis")]
use crate::engine::frida_handler::get_session_manager;
use crate::tools::{ParamDef, Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::time::Instant;

/// Create a new Frida session (spawn or attach)
pub struct FridaSessionCreate;

#[async_trait]
impl Tool for FridaSessionCreate {
    fn name(&self) -> &str {
        "frida_session_create"
    }
    fn description(&self) -> &str {
        "Create a persistent Frida session. Args: pid (attach) OR path (spawn). Returns session_id."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("pid", "number", false, "Process ID to attach to"),
            ParamDef::new("path", "string", false, "Path to executable to spawn"),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();

        let pid = args["pid"].as_u64().map(|p| p as u32);
        let path = args["path"].as_str();

        let mut manager = get_session_manager().lock().unwrap();

        let session_id = match manager.create_session(pid, path) {
            Ok(id) => id,
            Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
        };

        let target_pid = manager.get_pid(&session_id).unwrap_or(0);

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "pid": target_pid,
                "mode": if path.is_some() { "spawned" } else { "attached" }
            }),
            start,
        ))
    }
}

/// Inject script into existing Frida session
pub struct FridaSessionInject;

#[async_trait]
impl Tool for FridaSessionInject {
    fn name(&self) -> &str {
        "frida_session_inject"
    }
    fn description(&self) -> &str {
        "Inject JS script into Frida session. Args: session_id, script (JS code)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("session_id", "string", true, "Frida session ID"),
            ParamDef::new("script", "string", true, "JavaScript code to inject"),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();

        let session_id = match args["session_id"].as_str() {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };
        let script = match args["script"].as_str() {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Missing script")),
        };

        let mut manager = get_session_manager().lock().unwrap();

        if let Err(e) = manager.inject_script(session_id, script) {
            return Ok(StandardResponse::error(tool_name, &e.to_string()));
        }

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "injected": true,
                "script_size": script.len()
            }),
            start,
        ))
    }
}

/// Resume a spawned process
pub struct FridaSessionResume;

#[async_trait]
impl Tool for FridaSessionResume {
    fn name(&self) -> &str {
        "frida_session_resume"
    }
    fn description(&self) -> &str {
        "Resume a spawned process. Args: session_id"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "session_id",
            "string",
            true,
            "Frida session ID",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();

        let session_id = match args["session_id"].as_str() {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };

        let manager = get_session_manager().lock().unwrap();

        if let Err(e) = manager.resume_process(session_id) {
            return Ok(StandardResponse::error(tool_name, &e.to_string()));
        }

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "resumed": true
            }),
        ))
    }
}

/// Get messages from Frida session
pub struct FridaSessionMessages;

#[async_trait]
impl Tool for FridaSessionMessages {
    fn name(&self) -> &str {
        "frida_session_messages"
    }
    fn description(&self) -> &str {
        "Get collected messages from Frida session. Args: session_id"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "session_id",
            "string",
            true,
            "Frida session ID",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();

        let session_id = match args["session_id"].as_str() {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };

        let mut manager = get_session_manager().lock().unwrap();
        let messages = manager.get_messages(session_id);

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "message_count": messages.len(),
                "messages": messages
            }),
        ))
    }
}

/// Destroy Frida session
pub struct FridaSessionDestroy;

#[async_trait]
impl Tool for FridaSessionDestroy {
    fn name(&self) -> &str {
        "frida_session_destroy"
    }
    fn description(&self) -> &str {
        "Destroy a Frida session and release resources. Args: session_id"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "session_id",
            "string",
            true,
            "Frida session ID",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();

        let session_id = match args["session_id"].as_str() {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };

        let mut manager = get_session_manager().lock().unwrap();
        manager.destroy_session(session_id)?;

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "destroyed": true
            }),
        ))
    }
}

/// List all active Frida sessions
pub struct FridaSessionList;

#[async_trait]
impl Tool for FridaSessionList {
    fn name(&self) -> &str {
        "frida_session_list"
    }
    fn description(&self) -> &str {
        "List all active Frida sessions"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::empty() // No parameters required
    }

    async fn execute(&self, _args: Value) -> Result<Value> {
        let tool_name = self.name();

        let manager = get_session_manager().lock().unwrap();
        let sessions: Vec<_> = manager
            .list_sessions()
            .into_iter()
            .map(|(id, pid, active)| {
                serde_json::json!({
                    "session_id": id,
                    "pid": pid,
                    "active": active
                })
            })
            .collect();

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "sessions": sessions,
                "count": sessions.len()
            }),
        ))
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(FridaSessionCreate))
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(FridaSessionInject))
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(FridaSessionResume))
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(FridaSessionMessages))
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(FridaSessionDestroy))
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(FridaSessionList))
}
