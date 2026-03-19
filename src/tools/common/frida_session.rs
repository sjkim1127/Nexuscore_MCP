#![cfg(feature = "dynamic-analysis")]
use crate::engine::frida_handler::get_frida_client;
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

        let client = get_frida_client();

        let session_id = if let Some(p) = pid {
            match client.attach(p).await {
                Ok(id) => id,
                Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
            }
        } else if let Some(p) = path {
            match client.spawn(p.to_string()).await {
                Ok(id) => id,
                Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
            }
        } else {
            return Ok(StandardResponse::error(tool_name, "Provide pid or path"));
        };

        // Get target PID from session list
        let sessions = client.list_sessions().await?;
        let target_pid = sessions.iter()
            .find(|(id, _, _)| id == &session_id)
            .map(|(_, p, _)| *p)
            .unwrap_or(0);

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

        let client = get_frida_client();

        if let Err(e) = client.inject(session_id.to_string(), script.to_string()).await {
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

        let client = get_frida_client();

        if let Err(e) = client.resume(session_id.to_string()).await {
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

        let client = get_frida_client();
        match client.get_messages(session_id.to_string()).await {
            Ok(messages) => {
                Ok(StandardResponse::success(
                    tool_name,
                    serde_json::json!({
                        "session_id": session_id,
                        "message_count": messages.len(),
                        "messages": messages
                    }),
                ))
            }
            Err(e) => Ok(StandardResponse::error(tool_name, &e.to_string())),
        }
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

        let client = get_frida_client();
        if let Err(e) = client.destroy_session(session_id.to_string()).await {
            return Ok(StandardResponse::error(tool_name, &e.to_string()));
        }

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

        let client = get_frida_client();
        match client.list_sessions().await {
            Ok(sessions_list) => {
                let sessions: Vec<_> = sessions_list
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
            Err(e) => Ok(StandardResponse::error(tool_name, &e.to_string())),
        }
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
