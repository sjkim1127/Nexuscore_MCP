#![cfg(feature = "dynamic-analysis")]

use crate::tools::{ParamDef, Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

static ANALYSIS_STORE: OnceLock<Mutex<HashMap<String, AnalysisSession>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<String, AnalysisSession>> {
    ANALYSIS_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AnalysisStatus {
    Created,
    Running,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AnalysisEvent {
    timestamp: u64,
    event: String,
    details: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AnalysisArtifact {
    kind: String,
    value: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AnalysisSession {
    session_id: String,
    sample_path: String,
    status: AnalysisStatus,
    created_at: u64,
    updated_at: u64,
    timeline: Vec<AnalysisEvent>,
    artifacts: Vec<AnalysisArtifact>,
}

pub struct AnalysisSessionCreate;
pub struct AnalysisSessionStatus;
pub struct AnalysisSessionTimeline;
pub struct AnalysisSessionArtifacts;
pub struct AnalysisSessionEnd;

#[async_trait]
impl Tool for AnalysisSessionCreate {
    fn name(&self) -> &str {
        "analysis_session_create"
    }

    fn description(&self) -> &str {
        "Create an analysis session. Args: sample_path"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "sample_path",
            "string",
            true,
            "Path to sample under analysis",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        let sample_path = match args["sample_path"].as_str() {
            Some(v) => v.to_string(),
            None => return Ok(StandardResponse::error(tool_name, "Missing sample_path")),
        };

        let session_id = format!("analysis_{}", Uuid::new_v4());
        let ts = now_unix();

        let session = AnalysisSession {
            session_id: session_id.clone(),
            sample_path: sample_path.clone(),
            status: AnalysisStatus::Created,
            created_at: ts,
            updated_at: ts,
            timeline: vec![AnalysisEvent {
                timestamp: ts,
                event: "session_created".to_string(),
                details: serde_json::json!({ "sample_path": sample_path }),
            }],
            artifacts: vec![],
        };

        let mut guard = store()
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock analysis store"))?;
        guard.insert(session_id.clone(), session);

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "status": "created"
            }),
            start,
        ))
    }
}

#[async_trait]
impl Tool for AnalysisSessionStatus {
    fn name(&self) -> &str {
        "analysis_session_status"
    }

    fn description(&self) -> &str {
        "Get analysis session status. Args: session_id"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "session_id",
            "string",
            true,
            "Analysis session ID",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();
        let session_id = match args["session_id"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };

        let mut guard = store()
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock analysis store"))?;
        let session = match guard.get_mut(session_id) {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Session not found")),
        };

        if matches!(session.status, AnalysisStatus::Created) {
            session.status = AnalysisStatus::Running;
            session.updated_at = now_unix();
            session.timeline.push(AnalysisEvent {
                timestamp: session.updated_at,
                event: "session_running".to_string(),
                details: serde_json::json!({}),
            });
        }

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session.session_id,
                "sample_path": session.sample_path,
                "status": session.status,
                "created_at": session.created_at,
                "updated_at": session.updated_at
            }),
        ))
    }
}

#[async_trait]
impl Tool for AnalysisSessionTimeline {
    fn name(&self) -> &str {
        "analysis_session_timeline"
    }

    fn description(&self) -> &str {
        "Get analysis session timeline. Args: session_id, limit (optional)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("session_id", "string", true, "Analysis session ID"),
            ParamDef::new("limit", "number", false, "Maximum events to return"),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();
        let session_id = match args["session_id"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };
        let limit = args["limit"].as_u64().unwrap_or(100) as usize;

        let guard = store()
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock analysis store"))?;
        let session = match guard.get(session_id) {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Session not found")),
        };

        let mut timeline = session.timeline.clone();
        if timeline.len() > limit {
            timeline = timeline[timeline.len() - limit..].to_vec();
        }

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "event_count": timeline.len(),
                "timeline": timeline
            }),
        ))
    }
}

#[async_trait]
impl Tool for AnalysisSessionArtifacts {
    fn name(&self) -> &str {
        "analysis_session_artifacts"
    }

    fn description(&self) -> &str {
        "Get artifacts collected in analysis session. Args: session_id"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "session_id",
            "string",
            true,
            "Analysis session ID",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();
        let session_id = match args["session_id"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };

        let guard = store()
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock analysis store"))?;
        let session = match guard.get(session_id) {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Session not found")),
        };

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "artifact_count": session.artifacts.len(),
                "artifacts": session.artifacts
            }),
        ))
    }
}

#[async_trait]
impl Tool for AnalysisSessionEnd {
    fn name(&self) -> &str {
        "analysis_session_end"
    }

    fn description(&self) -> &str {
        "End analysis session and freeze state. Args: session_id"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "session_id",
            "string",
            true,
            "Analysis session ID",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();
        let session_id = match args["session_id"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };

        let mut guard = store()
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock analysis store"))?;
        let session = match guard.get_mut(session_id) {
            Some(s) => s,
            None => return Ok(StandardResponse::error(tool_name, "Session not found")),
        };

        session.status = AnalysisStatus::Completed;
        session.updated_at = now_unix();
        session.timeline.push(AnalysisEvent {
            timestamp: session.updated_at,
            event: "session_completed".to_string(),
            details: serde_json::json!({}),
        });

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "status": "completed"
            }),
        ))
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(AnalysisSessionCreate))
}
inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(AnalysisSessionStatus))
}
inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(AnalysisSessionTimeline))
}
inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(AnalysisSessionArtifacts))
}
inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(AnalysisSessionEnd))
}
