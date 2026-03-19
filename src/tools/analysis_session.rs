use crate::app::analysis_session_service::{AnalysisSessionService, InMemoryAnalysisSessionService};
use crate::state::session_store;
use crate::tools::{ParamDef, Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::time::Instant;

pub struct AnalysisSessionCreate;
pub struct AnalysisSessionStatus;
pub struct AnalysisSessionTimeline;
pub struct AnalysisSessionArtifacts;
pub struct AnalysisSessionEnd;
pub struct AnalysisSessionAppendNote;
#[cfg(feature = "dynamic-analysis")]
pub struct AnalysisSessionIngestFridaMessages;

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
        let svc = InMemoryAnalysisSessionService;
        let session = match svc.create_session(&sample_path) {
            Ok(s) => s,
            Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
        };

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "session_id": session.session_id,
                "status": session.status
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
        let session = match session_store::get(session_id) {
            Ok(s) => s,
            Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
        };

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session.session_id,
                "sample_path": session.sample_path,
                "status": session.status,
                "created_at": session.created_at,
                "updated_at": session.updated_at,
                "last_error": session.last_error,
                "linked": session.linked
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
        let session = match session_store::get(session_id) {
            Ok(s) => s,
            Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
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
        let session = match session_store::get(session_id) {
            Ok(s) => s,
            Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
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
        let svc = InMemoryAnalysisSessionService;
        if let Err(e) = svc.complete(session_id) {
            return Ok(StandardResponse::error(tool_name, &e.to_string()));
        }

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "status": "completed"
            }),
        ))
    }
}

#[async_trait]
impl Tool for AnalysisSessionAppendNote {
    fn name(&self) -> &str {
        "analysis_session_append_note"
    }

    fn description(&self) -> &str {
        "Append a human-readable note to the session timeline and artifacts. Args: session_id, note"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("session_id", "string", true, "Analysis session ID"),
            ParamDef::new("note", "string", true, "Note text to append"),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let tool_name = self.name();
        let session_id = match args["session_id"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing session_id")),
        };
        let note = match args["note"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing note")),
        };

        let svc = InMemoryAnalysisSessionService;
        if let Err(e) = svc.append_note(session_id, note) {
            return Ok(StandardResponse::error(tool_name, &e.to_string()));
        }

        Ok(StandardResponse::success(
            tool_name,
            serde_json::json!({
                "session_id": session_id,
                "appended": true
            }),
        ))
    }
}

#[cfg(feature = "dynamic-analysis")]
#[async_trait]
impl Tool for AnalysisSessionIngestFridaMessages {
    fn name(&self) -> &str {
        "analysis_session_ingest_frida_messages"
    }

    fn description(&self) -> &str {
        "Drains Frida messages and ingests them as a FridaEventBatch artifact. Args: analysis_session_id, frida_session_id, limit (optional)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("analysis_session_id", "string", true, "Analysis session ID"),
            ParamDef::new("frida_session_id", "string", true, "Frida session ID"),
            ParamDef::new("limit", "number", false, "Max messages to drain and ingest"),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();

        let analysis_session_id = match args["analysis_session_id"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing analysis_session_id")),
        };
        let frida_session_id = match args["frida_session_id"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing frida_session_id")),
        };
        let limit = args["limit"].as_u64().map(|v| v as usize);

        let client = crate::engine::frida_handler::get_frida_client();
        let drained = match client
            .drain_messages(frida_session_id.to_string(), limit)
            .await
        {
            Ok(r) => r,
            Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
        };

        let ingested_count = drained.messages.len() as u64;
        if ingested_count == 0 {
            return Ok(StandardResponse::success_timed(
                tool_name,
                serde_json::json!({
                    "analysis_session_id": analysis_session_id,
                    "frida_session_id": frida_session_id,
                    "ingested_count": 0,
                    "parsed_count": 0,
                    "invalid_count": 0,
                    "artifact_id": Value::Null,
                    "from_ts": Value::Null,
                    "to_ts": Value::Null,
                    "severity_counts": {},
                    "category_counts": {},
                    "dropped_count": drained.dropped_count
                }),
                start,
            ));
        }

        let svc = InMemoryAnalysisSessionService;
        let pid = session_store::get(analysis_session_id)
            .ok()
            .and_then(|s| s.linked.pid);

        let artifact = match svc.add_frida_event_batch(
            analysis_session_id,
            frida_session_id,
            pid,
            drained.messages,
            drained.dropped_count,
        ) {
            Ok(a) => a,
            Err(e) => return Ok(StandardResponse::error(tool_name, &e.to_string())),
        };

        let md = &artifact.metadata;
        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "analysis_session_id": analysis_session_id,
                "frida_session_id": frida_session_id,
                "ingested_count": md["ingested_count"],
                "parsed_count": md["parsed_count"],
                "invalid_count": md["invalid_count"],
                "artifact_id": artifact.id,
                "from_ts": md["from_ts"],
                "to_ts": md["to_ts"],
                "severity_counts": md["severity_counts"],
                "category_counts": md["category_counts"],
                "dropped_count": md["dropped_count"]
            }),
            start,
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

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(AnalysisSessionAppendNote))
}

#[cfg(feature = "dynamic-analysis")]
inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(AnalysisSessionIngestFridaMessages))
}
