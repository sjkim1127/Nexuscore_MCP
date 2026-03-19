use crate::tools::{ParamDef, Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use crate::app::analysis_session_service::{AnalysisSessionService, InMemoryAnalysisSessionService};
use crate::state::analysis_session::{AnalysisArtifact, ArtifactKind, AnalysisEvent, EventType, Severity};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::time::Instant;
use tokio::process::Command;
use uuid::Uuid;

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct HandleScanner;

#[async_trait]
impl Tool for HandleScanner {
    fn name(&self) -> &str {
        "scan_handles"
    }
    fn description(&self) -> &str {
        "Scans open handles and mutexes of a process using Sysinternals handle.exe. Args: pid (number)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("pid", "number", true, "Target process ID"),
            ParamDef::new(
                "analysis_session_id",
                "string",
                false,
                "Optional analysis session ID to attach snapshot to",
            ),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))?;
        let analysis_session_id = args["analysis_session_id"].as_str().map(|s| s.to_string());

        // Execute handle.exe -a (all types) -p <pid> -accepteula
        let output = Command::new("handle.exe")
            .arg("-a")
            .arg("-p")
            .arg(pid.to_string())
            .arg("-accepteula") // Crucial for automation
            .arg("-nobanner")
            .output()
            .await;

        match output {
            Ok(out) => {
                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    return Err(anyhow::anyhow!("handle.exe failed: {}", err));
                }

                let stdout = String::from_utf8_lossy(&out.stdout);
                let lines: Vec<&str> = stdout.lines().collect();
                let mut handles = Vec::new();
                let mut type_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

                // Parsing simplified: Type : HandlePath
                // Handle.exe output format:
                // Type           Pid User   Handle   Path
                // File           123 User   4C       C:\Windows
                // Mutex          123 User   50       \BaseNamedObjects\MyMutex

                for line in lines {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let obj_type = parts[0];
                        // Skip header
                        if obj_type == "Type" || obj_type.starts_with("---") {
                            continue;
                        }

                        // Extract Name (Everything after the handle hex code)
                        // This logic is rough, handle.exe output is fixed width but varies.
                        // Let's grab the last part if it looks like a path or mutex name.
                        if parts.len() > 4 {
                            let name = parts[4..].join(" ");
                            if !name.is_empty() {
                                *type_counts.entry(obj_type.to_string()).or_insert(0) += 1;
                                handles.push(serde_json::json!({
                                    "type": obj_type,
                                    "name": name
                                }));
                            }
                        }
                    }
                }

                if let Some(session_id) = analysis_session_id.as_deref() {
                    let svc = InMemoryAnalysisSessionService;
                    let ts = now_unix();
                    let _ = svc.add_artifact(
                        session_id,
                        AnalysisArtifact {
                            id: format!("artifact_{}", Uuid::new_v4()),
                            kind: ArtifactKind::HandleSnapshot,
                            created_at: ts,
                            source_tool: tool_name.to_string(),
                            metadata: serde_json::json!({
                                "pid": pid,
                                "handle_count": handles.len(),
                                "type_counts": type_counts
                            }),
                            data_ref: None,
                            inline_data: Some(serde_json::json!({ "handles": handles })),
                        },
                    );
                    let _ = svc.add_event(
                        session_id,
                        AnalysisEvent {
                            timestamp: ts,
                            event_type: EventType::ArtifactAdded,
                            severity: Severity::Info,
                            details: serde_json::json!({ "kind": "handle_snapshot", "tool": tool_name }),
                        },
                    );
                }

                Ok(StandardResponse::success_timed(
                    tool_name,
                    serde_json::json!({
                        "pid": pid,
                        "handle_count": handles.len(),
                        "type_counts": type_counts,
                        "handles": handles
                    }),
                    start,
                ))
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to run handle.exe. Is it in PATH? Error: {}",
                e
            )),
        }
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(HandleScanner))
}
