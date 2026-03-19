use crate::tools::{Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use crate::app::analysis_session_service::{AnalysisSessionService, InMemoryAnalysisSessionService};
use crate::state::analysis_session::{AnalysisArtifact, ArtifactKind, AnalysisEvent, EventType, Severity};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::path::Path;
use std::time::Instant;
use winreg::enums::*;
use winreg::RegKey;
use uuid::Uuid;

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct PersistenceHunter;

#[async_trait]
impl Tool for PersistenceHunter {
    fn name(&self) -> &str {
        "scan_persistence"
    }
    fn description(&self) -> &str {
        "Scans registry Run keys and Startup folders for persistence. No args."
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![crate::tools::ParamDef::new(
            "analysis_session_id",
            "string",
            false,
            "Optional analysis session ID to attach snapshot to",
        )])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        let mut results = Vec::new();
        let analysis_session_id = args["analysis_session_id"].as_str().map(|s| s.to_string());

        let keys = [
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM",
            ),
        ];

        for (hive, path, hive_name) in keys {
            if let Ok(root) = RegKey::predef(hive).open_subkey(path) {
                for (name, value) in root.enum_values().filter_map(|x| x.ok()) {
                    results.push(serde_json::json!({
                        "type": "registry", "hive": hive_name, "name": name, "value": value.to_string()
                    }));
                }
            }
        }

        // Startup folders
        let mut startup_file_count: u64 = 0;
        if let Ok(appdata) = std::env::var("APPDATA") {
            let startup =
                Path::new(&appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if let Ok(entries) = std::fs::read_dir(&startup) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|f| f.is_file()).unwrap_or(false) {
                        startup_file_count += 1;
                        results.push(serde_json::json!({
                            "type": "file", "path": entry.path().to_string_lossy()
                        }));
                    }
                }
            }
        }

        if let Some(session_id) = analysis_session_id.as_deref() {
            let svc = InMemoryAnalysisSessionService;
            let ts = now_unix();

            // hive counts
            let mut hive_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for item in &results {
                if item["type"].as_str() == Some("registry") {
                    let hive = item["hive"].as_str().unwrap_or("unknown").to_string();
                    *hive_counts.entry(hive).or_insert(0) += 1;
                }
            }

            let _ = svc.add_artifact(
                session_id,
                AnalysisArtifact {
                    id: format!("artifact_{}", Uuid::new_v4()),
                    kind: ArtifactKind::PersistenceSnapshot,
                    created_at: ts,
                    source_tool: tool_name.to_string(),
                    metadata: serde_json::json!({
                        "count": results.len(),
                        "hive_counts": hive_counts,
                        "startup_file_count": startup_file_count
                    }),
                    data_ref: None,
                    inline_data: Some(serde_json::json!({ "items": results })),
                },
            );
            let _ = svc.add_event(
                session_id,
                AnalysisEvent {
                    timestamp: ts,
                    event_type: EventType::ArtifactAdded,
                    severity: Severity::Info,
                    details: serde_json::json!({ "kind": "persistence_snapshot", "tool": tool_name }),
                },
            );
        }

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "count": results.len(),
                "startup_file_count": startup_file_count,
                "items": results
            }),
            start,
        ))
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(PersistenceHunter))
}
