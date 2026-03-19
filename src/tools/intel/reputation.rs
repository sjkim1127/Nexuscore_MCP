use crate::tools::{ParamDef, Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use crate::app::analysis_session_service::{AnalysisSessionService, InMemoryAnalysisSessionService};
use crate::state::analysis_session::{AnalysisArtifact, ArtifactKind, AnalysisEvent, EventType, Severity};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::env;
use std::time::Instant;
use uuid::Uuid;

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct ReputationChecker;

#[async_trait]
impl Tool for ReputationChecker {
    fn name(&self) -> &str {
        "check_reputation"
    }
    fn description(&self) -> &str {
        "Checks reputation via VirusTotal. Args: type (hash/ip/domain), value"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("type", "string", true, "Query type: hash, ip, or domain"),
            ParamDef::new("value", "string", true, "Value to check"),
            ParamDef::new(
                "analysis_session_id",
                "string",
                false,
                "Optional analysis session ID to attach result to",
            ),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();

        let query_type = match args["type"].as_str() {
            Some(t) => t,
            None => return Ok(StandardResponse::error(tool_name, "Missing type")),
        };
        let value = match args["value"].as_str() {
            Some(v) => v,
            None => return Ok(StandardResponse::error(tool_name, "Missing value")),
        };
        let analysis_session_id = args["analysis_session_id"].as_str().map(|s| s.to_string());

        let vt_key = env::var("VT_API_KEY")
            .ok()
            .or_else(|| env::var("VIRUSTOTAL_API_KEY").ok());
        let mut results = serde_json::Map::new();
        results.insert("query_type".to_string(), serde_json::json!(query_type));
        results.insert("query_value".to_string(), serde_json::json!(value));

        if let Some(key) = vt_key {
            let vt_result = query_virustotal(query_type, value, &key).await;
            results.insert("virustotal".to_string(), vt_result);
        } else {
            results.insert(
                "virustotal".to_string(),
                serde_json::json!({"status": "disabled", "reason": "VT_API_KEY or VIRUSTOTAL_API_KEY not set"}),
            );
        }

        if let Some(session_id) = analysis_session_id.as_deref() {
            let svc = InMemoryAnalysisSessionService;
            let ts = now_unix();

            let provider_statuses = serde_json::json!({
                "virustotal": if results.get("virustotal").and_then(|v| v.get("status")).is_some() { "enabled" } else { "disabled" }
            });

            // inline_data: provider별 요약만 (원본 전체는 과하지 않게)
            let vt_summary = results
                .get("virustotal")
                .cloned()
                .unwrap_or(Value::Null);
            let inline = serde_json::json!({
                "query_type": query_type,
                "value": value,
                "virustotal": {
                    "status": vt_summary.get("status").cloned().unwrap_or(Value::Null),
                    "detected": vt_summary.get("detected").cloned().unwrap_or(Value::Null),
                    "stats": vt_summary.get("stats").cloned().unwrap_or(Value::Null)
                }
            });

            let _ = svc.add_artifact(
                session_id,
                AnalysisArtifact {
                    id: format!("artifact_{}", Uuid::new_v4()),
                    kind: ArtifactKind::ReputationResult,
                    created_at: ts,
                    source_tool: tool_name.to_string(),
                    metadata: serde_json::json!({
                        "provider_statuses": provider_statuses,
                        "query_type": query_type,
                        "value": value
                    }),
                    data_ref: None,
                    inline_data: Some(inline),
                },
            );
            let _ = svc.add_event(
                session_id,
                AnalysisEvent {
                    timestamp: ts,
                    event_type: EventType::ArtifactAdded,
                    severity: Severity::Info,
                    details: serde_json::json!({ "kind": "reputation_result", "tool": tool_name }),
                },
            );
        }

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!(results),
            start,
        ))
    }
}

async fn query_virustotal(query_type: &str, value: &str, api_key: &str) -> Value {
    let client = reqwest::Client::new();
    let url = match query_type {
        "hash" => format!("https://www.virustotal.com/api/v3/files/{}", value),
        "ip" => format!("https://www.virustotal.com/api/v3/ip_addresses/{}", value),
        "domain" => format!("https://www.virustotal.com/api/v3/domains/{}", value),
        _ => return serde_json::json!({ "error": "Invalid type" }),
    };

    match client.get(&url).header("x-apikey", api_key).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.json::<Value>().await {
                Ok(data) => {
                    let stats = data["data"]["attributes"]["last_analysis_stats"].clone();
                    serde_json::json!({ "status": status, "detected": stats["malicious"], "stats": stats })
                }
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            }
        }
        Err(e) => serde_json::json!({ "error": e.to_string() }),
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(ReputationChecker))
}
