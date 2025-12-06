use anyhow::Result;
use serde_json::Value;
use crate::tools::{Tool, ToolSchema, ParamDef};
use crate::utils::response::StandardResponse;
use async_trait::async_trait;
use std::env;
use std::time::Instant;

pub struct ReputationChecker;

#[async_trait]
impl Tool for ReputationChecker {
    fn name(&self) -> &str { "check_reputation" }
    fn description(&self) -> &str { "Checks reputation via VirusTotal/AbuseIPDB. Args: type (hash/ip/domain), value" }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("type", "string", true, "Query type: hash, ip, or domain"),
            ParamDef::new("value", "string", true, "Value to check"),
        ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        
        let query_type = match args["type"].as_str() { Some(t) => t, None => return Ok(StandardResponse::error(tool_name, "Missing type")) };
        let value = match args["value"].as_str() { Some(v) => v, None => return Ok(StandardResponse::error(tool_name, "Missing value")) };

        let vt_key = env::var("VT_API_KEY").ok();
        let mut results = serde_json::Map::new();
        results.insert("query_type".to_string(), serde_json::json!(query_type));
        results.insert("query_value".to_string(), serde_json::json!(value));

        if let Some(key) = vt_key {
            let vt_result = query_virustotal(query_type, value, &key).await;
            results.insert("virustotal".to_string(), vt_result);
        } else {
            results.insert("virustotal".to_string(), serde_json::json!({"status": "disabled", "reason": "VT_API_KEY not set"}));
        }

        Ok(StandardResponse::success_timed(tool_name, serde_json::json!(results), start))
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
                },
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            }
        },
        Err(e) => serde_json::json!({ "error": e.to_string() }),
    }
}
