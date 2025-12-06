use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use async_trait::async_trait;
use std::env;

/// Threat Intelligence - Checks reputation of hashes, IPs, domains
pub struct ReputationChecker;

#[async_trait]
impl Tool for ReputationChecker {
    fn name(&self) -> &str { "check_reputation" }
    fn description(&self) -> &str { "Checks reputation of hash/IP/domain via VirusTotal and AbuseIPDB. Args: type (hash/ip/domain), value (string)" }

    async fn execute(&self, args: Value) -> Result<Value> {
        let query_type = args["type"].as_str().ok_or(anyhow::anyhow!("Missing type"))?;
        let value = args["value"].as_str().ok_or(anyhow::anyhow!("Missing value"))?;

        let vt_key = env::var("VT_API_KEY").ok();
        let abuse_key = env::var("ABUSEIPDB_KEY").ok();

        let mut results = serde_json::Map::new();
        results.insert("query_type".to_string(), serde_json::json!(query_type));
        results.insert("query_value".to_string(), serde_json::json!(value));

        // VirusTotal Query
        if let Some(key) = vt_key {
            let vt_result = query_virustotal(query_type, value, &key).await;
            results.insert("virustotal".to_string(), vt_result);
        } else {
            results.insert("virustotal".to_string(), serde_json::json!({
                "status": "disabled",
                "reason": "VT_API_KEY not set in environment"
            }));
        }

        // AbuseIPDB (only for IPs)
        if query_type == "ip" {
            if let Some(key) = abuse_key {
                let abuse_result = query_abuseipdb(value, &key).await;
                results.insert("abuseipdb".to_string(), abuse_result);
            } else {
                results.insert("abuseipdb".to_string(), serde_json::json!({
                    "status": "disabled",
                    "reason": "ABUSEIPDB_KEY not set in environment"
                }));
            }
        }

        Ok(serde_json::json!(results))
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

    match client.get(&url)
        .header("x-apikey", api_key)
        .send()
        .await 
    {
        Ok(resp) => {
            let status = resp.status();
            match resp.json::<Value>().await {
                Ok(data) => {
                    // Extract key stats
                    let stats = data["data"]["attributes"]["last_analysis_stats"].clone();
                    serde_json::json!({
                        "status": status.as_u16(),
                        "detected": stats["malicious"].as_u64().unwrap_or(0),
                        "total": stats["malicious"].as_u64().unwrap_or(0) + stats["undetected"].as_u64().unwrap_or(0),
                        "stats": stats
                    })
                },
                Err(e) => serde_json::json!({ "error": format!("Parse error: {}", e) }),
            }
        },
        Err(e) => serde_json::json!({ "error": format!("Request failed: {}", e) }),
    }
}

async fn query_abuseipdb(ip: &str, api_key: &str) -> Value {
    let client = reqwest::Client::new();
    
    match client.get("https://api.abuseipdb.com/api/v2/check")
        .header("Key", api_key)
        .header("Accept", "application/json")
        .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
        .send()
        .await 
    {
        Ok(resp) => {
            match resp.json::<Value>().await {
                Ok(data) => {
                    let info = &data["data"];
                    serde_json::json!({
                        "abuse_score": info["abuseConfidenceScore"],
                        "country": info["countryCode"],
                        "isp": info["isp"],
                        "total_reports": info["totalReports"],
                        "is_tor": info["isTor"],
                        "is_whitelisted": info["isWhitelisted"]
                    })
                },
                Err(e) => serde_json::json!({ "error": format!("Parse error: {}", e) }),
            }
        },
        Err(e) => serde_json::json!({ "error": format!("Request failed: {}", e) }),
    }
}
