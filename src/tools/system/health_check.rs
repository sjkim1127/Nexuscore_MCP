use crate::tools::{Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::time::Instant;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub struct HealthCheckTool;

#[async_trait]
impl Tool for HealthCheckTool {
    fn name(&self) -> &str {
        "health_check"
    }

    fn description(&self) -> &str {
        "Checks runtime dependencies and optional API credentials for NexusCore."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::empty()
    }

    async fn execute(&self, _args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();

        let checks = vec![
            check_dependency("frida", "frida", &["--version"], 3).await,
            check_dependency("cdb", "cdb", &["-?"], 3).await,
            check_dependency("diec", "diec", &["--help"], 3).await,
            check_dependency("capa", "capa", &["--version"], 3).await,
            check_dependency("floss", "floss", &["--help"], 3).await,
            check_dependency("handle.exe", "handle.exe", &["-?"], 3).await,
        ];

        let vt_key = std::env::var("VIRUSTOTAL_API_KEY").ok();
        let cape_url = std::env::var("CAPE_API_URL")
            .ok()
            .or_else(|| std::env::var("CAPE_URL").ok());
        let cape_token = std::env::var("CAPE_API_TOKEN").ok();

        let api_keys = serde_json::json!({
            "virustotal_api_key_present": vt_key.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "cape_url_present": cape_url.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "cape_api_token_present": cape_token.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        });

        let readiness_failures = checks
            .iter()
            .filter(|c| !c["readiness_ok"].as_bool().unwrap_or(false))
            .count();

        let cape_ping = if let Some(url) = cape_url.as_deref() {
            check_http_reachability("cape", url, 3).await
        } else {
            serde_json::json!({"name":"cape","enabled":false})
        };

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "healthy": readiness_failures == 0,
                "dependency_failures": readiness_failures,
                "dependencies": checks,
                "api_keys": api_keys,
                "network": {
                    "cape_reachable": cape_ping
                }
            }),
            start,
        ))
    }
}

async fn check_dependency(name: &str, command: &str, args: &[&str], timeout_secs: u64) -> Value {
    let start = Instant::now();
    let where_status = Command::new("where")
        .arg(command)
        .output()
        .await
        .ok()
        .map(|out| out.status.success())
        .unwrap_or(false);

    if !where_status {
        return serde_json::json!({
            "name": name,
            "available": false,
            "where_ok": false,
            "readiness_ok": false,
            "command": format!("{} {}", command, args.join(" ")),
            "exit_code": Value::Null,
            "stdout_head": "",
            "stderr_head": "",
            "duration_ms": start.elapsed().as_millis() as u64
        });
    }

    let cmdline = format!("{} {}", command, args.join(" "));
    let output = timeout(
        Duration::from_secs(timeout_secs),
        Command::new(command).args(args).output(),
    )
    .await;

    match output {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let exit_code = out.status.code();
            serde_json::json!({
                "name": name,
                "available": true,
                "where_ok": true,
                "readiness_ok": out.status.success(),
                "command": cmdline,
                "exit_code": exit_code,
                "stdout_head": truncate_head(&stdout, 1024),
                "stderr_head": truncate_head(&stderr, 1024),
                "duration_ms": start.elapsed().as_millis() as u64
            })
        }
        Ok(Err(e)) => serde_json::json!({
            "name": name,
            "available": true,
            "where_ok": true,
            "readiness_ok": false,
            "command": cmdline,
            "exit_code": Value::Null,
            "stdout_head": "",
            "stderr_head": format!("{}", e),
            "duration_ms": start.elapsed().as_millis() as u64
        }),
        Err(_) => serde_json::json!({
            "name": name,
            "available": true,
            "where_ok": true,
            "readiness_ok": false,
            "command": cmdline,
            "exit_code": Value::Null,
            "stdout_head": "",
            "stderr_head": "timeout",
            "duration_ms": start.elapsed().as_millis() as u64
        }),
    }
}

fn truncate_head(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

async fn check_http_reachability(name: &str, url: &str, timeout_secs: u64) -> Value {
    let start = Instant::now();
    let client = reqwest::Client::new();
    let res = timeout(
        Duration::from_secs(timeout_secs),
        client.get(url).send(),
    )
    .await;

    match res {
        Ok(Ok(resp)) => serde_json::json!({
            "name": name,
            "enabled": true,
            "reachable": resp.status().is_success() || resp.status().as_u16() < 500,
            "status": resp.status().as_u16(),
            "duration_ms": start.elapsed().as_millis() as u64
        }),
        Ok(Err(e)) => serde_json::json!({
            "name": name,
            "enabled": true,
            "reachable": false,
            "error": e.to_string(),
            "duration_ms": start.elapsed().as_millis() as u64
        }),
        Err(_) => serde_json::json!({
            "name": name,
            "enabled": true,
            "reachable": false,
            "error": "timeout",
            "duration_ms": start.elapsed().as_millis() as u64
        }),
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(HealthCheckTool))
}
