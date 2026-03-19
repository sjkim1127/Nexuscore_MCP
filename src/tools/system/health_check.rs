use crate::tools::{Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::time::Instant;
use tokio::process::Command;

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
            check_dependency("frida", "frida", &["--version"]).await,
            check_dependency("cdb", "cdb", &["-?"]).await,
            check_dependency("diec", "diec", &["--help"]).await,
            check_dependency("capa", "capa", &["--help"]).await,
            check_dependency("floss", "floss", &["--help"]).await,
            check_dependency("handle.exe", "handle.exe", &["-?"]).await,
        ];

        let vt_key = std::env::var("VIRUSTOTAL_API_KEY").ok();
        let cape_url = std::env::var("CAPE_URL").ok();
        let cape_token = std::env::var("CAPE_API_TOKEN").ok();

        let api_keys = serde_json::json!({
            "virustotal_api_key_present": vt_key.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "cape_url_present": cape_url.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
            "cape_api_token_present": cape_token.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        });

        let dependency_failures = checks
            .iter()
            .filter(|c| !c["available"].as_bool().unwrap_or(false))
            .count();

        Ok(StandardResponse::success_timed(
            tool_name,
            serde_json::json!({
                "healthy": dependency_failures == 0,
                "dependency_failures": dependency_failures,
                "dependencies": checks,
                "api_keys": api_keys,
            }),
            start,
        ))
    }
}

async fn check_dependency(name: &str, command: &str, version_args: &[&str]) -> Value {
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
            "version": Value::Null
        });
    }

    let version = Command::new(command)
        .args(version_args)
        .output()
        .await
        .ok()
        .and_then(|out| {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !stdout.is_empty() {
                return Some(stdout.lines().next().unwrap_or_default().to_string());
            }
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if !stderr.is_empty() {
                return Some(stderr.lines().next().unwrap_or_default().to_string());
            }
            None
        });

    serde_json::json!({
        "name": name,
        "available": true,
        "version": version
    })
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(HealthCheckTool))
}
