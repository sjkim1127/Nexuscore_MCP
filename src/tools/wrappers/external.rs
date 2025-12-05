use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use async_trait::async_trait;
use tokio::process::Command;
use std::path::Path;

pub struct CapaTool;
#[async_trait]
impl Tool for CapaTool {
    fn name(&self) -> &str { "capa_scan" }
    fn description(&self) -> &str { "Identifies capabilities in executable files using Capa (MITRE ATT&CK). Args: file_path" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let path = args["file_path"].as_str().ok_or(anyhow::anyhow!("Missing file_path"))?;

        // Run capa with -j for JSON output
        let output = Command::new("capa")
            .arg("-j")
            .arg(path)
            .output()
            .await?;

        if !output.status.success() {
             return Err(anyhow::anyhow!("Capa failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8(output.stdout)?;
        // Parse JSON output from Capa
        let json_result: Value = serde_json::from_str(&stdout).unwrap_or(json!({"raw_output": stdout}));
        Ok(json_result)
    }
}

pub struct FlossTool;
#[async_trait]
impl Tool for FlossTool {
    fn name(&self) -> &str { "floss_strings" }
    fn description(&self) -> &str { "Extracts obfuscated strings using FireEye FLOSS. Args: file_path" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let path = args["file_path"].as_str().ok_or(anyhow::anyhow!("Missing file_path"))?;
        
        // Floss can take time, maybe -j for JSON or -q for quiet
        let output = Command::new("floss")
             .arg("-j")
             .arg(path)
             .output()
             .await?;

        if !output.status.success() {
             return Err(anyhow::anyhow!("Floss failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8(output.stdout)?;
        let json_result: Value = serde_json::from_str(&stdout).unwrap_or(json!({"raw_output": stdout}));
        Ok(json_result)
    }
}

pub struct ProcDumpTool;
#[async_trait]
impl Tool for ProcDumpTool {
    fn name(&self) -> &str { "procdump" }
    fn description(&self) -> &str { "Dumps process memory using Sysinternals ProcDump. Args: pid, output_dir" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))?;
        let out_dir = args["output_dir"].as_str().unwrap_or(".");
        let dump_name = format!("dump_{}.dmp", pid);
        let dump_path = Path::new(out_dir).join(&dump_name);

        // procdump -ma [pid] [output connection]
        // -ma: Write a 'Full' dump file.
        // -accepteula: Automatically accept the Sysinternals EULA
        let output = Command::new("procdump")
            .arg("-accepteula")
            .arg("-ma")
            .arg(pid.to_string())
            .arg(dump_path.to_string_lossy().to_string())
            .output()
            .await?;

        if !output.status.success() {
             return Err(anyhow::anyhow!("ProcDump failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        Ok(serde_json::json!({
            "status": "dump_created",
            "file": dump_path.to_string_lossy()
        }))
    }
}
