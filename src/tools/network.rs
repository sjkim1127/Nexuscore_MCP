use anyhow::Result;
use std::process::Stdio;
use tokio::process::Command;
use crate::tools::Tool;
use async_trait::async_trait;
use serde_json::Value;

pub struct NetworkCapture;

#[async_trait]
impl Tool for NetworkCapture {
    fn name(&self) -> &str { "network_capture" }
    fn description(&self) -> &str { "Starts/Stops packet capture using Tshark. Args: action ('start'/'stop'), interface (string), output (string, optional)" }
    
    async fn execute(&self, args: Value) -> Result<Value> {
        let action = args["action"].as_str().ok_or(anyhow::anyhow!("Missing action"))?;
        
        match action {
            "start" => {
                let interface = args["interface"].as_str().unwrap_or("eth0"); // Default interface or detect?
                let output = args["output"].as_str().unwrap_or("capture.pcap");
                
                // Spawn Tshark
                // Note: Managing child process ID lifecycle in a stateless tool request is tricky.
                // ideally we store the child process handle in a global state (like Arc<Mutex<HashMap<..>>>).
                // For this MVP, we will spawn and return the PID, assuming the user manages it or we detach.
                
                let child = Command::new("tshark")
                    .arg("-i").arg(interface)
                    .arg("-w").arg(output)
                    .arg("-q")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();

                match child {
                    Ok(c) => {
                         let pid = c.id().unwrap_or(0);
                         // In a real server, we MUST save this PID to kill it later.
                         Ok(serde_json::json!({ "status": "capture_started", "pid": pid, "file": output }))
                    },
                    Err(e) => Err(anyhow::anyhow!("Failed to start tshark: {}", e))
                }
            },
            "stop" => {
                let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))? as u32;
                // Kill process logic
                #[cfg(windows)]
                {
                    Command::new("taskkill").arg("/F").arg("/PID").arg(pid.to_string()).output().await?;
                }
                #[cfg(unix)]
                {
                    Command::new("kill").arg(pid.to_string()).output().await?;
                }
                
                Ok(serde_json::json!({ "status": "capture_stopped" }))
            },
            _ => Err(anyhow::anyhow!("Unknown action"))
        }
    }
}
