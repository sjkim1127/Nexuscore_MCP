use crate::tools::Tool;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::process::Command;

pub struct HandleScanner;

#[async_trait]
impl Tool for HandleScanner {
    fn name(&self) -> &str {
        "scan_handles"
    }
    fn description(&self) -> &str {
        "Scans open handles and mutexes of a process using Sysinternals handle.exe. Args: pid (number)"
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))?;

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
                                handles.push(serde_json::json!({
                                    "type": obj_type,
                                    "name": name
                                }));
                            }
                        }
                    }
                }

                Ok(serde_json::json!({
                    "pid": pid,
                    "handle_count": handles.len(),
                    "handles": handles
                }))
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to run handle.exe. Is it in PATH? Error: {}",
                e
            )),
        }
    }
}
