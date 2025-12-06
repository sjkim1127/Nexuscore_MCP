use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use async_trait::async_trait;
use std::process::Command;

/// Windows Event Log Query - Queries Sysmon and Security logs
pub struct EventLogQuery;

#[async_trait]
impl Tool for EventLogQuery {
    fn name(&self) -> &str { "query_sysmon" }
    fn description(&self) -> &str { "Queries Windows Event Logs (Sysmon/Security). Args: event_id (number), minutes (default 60)" }

    async fn execute(&self, args: Value) -> Result<Value> {
        let event_id = args["event_id"].as_u64().unwrap_or(1); // Default: Process Create
        let minutes = args["minutes"].as_u64().unwrap_or(60);
        
        // Build PowerShell query for Sysmon
        let ps_script = format!(
            r#"
            $events = Get-WinEvent -FilterHashtable @{{
                LogName='Microsoft-Windows-Sysmon/Operational'
                ID={}
                StartTime=(Get-Date).AddMinutes(-{})
            }} -ErrorAction SilentlyContinue | Select-Object -First 50
            
            if ($events) {{
                $events | ForEach-Object {{
                    [PSCustomObject]@{{
                        TimeCreated = $_.TimeCreated.ToString('o')
                        EventId = $_.Id
                        Message = $_.Message.Substring(0, [Math]::Min(500, $_.Message.Length))
                    }}
                }} | ConvertTo-Json -Depth 3
            }} else {{
                '[]'
            }}
            "#,
            event_id, minutes
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_script])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run PowerShell: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Parse JSON output
        let events: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| {
            serde_json::json!([])
        });

        let event_count = if events.is_array() { 
            events.as_array().map(|a| a.len()).unwrap_or(0) 
        } else { 
            1 
        };

        Ok(serde_json::json!({
            "status": if stderr.is_empty() { "success" } else { "partial" },
            "query": {
                "event_id": event_id,
                "minutes": minutes,
                "log": "Microsoft-Windows-Sysmon/Operational"
            },
            "event_count": event_count,
            "events": events,
            "note": if stderr.contains("No events") || event_count == 0 { 
                "No events found. Is Sysmon installed and running?" 
            } else { 
                "" 
            }
        }))
    }
}

/// Common Sysmon Event IDs Reference
/// 1 = Process Create
/// 3 = Network Connection
/// 7 = Image Load (DLL)
/// 8 = CreateRemoteThread
/// 10 = Process Access
/// 11 = File Create
/// 12/13/14 = Registry Events
/// 22 = DNS Query
