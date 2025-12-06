use anyhow::Result;
use serde_json::Value;
use crate::tools::{Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use async_trait::async_trait;
use winreg::enums::*;
use winreg::RegKey;
use std::path::Path;
use std::time::Instant;

pub struct PersistenceHunter;

#[async_trait]
impl Tool for PersistenceHunter {
    fn name(&self) -> &str { "scan_persistence" }
    fn description(&self) -> &str { "Scans registry Run keys and Startup folders for persistence. No args." }
    fn schema(&self) -> ToolSchema { ToolSchema::empty() }
    
    async fn execute(&self, _args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        let mut results = Vec::new();

        let keys = [
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
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
        if let Ok(appdata) = std::env::var("APPDATA") {
            let startup = Path::new(&appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if let Ok(entries) = std::fs::read_dir(&startup) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|f| f.is_file()).unwrap_or(false) {
                        results.push(serde_json::json!({
                            "type": "file", "path": entry.path().to_string_lossy()
                        }));
                    }
                }
            }
        }

        Ok(StandardResponse::success_timed(tool_name, serde_json::json!({
            "count": results.len(),
            "items": results
        }), start))
    }
}
