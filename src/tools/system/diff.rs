use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use crate::utils::response::StandardResponse;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Mutex;
use walkdir::WalkDir;
use std::time::Instant;

// Global snapshot storage
static SNAPSHOT: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub struct SystemDiff;

/// Scan files in background thread (non-blocking)
fn scan_files_blocking(paths: Vec<String>) -> HashSet<String> {
    let mut files = HashSet::new();
    for scan_path in &paths {
        for entry in WalkDir::new(scan_path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok()) 
        {
            if entry.file_type().is_file() {
                files.insert(entry.path().to_string_lossy().to_string());
            }
        }
    }
    files
}

#[async_trait]
impl Tool for SystemDiff {
    fn name(&self) -> &str { "system_diff" }
    fn description(&self) -> &str { "Takes/compares filesystem snapshots. Args: action (take/compare), paths (array of dirs to scan, default [C:\\Users\\Public])" }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();

        let action = match args["action"].as_str() {
            Some(a) => a,
            None => return Ok(StandardResponse::error(tool_name, "Missing action")),
        };
        let paths: Vec<String> = args["paths"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["C:\\Users\\Public".to_string()]);

        match action {
            "take" => {
                let paths_clone = paths.clone();
                
                let files = tokio::task::spawn_blocking(move || {
                    scan_files_blocking(paths_clone)
                }).await.map_err(|e| anyhow::anyhow!("Spawn error: {}", e))?;
                
                let count = files.len();
                
                let mut lock = SNAPSHOT.lock().unwrap();
                *lock = Some(files);
                
                Ok(StandardResponse::success_timed(tool_name, serde_json::json!({ 
                    "action": "take",
                    "file_count": count,
                    "paths": paths
                }), start))
            },
            "compare" => {
                let lock = SNAPSHOT.lock().unwrap();
                let old_files = match &*lock {
                    Some(f) => f.clone(),
                    None => return Ok(StandardResponse::error(tool_name, "No snapshot taken yet. Run with action='take' first.")),
                };
                drop(lock);

                let paths_clone = paths.clone();
                
                let new_files = tokio::task::spawn_blocking(move || {
                    scan_files_blocking(paths_clone)
                }).await.map_err(|e| anyhow::anyhow!("Spawn error: {}", e))?;

                let created: Vec<String> = new_files.difference(&old_files).cloned().collect();
                let deleted: Vec<String> = old_files.difference(&new_files).cloned().collect();

                Ok(StandardResponse::success_timed(tool_name, serde_json::json!({ 
                    "action": "compare",
                    "created_count": created.len(),
                    "deleted_count": deleted.len(),
                    "created_files": created.iter().take(50).collect::<Vec<_>>(),
                    "deleted_files": deleted.iter().take(50).collect::<Vec<_>>()
                }), start))
            },
            _ => Ok(StandardResponse::error(tool_name, &format!("Unknown action: {}. Use 'take' or 'compare'", action)))
        }
    }
}
