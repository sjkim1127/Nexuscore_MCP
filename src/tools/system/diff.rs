use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Mutex;
use walkdir::WalkDir;
use std::time::SystemTime;

// Global snapshot storage
static SNAPSHOT: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub struct SystemDiff;

#[async_trait]
impl Tool for SystemDiff {
    fn name(&self) -> &str { "system_diff" }
    fn description(&self) -> &str { "Takes/compares filesystem snapshots. Args: action (take/compare), paths (array of dirs to scan, default [C:\\Users\\Public])" }

    async fn execute(&self, args: Value) -> Result<Value> {
        let action = args["action"].as_str().ok_or(anyhow::anyhow!("Missing action"))?;
        let paths: Vec<String> = args["paths"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["C:\\Users\\Public".to_string()]);

        match action {
            "take" => {
                let mut files = HashSet::new();
                let start = SystemTime::now();
                
                for scan_path in &paths {
                    for entry in WalkDir::new(scan_path)
                        .max_depth(5) // Limit depth for performance
                        .into_iter()
                        .filter_map(|e| e.ok()) 
                    {
                        if entry.file_type().is_file() {
                            files.insert(entry.path().to_string_lossy().to_string());
                        }
                    }
                }
                
                let duration = start.elapsed().unwrap_or_default();
                let count = files.len();
                
                let mut lock = SNAPSHOT.lock().unwrap();
                *lock = Some(files);
                
                Ok(serde_json::json!({ 
                    "status": "snapshot_taken", 
                    "file_count": count,
                    "paths": paths,
                    "duration_ms": duration.as_millis()
                }))
            },
            "compare" => {
                let lock = SNAPSHOT.lock().unwrap();
                let old_files = match &*lock {
                    Some(f) => f.clone(),
                    None => return Err(anyhow::anyhow!("No snapshot taken yet. Run with action='take' first.")),
                };
                drop(lock); // Release lock before scanning

                let mut new_files = HashSet::new();
                for scan_path in &paths {
                    for entry in WalkDir::new(scan_path)
                        .max_depth(5)
                        .into_iter()
                        .filter_map(|e| e.ok()) 
                    {
                        if entry.file_type().is_file() {
                            new_files.insert(entry.path().to_string_lossy().to_string());
                        }
                    }
                }

                // Find changes
                let created: Vec<String> = new_files.difference(&old_files).cloned().collect();
                let deleted: Vec<String> = old_files.difference(&new_files).cloned().collect();

                Ok(serde_json::json!({ 
                    "status": "diff_complete", 
                    "created_count": created.len(),
                    "deleted_count": deleted.len(),
                    "created_files": created.iter().take(50).collect::<Vec<_>>(),
                    "deleted_files": deleted.iter().take(50).collect::<Vec<_>>(),
                    "note": "Showing max 50 items per category"
                }))
            },
            _ => Err(anyhow::anyhow!("Unknown action: {}. Use 'take' or 'compare'", action))
        }
    }
}
