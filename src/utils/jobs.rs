use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    Queued,
    Processing,
    Completed(serde_json::Value),
    Failed(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: String,
    pub tool_name: String,
    pub status: JobStatus,
    #[serde(skip)]
    pub start_time: Instant,
    pub elapsed_ms: u64,
}

pub struct JobManager {
    jobs: Mutex<HashMap<String, Job>>,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub fn create_job(&self, tool_name: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let job = Job {
            id: id.clone(),
            tool_name: tool_name.to_string(),
            status: JobStatus::Queued,
            start_time: Instant::now(),
            elapsed_ms: 0,
        };
        self.jobs.lock().unwrap().insert(id.clone(), job);
        id
    }

    pub fn update_status(&self, id: &str, status: JobStatus) {
        if let Some(job) = self.jobs.lock().unwrap().get_mut(id) {
            job.status = status;
            job.elapsed_ms = job.start_time.elapsed().as_millis() as u64;
        }
    }

    pub fn get_job(&self, id: &str) -> Option<Job> {
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(job) = jobs.get_mut(id) {
            job.elapsed_ms = job.start_time.elapsed().as_millis() as u64;
            Some(job.clone())
        } else {
            None
        }
    }
}

static JOB_MANAGER: std::sync::OnceLock<Arc<JobManager>> = std::sync::OnceLock::new();

pub fn get_job_manager() -> Arc<JobManager> {
    JOB_MANAGER
        .get_or_init(|| Arc::new(JobManager::new()))
        .clone()
}

use crate::tools::{ParamDef, Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use async_trait::async_trait;

pub struct CheckJobStatusTool;

#[async_trait]
impl Tool for CheckJobStatusTool {
    fn name(&self) -> &str {
        "check_job_status"
    }

    fn description(&self) -> &str {
        "Checks the status of a previously dispatched background job. Args: job_id (string)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ParamDef::new(
            "job_id",
            "string",
            true,
            "The UUID of the job to check",
        )])
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let job_id = match args["job_id"].as_str() {
            Some(id) => id,
            None => {
                return Ok(StandardResponse::error(
                    "check_job_status",
                    "Missing job_id",
                ))
            }
        };

        let manager = get_job_manager();
        if let Some(job) = manager.get_job(job_id) {
            Ok(StandardResponse::success_cached(
                "check_job_status",
                serde_json::to_value(&job).unwrap(),
            ))
        } else {
            Ok(StandardResponse::error(
                "check_job_status",
                &format!("Job {} not found", job_id),
            ))
        }
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(CheckJobStatusTool))
}
