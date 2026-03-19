use nexuscore_mcp::tools::malware::sandbox_submit::CapeSubmitter;
use nexuscore_mcp::tools::malware::wrappers::external::{CapaTool, DieTool};
use nexuscore_mcp::tools::Tool;
use serde_json::json;
use std::fs;

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_cape_submitter_flow() {
        let mut server = Server::new_async().await;
        // Mock 1: File Submission
        let mock_submit = server
            .mock("POST", "/tasks/create/file/")
            .with_status(200)
            .with_body(r#"{"task_id": 100}"#)
            .create_async()
            .await;

        // Mock 2: Status Check (Running -> Completed)
        // Note: In real logic, it might poll. Here we return 'reported' immediately for speed.
        let mock_status = server
            .mock("GET", "/tasks/view/100/")
            .with_status(200)
            .with_body(r#"{"task": {"status": "reported"}}"#)
            .create_async()
            .await;

        // Mock 3: Get Report
        let mock_report = server
            .mock("GET", "/tasks/report/100/")
            .with_status(200)
            .with_body(r#"{"target": {"file": {"name": "malware.exe"}}}"#)
            .create_async()
            .await;

        // Create dummy file for submission
        let dummy_path = "test_sample.exe";
        fs::write(dummy_path, "MZ_DUMMY_CONTENT").unwrap();

        let tool = CapeSubmitter;
        let result = tool
            .execute(json!({
                "file_path": dummy_path,
                "base_url": server.url(),
                "timeout": 10
            }))
            .await;

        assert!(
            result.is_ok(),
            "Sandbox submission flow failed: {:?}",
            result.err()
        );
        let output = result.unwrap();
        let job_id = output["data"]["job_id"]
            .as_str()
            .expect("job_id missing");

        let job_manager = nexuscore_mcp::utils::jobs::get_job_manager();
        let mut completed = false;
        let mut last_status = None;
        for _ in 0..150 {
            if let Some(job) = job_manager.get_job(job_id) {
                last_status = Some(job.status.clone());
                if let nexuscore_mcp::utils::jobs::JobStatus::Completed(data) = &job.status {
                    assert_eq!(data["task_id"], 100);
                    assert_eq!(data["cape_status"], "reported");
                    completed = true;
                    break;
                } else if let nexuscore_mcp::utils::jobs::JobStatus::Failed(err) = &job.status {
                    panic!("Job failed: {}", err);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        assert!(
            completed,
            "Job did not complete in time. Last status: {:?}",
            last_status
        );

        // Cleanup after background job finished
        let _ = fs::remove_file(dummy_path);

        mock_submit.assert_async().await;
        mock_status.assert_async().await;
        mock_report.assert_async().await;
    }
}

#[tokio::test]
async fn test_die_tool_metadata() {
    let tool = DieTool;
    assert_eq!(tool.name(), "die_scan");
}

#[tokio::test]
async fn test_capa_tool_metadata() {
    let tool = CapaTool;
    assert_eq!(tool.name(), "capa_scan");
}
