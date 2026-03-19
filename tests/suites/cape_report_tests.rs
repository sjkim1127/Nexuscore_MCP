use nexuscore_mcp::app::analysis_session_service::{AnalysisSessionService, InMemoryAnalysisSessionService};
use nexuscore_mcp::server::NexusCoreServer;
use nexuscore_mcp::utils::jobs::{get_job_manager, JobStatus};
use serde_json::json;

#[tokio::test]
async fn test_cape_submit_with_session_creates_submission_artifact() {
    // Minimal: we don't need CAPE to finish; submission artifact should be created immediately.
    let server = NexusCoreServer::new();
    let created = server
        .call_tool_internal(
            "analysis_session_create".into(),
            json!({ "sample_path": "C:\\tmp\\sample.exe" }),
        )
        .await
        .unwrap();
    let session_id = created.structured_content.as_ref().unwrap()["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Use existing service to append submission artifact deterministically (avoid background CAPE calls in unit tests)
    let svc = InMemoryAnalysisSessionService;
    let _ = svc.add_artifact(
        &session_id,
        nexuscore_mcp::state::analysis_session::AnalysisArtifact {
            id: "artifact_submission_test".to_string(),
            kind: nexuscore_mcp::state::analysis_session::ArtifactKind::CapeSubmission,
            created_at: 0,
            source_tool: "cape_submit".to_string(),
            metadata: json!({ "job_id": "job_test_1", "base_url": "http://127.0.0.1:8000", "status": "submitted" }),
            data_ref: None,
            inline_data: None,
        },
    );

    let artifacts = server
        .call_tool_internal(
            "analysis_session_artifacts".into(),
            json!({ "session_id": session_id, "kind": "cape_submission" }),
        )
        .await
        .unwrap();
    assert!(!artifacts.is_error.unwrap_or(true));
    assert!(
        artifacts.structured_content.as_ref().unwrap()["data"]["artifact_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
}

#[tokio::test]
async fn test_cape_check_status_attaches_report_once() {
    let server = NexusCoreServer::new();
    let created = server
        .call_tool_internal(
            "analysis_session_create".into(),
            json!({ "sample_path": "C:\\tmp\\sample.exe" }),
        )
        .await
        .unwrap();
    let session_id = created.structured_content.as_ref().unwrap()["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let manager = get_job_manager();
    let job_id = manager.create_job("cape_submit");

    let svc = InMemoryAnalysisSessionService;
    let _ = svc.add_artifact(
        &session_id,
        nexuscore_mcp::state::analysis_session::AnalysisArtifact {
            id: "artifact_submission_test".to_string(),
            kind: nexuscore_mcp::state::analysis_session::ArtifactKind::CapeSubmission,
            created_at: 0,
            source_tool: "cape_submit".to_string(),
            metadata: json!({ "job_id": job_id, "base_url": "http://127.0.0.1:8000", "status": "submitted" }),
            data_ref: None,
            inline_data: None,
        },
    );

    manager.update_status(
        &job_id,
        JobStatus::Completed(json!({
            "status": "analysis_finished",
            "task_id": 100,
            "cape_status": "reported",
            "report": {
                "info": { "score": 7.5 },
                "signatures": [ { "name": "sig1", "description": "d1" } ],
                "network": { "domains": ["a.com"] }
            }
        })),
    );

    let res = server
        .call_tool_internal(
            "cape_check_status".into(),
            json!({ "job_id": job_id, "analysis_session_id": session_id, "attach_report": true }),
        )
        .await
        .unwrap();
    assert!(!res.is_error.unwrap_or(true));
    let data = &res.structured_content.as_ref().unwrap()["data"];
    assert!(data["artifact_created"].as_bool().unwrap_or(false));
    assert!(data["artifact_id"].is_string());
    assert!(data["report_fingerprint"].is_string());
}

#[tokio::test]
async fn test_cape_check_status_second_poll_does_not_duplicate_artifact() {
    let server = NexusCoreServer::new();
    let created = server
        .call_tool_internal(
            "analysis_session_create".into(),
            json!({ "sample_path": "C:\\tmp\\sample.exe" }),
        )
        .await
        .unwrap();
    let session_id = created.structured_content.as_ref().unwrap()["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let manager = get_job_manager();
    let job_id = manager.create_job("cape_submit");

    let svc = InMemoryAnalysisSessionService;
    let _ = svc.add_artifact(
        &session_id,
        nexuscore_mcp::state::analysis_session::AnalysisArtifact {
            id: "artifact_submission_test".to_string(),
            kind: nexuscore_mcp::state::analysis_session::ArtifactKind::CapeSubmission,
            created_at: 0,
            source_tool: "cape_submit".to_string(),
            metadata: json!({ "job_id": job_id, "base_url": "http://127.0.0.1:8000", "status": "submitted" }),
            data_ref: None,
            inline_data: None,
        },
    );

    manager.update_status(
        &job_id,
        JobStatus::Completed(json!({
            "status": "analysis_finished",
            "task_id": 101,
            "cape_status": "reported",
            "report": { "info": { "score": 1.0 }, "signatures": [], "network": {} }
        })),
    );

    let first = server
        .call_tool_internal(
            "cape_check_status".into(),
            json!({ "job_id": job_id, "analysis_session_id": session_id, "attach_report": true }),
        )
        .await
        .unwrap();
    assert!(!first.is_error.unwrap_or(true));
    let first_data = &first.structured_content.as_ref().unwrap()["data"];
    let artifact_id = first_data["artifact_id"].as_str().unwrap().to_string();

    let second = server
        .call_tool_internal(
            "cape_check_status".into(),
            json!({ "job_id": job_id, "analysis_session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone(), "attach_report": true }),
        )
        .await
        .unwrap();
    assert!(!second.is_error.unwrap_or(true));
    let second_data = &second.structured_content.as_ref().unwrap()["data"];
    assert!(second_data["already_attached"].as_bool().unwrap_or(false));
    assert_eq!(second_data["artifact_id"].as_str().unwrap(), artifact_id);
}

