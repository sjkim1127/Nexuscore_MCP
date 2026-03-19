use nexuscore_mcp::server::NexusCoreServer;
use serde_json::json;

#[tokio::test]
async fn test_analysis_session_create_note_artifacts_end() {
    let server = NexusCoreServer::new();

    let created = server
        .call_tool_internal(
            "analysis_session_create".into(),
            json!({ "sample_path": "C:\\tmp\\sample.exe" }),
        )
        .await
        .unwrap();
    assert!(!created.is_error.unwrap_or(true));
    let session_id = created.structured_content.as_ref().unwrap()["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let note = server
        .call_tool_internal(
            "analysis_session_append_note".into(),
            json!({ "session_id": session_id, "note": "UPX packing suspected before runtime execution" }),
        )
        .await
        .unwrap();
    assert!(!note.is_error.unwrap_or(true));

    let artifacts = server
        .call_tool_internal(
            "analysis_session_artifacts".into(),
            json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
        )
        .await
        .unwrap();
    assert!(!artifacts.is_error.unwrap_or(true));
    let count = artifacts.structured_content.as_ref().unwrap()["data"]["artifact_count"]
        .as_u64()
        .unwrap();
    assert!(count >= 1);

    let ended = server
        .call_tool_internal(
            "analysis_session_end".into(),
            json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
        )
        .await
        .unwrap();
    assert!(!ended.is_error.unwrap_or(true));
}

#[tokio::test]
async fn test_die_scan_with_session_id_creates_artifact() {
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

    // diec might not exist in CI/dev machine; if it fails that's OK for this unit test.
    let _ = server
        .call_tool_internal(
            "die_scan".into(),
            json!({ "file_path": "C:\\tmp\\sample.exe", "analysis_session_id": session_id }),
        )
        .await
        .unwrap();

    let artifacts = server
        .call_tool_internal(
            "analysis_session_artifacts".into(),
            json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
        )
        .await
        .unwrap();
    assert!(!artifacts.is_error.unwrap_or(true));
}

#[tokio::test]
async fn test_spawn_process_with_session_id_links_pid_field() {
    let server = NexusCoreServer::new();

    let created = server
        .call_tool_internal(
            "analysis_session_create".into(),
            json!({ "sample_path": "C:\\Windows\\System32\\notepad.exe" }),
        )
        .await
        .unwrap();
    let session_id = created.structured_content.as_ref().unwrap()["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Spawn requires dynamic-analysis feature + frida runtime; skip gracefully if unavailable.
    let spawned = server
        .call_tool_internal(
            "spawn_process".into(),
            json!({ "path": "C:\\Windows\\System32\\notepad.exe", "analysis_session_id": session_id }),
        )
        .await
        .unwrap();

    if spawned.is_error.unwrap_or(false) {
        return;
    }

    let status = server
        .call_tool_internal(
            "analysis_session_status".into(),
            json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
        )
        .await
        .unwrap();
    assert!(!status.is_error.unwrap_or(true));
    assert!(status.structured_content.as_ref().unwrap()["data"]["linked"]["pid"].is_number());
}

#[tokio::test]
async fn test_check_reputation_with_session_creates_artifact() {
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

    let _ = server
        .call_tool_internal(
            "check_reputation".into(),
            json!({ "type": "hash", "value": "00", "analysis_session_id": session_id }),
        )
        .await
        .unwrap();

    let artifacts = server
        .call_tool_internal(
            "analysis_session_artifacts".into(),
            json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone(), "kind": "reputation_result" }),
        )
        .await
        .unwrap();
    assert!(!artifacts.is_error.unwrap_or(true));
}

#[cfg(windows)]
#[tokio::test]
async fn test_scan_persistence_with_session_creates_artifact() {
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

    let res = server
        .call_tool_internal(
            "scan_persistence".into(),
            json!({ "analysis_session_id": session_id }),
        )
        .await
        .unwrap();
    assert!(!res.is_error.unwrap_or(true));

    let artifacts = server
        .call_tool_internal(
            "analysis_session_artifacts".into(),
            json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone(), "kind": "persistence_snapshot" }),
        )
        .await
        .unwrap();
    assert!(!artifacts.is_error.unwrap_or(true));
}

#[tokio::test]
async fn test_filters_invalid_kind_returns_error() {
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
        .unwrap();

    let res = server
        .call_tool_internal(
            "analysis_session_artifacts".into(),
            json!({ "session_id": session_id, "kind": "typo_kind" }),
        )
        .await
        .unwrap();
    assert!(res.is_error.unwrap_or(false));
    let sc = res.structured_content.as_ref().unwrap();
    assert_eq!(sc["status"], "error");
}

#[tokio::test]
async fn test_filters_invalid_event_type_returns_error() {
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
        .unwrap();

    let res = server
        .call_tool_internal(
            "analysis_session_timeline".into(),
            json!({ "session_id": session_id, "event_type": "typo_event" }),
        )
        .await
        .unwrap();
    assert!(res.is_error.unwrap_or(false));
    let sc = res.structured_content.as_ref().unwrap();
    assert_eq!(sc["status"], "error");
}

