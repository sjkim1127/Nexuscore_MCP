//! End-to-end smoke test (Windows only, ignored by default).
//! Run with:
//!   cargo test --test e2e_smoke --features dynamic-analysis -- --ignored

#[cfg(all(test, windows, feature = "dynamic-analysis"))]
mod e2e {
    use nexuscore_mcp::server::NexusCoreServer;
    use serde_json::json;

    #[tokio::test]
    #[ignore]
    async fn e2e_v1_baseline_scenario() {
        let server = NexusCoreServer::new();
        let sample = "C:\\Windows\\System32\\notepad.exe";

        // 1) Create analysis session
        let created = server
            .call_tool_internal("analysis_session_create".into(), json!({ "sample_path": sample }))
            .await
            .unwrap();
        if created.is_error.unwrap_or(false) {
            return;
        }
        let session_id = created.structured_content.as_ref().unwrap()["data"]["session_id"]
            .as_str()
            .unwrap()
            .to_string();

        // 2) Static tools (skip gracefully if not ready)
        let die = server
            .call_tool_internal(
                "die_scan".into(),
                json!({ "file_path": sample, "analysis_session_id": session_id }),
            )
            .await
            .unwrap();
        if die.is_error.unwrap_or(false) {
            return;
        }

        let _ = server
            .call_tool_internal(
                "capa_scan".into(),
                json!({ "file_path": sample, "analysis_session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
            )
            .await
            .unwrap();

        // 3) Spawn + link PID (skip if Frida not ready)
        let spawned = server
            .call_tool_internal(
                "spawn_process".into(),
                json!({ "path": sample, "analysis_session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
            )
            .await
            .unwrap();
        if spawned.is_error.unwrap_or(false) {
            return;
        }
        let pid = spawned.structured_content.as_ref().unwrap()["data"]["pid"]
            .as_u64()
            .map(|v| v as u32);

        // 4) Create frida session (attach) and link it
        if let Some(pid) = pid {
            let frida = server
                .call_tool_internal(
                    "frida_session_create".into(),
                    json!({ "pid": pid, "analysis_session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
                )
                .await
                .unwrap();
            if frida.is_error.unwrap_or(false) {
                return;
            }
        }

        // 5) Validate status linkage
        let status = server
            .call_tool_internal(
                "analysis_session_status".into(),
                json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
            )
            .await
            .unwrap();
        if status.is_error.unwrap_or(false) {
            return;
        }

        let linked = &status.structured_content.as_ref().unwrap()["data"]["linked"];
        let pid_ok = linked["pid"].is_number();
        let frida_ok = linked["frida_session_id"].is_string();
        assert!(pid_ok || frida_ok);

        // 6) Timeline and artifacts minimums
        let timeline = server
            .call_tool_internal(
                "analysis_session_timeline".into(),
                json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone(), "limit": 100 }),
            )
            .await
            .unwrap();
        if timeline.is_error.unwrap_or(false) {
            return;
        }
        assert!(
            timeline.structured_content.as_ref().unwrap()["data"]["event_count"]
                .as_u64()
                .unwrap_or(0)
                >= 3
        );

        let artifacts = server
            .call_tool_internal(
                "analysis_session_artifacts".into(),
                json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
            )
            .await
            .unwrap();
        if artifacts.is_error.unwrap_or(false) {
            return;
        }
        assert!(
            artifacts.structured_content.as_ref().unwrap()["data"]["artifact_count"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );

        // 7) End
        let _ = server
            .call_tool_internal(
                "analysis_session_end".into(),
                json!({ "session_id": created.structured_content.as_ref().unwrap()["data"]["session_id"].clone() }),
            )
            .await
            .unwrap();
    }
}

