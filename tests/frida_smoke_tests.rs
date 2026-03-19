//! Frida Runtime Smoke Tests
//! Verifies actual interaction with a live process.
//! These tests are IGNORED by default and should be run with:
//! cargo test --test frida_smoke_tests --features dynamic-analysis -- --ignored

#[cfg(all(test, feature = "dynamic-analysis"))]
mod smoke_tests {
    use nexuscore_mcp::engine::frida_handler::get_frida_client;
    use std::process::{Command, Child};
    use std::time::Duration;
    use tokio::time::sleep;

    struct TestTarget {
        child: Child,
        pid: u32,
    }

    impl TestTarget {
        fn spawn() -> Self {
            // Using notepad.exe as it's a stable target on Windows
            let child = Command::new("notepad.exe")
                .spawn()
                .expect("Failed to spawn notepad.exe");
            let pid = child.id();
            Self { child, pid }
        }
    }

    impl Drop for TestTarget {
        fn drop(&mut self) {
            let _ = self.child.kill();
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_fs_01_02_attach_message_roundtrip() {
        let target = TestTarget::spawn();
        let client = get_frida_client();

        // 1. Attach (FS-01)
        let session_id = client.attach(target.pid).await
            .expect("Failed to attach to notepad");
        assert!(session_id.starts_with("frida_"), "Session ID should have frida_ prefix");

        // 2. Inject & Send Message (FS-02)
        let script = "send('hello_from_frida');";
        client.inject(session_id.clone(), script.to_string()).await
            .expect("Failed to inject script");

        // Give it a moment to process the script and send the message
        sleep(Duration::from_millis(500)).await;

        // 3. Collect Messages
        let messages = client.get_messages(session_id.clone()).await
            .expect("Failed to get messages");
        
        // Debug representation contains the string "hello_from_frida"
        assert!(messages.iter().any(|m| m.contains("hello_from_frida")), 
                "Message 'hello_from_frida' not found in: {:?}", messages);

        // 4. Detach (FS-01 cleanup)
        client.destroy_session(session_id).await
            .expect("Failed to destroy session");
    }

    #[tokio::test]
    #[ignore]
    async fn test_fs_03_script_runtime_error_handling() {
        let target = TestTarget::spawn();
        let client = get_frida_client();
        let session_id = client.attach(target.pid).await.unwrap();

        // Inject script with deliberate runtime error
        let script = "nonExistentFunction();";
        client.inject(session_id.clone(), script.to_string()).await.unwrap();

        sleep(Duration::from_millis(500)).await;

        // Check messages - Frida should send an error message (Exception)
        let messages = client.get_messages(session_id.clone()).await.unwrap();
        
        // Frida's Error message usually contains "Error" or "exception" in its Debug string
        assert!(messages.iter().any(|m| m.to_lowercase().contains("error") || m.to_lowercase().contains("exception")), 
                "Error message not captured. Messages: {:?}", messages);

        client.destroy_session(session_id).await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_fs_04_target_termination_cleanup() {
        let mut target = TestTarget::spawn();
        let client = get_frida_client();
        let session_id = client.attach(target.pid).await.unwrap();

        // Kill the target process while attached
        target.child.kill().expect("Failed to kill target");
        
        // Wait for the OS and Frida to settle
        sleep(Duration::from_secs(1)).await;

        // Try to destroy the session - should be handled gracefully even if target is gone
        let _ = client.destroy_session(session_id.clone()).await;
        
        // Check if session is indeed removed from our internal map
        let sessions = client.list_sessions().await.unwrap();
        assert!(sessions.iter().all(|(id, _, _)| id != &session_id), "Session should be removed from the list after destruction");
    }
}
