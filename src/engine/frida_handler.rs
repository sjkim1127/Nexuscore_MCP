use anyhow::Result;
use frida::{DeviceManager, Frida};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Mutex;

// Global Frida instance for reuse
static FRIDA: std::sync::OnceLock<Frida> = std::sync::OnceLock::new();

fn get_frida() -> &'static Frida {
    FRIDA.get_or_init(|| unsafe { Frida::obtain() })
}

/// Frida Session Manager - Keeps sessions alive between tool calls
static SESSION_MANAGER: std::sync::OnceLock<Mutex<FridaSessionManager>> =
    std::sync::OnceLock::new();

pub fn get_session_manager() -> &'static Mutex<FridaSessionManager> {
    SESSION_MANAGER.get_or_init(|| Mutex::new(FridaSessionManager::new()))
}

/// Stored session with message receiver
struct FridaSession {
    pid: u32,
    message_rx: Receiver<String>,
    active: bool,
}

pub struct FridaSessionManager {
    sessions: HashMap<String, FridaSession>,
    next_id: u32,
    message_buffer: HashMap<String, Vec<String>>,
}

impl FridaSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
            message_buffer: HashMap::new(),
        }
    }

    /// Create a new Frida session (attach or spawn)
    pub fn create_session(&mut self, pid: Option<u32>, spawn_path: Option<&str>) -> Result<String> {
        let session_id = format!("frida_{}", self.next_id);
        self.next_id += 1;

        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        let device = device_manager.get_local_device()?;

        let target_pid = if let Some(path) = spawn_path {
            // Spawn new process
            let pid = device.spawn(path, &frida::SpawnOptions::default())?;
            tracing::info!("Spawned process: {} -> PID {}", path, pid);
            pid
        } else if let Some(p) = pid {
            p
        } else {
            return Err(anyhow::anyhow!("Provide pid or spawn_path"));
        };

        // Attach to process
        let session = device.attach(target_pid)?;

        // Create message channel
        let (_tx, rx) = channel::<String>();

        // Store session
        self.sessions.insert(
            session_id.clone(),
            FridaSession {
                pid: target_pid,
                message_rx: rx,
                active: true,
            },
        );

        self.message_buffer.insert(session_id.clone(), Vec::new());

        // Note: We intentionally keep `session` alive by not dropping it
        // In production, we'd use Arc<Session> but frida-rs Session isn't thread-safe
        std::mem::forget(session);

        Ok(session_id)
    }

    /// Inject script into existing session
    pub fn inject_script(&mut self, session_id: &str, script_content: &str) -> Result<()> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        if !session.active {
            return Err(anyhow::anyhow!(
                "Session {} is no longer active",
                session_id
            ));
        }

        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        let device = device_manager.get_local_device()?;

        // Re-attach to get session reference
        let frida_session = device.attach(session.pid)?;

        // Create and load script
        let script =
            frida_session.create_script(script_content, &mut frida::ScriptOption::default())?;
        script.load()?;

        tracing::info!(
            "Injected script into session {} (PID {})",
            session_id,
            session.pid
        );

        // Keep script loaded by not dropping
        std::mem::forget(script);
        std::mem::forget(frida_session);

        Ok(())
    }

    /// Resume a spawned process
    pub fn resume_process(&self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        let device = device_manager.get_local_device()?;
        device.resume(session.pid)?;

        Ok(())
    }

    /// Get collected messages from a session
    pub fn get_messages(&mut self, session_id: &str) -> Vec<String> {
        let session = match self.sessions.get(session_id) {
            Some(s) => s,
            None => return vec![],
        };

        // Collect any pending messages
        let mut messages = Vec::new();
        while let Ok(msg) = session.message_rx.try_recv() {
            messages.push(msg);
        }

        // Also return buffered messages
        if let Some(buffer) = self.message_buffer.get_mut(session_id) {
            buffer.extend(messages.clone());
            return buffer.clone();
        }

        messages
    }

    /// Destroy a session
    pub fn destroy_session(&mut self, session_id: &str) -> Result<()> {
        if let Some(mut session) = self.sessions.remove(session_id) {
            session.active = false;
            // Note: In a real implementation, we'd properly detach
            tracing::info!("Destroyed session {} (PID {})", session_id, session.pid);
        }
        self.message_buffer.remove(session_id);
        Ok(())
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<(String, u32, bool)> {
        self.sessions
            .iter()
            .map(|(id, s)| (id.clone(), s.pid, s.active))
            .collect()
    }

    /// Get session PID
    pub fn get_pid(&self, session_id: &str) -> Option<u32> {
        self.sessions.get(session_id).map(|s| s.pid)
    }

    /// Cleanup all active sessions and processes
    pub fn cleanup_all(&mut self) {
        tracing::info!("Cleaning up {} active Frida sessions", self.sessions.len());
        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        if let Ok(device) = device_manager.get_local_device() {
            for (id, session) in self.sessions.drain() {
                tracing::info!("Killing PID {} from session {}", session.pid, id);
                let _: Result<(), _> = device.kill(session.pid);
            }
        }
    }
}

// ============================================
// Legacy API (for backward compatibility)
// ============================================

pub struct FridaHandler;

impl FridaHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn spawn_and_instrument(&self, path: &str, script_content: &str) -> Result<u32> {
        let mut manager = get_session_manager().lock().unwrap();
        let session_id = manager.create_session(None, Some(path))?;

        if !script_content.is_empty() {
            manager.inject_script(&session_id, script_content)?;
        }

        manager.resume_process(&session_id)?;

        manager
            .get_pid(&session_id)
            .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))
    }

    pub async fn attach_process(&self, pid: u32) -> Result<u32> {
        let mut manager = get_session_manager().lock().unwrap();
        let _session_id = manager.create_session(Some(pid), None)?;
        Ok(pid)
    }

    pub async fn resume_process(&self, pid: u32) -> Result<()> {
        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        let device = device_manager.get_local_device()?;
        device.resume(pid)?;
        Ok(())
    }

    pub async fn inject_script(&self, pid: u32, script_content: &str) -> Result<()> {
        // Find session by PID or create new one
        let mut manager = get_session_manager().lock().unwrap();

        // Check if we already have a session for this PID
        let session_id = {
            let existing = manager
                .list_sessions()
                .into_iter()
                .find(|(_, p, active)| *p == pid && *active);

            if let Some((id, _, _)) = existing {
                id
            } else {
                manager.create_session(Some(pid), None)?
            }
        };

        manager.inject_script(&session_id, script_content)
    }
}

/// Standalone function to execute a Frida script on a process (maintains session)
pub fn execute_script(pid: u32, script_content: &str) -> Result<()> {
    let mut manager = get_session_manager().lock().unwrap();

    // Find or create session
    let session_id = {
        let existing = manager
            .list_sessions()
            .into_iter()
            .find(|(_, p, active)| *p == pid && *active);

        if let Some((id, _, _)) = existing {
            id
        } else {
            manager.create_session(Some(pid), None)?
        }
    };

    manager.inject_script(&session_id, script_content)?;
    Ok(())
}

/// Execute script and return session ID (for tools that need to track sessions)
pub fn execute_script_with_session(pid: u32, script_content: &str) -> Result<String> {
    let mut manager = get_session_manager().lock().unwrap();

    let session_id = {
        let existing = manager
            .list_sessions()
            .into_iter()
            .find(|(_, p, active)| *p == pid && *active);

        if let Some((id, _, _)) = existing {
            id
        } else {
            manager.create_session(Some(pid), None)?
        }
    };

    manager.inject_script(&session_id, script_content)?;
    Ok(session_id)
}
