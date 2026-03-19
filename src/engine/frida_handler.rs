use anyhow::{anyhow, Result};
use frida::{Device, DeviceManager, Frida, ScriptHandler, ScriptOption};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, OnceLock};
use std::thread;
use tokio::sync::{mpsc, oneshot};

/// Global Frida Client
static FRIDA_CLIENT: OnceLock<FridaClient> = OnceLock::new();
const MAX_FRIDA_MESSAGES: usize = 2_000;

pub fn get_frida_client() -> &'static FridaClient {
    FRIDA_CLIENT.get_or_init(|| {
        let (tx, rx) = mpsc::channel(100);
        thread::spawn(move || {
            let mut worker = FridaWorker::new(rx);
            if let Err(e) = worker.run() {
                tracing::error!("Frida worker error: {}", e);
            }
        });
        FridaClient { tx }
    })
}

// ============================================
// Internal Worker Types
// ============================================

enum FridaCommand {
    Attach {
        pid: u32,
        resp: oneshot::Sender<Result<String>>,
    },
    Spawn {
        path: String,
        resp: oneshot::Sender<Result<String>>,
    },
    Inject {
        session_id: String,
        script_content: String,
        resp: oneshot::Sender<Result<()>>,
    },
    Resume {
        session_id: String,
        resp: oneshot::Sender<Result<()>>,
    },
    GetMessagesSnapshot {
        session_id: String,
        limit: Option<usize>,
        resp: oneshot::Sender<Result<Vec<String>>>,
    },
    DrainMessages {
        session_id: String,
        limit: Option<usize>,
        resp: oneshot::Sender<Result<DrainResult>>,
    },
    Destroy {
        session_id: String,
        resp: oneshot::Sender<Result<()>>,
    },
    Cleanup {
        resp: oneshot::Sender<Result<()>>,
    },
    ListSessions {
        resp: oneshot::Sender<Vec<(String, u32, bool)>>,
    },
}

#[derive(Debug)]
pub struct DrainResult {
    pub messages: Vec<String>,
    pub dropped_count: u64,
}

struct ManagedSession<'a> {
    pid: u32,
    session: frida::Session<'a>,
    scripts: Vec<frida::Script<'a>>,
    messages: Arc<std::sync::Mutex<MessageBuffer>>,
    is_spawned: bool,
    state: SessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Created,
    Attached,
    Monitoring,
    Ended,
    Error,
}

#[derive(Debug, Default)]
struct MessageBuffer {
    queue: VecDeque<String>,
    dropped_count: u64,
}

impl MessageBuffer {
    fn push(&mut self, message: String) {
        if self.queue.len() >= MAX_FRIDA_MESSAGES {
            self.queue.pop_front();
            self.dropped_count += 1;
        }
        self.queue.push_back(message);
    }

    fn take_all(&mut self) -> Vec<String> {
        self.queue.drain(..).collect()
    }

    fn snapshot(&self, limit: Option<usize>) -> Vec<String> {
        match limit {
            Some(n) => self.queue.iter().take(n).cloned().collect(),
            None => self.queue.iter().cloned().collect(),
        }
    }

    fn drain(&mut self, limit: Option<usize>) -> Vec<String> {
        match limit {
            Some(n) => self.queue.drain(..std::cmp::min(n, self.queue.len())).collect(),
            None => self.take_all(),
        }
    }
}

struct FridaWorker {
    rx: mpsc::Receiver<FridaCommand>,
    next_id: u32,
}

impl FridaWorker {
    fn new(rx: mpsc::Receiver<FridaCommand>) -> Self {
        Self {
            rx,
            next_id: 1,
        }
    }

    fn run(&mut self) -> Result<()> {
        // IMPORTANT: Frida must be obtained and used within the SAME thread.
        let frida = unsafe { Frida::obtain() };
        let mut dm = DeviceManager::obtain(&frida);
        let mut device = dm.get_local_device()?;
        
        // Safety: We extend lifetimes to 'static because this thread owns these objects
        // and lives for the entire process duration. The objects are never sent to other threads.
        let device_static: &'static mut Device<'static> = unsafe { std::mem::transmute(&mut device) };
        let mut sessions: HashMap<String, ManagedSession<'static>> = HashMap::new();

        while let Some(cmd) = self.rx.blocking_recv() {
            match cmd {
                FridaCommand::Attach { pid, resp } => {
                    let res = self.handle_attach(&mut sessions, device_static, pid);
                    let _ = resp.send(res);
                }
                FridaCommand::Spawn { path, resp } => {
                    let res = self.handle_spawn(&mut sessions, device_static, path);
                    let _ = resp.send(res);
                }
                FridaCommand::Inject { session_id, script_content, resp } => {
                    let res = self.handle_inject(&mut sessions, session_id, script_content);
                    let _ = resp.send(res);
                }
                FridaCommand::Resume { session_id, resp } => {
                    let res = self.handle_resume(&mut sessions, device_static, session_id);
                    let _ = resp.send(res);
                }
                FridaCommand::GetMessagesSnapshot { session_id, limit, resp } => {
                    let res = self.handle_get_messages_snapshot(&sessions, session_id, limit);
                    let _ = resp.send(res);
                }
                FridaCommand::DrainMessages { session_id, limit, resp } => {
                    let res = self.handle_drain_messages(&sessions, session_id, limit);
                    let _ = resp.send(res);
                }
                FridaCommand::Destroy { session_id, resp } => {
                    let res = self.handle_destroy(&mut sessions, device_static, session_id);
                    let _ = resp.send(res);
                }
                FridaCommand::Cleanup { resp } => {
                    let res = self.handle_cleanup(&mut sessions, device_static);
                    let _ = resp.send(res);
                }
                FridaCommand::ListSessions { resp } => {
                    let session_info = sessions.iter()
                        .map(|(id, s)| (id.clone(), s.pid, s.state != SessionState::Ended))
                        .collect();
                    let _ = resp.send(session_info);
                }
            }
        }
        Ok(())
    }

    fn handle_attach(
        &mut self, 
        sessions: &mut HashMap<String, ManagedSession<'static>>, 
        device: &mut Device<'static>, 
        pid: u32
    ) -> Result<String> {
        if let Some((id, _)) = sessions.iter().find(|(_, s)| s.pid == pid) {
            return Ok(id.clone());
        }

        let session = device.attach(pid)?;
        let session_static: frida::Session<'static> = unsafe { std::mem::transmute(session) };
        let session_id = format!("frida_{}", self.next_id);
        self.next_id += 1;

        sessions.insert(session_id.clone(), ManagedSession {
            pid,
            session: session_static,
            scripts: Vec::new(),
            messages: Arc::new(std::sync::Mutex::new(MessageBuffer::default())),
            is_spawned: false,
            state: SessionState::Attached,
        });

        Ok(session_id)
    }

    fn handle_spawn(
        &mut self, 
        sessions: &mut HashMap<String, ManagedSession<'static>>, 
        device: &mut Device<'static>, 
        path: String
    ) -> Result<String> {
        let pid = device.spawn(&path, &frida::SpawnOptions::default())?;
        let session = device.attach(pid)?;
        let session_static: frida::Session<'static> = unsafe { std::mem::transmute(session) };
        
        let session_id = format!("frida_{}", self.next_id);
        self.next_id += 1;

        sessions.insert(session_id.clone(), ManagedSession {
            pid,
            session: session_static,
            scripts: Vec::new(),
            messages: Arc::new(std::sync::Mutex::new(MessageBuffer::default())),
            is_spawned: true,
            state: SessionState::Created,
        });

        Ok(session_id)
    }

    fn handle_inject(
        &mut self, 
        sessions: &mut HashMap<String, ManagedSession<'static>>, 
        session_id: String, 
        script_content: String
    ) -> Result<()> {
        let managed = sessions.get_mut(&session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        let script = managed.session.create_script(&script_content, &mut ScriptOption::default())?;
        let mut script_static: frida::Script<'static> = unsafe { std::mem::transmute(script) };
        
        let messages_clone = Arc::clone(&managed.messages);
        
        struct MyHandler(Arc<std::sync::Mutex<MessageBuffer>>);
        impl ScriptHandler for MyHandler {
            fn on_message(&mut self, message: frida::Message, _data: Option<Vec<u8>>) {
                let encoded = serde_json::json!({
                    "source": "frida_script",
                    "payload": message,
                    "timestamp_ms": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0)
                })
                .to_string();
                if let Ok(mut msgs) = self.0.lock() {
                    msgs.push(encoded);
                }
            }
        }

        let _ = script_static.handle_message(MyHandler(messages_clone));
        if let Err(e) = script_static.load() {
            managed.state = SessionState::Error;
            return Err(e.into());
        }
        
        managed.scripts.push(script_static);
        managed.state = SessionState::Monitoring;
        Ok(())
    }

    fn handle_resume(
        &self, 
        sessions: &mut HashMap<String, ManagedSession<'static>>, 
        device: &mut Device<'static>, 
        session_id: String
    ) -> Result<()> {
        let managed = sessions.get_mut(&session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;
        device.resume(managed.pid)?;
        if managed.state == SessionState::Created {
            managed.state = SessionState::Attached;
        }
        Ok(())
    }

    fn handle_get_messages_snapshot(
        &self, 
        sessions: &HashMap<String, ManagedSession<'static>>, 
        session_id: String,
        limit: Option<usize>,
    ) -> Result<Vec<String>> {
        let managed = sessions.get(&session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;
        let msgs = managed
            .messages
            .lock()
            .map_err(|_| anyhow!("Failed to lock messages"))?;
        Ok(msgs.snapshot(limit))
    }

    fn handle_drain_messages(
        &self,
        sessions: &HashMap<String, ManagedSession<'static>>,
        session_id: String,
        limit: Option<usize>,
    ) -> Result<DrainResult> {
        let managed = sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;
        let mut msgs = managed
            .messages
            .lock()
            .map_err(|_| anyhow!("Failed to lock messages"))?;

        let dropped = msgs.dropped_count;
        let drained = msgs.drain(limit);
        msgs.dropped_count = 0;

        Ok(DrainResult {
            messages: drained,
            dropped_count: dropped,
        })
    }

    fn handle_destroy(
        &mut self, 
        sessions: &mut HashMap<String, ManagedSession<'static>>, 
        device: &mut Device<'static>,
        session_id: String
    ) -> Result<()> {
        if let Some(mut managed) = sessions.remove(&session_id) {
            for mut script in managed.scripts {
                let _ = script.unload();
            }
            let _ = managed.session.detach();
            if managed.is_spawned {
                let _ = device.kill(managed.pid);
            }
            managed.state = SessionState::Ended;
        }
        Ok(())
    }

    fn handle_cleanup(
        &mut self, 
        sessions: &mut HashMap<String, ManagedSession<'static>>, 
        device: &mut Device<'static>
    ) -> Result<()> {
        for (_, mut managed) in sessions.drain() {
            for mut script in managed.scripts {
                let _ = script.unload();
            }
            let _ = managed.session.detach();
            if managed.is_spawned {
                let _ = device.kill(managed.pid);
            }
        }
        Ok(())
    }
}

// ============================================
// Public Client API
// ============================================

pub struct FridaClient {
    tx: mpsc::Sender<FridaCommand>,
}

impl FridaClient {
    pub async fn attach(&self, pid: u32) -> Result<String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(FridaCommand::Attach { pid, resp: resp_tx }).await?;
        resp_rx.await?
    }

    pub async fn spawn(&self, path: String) -> Result<String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(FridaCommand::Spawn { path, resp: resp_tx }).await?;
        resp_rx.await?
    }

    pub async fn inject(&self, session_id: String, script_content: String) -> Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(FridaCommand::Inject { session_id, script_content, resp: resp_tx }).await?;
        resp_rx.await?
    }

    pub async fn resume(&self, session_id: String) -> Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(FridaCommand::Resume { session_id, resp: resp_tx }).await?;
        resp_rx.await?
    }

    /// Debug/inspection: non-destructive snapshot of current buffer.
    pub async fn get_messages(&self, session_id: String) -> Result<Vec<String>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(FridaCommand::GetMessagesSnapshot {
                session_id,
                limit: None,
                resp: resp_tx,
            })
            .await?;
        resp_rx.await?
    }

    /// Ingest: destructive drain of buffered messages (prevents double-ingest).
    pub async fn drain_messages(
        &self,
        session_id: String,
        limit: Option<usize>,
    ) -> Result<DrainResult> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(FridaCommand::DrainMessages {
                session_id,
                limit,
                resp: resp_tx,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn destroy_session(&self, session_id: String) -> Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(FridaCommand::Destroy { session_id, resp: resp_tx }).await?;
        resp_rx.await?
    }

    pub async fn cleanup_all(&self) -> Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(FridaCommand::Cleanup { resp: resp_tx }).await?;
        resp_rx.await?
    }

    pub async fn list_sessions(&self) -> Result<Vec<(String, u32, bool)>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(FridaCommand::ListSessions { resp: resp_tx }).await?;
        Ok(resp_rx.await?)
    }
}

// ============================================
// Compatibility Layer
// ============================================

pub struct FridaHandler;

impl FridaHandler {
    pub fn new() -> Self { Self {} }

    pub async fn spawn_and_instrument(&self, path: &str, script_content: &str) -> Result<u32> {
        let client = get_frida_client();
        let session_id = client.spawn(path.to_string()).await?;
        if !script_content.is_empty() {
            client.inject(session_id.clone(), script_content.to_string()).await?;
        }
        client.resume(session_id.clone()).await?;
        let sessions = client.list_sessions().await?;
        sessions.iter()
            .find(|(id, _, _)| id == &session_id)
            .map(|(_, pid, _)| *pid)
            .ok_or_else(|| anyhow!("Failed to get PID for session"))
    }

    pub async fn attach_process(&self, pid: u32) -> Result<u32> {
        let client = get_frida_client();
        client.attach(pid).await?;
        Ok(pid)
    }

    pub async fn resume_process(&self, pid: u32) -> Result<()> {
        let client = get_frida_client();
        let sessions = client.list_sessions().await?;
        if let Some((id, _, _)) = sessions.iter().find(|(_, p, _)| *p == pid) {
            client.resume(id.clone()).await?;
        }
        Ok(())
    }

    pub async fn inject_script(&self, pid: u32, script_content: &str) -> Result<()> {
        let client = get_frida_client();
        let sessions = client.list_sessions().await?;
        let session_id = if let Some((id, _, _)) = sessions.iter().find(|(_, p, _)| *p == pid) {
            id.clone()
        } else {
            client.attach(pid).await?
        };
        client.inject(session_id, script_content.to_string()).await
    }
}

pub async fn execute_script(pid: u32, script_content: &str) -> Result<()> {
    let handler = FridaHandler::new();
    handler.inject_script(pid, script_content).await
}

pub async fn execute_script_with_session(pid: u32, script_content: &str) -> Result<String> {
    let client = get_frida_client();
    let sessions = client.list_sessions().await?;
    let session_id = if let Some((id, _, _)) = sessions.iter().find(|(_, p, _)| *p == pid) {
        id.clone()
    } else {
        client.attach(pid).await?
    };
    client.inject(session_id.clone(), script_content.to_string()).await?;
    Ok(session_id)
}

pub struct FridaSessionManagerProxy;
impl FridaSessionManagerProxy {
    pub fn cleanup_all(&self) {
        let client = get_frida_client();
        let rt = tokio::runtime::Handle::current();
        let _ = rt.block_on(client.cleanup_all());
    }
}

pub fn get_session_manager() -> FridaSessionManagerProxy {
    FridaSessionManagerProxy
}
