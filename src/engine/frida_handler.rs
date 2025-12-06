use anyhow::Result;
use frida::{DeviceManager, Frida};
use std::sync::OnceLock;

// Global Frida instance for reuse
static FRIDA: OnceLock<Frida> = OnceLock::new();

fn get_frida() -> &'static Frida {
    FRIDA.get_or_init(|| unsafe { Frida::obtain() })
}

pub struct FridaHandler;

impl FridaHandler {
    pub fn new() -> Self {
        Self {}
    }

    /// Spawns a process in suspended state, injects script, and resumes
    pub async fn spawn_and_instrument(&self, path: &str, script_content: &str) -> Result<u32> {
        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        let device = device_manager.get_local_device()?;
        
        // 1. Spawn suspended
        let pid = device.spawn(path, &frida::SpawnOptions::default())?;
        
        // 2. Attach
        let session = device.attach(pid)?;
        
        // 3. Load Script (if any)
        if !script_content.is_empty() {
             let script = session.create_script(script_content, &mut frida::ScriptOption::default())?;
             script.load()?;
             tracing::info!("Script loaded for PID {}", pid);
             // Note: Session dropping here might unload script. 
             // Ideally we need a session manager. For MVP/Stealth, some hooks persist or we rely on race.
        }

        // 4. Resume
        device.resume(pid)?;
        
        Ok(pid)
    }

    /// Attaches to a running process
    pub async fn attach_process(&self, pid: u32) -> Result<u32> {
        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        let device = device_manager.get_local_device()?;
        let _session = device.attach(pid)?;
        Ok(pid)
    }

    /// Resumes a process
    pub async fn resume_process(&self, pid: u32) -> Result<()> {
        let frida = get_frida();
        let device_manager = DeviceManager::obtain(frida);
        let device = device_manager.get_local_device()?;
        device.resume(pid)?;
        Ok(())
    }

    /// Injects an arbitrary JS script into an existing process
    pub async fn inject_script(&self, pid: u32, script_content: &str) -> Result<()> {
         execute_script(pid, script_content)
    }
}

/// Standalone function to execute a Frida script on a process
/// This is used by hook.rs, memory.rs and other tools
pub fn execute_script(pid: u32, script_content: &str) -> Result<()> {
    let frida = get_frida();
    let device_manager = DeviceManager::obtain(frida);
    let device = device_manager.get_local_device()?;
    let session = device.attach(pid)?;

    if !script_content.is_empty() {
        let script = session.create_script(script_content, &mut frida::ScriptOption::default())?;
        script.load()?;
        tracing::info!("Executed script on PID {}", pid);
    }
    Ok(())
}
