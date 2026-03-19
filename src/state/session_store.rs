use crate::state::analysis_session::AnalysisSession;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static STORE: OnceLock<Mutex<HashMap<String, AnalysisSession>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<String, AnalysisSession>> {
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn insert(session: AnalysisSession) -> Result<()> {
    let mut g = store()
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock session store"))?;
    g.insert(session.session_id.clone(), session);
    Ok(())
}

pub fn get(session_id: &str) -> Result<AnalysisSession> {
    let g = store()
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock session store"))?;
    g.get(session_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Session not found"))
}

pub fn update<F>(session_id: &str, f: F) -> Result<AnalysisSession>
where
    F: FnOnce(&mut AnalysisSession) -> Result<()>,
{
    let mut g = store()
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock session store"))?;
    let s = g
        .get_mut(session_id)
        .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
    f(s)?;
    Ok(s.clone())
}
