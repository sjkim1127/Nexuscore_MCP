use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TIMELINE_MAX: usize = 1_000;
pub const ARTIFACT_INLINE_MAX_BYTES: usize = 64 * 1024;
pub const ARTIFACT_MAX_COUNT: usize = 500;
pub const NOTE_MAX_LEN: usize = 2_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Created,
    Triage,
    Running,
    Monitoring,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    StaticReport,
    CapaResult,
    FlossResult,
    HandleSnapshot,
    PersistenceSnapshot,
    FridaEventBatch,
    DebuggerOutput,
    CapeSubmission,
    ReputationResult,
    Note,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    SessionCreated,
    TriageStarted,
    StatusChanged,
    ProcessSpawned,
    FridaAttached,
    MonitoringStarted,
    ArtifactAdded,
    NoteAppended,
    SessionEnded,
    SessionFailed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedSessions {
    pub pid: Option<u32>,
    pub frida_session_id: Option<String>,
    pub debug_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisEvent {
    pub timestamp: u64,
    pub event_type: EventType,
    pub severity: Severity,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisArtifact {
    pub id: String,
    pub kind: ArtifactKind,
    pub created_at: u64,
    pub source_tool: String,
    pub metadata: Value,
    pub data_ref: Option<String>,
    pub inline_data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSession {
    pub session_id: String,
    pub sample_path: String,
    pub status: AnalysisStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_error: Option<String>,
    pub linked: LinkedSessions,
    pub timeline: Vec<AnalysisEvent>,
    pub artifacts: Vec<AnalysisArtifact>,
}
