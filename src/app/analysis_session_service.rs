use crate::state::analysis_session::*;
use crate::state::session_store;
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub trait AnalysisSessionService {
    fn create_session(&self, sample_path: &str) -> Result<AnalysisSession>;
    fn mark_triage(&self, session_id: &str) -> Result<()>;
    fn link_process(&self, session_id: &str, pid: u32) -> Result<()>;
    fn link_frida(&self, session_id: &str, frida_session_id: &str, pid: Option<u32>) -> Result<()>;
    fn link_debugger(&self, session_id: &str, debug_session_id: &str) -> Result<()>;
    fn add_event(&self, session_id: &str, event: AnalysisEvent) -> Result<()>;
    fn add_artifact(&self, session_id: &str, artifact: AnalysisArtifact) -> Result<()>;
    fn append_note(&self, session_id: &str, note: &str) -> Result<()>;
    fn add_frida_event_batch(
        &self,
        session_id: &str,
        frida_session_id: &str,
        pid: Option<u32>,
        raw_events: Vec<String>,
        dropped_count: u64,
    ) -> Result<AnalysisArtifact>;
    fn set_failed(&self, session_id: &str, error: &str) -> Result<()>;
    fn complete(&self, session_id: &str) -> Result<()>;
}

pub struct InMemoryAnalysisSessionService;

impl InMemoryAnalysisSessionService {
    fn push_event(session: &mut AnalysisSession, event: AnalysisEvent) {
        session.timeline.push(event);
        if session.timeline.len() > TIMELINE_MAX {
            let excess = session.timeline.len() - TIMELINE_MAX;
            session.timeline.drain(0..excess);
        }
    }

    fn enforce_artifact_limits(session: &mut AnalysisSession) {
        while session.artifacts.len() > ARTIFACT_MAX_COUNT {
            // Prefer dropping oldest low-value artifacts first.
            if let Some(pos) = session
                .artifacts
                .iter()
                .position(|a| matches!(a.kind, ArtifactKind::Note | ArtifactKind::DebuggerOutput))
            {
                session.artifacts.remove(pos);
            } else {
                session.artifacts.remove(0);
            }
        }
    }

    fn normalize_artifact(mut artifact: AnalysisArtifact) -> AnalysisArtifact {
        if let Some(inline) = artifact.inline_data.take() {
            match serde_json::to_vec(&inline) {
                Ok(bytes) if bytes.len() <= ARTIFACT_INLINE_MAX_BYTES => {
                    artifact.inline_data = Some(inline);
                }
                Ok(bytes) => {
                    artifact.metadata = merge_metadata(
                        artifact.metadata,
                        serde_json::json!({
                            "inline_data_truncated": true,
                            "inline_bytes": bytes.len(),
                            "inline_max_bytes": ARTIFACT_INLINE_MAX_BYTES
                        }),
                    );
                    artifact.inline_data = None;
                }
                Err(_) => {
                    artifact.metadata = merge_metadata(
                        artifact.metadata,
                        serde_json::json!({
                            "inline_data_truncated": true,
                            "reason": "serialization_failed"
                        }),
                    );
                    artifact.inline_data = None;
                }
            }
        }
        artifact
    }
}

fn merge_metadata(base: Value, extra: Value) -> Value {
    match (base, extra) {
        (Value::Object(mut a), Value::Object(b)) => {
            for (k, v) in b {
                a.insert(k, v);
            }
            Value::Object(a)
        }
        (a, _) => a,
    }
}

impl AnalysisSessionService for InMemoryAnalysisSessionService {
    fn create_session(&self, sample_path: &str) -> Result<AnalysisSession> {
        let ts = now_unix();
        let session_id = format!("analysis_{}", Uuid::new_v4());

        let mut session = AnalysisSession {
            session_id: session_id.clone(),
            sample_path: sample_path.to_string(),
            status: AnalysisStatus::Created,
            created_at: ts,
            updated_at: ts,
            last_error: None,
            linked: LinkedSessions {
                pid: None,
                frida_session_id: None,
                debug_session_id: None,
            },
            timeline: vec![],
            artifacts: vec![],
        };

        Self::push_event(
            &mut session,
            AnalysisEvent {
                timestamp: ts,
                event_type: EventType::SessionCreated,
                severity: Severity::Info,
                details: serde_json::json!({ "sample_path": sample_path }),
            },
        );

        session_store::insert(session.clone())?;
        Ok(session)
    }

    fn mark_triage(&self, session_id: &str) -> Result<()> {
        session_store::update(session_id, |s| {
            let ts = now_unix();
            s.status = AnalysisStatus::Triage;
            s.updated_at = ts;
            Self::push_event(
                s,
                AnalysisEvent {
                    timestamp: ts,
                    event_type: EventType::TriageStarted,
                    severity: Severity::Info,
                    details: Value::Null,
                },
            );
            Ok(())
        })?;
        Ok(())
    }

    fn link_process(&self, session_id: &str, pid: u32) -> Result<()> {
        session_store::update(session_id, |s| {
            let ts = now_unix();
            s.linked.pid = Some(pid);
            if matches!(s.status, AnalysisStatus::Created | AnalysisStatus::Triage) {
                s.status = AnalysisStatus::Running;
            }
            s.updated_at = ts;
            Self::push_event(
                s,
                AnalysisEvent {
                    timestamp: ts,
                    event_type: EventType::ProcessSpawned,
                    severity: Severity::Info,
                    details: serde_json::json!({ "pid": pid }),
                },
            );
            Ok(())
        })?;
        Ok(())
    }

    fn link_frida(&self, session_id: &str, frida_session_id: &str, pid: Option<u32>) -> Result<()> {
        session_store::update(session_id, |s| {
            let ts = now_unix();
            s.linked.frida_session_id = Some(frida_session_id.to_string());
            if let Some(pid) = pid {
                s.linked.pid = Some(pid);
            }
            s.updated_at = ts;
            Self::push_event(
                s,
                AnalysisEvent {
                    timestamp: ts,
                    event_type: EventType::FridaAttached,
                    severity: Severity::Info,
                    details: serde_json::json!({
                        "frida_session_id": frida_session_id,
                        "pid": s.linked.pid
                    }),
                },
            );
            Ok(())
        })?;
        Ok(())
    }

    fn link_debugger(&self, session_id: &str, debug_session_id: &str) -> Result<()> {
        session_store::update(session_id, |s| {
            let ts = now_unix();
            s.linked.debug_session_id = Some(debug_session_id.to_string());
            s.updated_at = ts;
            Ok(())
        })?;
        Ok(())
    }

    fn add_event(&self, session_id: &str, event: AnalysisEvent) -> Result<()> {
        session_store::update(session_id, |s| {
            s.updated_at = now_unix();
            Self::push_event(s, event);
            Ok(())
        })?;
        Ok(())
    }

    fn add_artifact(&self, session_id: &str, artifact: AnalysisArtifact) -> Result<()> {
        session_store::update(session_id, |s| {
            let ts = now_unix();
            let artifact = Self::normalize_artifact(artifact);
            s.updated_at = ts;
            s.artifacts.push(artifact);
            Self::enforce_artifact_limits(s);
            Ok(())
        })?;
        Ok(())
    }

    fn append_note(&self, session_id: &str, note: &str) -> Result<()> {
        let note = note.chars().take(NOTE_MAX_LEN).collect::<String>();
        let ts = now_unix();

        self.add_artifact(
            session_id,
            AnalysisArtifact {
                id: format!("note_{}", Uuid::new_v4()),
                kind: ArtifactKind::Note,
                created_at: ts,
                source_tool: "analysis_session_append_note".to_string(),
                metadata: serde_json::json!({}),
                data_ref: None,
                inline_data: Some(serde_json::json!({ "note": note })),
            },
        )?;

        // v1: timeline 소음 방지 — NoteAppended만 기록 (ArtifactAdded는 기록하지 않음)
        self.add_event(
            session_id,
            AnalysisEvent {
                timestamp: ts,
                event_type: EventType::NoteAppended,
                severity: Severity::Info,
                details: Value::Null,
            },
        )?;

        Ok(())
    }

    fn add_frida_event_batch(
        &self,
        session_id: &str,
        frida_session_id: &str,
        pid: Option<u32>,
        raw_events: Vec<String>,
        dropped_count: u64,
    ) -> Result<AnalysisArtifact> {
        let ts = now_unix();

        let mut parsed: Vec<Value> = Vec::new();
        let mut invalid_count: u64 = 0;

        let mut from_ts: Option<u64> = None;
        let mut to_ts: Option<u64> = None;

        let mut severity_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut category_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

        for raw in &raw_events {
            match serde_json::from_str::<Value>(raw) {
                Ok(v) => {
                    let sev = v
                        .get("severity")
                        .and_then(|x| x.as_str())
                        .unwrap_or("info")
                        .to_string();
                    let cat = v
                        .get("category")
                        .and_then(|x| x.as_str())
                        .unwrap_or("unknown")
                        .to_string();

                    *severity_counts.entry(sev).or_insert(0) += 1;
                    *category_counts.entry(cat).or_insert(0) += 1;

                    let candidate_ts = v
                        .get("ts")
                        .and_then(|x| x.as_u64())
                        .or_else(|| v.get("timestamp_ms").and_then(|x| x.as_u64()));

                    if let Some(t) = candidate_ts {
                        from_ts = Some(from_ts.map(|m| m.min(t)).unwrap_or(t));
                        to_ts = Some(to_ts.map(|m| m.max(t)).unwrap_or(t));
                    }

                    parsed.push(v);
                }
                Err(_) => invalid_count += 1,
            }
        }

        let ingested_count = raw_events.len() as u64;
        let parsed_count = parsed.len() as u64;

        // v1: inline payload 상한 준수 — 넘치면 앞부분만 저장
        let mut stored_events = parsed;
        let mut truncated = false;
        let original_count = stored_events.len();
        while let Ok(bytes) = serde_json::to_vec(&stored_events) {
            if bytes.len() <= ARTIFACT_INLINE_MAX_BYTES {
                break;
            }
            if stored_events.len() <= 1 {
                truncated = true;
                stored_events.clear();
                break;
            }
            truncated = true;
            stored_events.pop();
        }

        let artifact_id = format!("artifact_{}", Uuid::new_v4());
        let artifact = AnalysisArtifact {
            id: artifact_id.clone(),
            kind: ArtifactKind::FridaEventBatch,
            created_at: ts,
            source_tool: "analysis_session_ingest_frida_messages".to_string(),
            metadata: serde_json::json!({
                "frida_session_id": frida_session_id,
                "pid": pid,
                "ingested_count": ingested_count,
                "parsed_count": parsed_count,
                "invalid_count": invalid_count,
                "from_ts": from_ts,
                "to_ts": to_ts,
                "severity_counts": severity_counts,
                "category_counts": category_counts,
                "dropped_count": dropped_count,
                "truncated": truncated,
                "original_count": original_count,
                "stored_count": stored_events.len(),
            }),
            data_ref: None,
            inline_data: Some(Value::Array(stored_events)),
        };

        self.add_artifact(session_id, artifact.clone())?;
        // v1: timeline 소음 방지 — 요약 이벤트 1개만 기록
        self.add_event(
            session_id,
            AnalysisEvent {
                timestamp: ts,
                event_type: EventType::FridaBatchIngested,
                severity: Severity::Info,
                details: serde_json::json!({
                    "frida_session_id": frida_session_id,
                    "pid": pid,
                    "ingested_count": ingested_count,
                    "parsed_count": parsed_count,
                    "invalid_count": invalid_count,
                    "dropped_count": dropped_count
                }),
            },
        )?;

        Ok(artifact)
    }

    fn set_failed(&self, session_id: &str, error: &str) -> Result<()> {
        session_store::update(session_id, |s| {
            let ts = now_unix();
            s.status = AnalysisStatus::Failed;
            s.last_error = Some(error.to_string());
            s.updated_at = ts;
            Self::push_event(
                s,
                AnalysisEvent {
                    timestamp: ts,
                    event_type: EventType::SessionFailed,
                    severity: Severity::Warning,
                    details: serde_json::json!({ "error": error }),
                },
            );
            Ok(())
        })?;
        Ok(())
    }

    fn complete(&self, session_id: &str) -> Result<()> {
        session_store::update(session_id, |s| {
            let ts = now_unix();
            s.status = AnalysisStatus::Completed;
            s.updated_at = ts;
            Self::push_event(
                s,
                AnalysisEvent {
                    timestamp: ts,
                    event_type: EventType::SessionEnded,
                    severity: Severity::Info,
                    details: Value::Null,
                },
            );
            Ok(())
        })?;
        Ok(())
    }
}

