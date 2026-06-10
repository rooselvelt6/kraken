use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisNote {
    pub id: String,
    pub description: String,
    pub related_findings: Vec<String>,
    pub probability: f32,
    pub impact: Severity,
    pub created_at: DateTime<Utc>,
    pub validated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntSession {
    pub id: String,
    pub target_path: PathBuf,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_findings: usize,
    pub notes: HashMap<String, String>,
    pub hypotheses: Vec<HypothesisNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntMemory {
    pub sessions: Vec<HuntSession>,
    pub cross_session_notes: HashMap<String, String>,
    pub known_patterns: Vec<String>,
    memory_dir: PathBuf,
}

impl HuntMemory {
    pub fn load(base_path: &Path) -> Self {
        let memory_dir = base_path.join(".kraken").join("hunt-memory");
        let path = memory_dir.join("memory.json");

        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(memory) = serde_json::from_str::<HuntMemory>(&content) {
                    return memory;
                }
            }
        }

        let _ = fs::create_dir_all(&memory_dir);
        HuntMemory {
            sessions: Vec::new(),
            cross_session_notes: HashMap::new(),
            known_patterns: Vec::new(),
            memory_dir,
        }
    }

    pub fn save(&self) {
        let path = self.memory_dir.join("memory.json");
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = fs::write(&path, &content);
        }
    }

    pub fn start_session(&mut self, target_path: &Path) -> String {
        let session_id = format!("hunt-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
        self.sessions.push(HuntSession {
            id: session_id.clone(),
            target_path: target_path.to_path_buf(),
            started_at: chrono::Utc::now(),
            completed_at: None,
            total_findings: 0,
            notes: HashMap::new(),
            hypotheses: Vec::new(),
        });
        self.save();
        session_id
    }

    pub fn end_session(&mut self, session_id: &str, total_findings: usize) {
        if let Some(session) = self.sessions.iter_mut().find(|s| s.id == session_id) {
            session.completed_at = Some(chrono::Utc::now());
            session.total_findings = total_findings;
        }
        self.save();
    }

    pub fn store_note(&mut self, session_id: &str, key: &str, value: &str) {
        if let Some(session) = self.sessions.iter_mut().find(|s| s.id == session_id) {
            session.notes.insert(key.to_string(), value.to_string());
        }
        self.save();
    }

    pub fn get_note(&self, session_id: &str, key: &str) -> Option<String> {
        self.sessions
            .iter()
            .find(|s| s.id == session_id)
            .and_then(|s| s.notes.get(key).cloned())
    }

    pub fn store_cross_session_note(&mut self, key: &str, value: &str) {
        self.cross_session_notes
            .insert(key.to_string(), value.to_string());
        self.save();
    }

    pub fn get_cross_session_note(&self, key: &str) -> Option<String> {
        self.cross_session_notes.get(key).cloned()
    }

    pub fn add_hypothesis(&mut self, session_id: &str, hypothesis: HypothesisNote) {
        if let Some(session) = self.sessions.iter_mut().find(|s| s.id == session_id) {
            session.hypotheses.push(hypothesis);
        }
        self.save();
    }

    pub fn get_hypotheses(&self, session_id: &str) -> Vec<&HypothesisNote> {
        self.sessions
            .iter()
            .find(|s| s.id == session_id)
            .map(|s| s.hypotheses.iter().collect())
            .unwrap_or_default()
    }

    pub fn get_active_hypotheses(&self, session_id: &str) -> Vec<&HypothesisNote> {
        self.sessions
            .iter()
            .find(|s| s.id == session_id)
            .map(|s| s.hypotheses.iter().filter(|h| !h.validated).collect())
            .unwrap_or_default()
    }

    pub fn get_recent_sessions(&self, n: usize) -> Vec<&HuntSession> {
        let mut sessions: Vec<&HuntSession> = self.sessions.iter().collect();
        sessions.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        sessions.into_iter().take(n).collect()
    }

    pub fn validate_hypothesis(&mut self, session_id: &str, hypothesis_id: &str) {
        if let Some(session) = self.sessions.iter_mut().find(|s| s.id == session_id) {
            if let Some(h) = session
                .hypotheses
                .iter_mut()
                .find(|h| h.id == hypothesis_id)
            {
                h.validated = true;
            }
        }
        self.save();
    }

    pub fn get_all_unvalidated_hypotheses(&self) -> Vec<&HypothesisNote> {
        self.sessions
            .iter()
            .flat_map(|s| s.hypotheses.iter())
            .filter(|h| !h.validated)
            .collect()
    }

    pub fn learn_pattern(&mut self, pattern: &str) {
        if !self.known_patterns.contains(&pattern.to_string()) {
            self.known_patterns.push(pattern.to_string());
        }
        self.save();
    }

    pub fn get_known_patterns(&self) -> &[String] {
        &self.known_patterns
    }
}
