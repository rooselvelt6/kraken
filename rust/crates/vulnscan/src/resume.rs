use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanPhase {
    Reconnaissance,
    FileScanning,
    PatternAnalysis,
    LlmAnalysis,
    Chaining,
    ExploitGeneration,
    Reporting,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub id: String,
    pub target_path: PathBuf,
    pub phase: ScanPhase,
    pub files_scanned: Vec<PathBuf>,
    pub files_remaining: Vec<PathBuf>,
    pub findings_so_far: Vec<Finding>,
    pub started_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub progress_pct: f32,
    pub estimated_remaining_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub checkpoint: ScanCheckpoint,
    pub mode: String,
    pub config_snapshot: String,
    pub memory_session_id: Option<String>,
}

pub struct Checkpointer {
    checkpoint_dir: PathBuf,
}

impl Checkpointer {
    pub fn new(base_path: &Path) -> Self {
        let dir = base_path.join(".kraken").join("hunt-checkpoints");
        let _ = fs::create_dir_all(&dir);
        Checkpointer {
            checkpoint_dir: dir,
        }
    }

    pub fn save_checkpoint(&self, state: &ScanState) {
        let path = self.checkpoint_path(&state.checkpoint.id);
        if let Ok(content) = serde_json::to_string_pretty(state) {
            let _ = fs::write(&path, &content);
        }
    }

    pub fn load_checkpoint(&self, hunt_id: &str) -> Option<ScanState> {
        let path = self.checkpoint_path(hunt_id);
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str::<ScanState>(&content) {
                    return Some(state);
                }
            }
        }
        None
    }

    pub fn load_latest_checkpoint(&self) -> Option<ScanState> {
        let mut entries: Vec<_> = fs::read_dir(&self.checkpoint_dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
            .collect();

        entries.sort_by_key(|e| e.path().metadata().ok().and_then(|m| m.modified().ok()));

        entries.last().and_then(|e| {
            let path = e.path();
            let name = path.file_stem()?.to_str()?;
            self.load_checkpoint(name)
        })
    }

    pub fn list_hunts(&self) -> Vec<String> {
        fs::read_dir(&self.checkpoint_dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
            .filter_map(|e| {
                let name = e.path().file_stem()?.to_str()?.to_string();
                Some(name)
            })
            .collect()
    }

    pub fn delete_checkpoint(&self, hunt_id: &str) {
        let path = self.checkpoint_path(hunt_id);
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
    }

    pub fn update_progress(
        &self,
        state: &mut ScanState,
        scanned: Vec<PathBuf>,
        remaining: Vec<PathBuf>,
    ) {
        state.checkpoint.files_scanned = scanned;
        state.checkpoint.files_remaining = remaining;
        let total =
            (state.checkpoint.files_scanned.len() + state.checkpoint.files_remaining.len()) as f32;
        state.checkpoint.progress_pct = if total > 0.0 {
            (state.checkpoint.files_scanned.len() as f32 / total) * 100.0
        } else {
            0.0
        };
        state.checkpoint.last_updated = chrono::Utc::now();
        self.save_checkpoint(state);
    }

    pub fn add_finding(&self, state: &mut ScanState, finding: Finding) {
        state.checkpoint.findings_so_far.push(finding);
        self.save_checkpoint(state);
    }

    pub fn advance_phase(&self, state: &mut ScanState, phase: ScanPhase) {
        state.checkpoint.phase = phase;
        state.checkpoint.last_updated = chrono::Utc::now();
        self.save_checkpoint(state);
    }

    pub fn has_resumable_hunt(&self) -> bool {
        self.load_latest_checkpoint().is_some()
    }

    pub fn resume_latest(&self) -> Option<ScanState> {
        self.load_latest_checkpoint()
    }

    pub fn checkpoint_summary(&self, hunt_id: &str) -> Option<String> {
        self.load_checkpoint(hunt_id).map(|state| {
            let cp = &state.checkpoint;
            format!(
                "Hunt {} | Phase: {:?} | Progress: {:.1}% | Findings: {} | Scanned: {}/{} files",
                cp.id,
                cp.phase,
                cp.progress_pct,
                cp.findings_so_far.len(),
                cp.files_scanned.len(),
                cp.files_scanned.len() + cp.files_remaining.len()
            )
        })
    }

    fn checkpoint_path(&self, hunt_id: &str) -> PathBuf {
        self.checkpoint_dir.join(format!("{}.json", hunt_id))
    }
}
