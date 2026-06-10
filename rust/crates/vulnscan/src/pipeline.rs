use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hypothesis::{GeneratedHypothesis, HypothesisGenerator};
use crate::lateral::{AttackGraph, AttackPath, LateralMovement};
use crate::memory::HuntMemory;
use crate::recon::{AttackSurface, SurfaceRecon};
use crate::resume::{Checkpointer, ScanCheckpoint, ScanPhase, ScanState};
use crate::scan::VulnerabilityScanner;
use crate::{Finding, ScanConfig, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HuntMode {
    Fast,
    Deep,
    Overnight,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    pub hunt_id: String,
    pub mode: HuntMode,
    pub target_path: PathBuf,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    pub attack_surface: Option<AttackSurface>,
    pub attack_graph: Option<AttackGraph>,
    pub attack_paths: Vec<AttackPath>,
    pub hypotheses: Vec<GeneratedHypothesis>,
    pub deorphaned_findings: Vec<String>,
    pub phases_completed: Vec<ScanPhase>,
}

pub struct HuntPipeline {
    config: ScanConfig,
    memory: HuntMemory,
    checkpointer: Checkpointer,
}

impl HuntPipeline {
    pub fn new(config: ScanConfig) -> Self {
        let target = config
            .target_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));

        HuntPipeline {
            memory: HuntMemory::load(&target),
            checkpointer: Checkpointer::new(&target),
            config,
        }
    }

    pub fn run(&mut self, mode: HuntMode) -> HuntReport {
        let target = self
            .config
            .target_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));

        let session_id = self.memory.start_session(&target);
        let mut phases = Vec::new();
        let start = Instant::now();
        let hunt_id = session_id.clone();

        let attack_surface = SurfaceRecon::enumerate_attack_surface(&target, &self.config);
        phases.push(ScanPhase::Reconnaissance);

        let scanner = VulnerabilityScanner::new(self.config.clone());
        let findings = scanner.scan();
        phases.push(ScanPhase::FileScanning);
        phases.push(ScanPhase::PatternAnalysis);

        let attack_graph = LateralMovement::build_attack_graph(&findings);
        let attack_paths = LateralMovement::find_attack_paths(&attack_graph);
        let deorphaned = LateralMovement::deorphan_findings(&attack_graph);
        phases.push(ScanPhase::Chaining);

        let hypotheses = if matches!(mode, HuntMode::Deep | HuntMode::Overnight) {
            HypothesisGenerator::generate_from_findings(&findings)
        } else {
            Vec::new()
        };

        for h in &hypotheses {
            self.memory.add_hypothesis(
                &session_id,
                HypothesisGenerator::to_hypothesis_notes(&[h.clone()])
                    .into_iter()
                    .next()
                    .unwrap(),
            );
        }

        let high_count = findings
            .iter()
            .filter(|f| f.severity == Severity::High || f.severity == Severity::Critical)
            .count();
        self.memory.store_cross_session_note(
            &format!("last-hunt-{}", &hunt_id),
            &format!(
                "{} high/critical findings in {}",
                high_count,
                target.display()
            ),
        );

        for f in &findings {
            if let Some(cwe) = &f.cwe {
                self.memory
                    .learn_pattern(&format!("{}:{}", cwe, f.description));
            }
        }

        self.memory.end_session(&session_id, findings.len());
        phases.push(ScanPhase::Complete);

        let duration_ms = start.elapsed().as_millis() as u64;

        HuntReport {
            hunt_id,
            mode,
            target_path: target,
            started_at: chrono::Utc::now(),
            duration_ms,
            findings,
            attack_surface: Some(attack_surface),
            attack_graph: Some(attack_graph),
            attack_paths,
            hypotheses,
            deorphaned_findings: deorphaned,
            phases_completed: phases,
        }
    }

    pub fn run_deep(&mut self) -> HuntReport {
        let target = self
            .config
            .target_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));

        let session_id = self.memory.start_session(&target);
        let mut phases = Vec::new();
        let start = Instant::now();
        let hunt_id = session_id.clone();

        let attack_surface = SurfaceRecon::enumerate_attack_surface(&target, &self.config);
        phases.push(ScanPhase::Reconnaissance);

        let scanner = VulnerabilityScanner::new(self.config.clone());
        let findings = scanner.scan();
        phases.push(ScanPhase::FileScanning);
        phases.push(ScanPhase::PatternAnalysis);

        let attack_graph = LateralMovement::build_attack_graph(&findings);
        let attack_paths = LateralMovement::find_attack_paths(&attack_graph);
        let deorphaned = LateralMovement::deorphan_findings(&attack_graph);
        phases.push(ScanPhase::Chaining);

        let mut all_hypotheses = HypothesisGenerator::generate_from_findings(&findings);

        for orphan_id in &deorphaned {
            if let Some(finding) = findings.iter().find(|f| f.id == *orphan_id) {
                let hyps = HypothesisGenerator::generate_from_findings(&[finding.clone()]);
                all_hypotheses.extend(hyps);
            }
        }

        for h in &all_hypotheses {
            self.memory.add_hypothesis(
                &session_id,
                HypothesisGenerator::to_hypothesis_notes(&[h.clone()])
                    .into_iter()
                    .next()
                    .unwrap(),
            );
        }

        self.memory.store_cross_session_note(
            &format!("deep-hunt-{}", &hunt_id),
            &format!(
                "{} hypotheses generated from {} findings",
                all_hypotheses.len(),
                findings.len()
            ),
        );

        self.memory.end_session(&session_id, findings.len());
        phases.push(ScanPhase::Complete);

        let duration_ms = start.elapsed().as_millis() as u64;

        HuntReport {
            hunt_id,
            mode: HuntMode::Deep,
            target_path: target,
            started_at: chrono::Utc::now(),
            duration_ms,
            findings,
            attack_surface: Some(attack_surface),
            attack_graph: Some(attack_graph),
            attack_paths,
            hypotheses: all_hypotheses,
            deorphaned_findings: deorphaned,
            phases_completed: phases,
        }
    }

    pub fn run_overnight(&mut self) -> HuntReport {
        let target = self
            .config
            .target_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));

        let hunt_id = format!("overnight-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));

        let resume_state = self.checkpointer.resume_latest();
        let findings: Vec<Finding>;

        if let Some(state) = resume_state {
            if state.checkpoint.target_path == target {
                let scanner = VulnerabilityScanner::new(self.config.clone());
                findings = scanner.scan();
            } else {
                let session_id = self.memory.start_session(&target);
                let cp_state = ScanState {
                    checkpoint: ScanCheckpoint {
                        id: hunt_id.clone(),
                        target_path: target.clone(),
                        phase: ScanPhase::Reconnaissance,
                        files_scanned: Vec::new(),
                        files_remaining: Vec::new(),
                        findings_so_far: Vec::new(),
                        started_at: chrono::Utc::now(),
                        last_updated: chrono::Utc::now(),
                        progress_pct: 0.0,
                        estimated_remaining_secs: 0,
                    },
                    mode: "overnight".to_string(),
                    config_snapshot: format!("{:?}", self.config),
                    memory_session_id: Some(session_id.clone()),
                };
                self.checkpointer.save_checkpoint(&cp_state);

                let scanner = VulnerabilityScanner::new(self.config.clone());
                findings = scanner.scan();
            }
        } else {
            let session_id = self.memory.start_session(&target);
            let cp_state = ScanState {
                checkpoint: ScanCheckpoint {
                    id: hunt_id.clone(),
                    target_path: target.clone(),
                    phase: ScanPhase::Reconnaissance,
                    files_scanned: Vec::new(),
                    files_remaining: Vec::new(),
                    findings_so_far: Vec::new(),
                    started_at: chrono::Utc::now(),
                    last_updated: chrono::Utc::now(),
                    progress_pct: 0.0,
                    estimated_remaining_secs: 0,
                },
                mode: "overnight".to_string(),
                config_snapshot: format!("{:?}", self.config),
                memory_session_id: Some(session_id.clone()),
            };
            self.checkpointer.save_checkpoint(&cp_state);

            let scanner = VulnerabilityScanner::new(self.config.clone());
            findings = scanner.scan();
        }

        let attack_surface = SurfaceRecon::enumerate_attack_surface(&target, &self.config);
        let attack_graph = LateralMovement::build_attack_graph(&findings);
        let attack_paths = LateralMovement::find_attack_paths(&attack_graph);
        let deorphaned = LateralMovement::deorphan_findings(&attack_graph);
        let hypotheses = HypothesisGenerator::generate_from_findings(&findings);

        self.checkpointer.delete_checkpoint(&hunt_id);

        HuntReport {
            hunt_id,
            mode: HuntMode::Overnight,
            target_path: target,
            started_at: chrono::Utc::now(),
            duration_ms: 0,
            findings,
            attack_surface: Some(attack_surface),
            attack_graph: Some(attack_graph),
            attack_paths,
            hypotheses,
            deorphaned_findings: deorphaned,
            phases_completed: vec![
                ScanPhase::Reconnaissance,
                ScanPhase::FileScanning,
                ScanPhase::PatternAnalysis,
                ScanPhase::Chaining,
                ScanPhase::Complete,
            ],
        }
    }

    pub fn memory(&self) -> &HuntMemory {
        &self.memory
    }
}
