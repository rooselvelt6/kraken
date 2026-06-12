use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hypothesis::{GeneratedHypothesis, HypothesisGenerator};
use crate::lateral::{AttackGraph, AttackPath, LateralMovement};
use crate::llm_analyst::{LlmAnalyst, LlmAnalystConfig, LlmAnalysisReport};
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
    pub llm_analysis: Option<LlmAnalysisReport>,
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
            llm_analysis: None,
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

        let llm_analysis = if self.config.enable_llm_validation {
            let analyst = LlmAnalyst::new(LlmAnalystConfig {
                model: self.config.model.clone(),
                ..Default::default()
            });
            match analyst {
                Ok(analyst) => {
                    let findings_for_llm = findings.clone();
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    match runtime {
                        Ok(rt) => {
                            let result = rt.block_on(async {
                                let mut validations = Vec::new();

                                let mut by_file: std::collections::HashMap<std::path::PathBuf, Vec<Finding>> =
                                    std::collections::HashMap::new();
                                for f in &findings_for_llm {
                                    if let Some(ref path) = f.file_path {
                                        by_file.entry(path.clone()).or_default().push(f.clone());
                                    }
                                }

                                for (path, file_findings) in &by_file {
                                    if let Ok(content) = std::fs::read_to_string(path) {
                                        let lang = crate::analyzers::detect_language(path);
                                        let v = analyst
                                            .cross_validate(path, &content, lang, file_findings)
                                            .await;
                                        validations.extend(v);
                                    }
                                }

                                let rankings = analyst.rank_findings(&findings_for_llm).await;

                                Some(LlmAnalysisReport {
                                    validations,
                                    rankings,
                                    exploit_primitives: Vec::new(),
                                    bughunt_summary: String::new(),
                                })
                            });
                            result
                        }
                        Err(_) => None,
                    }
                }
                Err(e) => {
                    eprintln!("[pipeline] Failed to create LLM analyst: {e}");
                    None
                }
            }
        } else {
            None
        };

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
            llm_analysis,
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

        let llm_analysis = if self.config.enable_llm_validation || self.config.enable_bughunt_pipeline {
            let analyst = LlmAnalyst::new(LlmAnalystConfig {
                model: self.config.model.clone(),
                ..Default::default()
            });
            match analyst {
                Ok(analyst) => {
                    let findings_for_llm = findings.clone();
                    let attack_paths_for_llm = attack_paths.clone();
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    match runtime {
                        Ok(rt) => {
                            let result = rt.block_on(async {
                                let mut validations = Vec::new();

                                let mut by_file: std::collections::HashMap<
                                    std::path::PathBuf,
                                    Vec<Finding>,
                                > = std::collections::HashMap::new();
                                for f in &findings_for_llm {
                                    if let Some(ref path) = f.file_path {
                                        by_file.entry(path.clone()).or_default().push(f.clone());
                                    }
                                }

                                for (path, file_findings) in &by_file {
                                    if let Ok(content) = std::fs::read_to_string(path) {
                                        let lang = crate::analyzers::detect_language(path);
                                        let v = analyst
                                            .cross_validate(path, &content, lang, file_findings)
                                            .await;
                                        validations.extend(v);
                                    }
                                }

                                let rankings = analyst.rank_findings(&findings_for_llm).await;

                                let mut exploit_primitives = Vec::new();
                                if self.config.enable_bughunt_pipeline {
                                    let validated: Vec<&Finding> = findings_for_llm
                                        .iter()
                                        .filter(|f| {
                                            validations
                                                .iter()
                                                .any(|v| v.finding_id == f.id && v.validated)
                                        })
                                        .collect();
                                    for finding in validated.iter().take(5) {
                                        if let Some(code) =
                                            analyst.generate_exploit_primitive(finding).await
                                        {
                                            exploit_primitives
                                                .push((finding.id.clone(), code));
                                        }
                                    }
                                }

                                let bughunt_summary = if self.config.enable_bughunt_pipeline {
                                    analyst
                                        .generate_bughunt_summary(
                                            &findings_for_llm,
                                            &attack_paths_for_llm,
                                        )
                                        .await
                                } else {
                                    String::new()
                                };

                                Some(LlmAnalysisReport {
                                    validations,
                                    rankings,
                                    exploit_primitives,
                                    bughunt_summary,
                                })
                            });
                            result
                        }
                        Err(_) => None,
                    }
                }
                Err(e) => {
                    eprintln!("[pipeline] Failed to create LLM analyst: {e}");
                    None
                }
            }
        } else {
            None
        };

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
            llm_analysis,
        }
    }

    pub fn memory(&self) -> &HuntMemory {
        &self.memory
    }
}
