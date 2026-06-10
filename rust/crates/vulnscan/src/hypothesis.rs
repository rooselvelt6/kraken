use serde::{Deserialize, Serialize};

use crate::memory::HypothesisNote;
use crate::{DiscoveryMethod, Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedHypothesis {
    pub id: String,
    pub title: String,
    pub description: String,
    pub supporting_findings: Vec<String>,
    pub probability: f32,
    pub potential_severity: Severity,
    pub suggested_analysis: String,
    pub category: HypothesisCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HypothesisCategory {
    UseAfterFree,
    RaceCondition,
    LogicBypass,
    MemoryCorruption,
    CryptoWeakness,
    SupplyChain,
    Injection,
    PrivilegeEscalation,
    InformationLeak,
    Other,
}

pub struct HypothesisGenerator;

impl HypothesisGenerator {
    pub fn generate_from_findings(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hypotheses = Vec::new();

        hypotheses.extend(Self::detect_uaf_patterns(findings));
        hypotheses.extend(Self::detect_race_conditions(findings));
        hypotheses.extend(Self::detect_logic_bypasses(findings));
        hypotheses.extend(Self::detect_memory_corruption(findings));
        hypotheses.extend(Self::detect_crypto_weakness_hypotheses(findings));
        hypotheses.extend(Self::detect_injection_hypotheses(findings));
        hypotheses.extend(Self::detect_privilege_escalation_hypotheses(findings));

        hypotheses.sort_by(|a, b| {
            b.probability
                .partial_cmp(&a.probability)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    b.potential_severity
                        .value()
                        .cmp(&a.potential_severity.value())
                })
        });

        hypotheses
    }

    pub fn findings_from_hypotheses(hypotheses: &[GeneratedHypothesis]) -> Vec<Finding> {
        hypotheses
            .iter()
            .map(|h| {
                Finding::new(
                    h.potential_severity,
                    format!("[Hypothesis] {}: {}", h.title, h.description),
                    None,
                    None,
                    None,
                    Some(h.suggested_analysis.clone()),
                    None,
                    h.probability,
                    DiscoveryMethod::LLMAgent,
                )
            })
            .collect()
    }

    pub fn to_hypothesis_notes(hypotheses: &[GeneratedHypothesis]) -> Vec<HypothesisNote> {
        hypotheses
            .iter()
            .map(|h| HypothesisNote {
                id: h.id.clone(),
                description: format!("{}: {}", h.title, h.description),
                related_findings: h.supporting_findings.clone(),
                probability: h.probability,
                impact: h.potential_severity,
                created_at: chrono::Utc::now(),
                validated: false,
            })
            .collect()
    }

    fn detect_uaf_patterns(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hyps = Vec::new();
        let unsafe_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.vulnerable_code_snippet
                    .as_ref()
                    .map_or(false, |s| s.contains("unsafe"))
                    || f.description.to_lowercase().contains("pointer")
                    || f.description.to_lowercase().contains("buffer")
            })
            .collect();

        if unsafe_findings.len() >= 2 {
            let ids: Vec<String> = unsafe_findings.iter().map(|f| f.id.clone()).collect();
            hyps.push(GeneratedHypothesis {
                id: format!("hyp-uaf-{}", chrono::Utc::now().timestamp()),
                title: "Posible Use-After-Free".to_string(),
                description: format!(
                    "Múltiples operaciones unsafe con punteros ({}) sugieren posible UAF. \
                    Si un puntero es liberado pero otra rama del código aún lo referencia, \
                    puede resultar en UAF explotable para RCE.",
                    unsafe_findings.len()
                ),
                supporting_findings: ids,
                probability: 0.35,
                potential_severity: Severity::High,
                suggested_analysis:
                    "Revisar lifetime de punteros; buscar free() seguido de read/write. \
                    Instruments como AddressSanitizer pueden confirmar."
                        .to_string(),
                category: HypothesisCategory::UseAfterFree,
            });
        }

        hyps
    }

    fn detect_race_conditions(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hyps = Vec::new();
        let concurrency_hits: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.vulnerable_code_snippet.as_ref().map_or(false, |s| {
                    s.contains("thread")
                        || s.contains("spawn")
                        || s.contains("lock")
                        || s.contains("Mutex")
                }) || f.description.to_lowercase().contains("race")
            })
            .collect();

        if concurrency_hits.len() >= 2 {
            let ids: Vec<String> = concurrency_hits.iter().map(|f| f.id.clone()).collect();
            hyps.push(GeneratedHypothesis {
                id: format!("hyp-race-{}", chrono::Utc::now().timestamp()),
                title: "Posible Race Condition".to_string(),
                description: format!(
                    "Código concurrente detectado en {} ubicaciones. Si el locking \
                    es inconsistente o hay TOCTOU, podría haber race condition explotable.",
                    concurrency_hits.len()
                ),
                supporting_findings: ids,
                probability: 0.4,
                potential_severity: Severity::Medium,
                suggested_analysis:
                    "Revisar patrones lock/unlock; buscar TOCTOU en operaciones de archivos. \
                    ThreadSanitizer puede confirmar."
                        .to_string(),
                category: HypothesisCategory::RaceCondition,
            });
        }

        hyps
    }

    fn detect_logic_bypasses(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hyps = Vec::new();
        let auth_hits: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.description.to_lowercase().contains("auth")
                    || f.cwe
                        .as_ref()
                        .map_or(false, |c| c.contains("CWE-287") || c.contains("CWE-306"))
            })
            .collect();

        if auth_hits.len() >= 1 {
            let ids: Vec<String> = auth_hits.iter().map(|f| f.id.clone()).collect();
            hyps.push(GeneratedHypothesis {
                id: format!("hyp-auth-{}", chrono::Utc::now().timestamp()),
                title: "Posible Bypass de Autenticación".to_string(),
                description: format!(
                    "Hallazgos de autenticación ({}) pueden indicar lógica \
                    vulnerable a bypass. Revisar si hay endpoints sin protección \
                    consistente.",
                    auth_hits.len()
                ),
                supporting_findings: ids,
                probability: 0.5,
                potential_severity: Severity::Critical,
                suggested_analysis: "Probar manipulación de tokens JWT, cookies, \
                    y headers de autorización. Buscar consistencia entre rutas."
                    .to_string(),
                category: HypothesisCategory::LogicBypass,
            });
        }

        hyps
    }

    fn detect_memory_corruption(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hyps = Vec::new();
        let unsafe_count = findings
            .iter()
            .filter(|f| {
                f.vulnerable_code_snippet.as_ref().map_or(false, |s| {
                    s.contains("unsafe") || s.contains("raw pointer") || s.contains("transmute")
                })
            })
            .count();

        if unsafe_count >= 3 {
            let ids: Vec<String> = findings
                .iter()
                .filter(|f| {
                    f.vulnerable_code_snippet
                        .as_ref()
                        .map_or(false, |s| s.contains("unsafe"))
                })
                .map(|f| f.id.clone())
                .collect();

            hyps.push(GeneratedHypothesis {
                id: format!("hyp-mem-{}", chrono::Utc::now().timestamp()),
                title: "Posible Corrupción de Memoria".to_string(),
                description: format!(
                    "{} bloques unsafe sugieren alta superficie de corrupción de memoria. \
                    Posible stack overflow, heap overflow, o uso de punteros dangling.",
                    unsafe_count
                ),
                supporting_findings: ids,
                probability: 0.3,
                potential_severity: Severity::Critical,
                suggested_analysis: "Ejecutar con AddressSanitizer y MemorySanitizer. \
                    Revisar cada bloque unsafe individualmente."
                    .to_string(),
                category: HypothesisCategory::MemoryCorruption,
            });
        }

        hyps
    }

    fn detect_crypto_weakness_hypotheses(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hyps = Vec::new();
        let weak_crypto: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.description.to_lowercase().contains("aes-ecb")
                    || f.description.to_lowercase().contains("md5")
                    || f.description.to_lowercase().contains("sha1")
                    || f.cwe.as_ref().map_or(false, |c| c.contains("CWE-327"))
            })
            .collect();

        if !weak_crypto.is_empty() {
            let ids: Vec<String> = weak_crypto.iter().map(|f| f.id.clone()).collect();
            hyps.push(GeneratedHypothesis {
                id: format!("hyp-crypto-{}", chrono::Utc::now().timestamp()),
                title: "Posible Fortalecimiento Criptográfico".to_string(),
                description: "Algoritmos criptográficos débiles detectados. \
                    Si son usados para seguridad sensible, el sistema es comprometible."
                    .to_string(),
                supporting_findings: ids,
                probability: 0.6,
                potential_severity: Severity::Medium,
                suggested_analysis: "Reemplazar con AES-GCM, SHA-256/512. \
                    Verificar que no haya hardcoded keys."
                    .to_string(),
                category: HypothesisCategory::CryptoWeakness,
            });
        }

        hyps
    }

    fn detect_injection_hypotheses(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hyps = Vec::new();
        let injection_hits: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.description.to_lowercase().contains("command")
                    || f.description.to_lowercase().contains("sqli")
                    || f.description.to_lowercase().contains("injection")
            })
            .collect();

        if !injection_hits.is_empty() {
            let ids: Vec<String> = injection_hits.iter().map(|f| f.id.clone()).collect();
            hyps.push(GeneratedHypothesis {
                id: format!("hyp-inj-{}", chrono::Utc::now().timestamp()),
                title: "Posible Superficie de Inyección".to_string(),
                description: format!(
                    "Múltiples vectores de inyección ({}) pueden combinarse \
                    para lograr ejecución remota si hay sanitización inconsistente.",
                    injection_hits.len()
                ),
                supporting_findings: ids,
                probability: 0.45,
                potential_severity: Severity::High,
                suggested_analysis: "Probar combos de inyección en todos los endpoints. \
                    WAF bypass techniques."
                    .to_string(),
                category: HypothesisCategory::Injection,
            });
        }

        hyps
    }

    fn detect_privilege_escalation_hypotheses(findings: &[Finding]) -> Vec<GeneratedHypothesis> {
        let mut hyps = Vec::new();
        let entries = findings
            .iter()
            .filter(|f| {
                f.description.to_lowercase().contains("unsafe")
                    || f.description.to_lowercase().contains("deserializ")
                    || f.description.to_lowercase().contains("sandbox")
            })
            .count();

        if entries >= 1 {
            let ids: Vec<String> = findings
                .iter()
                .filter(|f| {
                    f.description.to_lowercase().contains("unsafe")
                        || f.description.to_lowercase().contains("deserializ")
                })
                .map(|f| f.id.clone())
                .collect();

            hyps.push(GeneratedHypothesis {
                id: format!("hyp-privesc-{}", chrono::Utc::now().timestamp()),
                title: "Posible Escalación de Privilegios".to_string(),
                description: "Entry points inseguros (unsafe, deserialización) \
                    pueden ser vectores de escalación de privilegios si el proceso \
                    corre con capacidades elevadas."
                    .to_string(),
                supporting_findings: ids,
                probability: 0.35,
                potential_severity: Severity::High,
                suggested_analysis: "Revisar capacidades del proceso (capabilities, \
                    suid, namespaces). Probar inyección en handlers inseguros."
                    .to_string(),
                category: HypothesisCategory::PrivilegeEscalation,
            });
        }

        hyps
    }

    pub fn prioritize_hypotheses(hypotheses: &mut [GeneratedHypothesis]) {
        hypotheses.sort_by(|a, b| {
            let a_score = a.probability * (a.potential_severity.value() as f32 + 1.0);
            let b_score = b.probability * (b.potential_severity.value() as f32 + 1.0);
            b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}
