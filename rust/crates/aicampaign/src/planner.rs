use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetType {
    WebApplication,
    NetworkInfrastructure,
    CloudEnvironment,
    MobileApp,
    ApiEndpoint,
    WirelessNetwork,
    PhysicalAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignPlan {
    pub name: String,
    pub target: String,
    pub target_type: TargetType,
    pub phases: Vec<CampaignPhase>,
    pub estimated_duration_minutes: u32,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignPhase {
    pub name: String,
    pub order: u32,
    pub tools: Vec<String>,
    pub estimated_time: u32,
    pub critical: bool,
}

pub struct CampaignPlanner;

impl CampaignPlanner {
    pub fn new() -> Self {
        CampaignPlanner
    }

    pub fn plan(target: &str, target_type: TargetType) -> CampaignPlan {
        let phases = Self::generate_phases(&target_type);
        let total_time: u32 = phases.iter().map(|p| p.estimated_time).sum();

        CampaignPlan {
            name: format!("Campaign against {}", target),
            target: target.to_string(),
            target_type,
            phases,
            estimated_duration_minutes: total_time,
            risk_level: "MEDIUM".to_string(),
        }
    }

    pub fn generate_phases(ttype: &TargetType) -> Vec<CampaignPhase> {
        match ttype {
            TargetType::WebApplication => vec![
                CampaignPhase { name: "Reconnaissance".to_string(), order: 1, tools: vec!["dns_enum".to_string(), "tech_detect".to_string()], estimated_time: 10, critical: true },
                CampaignPhase { name: "Vulnerability Scan".to_string(), order: 2, tools: vec!["sql_scanner".to_string(), "xss_scanner".to_string()], estimated_time: 30, critical: true },
                CampaignPhase { name: "Exploitation".to_string(), order: 3, tools: vec!["sql_inject".to_string(), "payload_gen".to_string()], estimated_time: 20, critical: false },
                CampaignPhase { name: "Post-Exploitation".to_string(), order: 4, tools: vec!["cred_dump".to_string(), "pivot".to_string()], estimated_time: 15, critical: false },
            ],
            TargetType::NetworkInfrastructure => vec![
                CampaignPhase { name: "Port Scan".to_string(), order: 1, tools: vec!["syn_scan".to_string(), "udp_scan".to_string()], estimated_time: 15, critical: true },
                CampaignPhase { name: "Service Enumeration".to_string(), order: 2, tools: vec!["banner_grab".to_string(), "os_detect".to_string()], estimated_time: 10, critical: true },
                CampaignPhase { name: "Vulnerability Assessment".to_string(), order: 3, tools: vec!["cve_lookup".to_string(), "exploit_search".to_string()], estimated_time: 25, critical: true },
            ],
            TargetType::CloudEnvironment => vec![
                CampaignPhase { name: "Cloud Enumeration".to_string(), order: 1, tools: vec!["s3_scanner".to_string(), "iam_audit".to_string()], estimated_time: 20, critical: true },
                CampaignPhase { name: "Misconfiguration Check".to_string(), order: 2, tools: vec!["bucket_acl".to_string(), "k8s_audit".to_string()], estimated_time: 30, critical: true },
            ],
            _ => vec![
                CampaignPhase { name: "Reconnaissance".to_string(), order: 1, tools: vec!["basic_scan".to_string()], estimated_time: 10, critical: true },
                CampaignPhase { name: "Exploitation".to_string(), order: 2, tools: vec!["auto_exploit".to_string()], estimated_time: 20, critical: true },
            ],
        }
    }

    pub fn estimate_duration(phases: &[CampaignPhase]) -> u32 {
        phases.iter().map(|p| p.estimated_time).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_web() {
        let plan = CampaignPlanner::plan("example.com", TargetType::WebApplication);
        assert_eq!(plan.target_type as usize, TargetType::WebApplication as usize);
        assert!(!plan.phases.is_empty());
    }

    #[test]
    fn test_plan_network() {
        let plan = CampaignPlanner::plan("10.0.0.0/24", TargetType::NetworkInfrastructure);
        assert_eq!(plan.phases.len(), 3);
    }

    #[test]
    fn test_generate_phases_cloud() {
        let phases = CampaignPlanner::generate_phases(&TargetType::CloudEnvironment);
        assert_eq!(phases.len(), 2);
    }

    #[test]
    fn test_estimate_duration() {
        let phases = CampaignPlanner::generate_phases(&TargetType::WebApplication);
        let duration = CampaignPlanner::estimate_duration(&phases);
        assert!(duration > 0);
    }

    #[test]
    fn test_campaign_plan_serde() {
        let plan = CampaignPlanner::plan("test.local", TargetType::ApiEndpoint);
        let json = serde_json::to_string_pretty(&plan).unwrap();
        assert!(json.contains("Campaign against"));
    }
}
