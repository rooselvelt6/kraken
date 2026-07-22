use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    pub version: String,
    pub endpoint: String,
    pub capabilities: Vec<String>,
    pub permissions: Vec<McpPermission>,
    pub data_flow: Vec<DataFlowEntry>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPermission {
    pub resource: String,
    pub action: String,
    pub scope: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEntry {
    pub from: String,
    pub to: String,
    pub data_type: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustReport {
    pub server_name: String,
    pub trust_score: f64,
    pub trust_level: String,
    pub findings: Vec<TrustFinding>,
    pub recommendations: Vec<String>,
    pub permissions_audit: PermissionsAudit,
    pub data_flow_audit: DataFlowAudit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFinding {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsAudit {
    pub total_permissions: usize,
    pub high_risk_count: usize,
    pub medium_risk_count: usize,
    pub low_risk_count: usize,
    pub excessive_permissions: Vec<String>,
    pub missing_restrictions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowAudit {
    pub total_flows: usize,
    pub encrypted_flows: usize,
    pub unencrypted_flows: usize,
    pub external_flows: usize,
    pub sensitive_data_flows: usize,
    pub risks: Vec<String>,
}

pub struct McpTrustEvaluator;

impl Default for McpTrustEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl McpTrustEvaluator {
    pub fn new() -> Self {
        McpTrustEvaluator
    }

    pub fn evaluate(server: &McpServer) -> TrustReport {
        let mut findings = Vec::new();
        let mut score = 1.0;

        let permissions_audit = Self::audit_permissions(server);
        let data_flow_audit = Self::audit_data_flow(server);

        if !permissions_audit.excessive_permissions.is_empty() {
            findings.push(TrustFinding {
                category: "Permissions".to_string(),
                severity: "HIGH".to_string(),
                description: format!("{} excessive permissions found", permissions_audit.excessive_permissions.len()),
                recommendation: "Remove or restrict excessive permissions".to_string(),
            });
            score -= 0.2 * permissions_audit.excessive_permissions.len() as f64;
        }

        if data_flow_audit.unencrypted_flows > 0 {
            findings.push(TrustFinding {
                category: "Data Flow".to_string(),
                severity: "HIGH".to_string(),
                description: format!("{} unencrypted data flows", data_flow_audit.unencrypted_flows),
                recommendation: "Enable encryption for all data flows".to_string(),
            });
            score -= 0.15 * data_flow_audit.unencrypted_flows as f64;
        }

        if data_flow_audit.external_flows > 2 {
            findings.push(TrustFinding {
                category: "Network".to_string(),
                severity: "MEDIUM".to_string(),
                description: format!("{} external data flows detected", data_flow_audit.external_flows),
                recommendation: "Review external connections and limit to necessary endpoints".to_string(),
            });
            score -= 0.1;
        }

        if server.capabilities.is_empty() {
            findings.push(TrustFinding {
                category: "Capabilities".to_string(),
                severity: "LOW".to_string(),
                description: "No capabilities declared".to_string(),
                recommendation: "Declare server capabilities for better transparency".to_string(),
            });
            score -= 0.05;
        }

        for perm in &server.permissions {
            if perm.action == "write" && perm.scope == "global" {
                findings.push(TrustFinding {
                    category: "Permissions".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("Global write permission on {}", perm.resource),
                    recommendation: "Restrict write permissions to specific resources".to_string(),
                });
                score -= 0.1;
            }
        }

        for flow in &server.data_flow {
            if flow.data_type == "credentials" && !flow.encrypted {
                findings.push(TrustFinding {
                    category: "Security".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: format!("Unencrypted credential flow from {} to {}", flow.from, flow.to),
                    recommendation: "Encrypt all credential transmissions".to_string(),
                });
                score -= 0.3;
            }
        }

        score = score.clamp(0.0, 1.0);

        let trust_level = match score {
            s if s >= 0.8 => "TRUSTED".to_string(),
            s if s >= 0.6 => "CONDITIONAL".to_string(),
            s if s >= 0.4 => "SUSPICIOUS".to_string(),
            _ => "UNTRUSTED".to_string(),
        };

        let mut recommendations = Vec::new();
        if score < 0.6 {
            recommendations.push("Review and restrict permissions".to_string());
            recommendations.push("Enable encryption for all data flows".to_string());
        }
        if permissions_audit.high_risk_count > 0 {
            recommendations.push("Audit high-risk permissions".to_string());
        }
        if data_flow_audit.sensitive_data_flows > 0 {
            recommendations.push("Review sensitive data handling".to_string());
        }

        TrustReport {
            server_name: server.name.clone(),
            trust_score: score,
            trust_level,
            findings,
            recommendations,
            permissions_audit,
            data_flow_audit,
        }
    }

    pub fn audit_permissions(server: &McpServer) -> PermissionsAudit {
        let mut high_risk = 0;
        let mut medium_risk = 0;
        let mut low_risk = 0;
        let mut excessive = Vec::new();
        let mut missing = Vec::new();

        for perm in &server.permissions {
            match perm.risk_level.as_str() {
                "HIGH" => high_risk += 1,
                "MEDIUM" => medium_risk += 1,
                _ => low_risk += 1,
            }

            if perm.action == "write" && perm.scope == "global" {
                excessive.push(format!("{}: {} on {}", perm.action, perm.resource, perm.scope));
            }

            if perm.action == "read" && perm.scope == "global"
                && !server.permissions.iter().any(|p| p.resource == perm.resource && p.action == "audit")
            {
                missing.push(format!("Audit permission for {}", perm.resource));
            }
        }

        PermissionsAudit {
            total_permissions: server.permissions.len(),
            high_risk_count: high_risk,
            medium_risk_count: medium_risk,
            low_risk_count: low_risk,
            excessive_permissions: excessive,
            missing_restrictions: missing,
        }
    }

    pub fn audit_data_flow(server: &McpServer) -> DataFlowAudit {
        let total = server.data_flow.len();
        let encrypted = server.data_flow.iter().filter(|f| f.encrypted).count();
        let unencrypted = total - encrypted;
        let external = server.data_flow.iter().filter(|f| f.from.contains("external") || f.to.contains("external")).count();
        let sensitive = server.data_flow.iter().filter(|f| f.data_type == "credentials" || f.data_type == "pii" || f.data_type == "secrets").count();

        let mut risks = Vec::new();
        if unencrypted > 0 {
            risks.push("Unencrypted data flows detected".to_string());
        }
        if sensitive > 0 {
            risks.push("Sensitive data flows require additional protection".to_string());
        }
        if external > 2 {
            risks.push("Multiple external connections increase attack surface".to_string());
        }

        DataFlowAudit {
            total_flows: total,
            encrypted_flows: encrypted,
            unencrypted_flows: unencrypted,
            external_flows: external,
            sensitive_data_flows: sensitive,
            risks,
        }
    }

    pub fn batch_evaluate(servers: &[McpServer]) -> Vec<TrustReport> {
        servers.iter().map(Self::evaluate).collect()
    }

    pub fn generate_summary(reports: &[TrustReport]) -> String {
        let total = reports.len();
        let trusted = reports.iter().filter(|r| r.trust_level == "TRUSTED").count();
        let conditional = reports.iter().filter(|r| r.trust_level == "CONDITIONAL").count();
        let suspicious = reports.iter().filter(|r| r.trust_level == "SUSPICIOUS").count();
        let untrusted = reports.iter().filter(|r| r.trust_level == "UNTRUSTED").count();

        let avg_score = reports.iter().map(|r| r.trust_score).sum::<f64>() / total as f64;

        format!(
            "MCP Trust Summary: {}/{} trusted, {}/{} conditional, {}/{} suspicious, {}/{} untrusted (avg score: {:.2})",
            trusted, total, conditional, total, suspicious, total, untrusted, total, avg_score
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server() -> McpServer {
        McpServer {
            name: "test-server".to_string(),
            version: "1.0.0".to_string(),
            endpoint: "https://example.com/mcp".to_string(),
            capabilities: vec!["read".to_string(), "write".to_string()],
            permissions: vec![
                McpPermission {
                    resource: "files".to_string(),
                    action: "read".to_string(),
                    scope: "local".to_string(),
                    risk_level: "LOW".to_string(),
                },
                McpPermission {
                    resource: "database".to_string(),
                    action: "write".to_string(),
                    scope: "local".to_string(),
                    risk_level: "MEDIUM".to_string(),
                },
            ],
            data_flow: vec![
                DataFlowEntry {
                    from: "client".to_string(),
                    to: "server".to_string(),
                    data_type: "commands".to_string(),
                    encrypted: true,
                },
            ],
            source: "trusted-registry".to_string(),
        }
    }

    #[test]
    fn test_evaluate_server() {
        let server = sample_server();
        let report = McpTrustEvaluator::evaluate(&server);
        assert_eq!(report.server_name, "test-server");
        assert!(report.trust_score >= 0.0 && report.trust_score <= 1.0);
    }

    #[test]
    fn test_audit_permissions() {
        let server = sample_server();
        let audit = McpTrustEvaluator::audit_permissions(&server);
        assert_eq!(audit.total_permissions, 2);
        assert!(audit.high_risk_count + audit.medium_risk_count + audit.low_risk_count == 2);
    }

    #[test]
    fn test_audit_data_flow() {
        let server = sample_server();
        let audit = McpTrustEvaluator::audit_data_flow(&server);
        assert_eq!(audit.total_flows, 1);
        assert_eq!(audit.encrypted_flows, 1);
        assert_eq!(audit.unencrypted_flows, 0);
    }

    #[test]
    fn test_batch_evaluate() {
        let servers = vec![sample_server(), sample_server()];
        let reports = McpTrustEvaluator::batch_evaluate(&servers);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_generate_summary() {
        let servers = vec![sample_server()];
        let reports = McpTrustEvaluator::batch_evaluate(&servers);
        let summary = McpTrustEvaluator::generate_summary(&reports);
        assert!(summary.contains("MCP Trust Summary"));
    }

    #[test]
    fn test_high_risk_server() {
        let mut server = sample_server();
        server.permissions.push(McpPermission {
            resource: "system".to_string(),
            action: "write".to_string(),
            scope: "global".to_string(),
            risk_level: "HIGH".to_string(),
        });
        server.data_flow.push(DataFlowEntry {
            from: "external".to_string(),
            to: "server".to_string(),
            data_type: "credentials".to_string(),
            encrypted: false,
        });
        let report = McpTrustEvaluator::evaluate(&server);
        assert!(report.trust_score < 0.6);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_trusted_server() {
        let mut server = sample_server();
        server.data_flow.clear();
        server.data_flow.push(DataFlowEntry {
            from: "client".to_string(),
            to: "server".to_string(),
            data_type: "commands".to_string(),
            encrypted: true,
        });
        let report = McpTrustEvaluator::evaluate(&server);
        assert!(report.trust_score >= 0.8);
        assert_eq!(report.trust_level, "TRUSTED");
    }

    #[test]
    fn test_permission_excessive_detection() {
        let mut server = sample_server();
        server.permissions.push(McpPermission {
            resource: "all".to_string(),
            action: "write".to_string(),
            scope: "global".to_string(),
            risk_level: "HIGH".to_string(),
        });
        let audit = McpTrustEvaluator::audit_permissions(&server);
        assert!(!audit.excessive_permissions.is_empty());
    }
}