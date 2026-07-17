

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ec2Instance {
    pub instance_id: String,
    pub instance_type: String,
    pub state: String,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub security_groups: Vec<String>,
    pub open_ports: Vec<u16>,
    pub public_sg: bool,
    pub has_ebs: bool,
    pub ebs_encrypted: bool,
    pub ebs_snapshot_public: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ec2Finding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub instance_id: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ec2AuditResult {
    pub instances: Vec<Ec2Instance>,
    pub findings: Vec<Ec2Finding>,
    pub total_instances: usize,
    pub public_instances: usize,
    pub unencrypted_volumes: usize,
    pub public_snapshots: usize,
}

pub struct Ec2Auditor;

impl Default for Ec2Auditor {
    fn default() -> Self {
        Self::new()
    }
}

impl Ec2Auditor {
    pub fn new() -> Self {
        Ec2Auditor
    }

    pub fn audit_instances(instances: &[Ec2Instance]) -> Ec2AuditResult {
        let total_instances = instances.len();
        let mut public_instances = 0;
        let mut unencrypted_volumes = 0;
        let mut public_snapshots = 0;
        let mut findings = Vec::new();

        for inst in instances {
            if inst.public_ip.is_some() {
                public_instances += 1;
                findings.push(Ec2Finding {
                    severity: "MEDIUM".to_string(),
                    category: "Public Instance".to_string(),
                    description: format!("Instance {} has public IP {}", inst.instance_id, inst.public_ip.as_deref().unwrap_or("?")),
                    instance_id: inst.instance_id.clone(),
                    recommendation: "Review if instance needs to be publicly accessible".to_string(),
                });
            }

            if inst.public_sg {
                findings.push(Ec2Finding {
                    severity: "HIGH".to_string(),
                    category: "Open Security Group".to_string(),
                    description: format!("Instance {} has security group open to 0.0.0.0/0", inst.instance_id),
                    instance_id: inst.instance_id.clone(),
                    recommendation: "Restrict security group ingress to specific IPs".to_string(),
                });
            }

            if inst.has_ebs && !inst.ebs_encrypted {
                unencrypted_volumes += 1;
                findings.push(Ec2Finding {
                    severity: "HIGH".to_string(),
                    category: "Unencrypted Volume".to_string(),
                    description: format!("Instance {} has unencrypted EBS volume", inst.instance_id),
                    instance_id: inst.instance_id.clone(),
                    recommendation: "Enable EBS encryption for all volumes".to_string(),
                });
            }

            if inst.ebs_snapshot_public {
                public_snapshots += 1;
                findings.push(Ec2Finding {
                    severity: "CRITICAL".to_string(),
                    category: "Public Snapshot".to_string(),
                    description: format!("Instance {} has publicly shared EBS snapshot", inst.instance_id),
                    instance_id: inst.instance_id.clone(),
                    recommendation: "Remove public access from EBS snapshots".to_string(),
                });
            }

            for port in &inst.open_ports {
                if *port == 22 || *port == 3389 {
                    findings.push(Ec2Finding {
                        severity: "HIGH".to_string(),
                        category: "Management Port Open".to_string(),
                        description: format!("Port {} open on instance {}", port, inst.instance_id),
                        instance_id: inst.instance_id.clone(),
                        recommendation: "Restrict SSH/RDP access with security group IP restrictions".to_string().to_string(),
                    });
                }
            }
        }

        Ec2AuditResult {
            instances: instances.to_vec(),
            findings,
            total_instances,
            public_instances,
            unencrypted_volumes,
            public_snapshots,
        }
    }

    pub fn check_security_group_rules(sg_rules: &str) -> Vec<String> {
        let mut issues = Vec::new();
        if sg_rules.contains("0.0.0.0/0") {
            issues.push("Security group allows traffic from any IP (0.0.0.0/0)".to_string());
        }
        if sg_rules.contains("::/0") {
            issues.push("Security group allows traffic from any IPv6 (::/0)".to_string());
        }
        issues
    }

    pub fn parse_aws_response(response: &str) -> Vec<Ec2Instance> {
        let mut instances = Vec::new();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
            if let Some(reservations) = json.get("Reservations").and_then(|r| r.as_array()) {
                for reservation in reservations {
                    if let Some(instances_arr) = reservation.get("Instances").and_then(|i| i.as_array()) {
                        for inst in instances_arr {
                            let instance_id = inst.get("InstanceId").and_then(|i| i.as_str()).unwrap_or("?").to_string();
                            let instance_type = inst.get("InstanceType").and_then(|i| i.as_str()).unwrap_or("?").to_string();
                            let state = inst.get("State").and_then(|s| s.get("Name")).and_then(|n| n.as_str()).unwrap_or("?").to_string();
                            let public_ip = inst.get("PublicIpAddress").and_then(|p| p.as_str()).map(String::from);
                            let private_ip = inst.get("PrivateIpAddress").and_then(|p| p.as_str()).map(String::from);
                            instances.push(Ec2Instance {
                                instance_id,
                                instance_type,
                                state,
                                public_ip,
                                private_ip,
                                security_groups: vec![],
                                open_ports: vec![],
                                public_sg: false,
                                has_ebs: false,
                                ebs_encrypted: false,
                                ebs_snapshot_public: false,
                            });
                        }
                    }
                }
            }
        }
        instances
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_public_instance() {
        let instances = vec![Ec2Instance {
            instance_id: "i-123".to_string(),
            instance_type: "t3.medium".to_string(),
            state: "running".to_string(),
            public_ip: Some("1.2.3.4".to_string()),
            private_ip: Some("10.0.0.1".to_string()),
            security_groups: vec!["sg-123".to_string()],
            open_ports: vec![22, 80],
            public_sg: true,
            has_ebs: true,
            ebs_encrypted: false,
            ebs_snapshot_public: false,
        }];
        let result = Ec2Auditor::audit_instances(&instances);
        assert!(result.public_instances > 0);
        assert!(result.unencrypted_volumes > 0);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_check_sg_rules() {
        let issues = Ec2Auditor::check_security_group_rules("0.0.0.0/0 open");
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_parse_aws_response() {
        let json = r#"{"Reservations":[{"Instances":[{"InstanceId":"i-abc","InstanceType":"t3.large","State":{"Name":"running"},"PublicIpAddress":"1.2.3.4","PrivateIpAddress":"10.0.0.5"}]}]}"#;
        let instances = Ec2Auditor::parse_aws_response(json);
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, "i-abc");
    }

    #[test]
    fn test_parse_empty_response() {
        let instances = Ec2Auditor::parse_aws_response("{}");
        assert!(instances.is_empty());
    }

    #[test]
    fn test_ec2_finding() {
        let f = Ec2Finding {
            severity: "HIGH".to_string(),
            category: "test".to_string(),
            description: "desc".to_string(),
            instance_id: "i-001".to_string(),
            recommendation: "fix it".to_string(),
        };
        let json = serde_json::to_string_pretty(&f).unwrap();
        assert!(json.contains("i-001"));
    }
}
