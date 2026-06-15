use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailCampaign {
    pub name: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: Option<String>,
    pub smtp_pass: Option<String>,
    pub from_name: String,
    pub from_email: String,
    pub subject: String,
    pub html_body: String,
    pub targets: Vec<String>,
    pub sent_count: usize,
    pub failed_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendResult {
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: String,
}

pub struct PhishMailer;

impl PhishMailer {
    pub fn new() -> Self {
        PhishMailer
    }

    pub fn send_email(
        smtp_host: &str,
        smtp_port: u16,
        from_name: &str,
        from_email: &str,
        to_email: &str,
        subject: &str,
        html_body: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<SendResult, String> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{Message, SmtpTransport, Transport};

        let email = Message::builder()
            .from(format!("{} <{}>", from_name, from_email).parse().map_err(|e| format!("from parse: {}", e))?)
            .to(to_email.parse().map_err(|e| format!("to parse: {}", e))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| format!("build message: {}", e))?;

        let mut mailer = SmtpTransport::relay(smtp_host)
            .map_err(|e| format!("relay: {}", e))?
            .port(smtp_port);

        if let (Some(user), Some(pass)) = (username, password) {
            let creds = Credentials::new(user.to_string(), pass.to_string());
            mailer = mailer.credentials(creds);
        }

        let result = mailer.build().send(&email);
        match result {
            Ok(_) => Ok(SendResult {
                target: to_email.to_string(),
                success: true,
                error: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            }),
            Err(e) => Ok(SendResult {
                target: to_email.to_string(),
                success: false,
                error: Some(format!("{}", e)),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }),
        }
    }

    pub fn send_campaign(campaign: &EmailCampaign) -> Vec<SendResult> {
        let mut results = Vec::new();
        for target in &campaign.targets {
            let result = Self::send_email(
                &campaign.smtp_host,
                campaign.smtp_port,
                &campaign.from_name,
                &campaign.from_email,
                target,
                &campaign.subject,
                &campaign.html_body,
                campaign.smtp_user.as_deref(),
                campaign.smtp_pass.as_deref(),
            );
            match result {
                Ok(r) => results.push(r),
                Err(e) => results.push(SendResult {
                    target: target.clone(),
                    success: false,
                    error: Some(e),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }),
            }
        }
        results
    }

    pub fn track_rates(results: &[SendResult]) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total".to_string(), results.len());
        stats.insert("sent".to_string(), results.iter().filter(|r| r.success).count());
        stats.insert("failed".to_string(), results.iter().filter(|r| !r.success).count());
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_email_invalid_relay() {
        let result = PhishMailer::send_email(
            "invalid.smtp.local",
            25,
            "Test",
            "test@test.com",
            "target@test.com",
            "Subject",
            "<p>body</p>",
            None,
            None,
        );
        assert!(result.is_err() || result.as_ref().map(|r| !r.success).unwrap_or(false));
    }

    #[test]
    fn test_track_rates() {
        let results = vec![
            SendResult { target: "a@b.com".to_string(), success: true, error: None, timestamp: "now".to_string() },
            SendResult { target: "b@b.com".to_string(), success: false, error: Some("timeout".to_string()), timestamp: "now".to_string() },
        ];
        let stats = PhishMailer::track_rates(&results);
        assert_eq!(stats.get("total").unwrap(), &2);
        assert_eq!(stats.get("sent").unwrap(), &1);
        assert_eq!(stats.get("failed").unwrap(), &1);
    }

    #[test]
    fn test_send_campaign_empty() {
        let campaign = EmailCampaign {
            name: "test".to_string(),
            smtp_host: "localhost".to_string(),
            smtp_port: 25,
            smtp_user: None,
            smtp_pass: None,
            from_name: "Tester".to_string(),
            from_email: "tester@test.com".to_string(),
            subject: "Test".to_string(),
            html_body: "<p>test</p>".to_string(),
            targets: vec![],
            sent_count: 0,
            failed_count: 0,
        };
        let results = PhishMailer::send_campaign(&campaign);
        assert!(results.is_empty());
    }

    #[test]
    fn test_send_result() {
        let r = SendResult {
            target: "user@test.com".to_string(),
            success: true,
            error: None,
            timestamp: "2026-01-15T10:00:00Z".to_string(),
        };
        let json = serde_json::to_string_pretty(&r).unwrap();
        assert!(json.contains("user@test.com"));
    }

    #[test]
    fn test_email_campaign() {
        let c = EmailCampaign {
            name: "Q1 Campaign".to_string(),
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_user: None,
            smtp_pass: None,
            from_name: "HR".to_string(),
            from_email: "hr@example.com".to_string(),
            subject: "Benefits".to_string(),
            html_body: "<p>Update</p>".to_string(),
            targets: vec!["a@b.com".to_string()],
            sent_count: 0,
            failed_count: 0,
        };
        assert_eq!(c.smtp_port, 587);
    }
}
