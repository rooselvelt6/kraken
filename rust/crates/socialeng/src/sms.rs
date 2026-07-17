use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmsMessage {
    pub to_number: String,
    pub body: String,
    pub status: String,
    pub sent_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmsCampaign {
    pub name: String,
    pub from_number: String,
    pub targets: Vec<String>,
    pub message_template: String,
    pub provider: String,
}

pub struct SmsPhisher;

impl Default for SmsPhisher {
    fn default() -> Self {
        Self::new()
    }
}

impl SmsPhisher {
    pub fn new() -> Self {
        SmsPhisher
    }

    pub fn create_campaign(name: &str, from_number: &str, targets: &[String], template: &str, provider: &str) -> SmsCampaign {
        SmsCampaign {
            name: name.to_string(),
            from_number: from_number.to_string(),
            targets: targets.to_vec(),
            message_template: template.to_string(),
            provider: provider.to_string(),
        }
    }

    pub fn render_message(template: &str, target: &str, replacements: &HashMap<String, String>) -> String {
        let mut msg = template
            .replace("{{TARGET}}", target)
            .replace("{{TARGET_NAME}}", target.split('@').next().unwrap_or(target));
        for (key, value) in replacements {
            msg = msg.replace(&format!("{{{{{}}}}}", key), value);
        }
        msg
    }

    pub fn simulate_send(to: &str, body: &str) -> SmsMessage {
        SmsMessage {
            to_number: to.to_string(),
            body: body.to_string(),
            status: if to.contains("invalid") { "failed".to_string() } else { "sent".to_string() },
            sent_at: Some(chrono::Utc::now().to_rfc3339()),
        }
    }

    pub fn send_campaign(campaign: &SmsCampaign, replacements: &HashMap<String, String>) -> Vec<SmsMessage> {
        let mut results = Vec::new();
        for target in &campaign.targets {
            let body = Self::render_message(&campaign.message_template, target, replacements);
            let result = Self::simulate_send(target, &body);
            results.push(result);
        }
        results
    }

    pub fn stats(results: &[SmsMessage]) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total".to_string(), results.len());
        stats.insert("sent".to_string(), results.iter().filter(|r| r.status == "sent").count());
        stats.insert("failed".to_string(), results.iter().filter(|r| r.status == "failed").count());
        stats
    }

    pub fn shorten_url(long_url: &str) -> String {
        format!("https://short.link/{}", Self::hash_url(long_url))
    }

    fn hash_url(url: &str) -> String {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(url.as_bytes());
        hex::encode(&hash[..4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_campaign() {
        let targets = vec!["+1234567890".to_string()];
        let campaign = SmsPhisher::create_campaign("Test", "+1987654321", &targets, "Click {{LINK}}", "twilio");
        assert_eq!(campaign.name, "Test");
        assert_eq!(campaign.provider, "twilio");
    }

    #[test]
    fn test_render_message() {
        let template = "Hi {{TARGET}}, click {{LINK}}";
        let mut replacements = HashMap::new();
        replacements.insert("LINK".to_string(), "http://evil.com".to_string());
        let msg = SmsPhisher::render_message(template, "user@test.com", &replacements);
        assert!(msg.contains("http://evil.com"));
        assert!(msg.contains("user@test.com"));
    }

    #[test]
    fn test_simulate_send() {
        let result = SmsPhisher::simulate_send("+1234567890", "Click http://evil.com");
        assert_eq!(result.status, "sent");
        assert!(result.sent_at.is_some());
    }

    #[test]
    fn test_simulate_send_invalid() {
        let result = SmsPhisher::simulate_send("invalid", "test");
        assert_eq!(result.status, "failed");
    }

    #[test]
    fn test_send_campaign() {
        let targets = vec!["+111".to_string(), "+222".to_string()];
        let campaign = SmsPhisher::create_campaign("Test", "+000", &targets, "Hello {{LINK}}", "sim");
        let mut replacements = HashMap::new();
        replacements.insert("LINK".to_string(), "http://evil.com".to_string());
        let results = SmsPhisher::send_campaign(&campaign, &replacements);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_stats() {
        let results = vec![
            SmsMessage { to_number: "+1".to_string(), body: "hi".to_string(), status: "sent".to_string(), sent_at: None },
            SmsMessage { to_number: "+2".to_string(), body: "hi".to_string(), status: "failed".to_string(), sent_at: None },
        ];
        let stats = SmsPhisher::stats(&results);
        assert_eq!(stats.get("sent").unwrap(), &1);
        assert_eq!(stats.get("failed").unwrap(), &1);
    }

    #[test]
    fn test_shorten_url() {
        let short = SmsPhisher::shorten_url("http://evil.com/long/path");
        assert!(short.starts_with("https://short.link/"));
    }

    #[test]
    fn test_sms_message() {
        let m = SmsMessage {
            to_number: "+123".to_string(),
            body: "test".to_string(),
            status: "sent".to_string(),
            sent_at: Some("now".to_string()),
        };
        let json = serde_json::to_string_pretty(&m).unwrap();
        assert!(json.contains("+123"));
    }
}
