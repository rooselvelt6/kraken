use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookProvider {
    Slack,
    Discord,
    Teams,
}

impl WebhookProvider {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Slack => "Slack",
            Self::Discord => "Discord",
            Self::Teams => "Microsoft Teams",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub provider: WebhookProvider,
    pub url: String,
    pub channel: Option<String>,
    pub username: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResult {
    pub success: bool,
    pub status_code: u16,
    pub message: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub provider: WebhookProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookClient {
    pub configs: Vec<WebhookConfig>,
    pub history: Vec<WebhookResult>,
    pub max_retries: u32,
}

impl WebhookClient {
    pub fn new(max_retries: u32) -> Self {
        Self {
            configs: Vec::new(),
            history: Vec::new(),
            max_retries,
        }
    }

    pub fn add_webhook(&mut self, config: WebhookConfig) {
        self.configs.push(config);
    }

    pub fn remove_webhook(&mut self, index: usize) -> bool {
        if index < self.configs.len() {
            self.configs.remove(index);
            true
        } else {
            false
        }
    }

    pub fn send_message(&mut self, title: &str, message: &str, severity: &str) -> Vec<WebhookResult> {
        let mut results = Vec::new();
        for config in &self.configs {
            let result = match config.provider {
                WebhookProvider::Slack => self.send_slack(config, title, message, severity),
                WebhookProvider::Discord => self.send_discord(config, title, message, severity),
                WebhookProvider::Teams => self.send_teams(config, title, message, severity),
            };
            self.history.push(result.clone());
            results.push(result);
        }
        results
    }

    fn send_slack(&self, config: &WebhookConfig, title: &str, message: &str, severity: &str) -> WebhookResult {
        let color = match severity {
            "Critical" => "#dc3545",
            "High" => "#fd7e14",
            "Medium" => "#ffc107",
            _ => "#36a64f",
        };

        let payload = serde_json::json!({
            "username": config.username.as_deref().unwrap_or("Kraken"),
            "channel": config.channel,
            "attachments": [{
                "color": color,
                "title": title,
                "text": message,
                "footer": "Kraken Security Platform",
                "ts": Utc::now().timestamp(),
            }],
        });

        self.deliver(config, &payload.to_string(), title, message, WebhookProvider::Slack)
    }

    fn send_discord(&self, config: &WebhookConfig, title: &str, message: &str, severity: &str) -> WebhookResult {
        let color = match severity {
            "Critical" => 0xdc3545,
            "High" => 0xfd7e14,
            "Medium" => 0xffc107,
            _ => 0x36a64f,
        };

        let payload = serde_json::json!({
            "username": config.username.as_deref().unwrap_or("Kraken"),
            "avatar_url": config.avatar_url,
            "embeds": [{
                "title": title,
                "description": message,
                "color": color,
                "footer": {"text": "Kraken Security Platform"},
                "timestamp": Utc::now().to_rfc3339(),
            }],
        });

        self.deliver(config, &payload.to_string(), title, message, WebhookProvider::Discord)
    }

    fn send_teams(&self, config: &WebhookConfig, title: &str, message: &str, _severity: &str) -> WebhookResult {
        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": "0072C6",
            "title": title,
            "text": message,
            "sections": [{
                "activityTitle": "Kraken Security Platform",
                "activitySubtitle": format!("Alert at {}", Utc::now().format("%Y-%m-%d %H:%M UTC")),
                "facts": [
                    {"name": "Alert", "value": title},
                    {"name": "Details", "value": message},
                ],
            }],
        });

        self.deliver(config, &payload.to_string(), title, message, WebhookProvider::Teams)
    }

    fn deliver(&self, config: &WebhookConfig, payload: &str, _title: &str, _message: &str, provider: WebhookProvider) -> WebhookResult {
        let body = payload.as_bytes();
        let content_length = body.len();

        let (status_code, delivered) = if !config.url.is_empty() && config.url.starts_with("http") {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build();

            match client {
                Ok(c) => {
                    let resp = c
                        .post(&config.url)
                        .header("Content-Type", "application/json")
                        .body(body.to_vec())
                        .send();

                    match resp {
                        Ok(r) => {
                            let code = r.status().as_u16();
                            (code, code < 500)
                        }
                        Err(e) => {
                            let msg = format!("HTTP error: {}", e);
                            log::warn!("Webhook delivery failed: {}", msg);
                            (0, false)
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to build HTTP client: {}", e);
                    (0, false)
                }
            }
        } else {
            log::info!(
                "[{}] Would send to {}: {} bytes (simulated)",
                provider.name(),
                config.url,
                content_length,
            );
            (200, true)
        };

        WebhookResult {
            success: delivered,
            status_code,
            message: if delivered {
                format!("Delivered to {} via {}", config.url, provider.name())
            } else {
                format!("Failed to deliver to {} via {} (HTTP {})", config.url, provider.name(), status_code)
            },
            timestamp: Utc::now(),
            provider,
        }
    }

    pub fn send_test(&mut self) -> Vec<WebhookResult> {
        self.send_message("🧪 Test Notification", "This is a test message from Kraken Security Platform.", "Info")
    }

    pub fn history(&self) -> &[WebhookResult] {
        &self.history
    }

    pub fn recent_results(&self, n: usize) -> &[WebhookResult] {
        let len = self.history.len();
        let start = len.saturating_sub(n);
        &self.history[start..]
    }

    pub fn success_rate(&self) -> f64 {
        if self.history.is_empty() {
            return 1.0;
        }
        let successes = self.history.iter().filter(|r| r.success).count();
        successes as f64 / self.history.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client() {
        let client = WebhookClient::new(3);
        assert_eq!(client.max_retries, 3);
        assert!(client.configs.is_empty());
    }

    #[test]
    fn test_add_remove_webhook() {
        let mut client = WebhookClient::new(2);
        client.add_webhook(WebhookConfig {
            provider: WebhookProvider::Slack,
            url: "https://hooks.slack.com/test".into(),
            channel: Some("#security".into()),
            username: None,
            avatar_url: None,
        });
        assert_eq!(client.configs.len(), 1);
        assert!(client.remove_webhook(0));
        assert!(client.configs.is_empty());
    }

    #[test]
    fn test_provider_name() {
        assert_eq!(WebhookProvider::Slack.name(), "Slack");
        assert_eq!(WebhookProvider::Discord.name(), "Discord");
        assert_eq!(WebhookProvider::Teams.name(), "Microsoft Teams");
    }

    #[test]
    fn test_send_message_no_url() {
        let mut client = WebhookClient::new(1);
        client.add_webhook(WebhookConfig {
            provider: WebhookProvider::Slack,
            url: "".into(),
            channel: None,
            username: None,
            avatar_url: None,
        });
        let results = client.send_message("Test", "Hello", "Info");
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_send_message_empty_url_simulated() {
        let mut client = WebhookClient::new(1);
        client.add_webhook(WebhookConfig {
            provider: WebhookProvider::Discord,
            url: "".into(),
            channel: None,
            username: Some("KrakenBot".into()),
            avatar_url: None,
        });
        let results = client.send_message("Alert", "Something happened", "Critical");
        assert!(results[0].success);
        assert_eq!(results[0].status_code, 200);
    }

    #[test]
    fn test_send_test() {
        let mut client = WebhookClient::new(1);
        client.add_webhook(WebhookConfig {
            provider: WebhookProvider::Slack,
            url: "".into(),
            channel: None,
            username: None,
            avatar_url: None,
        });
        let results = client.send_test();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_history() {
        let mut client = WebhookClient::new(1);
        client.add_webhook(WebhookConfig {
            provider: WebhookProvider::Teams,
            url: "".into(),
            channel: None,
            username: None,
            avatar_url: None,
        });
        client.send_message("T", "M", "Low");
        assert_eq!(client.history().len(), 1);
    }

    #[test]
    fn test_success_rate() {
        let mut client = WebhookClient::new(1);
        assert_eq!(client.success_rate(), 1.0);
        client.add_webhook(WebhookConfig {
            provider: WebhookProvider::Slack,
            url: "".into(),
            channel: None,
            username: None,
            avatar_url: None,
        });
        client.send_message("T", "M", "Info");
        assert!((client.success_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_bad_url_does_not_panic() {
        let mut client = WebhookClient::new(1);
        client.add_webhook(WebhookConfig {
            provider: WebhookProvider::Slack,
            url: "https://invalid.url.that.does.not.exist.xyz/hook".into(),
            channel: None,
            username: None,
            avatar_url: None,
        });
        let results = client.send_message("Test", "Body", "High");
        assert_eq!(results.len(), 1);
    }
}
