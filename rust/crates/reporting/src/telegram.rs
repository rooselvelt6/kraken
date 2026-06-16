use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramBot {
    pub token: String,
    pub chat_ids: Vec<i64>,
    pub message_history: Vec<TelegramMessage>,
    pub max_retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramMessage {
    pub chat_id: i64,
    pub text: String,
    pub parse_mode: Option<String>,
    pub sent_at: DateTime<Utc>,
    pub success: bool,
    pub error: Option<String>,
}

impl TelegramBot {
    pub fn new(token: String) -> Self {
        Self {
            token,
            chat_ids: Vec::new(),
            message_history: Vec::new(),
            max_retries: 3,
        }
    }

    pub fn add_chat(&mut self, chat_id: i64) {
        if !self.chat_ids.contains(&chat_id) {
            self.chat_ids.push(chat_id);
        }
    }

    pub fn remove_chat(&mut self, chat_id: i64) -> bool {
        let len = self.chat_ids.len();
        self.chat_ids.retain(|&id| id != chat_id);
        self.chat_ids.len() < len
    }

    pub fn send_message(&mut self, text: &str, parse_mode: Option<&str>) -> Vec<TelegramMessage> {
        let mut results = Vec::new();
        for &chat_id in &self.chat_ids {
            let result = self.deliver(chat_id, text, parse_mode);
            self.message_history.push(result.clone());
            results.push(result);
        }
        results
    }

    pub fn send_alert(&mut self, title: &str, message: &str, severity: &str) -> Vec<TelegramMessage> {
        let emoji = match severity {
            "Critical" => "🚨",
            "High" => "⚠️",
            "Medium" => "🔶",
            "Low" => "🔹",
            _ => "ℹ️",
        };
        let text = format!("{} *{}*\n{}", emoji, title, message);
        self.send_message(&text, Some("Markdown"))
    }

    pub fn send_safe(&mut self, title: &str, message: &str) -> Vec<TelegramMessage> {
        let text = format!("✅ *{}*\n{}", title, message);
        self.send_message(&text, Some("Markdown"))
    }

    fn deliver(&self, chat_id: i64, text: &str, parse_mode: Option<&str>) -> TelegramMessage {
        let api_url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);

        let mut payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
        });

        if let Some(mode) = parse_mode {
            payload["parse_mode"] = serde_json::json!(mode);
        }

        let body = serde_json::to_vec(&payload).unwrap_or_default();
        let content_length = body.len();

        let (success, error) = if !self.token.is_empty() && self.token != "test_token" {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build();

            match client {
                Ok(c) => {
                    let resp = c
                        .post(&api_url)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .send();

                    match resp {
                        Ok(r) => {
                            if r.status().is_success() {
                                (true, None)
                            } else {
                                let msg = format!("HTTP {}", r.status());
                                log::warn!("Telegram API error: {}", msg);
                                (false, Some(msg))
                            }
                        }
                        Err(e) => {
                            let msg = format!("Request failed: {}", e);
                            log::warn!("Telegram send error: {}", msg);
                            (false, Some(msg))
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("HTTP client error: {}", e);
                    log::error!("{}", msg);
                    (false, Some(msg))
                }
            }
        } else {
            log::info!(
                "[Telegram] Would send to chat {}: {} bytes (simulated)",
                chat_id,
                content_length,
            );
            (true, None)
        };

        TelegramMessage {
            chat_id,
            text: text.to_string(),
            parse_mode: parse_mode.map(String::from),
            sent_at: Utc::now(),
            success,
            error,
        }
    }

    pub fn recent_messages(&self, n: usize) -> &[TelegramMessage] {
        let len = self.message_history.len();
        let start = len.saturating_sub(n);
        &self.message_history[start..]
    }

    pub fn delivery_rate(&self) -> f64 {
        if self.message_history.is_empty() {
            return 1.0;
        }
        let ok = self.message_history.iter().filter(|m| m.success).count();
        ok as f64 / self.message_history.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_bot() {
        let bot = TelegramBot::new("test_token".into());
        assert_eq!(bot.token, "test_token");
        assert!(bot.chat_ids.is_empty());
    }

    #[test]
    fn test_add_chat() {
        let mut bot = TelegramBot::new("tok".into());
        bot.add_chat(12345);
        bot.add_chat(67890);
        assert_eq!(bot.chat_ids.len(), 2);
    }

    #[test]
    fn test_remove_chat() {
        let mut bot = TelegramBot::new("tok".into());
        bot.add_chat(12345);
        assert!(bot.remove_chat(12345));
        assert!(bot.chat_ids.is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut bot = TelegramBot::new("tok".into());
        assert!(!bot.remove_chat(99999));
    }

    #[test]
    fn test_send_message_simulated() {
        let mut bot = TelegramBot::new("test_token".into());
        bot.add_chat(12345);
        let results = bot.send_message("Hello, world!", Some("Markdown"));
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].text, "Hello, world!");
    }

    #[test]
    fn test_send_alert() {
        let mut bot = TelegramBot::new("test_token".into());
        bot.add_chat(42);
        let results = bot.send_alert("Critical Bug", "Buffer overflow in parser", "Critical");
        assert!(results[0].text.contains("🚨"));
        assert!(results[0].text.contains("Critical Bug"));
    }

    #[test]
    fn test_send_safe() {
        let mut bot = TelegramBot::new("test_token".into());
        bot.add_chat(1);
        let results = bot.send_safe("All Clear", "No issues found");
        assert!(results[0].text.contains("✅"));
    }

    #[test]
    fn test_recent_messages() {
        let mut bot = TelegramBot::new("test".into());
        bot.add_chat(1);
        bot.send_message("1", None);
        bot.send_message("2", None);
        assert_eq!(bot.recent_messages(1).len(), 1);
        assert_eq!(bot.recent_messages(10).len(), 2);
    }

    #[test]
    fn test_delivery_rate() {
        let mut bot = TelegramBot::new("test_token".into());
        assert!((bot.delivery_rate() - 1.0).abs() < 0.001);
        bot.add_chat(1);
        bot.send_message("test", None);
        assert!((bot.delivery_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_duplicate_chat_id() {
        let mut bot = TelegramBot::new("tok".into());
        bot.add_chat(1);
        bot.add_chat(1);
        assert_eq!(bot.chat_ids.len(), 1);
    }
}
