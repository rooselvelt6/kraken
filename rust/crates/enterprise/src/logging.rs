#[allow(clippy::all, clippy::should_implement_trait, clippy::inherent_to_string, clippy::unwrap_or_default, clippy::new_without_default)]
/// Structured logging in JSON format for production

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => Level::Trace,
            "debug" => Level::Debug,
            "info" => Level::Info,
            "warn" | "warning" => Level::Warn,
            "error" => Level::Error,
            _ => Level::Info,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Trace => write!(f, "TRACE"),
            Level::Debug => write!(f, "DEBUG"),
            Level::Info => write!(f, "INFO"),
            Level::Warn => write!(f, "WARN"),
            Level::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: Level,
    pub target: String,
    pub message: String,
    pub provider: Option<String>,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl LogEntry {
    pub fn new(level: Level, target: &str, message: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            target: target.to_string(),
            message: message.to_string(),
            provider: None,
            session_id: None,
            user_id: None,
            trace_id: None,
            span_id: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_provider(mut self, provider: &str) -> Self {
        self.provider = Some(provider.to_string());
        self
    }

    pub fn with_session(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }

    pub fn with_trace(mut self, trace_id: &str, span_id: &str) -> Self {
        self.trace_id = Some(trace_id.to_string());
        self.span_id = Some(span_id.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn to_string(&self) -> String {
        format!(
            "[{}] {} {}: {}",
            self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            self.level,
            self.target,
            self.message
        )
    }
}

pub struct JsonLogger {
    level: Level,
}

impl JsonLogger {
    pub fn new(level: Level) -> Self {
        Self { level }
    }

    pub fn log(&self, entry: &LogEntry) {
        if entry.level as u8 >= self.level as u8 {
            println!("{}", entry.to_json());
        }
    }

    pub fn trace(&self, target: &str, message: &str) {
        self.log(&LogEntry::new(Level::Trace, target, message));
    }

    pub fn debug(&self, target: &str, message: &str) {
        self.log(&LogEntry::new(Level::Debug, target, message));
    }

    pub fn info(&self, target: &str, message: &str) {
        self.log(&LogEntry::new(Level::Info, target, message));
    }

    pub fn warn(&self, target: &str, message: &str) {
        self.log(&LogEntry::new(Level::Warn, target, message));
    }

    pub fn error(&self, target: &str, message: &str) {
        self.log(&LogEntry::new(Level::Error, target, message));
    }
}

// Global logger for convenience
static LOGGER: Mutex<Option<JsonLogger>> = Mutex::new(None);

pub fn init_logger(level: Level) {
    if let Ok(mut guard) = LOGGER.lock() {
        *guard = Some(JsonLogger::new(level));
    }
}

pub fn get_logger() -> &'static Mutex<Option<JsonLogger>> {
    &LOGGER
}

pub fn log(level: Level, target: &str, message: &str) {
    if let Ok(guard) = LOGGER.lock() {
        if let Some(ref logger) = *guard {
            logger.log(&LogEntry::new(level, target, message));
        }
    }
}

pub fn trace(target: &str, message: &str) {
    log(Level::Trace, target, message);
}

pub fn debug(target: &str, message: &str) {
    log(Level::Debug, target, message);
}

pub fn info(target: &str, message: &str) {
    log(Level::Info, target, message);
}

pub fn warn(target: &str, message: &str) {
    log(Level::Warn, target, message);
}

pub fn error(target: &str, message: &str) {
    log(Level::Error, target, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(Level::Info, "test", "hello world");

        assert_eq!(entry.level, Level::Info);
        assert_eq!(entry.target, "test");
        assert_eq!(entry.message, "hello world");
    }

    #[test]
    fn test_log_entry_with_provider() {
        let entry = LogEntry::new(Level::Info, "api", "request")
            .with_provider("deepseek")
            .with_session("session-123");

        assert_eq!(entry.provider, Some("deepseek".to_string()));
        assert_eq!(entry.session_id, Some("session-123".to_string()));
    }

    #[test]
    fn test_log_entry_json() {
        let entry = LogEntry::new(Level::Info, "test", "message");
        let json = entry.to_json();

        assert!(!json.is_empty());
    }

    #[test]
    fn test_level_from_str() {
        assert_eq!(Level::from_str("DEBUG"), Level::Debug);
        assert_eq!(Level::from_str("warn"), Level::Warn);
        assert_eq!(Level::from_str("ERROR"), Level::Error);
    }
}
