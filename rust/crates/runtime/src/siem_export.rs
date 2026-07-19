use serde::{Deserialize, Serialize};
use security::audit::AuditLog;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiemFormat {
    Ecs,
    SplunkHec,
    OpenTelemetry,
    Json,
}

impl SiemFormat {
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ecs" => Some(Self::Ecs),
            "splunk" | "splunk-hec" => Some(Self::SplunkHec),
            "otel" | "opentelemetry" => Some(Self::OpenTelemetry),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    #[must_use]
    pub fn extensions(&self) -> &'static str {
        match self {
            Self::Ecs => "ecs.json",
            Self::SplunkHec => "splunk.json",
            Self::OpenTelemetry => "otel.json",
            Self::Json => "json",
        }
    }

    #[must_use]
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Ecs => "application/ecs+json",
            Self::SplunkHec => "application/x-splunk-json",
            Self::OpenTelemetry | Self::Json => "application/json",
        }
    }
}

pub struct SiemExporter {
    format: SiemFormat,
    output_dir: Option<String>,
    pretty: bool,
}

impl SiemExporter {
    #[must_use]
    pub fn new(format: SiemFormat) -> Self {
        Self {
            format,
            output_dir: None,
            pretty: false,
        }
    }

    #[must_use]
    pub fn with_output_dir(mut self, dir: &str) -> Self {
        self.output_dir = Some(dir.to_string());
        self
    }

    #[must_use]
    pub fn with_pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }

    pub fn export(&self, log: &AuditLog, name: &str) -> Result<ExportResult, ExportError> {
        let value = match self.format {
            SiemFormat::Ecs => {
                let entries = log.export_ecs();
                serde_json::json!({
                    "@timestamp": chrono_now(),
                    "event": {
                        "kind": "pipeline",
                        "category": ["database"],
                        "type": ["change"]
                    },
                    "audit": {
                        "entries": entries,
                        "total": log.len()
                    }
                })
            }
            SiemFormat::SplunkHec => {
                let entries = log.export_splunk_hec();
                serde_json::json!({
                    "entries": entries,
                    "total": log.len()
                })
            }
            SiemFormat::OpenTelemetry => log.export_opentelemetry(),
            SiemFormat::Json => log.export_json(),
        };

        let json_str = if self.pretty {
            serde_json::to_string_pretty(&value)
        } else {
            serde_json::to_string(&value)
        }
        .map_err(|e| ExportError::Serialize(e.to_string()))?;

        match self.output_dir {
            Some(ref dir) => {
                let _ = fs::create_dir_all(dir);
                let filename = format!("{}_{}.{}", name, unix_ts(), self.format.extensions());
                let path = Path::new(dir).join(&filename);
                fs::write(&path, &json_str)
                    .map_err(|e| ExportError::Io(e.to_string()))?;
                Ok(ExportResult {
                    path: Some(path.to_string_lossy().to_string()),
                    size: json_str.len(),
                    format: self.format,
                    entry_count: log.len(),
                })
            }
            None => Ok(ExportResult {
                path: None,
                size: json_str.len(),
                format: self.format,
                entry_count: log.len(),
            }),
        }
    }

    pub fn export_string(&self, log: &AuditLog) -> Result<String, ExportError> {
        let value = match self.format {
            SiemFormat::Ecs => {
                let entries = log.export_ecs();
                serde_json::json!({ "audit": { "entries": entries, "total": log.len() } })
            }
            SiemFormat::SplunkHec => {
                let entries = log.export_splunk_hec();
                serde_json::json!({ "entries": entries, "total": log.len() })
            }
            SiemFormat::OpenTelemetry => log.export_opentelemetry(),
            SiemFormat::Json => log.export_json(),
        };

        if self.pretty {
            serde_json::to_string_pretty(&value)
        } else {
            serde_json::to_string(&value)
        }
        .map_err(|e| ExportError::Serialize(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub path: Option<String>,
    pub size: usize,
    pub format: SiemFormat,
    pub entry_count: usize,
}

#[derive(Debug, Clone)]
pub enum ExportError {
    Serialize(String),
    Io(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(s) => write!(f, "serialization error: {s}"),
            Self::Io(s) => write!(f, "IO error: {s}"),
        }
    }
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn chrono_now() -> String {
    let secs = unix_ts();
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use security::audit::{AuditAction, AuditLog};

    fn sample_log() -> AuditLog {
        let mut log = AuditLog::new();
        log.log(AuditAction::SessionStart, Some("session-1".to_string()));
        log.log(AuditAction::ToolExecute, Some("read".to_string()));
        log.log(AuditAction::FileWrite, Some("/tmp/test.txt".to_string()));
        log.log(AuditAction::SessionEnd, Some("session-1".to_string()));
        log
    }

    #[test]
    fn test_siem_format_from_str() {
        assert_eq!(SiemFormat::from_str("ecs"), Some(SiemFormat::Ecs));
        assert_eq!(SiemFormat::from_str("splunk"), Some(SiemFormat::SplunkHec));
        assert_eq!(SiemFormat::from_str("otel"), Some(SiemFormat::OpenTelemetry));
        assert_eq!(SiemFormat::from_str("json"), Some(SiemFormat::Json));
        assert_eq!(SiemFormat::from_str("unknown"), None);
    }

    #[test]
    fn test_siem_format_extension() {
        assert_eq!(SiemFormat::Ecs.extensions(), "ecs.json");
        assert_eq!(SiemFormat::SplunkHec.extensions(), "splunk.json");
        assert_eq!(SiemFormat::OpenTelemetry.extensions(), "otel.json");
        assert_eq!(SiemFormat::Json.extensions(), "json");
    }

    #[test]
    fn test_siem_format_content_type() {
        assert_eq!(SiemFormat::Ecs.content_type(), "application/ecs+json");
        assert_eq!(SiemFormat::SplunkHec.content_type(), "application/x-splunk-json");
    }

    #[test]
    fn test_export_ecs_string() {
        let log = sample_log();
        let exporter = SiemExporter::new(SiemFormat::Ecs);
        let result = exporter.export_string(&log).unwrap();
        assert!(result.contains("audit"));
        assert!(result.contains("entries"));
    }

    #[test]
    fn test_export_splunk_string() {
        let log = sample_log();
        let exporter = SiemExporter::new(SiemFormat::SplunkHec);
        let result = exporter.export_string(&log).unwrap();
        assert!(result.contains("entries"));
    }

    #[test]
    fn test_export_otel_string() {
        let log = sample_log();
        let exporter = SiemExporter::new(SiemFormat::OpenTelemetry);
        let result = exporter.export_string(&log).unwrap();
        assert!(result.contains("resourceSpans"));
    }

    #[test]
    fn test_export_json_string() {
        let log = sample_log();
        let exporter = SiemExporter::new(SiemFormat::Json);
        let result = exporter.export_string(&log).unwrap();
        assert!(result.contains("entries"));
        assert!(result.contains("\"count\":4") || result.contains("\"count\": 4"));
    }

    #[test]
    fn test_export_pretty() {
        let log = sample_log();
        let exporter = SiemExporter::new(SiemFormat::Json).with_pretty(true);
        let result = exporter.export_string(&log).unwrap();
        assert!(result.contains('\n'));
    }

    #[test]
    fn test_export_to_file() {
        let log = sample_log();
        let dir = std::env::temp_dir().join("siem_test");
        let exporter = SiemExporter::new(SiemFormat::Json).with_output_dir(dir.to_str().unwrap());
        let result = exporter.export(&log, "test-export").unwrap();
        assert!(result.path.is_some());
        assert!(std::path::Path::new(result.path.as_ref().unwrap()).exists());
        assert_eq!(result.entry_count, 4);
        let _ = std::fs::remove_file(result.path.unwrap());
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_export_result() {
        let result = ExportResult {
            path: Some("/tmp/test.json".to_string()),
            size: 1024,
            format: SiemFormat::Ecs,
            entry_count: 10,
        };
        assert_eq!(result.size, 1024);
        assert_eq!(result.entry_count, 10);
    }

    #[test]
    fn test_export_error_display() {
        let err = ExportError::Serialize("msg".to_string());
        assert_eq!(err.to_string(), "serialization error: msg");
        let err = ExportError::Io("msg".to_string());
        assert_eq!(err.to_string(), "IO error: msg");
    }
}
