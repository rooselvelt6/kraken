use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ForensicEntry {
    pub timestamp: u64,
    pub event_type: String,
    pub data: HashMap<String, String>,
    pub capture_id: u64,
}

impl ForensicEntry {
    pub fn new(event_type: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        static CAPTURE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let capture_id = CAPTURE_COUNTER.fetch_add(1, Ordering::SeqCst);

        Self {
            timestamp,
            event_type: event_type.to_string(),
            data: HashMap::new(),
            capture_id,
        }
    }

    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.data.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_env(mut self) -> Self {
        for (key, value) in std::env::vars() {
            self.data.insert(format!("env:{key}"), value);
        }
        self
    }

    pub fn with_cwd(mut self) -> Self {
        if let Ok(cwd) = std::env::current_dir() {
            self.data
                .insert("cwd".to_string(), cwd.to_string_lossy().to_string());
        }
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "timestamp".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.timestamp)),
        );
        map.insert(
            "event_type".to_string(),
            serde_json::Value::String(self.event_type.clone()),
        );
        map.insert(
            "capture_id".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.capture_id)),
        );

        let data_map: serde_json::Map<String, serde_json::Value> = self
            .data
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        map.insert("data".to_string(), serde_json::Value::Object(data_map));

        serde_json::Value::Object(map)
    }
}

pub struct ForensicRecorder {
    enabled: bool,
    entries: Vec<ForensicEntry>,
    max_entries: usize,
    output_dir: Option<PathBuf>,
}

impl ForensicRecorder {
    pub fn new(max_entries: usize) -> Self {
        Self {
            enabled: false,
            entries: Vec::with_capacity(max_entries),
            max_entries,
            output_dir: None,
        }
    }

    pub fn enable(&mut self, output_dir: PathBuf) {
        self.enabled = true;
        self.output_dir = Some(output_dir);
        if let Some(ref dir) = self.output_dir {
            let _ = fs::create_dir_all(dir);
        }
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn record(&mut self, entry: ForensicEntry) {
        if !self.enabled {
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }

        if let Some(ref dir) = self.output_dir {
            let path = dir.join(format!(
                "forensic_{}_{}.json",
                entry.timestamp, entry.capture_id
            ));
            let json = entry.to_json().to_string();
            let _ = fs::write(&path, json);
        }

        self.entries.push(entry);
    }

    pub fn capture_environment(&mut self) {
        let entry = ForensicEntry::new("environment").with_env().with_cwd();
        self.record(entry);
    }

    pub fn capture_command(&mut self, command: &str, args: &[String]) {
        let mut entry = ForensicEntry::new("command").with("command", command);
        entry.data.insert(
            "args".to_string(),
            args.iter()
                .map(|a| shell_escape(a))
                .collect::<Vec<_>>()
                .join(" "),
        );
        self.record(entry);
    }

    pub fn capture_file_read(&mut self, path: &str) {
        self.record(
            ForensicEntry::new("file_read").with("path", path),
        );
    }

    pub fn capture_file_write(&mut self, path: &str, size: u64) {
        self.record(
            ForensicEntry::new("file_write")
                .with("path", path)
                .with("size", &size.to_string()),
        );
    }

    pub fn capture_network(&mut self, url: &str, method: &str) {
        self.record(
            ForensicEntry::new("network")
                .with("url", url)
                .with("method", method),
        );
    }

    pub fn entries(&self) -> &[ForensicEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn export_json(&self) -> Vec<serde_json::Value> {
        self.entries.iter().map(|e| e.to_json()).collect()
    }
}

fn shell_escape(s: &str) -> String {
    if s.contains(char::is_whitespace) || s.contains('\'') || s.contains('"') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

static GLOBAL_FORENSIC: OnceLock<Mutex<ForensicRecorder>> = OnceLock::new();

pub fn global_forensic() -> &'static Mutex<ForensicRecorder> {
    GLOBAL_FORENSIC.get_or_init(|| Mutex::new(ForensicRecorder::new(10000)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forensic_entry_creation() {
        let entry = ForensicEntry::new("test");
        assert_eq!(entry.event_type, "test");
        assert!(entry.data.is_empty());
    }

    #[test]
    fn test_forensic_entry_with_data() {
        let entry = ForensicEntry::new("cmd").with("key1", "val1").with("key2", "val2");
        assert_eq!(entry.data.get("key1").unwrap(), "val1");
        assert_eq!(entry.data.len(), 2);
    }

    #[test]
    fn test_forensic_entry_with_env() {
        std::env::set_var("FORENSIC_TEST_VAR", "test_value");
        let entry = ForensicEntry::new("env").with_env();
        assert!(entry.data.contains_key("env:FORENSIC_TEST_VAR"));
    }

    #[test]
    fn test_forensic_recorder_disabled_by_default() {
        let recorder = ForensicRecorder::new(100);
        assert!(!recorder.is_enabled());
    }

    #[test]
    fn test_forensic_recorder_enable() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        assert!(recorder.is_enabled());
    }

    #[test]
    fn test_forensic_recorder_disabled_does_not_record() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.record(ForensicEntry::new("test"));
        assert!(recorder.is_empty());
    }

    #[test]
    fn test_forensic_recorder_records_when_enabled() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        recorder.record(ForensicEntry::new("test"));
        assert_eq!(recorder.len(), 1);
    }

    #[test]
    fn test_forensic_recorder_max_entries() {
        let mut recorder = ForensicRecorder::new(3);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        for i in 0..5 {
            recorder.record(ForensicEntry::new(&format!("event-{i}")));
        }
        assert_eq!(recorder.len(), 3);
        assert_eq!(recorder.entries()[0].event_type, "event-2");
    }

    #[test]
    fn test_forensic_recorder_capture_environment() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        recorder.capture_environment();
        assert_eq!(recorder.len(), 1);
        assert_eq!(recorder.entries()[0].event_type, "environment");
    }

    #[test]
    fn test_forensic_recorder_capture_command() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        recorder.capture_command("bash", &["-c".to_string(), "echo hi".to_string()]);
        assert_eq!(recorder.len(), 1);
        assert_eq!(recorder.entries()[0].event_type, "command");
    }

    #[test]
    fn test_forensic_recorder_capture_file_ops() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        recorder.capture_file_read("/etc/passwd");
        recorder.capture_file_write("/tmp/test.txt", 1024);
        assert_eq!(recorder.len(), 2);
    }

    #[test]
    fn test_forensic_recorder_capture_network() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        recorder.capture_network("https://api.example.com", "POST");
        assert_eq!(recorder.len(), 1);
    }

    #[test]
    fn test_forensic_entry_json() {
        let entry = ForensicEntry::new("test").with("key", "val");
        let json = entry.to_json();
        assert_eq!(json["event_type"], "test");
        assert_eq!(json["data"]["key"], "val");
    }

    #[test]
    fn test_forensic_export_json() {
        let mut recorder = ForensicRecorder::new(100);
        recorder.enable(PathBuf::from("/tmp/forensic_test"));
        recorder.record(ForensicEntry::new("e1"));
        recorder.record(ForensicEntry::new("e2"));
        let json = recorder.export_json();
        assert_eq!(json.len(), 2);
    }

    #[test]
    fn test_global_forensic() {
        let forensic = global_forensic();
        let guard = forensic.lock().unwrap();
        assert!(!guard.is_enabled());
    }

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("simple"), "simple");
        assert_eq!(shell_escape("has space"), "'has space'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_capture_id_increment() {
        let e1 = ForensicEntry::new("test");
        let e2 = ForensicEntry::new("test");
        assert!(e2.capture_id > e1.capture_id);
    }
}
