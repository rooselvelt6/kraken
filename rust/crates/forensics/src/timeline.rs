use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub file_path: String,
    pub event_type: String,
    pub size: u64,
    pub permissions: String,
    pub owner: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineResult {
    pub entries: Vec<TimelineEntry>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub total_entries: usize,
    pub by_event_type: HashMap<String, usize>,
}

pub struct TimelineAnalyzer;

impl Default for TimelineAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TimelineAnalyzer {
    pub fn new() -> Self {
        TimelineAnalyzer
    }

    pub fn build_timeline(paths: &[&str]) -> TimelineResult {
        let mut entries = Vec::new();
        let mut by_event_type: HashMap<String, usize> = HashMap::new();

        for path_str in paths {
            let path = Path::new(path_str);
            if path.is_dir() {
                Self::scan_dir(path, &mut entries);
            } else if path.exists() {
                Self::add_file_entry(path, &mut entries, "scanned");
            }
        }

        for entry in &entries {
            *by_event_type.entry(entry.event_type.clone()).or_default() += 1;
        }

        let timestamps: Vec<_> = entries.iter()
            .filter_map(|e| {
                chrono::DateTime::parse_from_rfc3339(&e.timestamp).ok()
            })
            .collect();

        let start_time = timestamps.iter().min().map(|d| d.to_rfc3339());
        let end_time = timestamps.iter().max().map(|d| d.to_rfc3339());
        let total_entries = entries.len();

        TimelineResult {
            entries,
            start_time,
            end_time,
            total_entries,
            by_event_type,
        }
    }

    fn scan_dir(dir: &Path, entries: &mut Vec<TimelineEntry>) {
        let walker = walkdir::WalkDir::new(dir).follow_links(false);
        for entry in walker.into_iter().flatten() {
            Self::add_file_entry(entry.path(), entries, "scanned");
        }
    }

    fn add_file_entry(path: &Path, entries: &mut Vec<TimelineEntry>, event_type: &str) {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        let size = meta.len();

        let permissions = format!("{:?}", meta.permissions());
        let owner = "unknown".to_string();

        if let Ok(modified) = meta.modified() {
            let duration = modified.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            if let Some(dt) = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0) {
                entries.push(TimelineEntry {
                    timestamp: dt.to_rfc3339(),
                    file_path: path.to_string_lossy().to_string(),
                    event_type: format!("{}_{}", event_type, "modified"),
                    size,
                    permissions: permissions.clone(),
                    owner: owner.clone(),
                });
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if let Ok(created) = meta.created() {
                let duration = created.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                if let Some(dt) = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0) {
                    entries.push(TimelineEntry {
                        timestamp: dt.to_rfc3339(),
                        file_path: path.to_string_lossy().to_string(),
                        event_type: format!("{}_{}", event_type, "created"),
                        size,
                        permissions: format!("{:o}", mode & 0o7777),
                        owner: meta.uid().to_string(),
                    });
                }
            }
            if let Ok(accessed) = meta.accessed() {
                let duration = accessed.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                if let Some(dt) = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0) {
                    entries.push(TimelineEntry {
                        timestamp: dt.to_rfc3339(),
                        file_path: path.to_string_lossy().to_string(),
                        event_type: format!("{}_{}", event_type, "accessed"),
                        size,
                        permissions: format!("{:o}", mode & 0o7777),
                        owner: meta.uid().to_string(),
                    });
                }
            }
        }
    }

    pub fn analyze_modified_files(paths: &[&str], since_hours: u64) -> Vec<TimelineEntry> {
        let result = Self::build_timeline(paths);
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(since_hours as i64);
        result.entries.into_iter()
            .filter(|e| {
                chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                    .map(|t| t >= cutoff)
                    .unwrap_or(false)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_timeline() {
        let tmp = std::env::temp_dir().join("timeline_test");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("file1.txt"), b"hello").unwrap();
        std::fs::write(tmp.join("file2.txt"), b"world").unwrap();

        let result = TimelineAnalyzer::build_timeline(&[tmp.to_str().unwrap()]);
        assert!(result.total_entries >= 2);
        assert!(result.by_event_type.contains_key("scanned_modified"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_timeline_entry() {
        let entry = TimelineEntry {
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            file_path: "/etc/passwd".to_string(),
            event_type: "modified".to_string(),
            size: 2048,
            permissions: "644".to_string(),
            owner: "root".to_string(),
        };
        assert!(entry.file_path.contains("passwd"));
    }

    #[test]
    fn test_timeline_result() {
        let mut by_type = HashMap::new();
        by_type.insert("modified".to_string(), 5);
        by_type.insert("accessed".to_string(), 3);
        let result = TimelineResult {
            entries: vec![],
            start_time: None,
            end_time: None,
            total_entries: 8,
            by_event_type: by_type,
        };
        assert_eq!(result.total_entries, 8);
        assert_eq!(result.by_event_type.get("modified").unwrap(), &5);
    }

    #[test]
    fn test_analyze_recent() {
        let tmp = std::env::temp_dir().join("recent_test");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("recent.txt"), b"data").unwrap();

        let recent = TimelineAnalyzer::analyze_modified_files(&[tmp.to_str().unwrap()], 24);
        assert!(!recent.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_nonexistent_path() {
        let result = TimelineAnalyzer::build_timeline(&["/nonexistent/path"]);
        assert_eq!(result.total_entries, 0);
    }
}
