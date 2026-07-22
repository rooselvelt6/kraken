use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub title: String,
    pub detail: String,
    pub severity: String,
    pub source: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub target: String,
    pub phase: String,
    pub progress_pct: f64,
    pub findings_count: usize,
    pub started_at: String,
    pub elapsed_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapData {
    pub categories: Vec<HeatmapCategory>,
    pub total_findings: usize,
    pub time_range: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapCategory {
    pub name: String,
    pub count: usize,
    pub severity_breakdown: HashMap<String, usize>,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub scan_id: String,
    pub target: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub status: String,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub msg_type: String,
    pub payload: String,
    pub timestamp: String,
}

pub struct LiveDashboard {
    events: Arc<RwLock<Vec<LiveEvent>>>,
    scan_progress: Arc<RwLock<HashMap<String, ScanProgress>>>,
    scan_history: Arc<RwLock<Vec<ScanHistoryEntry>>>,
    max_events: usize,
}

impl Default for LiveDashboard {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveDashboard {
    pub fn new() -> Self {
        LiveDashboard {
            events: Arc::new(RwLock::new(Vec::new())),
            scan_progress: Arc::new(RwLock::new(HashMap::new())),
            scan_history: Arc::new(RwLock::new(Vec::new())),
            max_events: 1000,
        }
    }

    pub fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    pub async fn push_event(&self, event: LiveEvent) {
        let mut events = self.events.write().await;
        events.push(event);
        if events.len() > self.max_events {
            events.remove(0);
        }
    }

    pub async fn get_events(&self, limit: Option<usize>) -> Vec<LiveEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(events.len());
        events.iter().rev().take(limit).cloned().collect()
    }

    pub async fn update_scan_progress(&self, progress: ScanProgress) {
        let mut map = self.scan_progress.write().await;
        map.insert(progress.scan_id.clone(), progress);
    }

    pub async fn get_scan_progress(&self, scan_id: &str) -> Option<ScanProgress> {
        let map = self.scan_progress.read().await;
        map.get(scan_id).cloned()
    }

    pub async fn get_all_scan_progress(&self) -> Vec<ScanProgress> {
        let map = self.scan_progress.read().await;
        map.values().cloned().collect()
    }

    pub async fn complete_scan(&self, scan_id: &str) {
        let mut map = self.scan_progress.write().await;
        if let Some(mut progress) = map.remove(scan_id) {
            progress.phase = "completed".to_string();
            progress.progress_pct = 100.0;
            let mut history = self.scan_history.write().await;
            history.push(ScanHistoryEntry {
                scan_id: progress.scan_id,
                target: progress.target,
                started_at: progress.started_at,
                completed_at: Some(chrono::Utc::now().to_rfc3339()),
                status: "completed".to_string(),
                findings_count: progress.findings_count,
                critical_count: 0,
                high_count: 0,
            });
        }
    }

    pub async fn get_scan_history(&self, limit: Option<usize>) -> Vec<ScanHistoryEntry> {
        let history = self.scan_history.read().await;
        let limit = limit.unwrap_or(history.len());
        history.iter().rev().take(limit).cloned().collect()
    }

    pub fn build_heatmap(events: &[LiveEvent]) -> HeatmapData {
        let mut categories: HashMap<String, HashMap<String, usize>> = HashMap::new();
        let mut total = 0;

        for event in events {
            let cat = categories.entry(event.event_type.clone()).or_default();
            *cat.entry(event.severity.clone()).or_insert(0) += 1;
            total += 1;
        }

        let heatmap_categories: Vec<HeatmapCategory> = categories
            .into_iter()
            .map(|(name, severity_breakdown)| {
                let count: usize = severity_breakdown.values().sum();
                HeatmapCategory {
                    name,
                    count,
                    severity_breakdown,
                    percentage: if total > 0 { count as f64 / total as f64 * 100.0 } else { 0.0 },
                }
            })
            .collect();

        HeatmapData {
            categories: heatmap_categories,
            total_findings: total,
            time_range: "last_hour".to_string(),
        }
    }

    pub fn format_event(event: &LiveEvent) -> String {
        let sev_color = match event.severity.as_str() {
            "Critical" => "\x1b[91m",
            "High" => "\x1b[93m",
            "Medium" => "\x1b[33m",
            "Low" => "\x1b[96m",
            _ => "\x1b[37m",
        };
        format!(
            "{}[{}]{}\t{}\t{} — {}",
            sev_color, event.severity, "\x1b[0m",
            event.timestamp, event.title, event.detail
        )
    }

    pub fn render_heatmap_text(data: &HeatmapData) -> String {
        let mut output = format!("Vulnerability Heatmap ({} total findings)\n", data.total_findings);
        output.push_str("==========================================\n\n");

        for cat in &data.categories {
            let bar_len = (cat.percentage / 5.0) as usize;
            let bar: String = "█".repeat(bar_len);
            output.push_str(&format!(
                "{:<20} {:>5} ({:>5.1}%) {}\n",
                cat.name, cat.count, cat.percentage, bar
            ));

            for (sev, count) in &cat.severity_breakdown {
                output.push_str(&format!("  {:<18} {}\n", sev, count));
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(id: &str) -> LiveEvent {
        let mut metadata = HashMap::new();
        metadata.insert("port".to_string(), "443".to_string());
        LiveEvent {
            id: id.to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
            event_type: "vulnerability".to_string(),
            title: "SQL Injection".to_string(),
            detail: "Found in /login.php".to_string(),
            severity: "Critical".to_string(),
            source: "vulnscan".to_string(),
            metadata,
        }
    }

    #[tokio::test]
    async fn test_push_and_get_events() {
        let dash = LiveDashboard::new();
        dash.push_event(sample_event("1")).await;
        dash.push_event(sample_event("2")).await;
        let events = dash.get_events(None).await;
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_get_events_limit() {
        let dash = LiveDashboard::new();
        for i in 0..10 {
            dash.push_event(sample_event(&i.to_string())).await;
        }
        let events = dash.get_events(Some(5)).await;
        assert_eq!(events.len(), 5);
    }

    #[tokio::test]
    async fn test_max_events_eviction() {
        let dash = LiveDashboard::new().with_max_events(3);
        for i in 0..5 {
            dash.push_event(sample_event(&i.to_string())).await;
        }
        let events = dash.get_events(None).await;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].id, "4");
    }

    #[tokio::test]
    async fn test_scan_progress() {
        let dash = LiveDashboard::new();
        let progress = ScanProgress {
            scan_id: "scan-1".to_string(),
            target: "192.168.1.0/24".to_string(),
            phase: "scanning".to_string(),
            progress_pct: 45.0,
            findings_count: 12,
            started_at: chrono::Utc::now().to_rfc3339(),
            elapsed_secs: 30,
        };
        dash.update_scan_progress(progress).await;
        let result = dash.get_scan_progress("scan-1").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().progress_pct, 45.0);
    }

    #[tokio::test]
    async fn test_complete_scan() {
        let dash = LiveDashboard::new();
        let progress = ScanProgress {
            scan_id: "scan-1".to_string(),
            target: "test".to_string(),
            phase: "scanning".to_string(),
            progress_pct: 90.0,
            findings_count: 5,
            started_at: chrono::Utc::now().to_rfc3339(),
            elapsed_secs: 60,
        };
        dash.update_scan_progress(progress).await;
        dash.complete_scan("scan-1").await;
        assert!(dash.get_scan_progress("scan-1").await.is_none());
        let history = dash.get_scan_history(None).await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, "completed");
    }

    #[tokio::test]
    async fn test_get_scan_history() {
        let dash = LiveDashboard::new();
        for i in 0..5 {
            let progress = ScanProgress {
                scan_id: format!("scan-{}", i),
                target: "test".to_string(),
                phase: "completed".to_string(),
                progress_pct: 100.0,
                findings_count: i,
                started_at: chrono::Utc::now().to_rfc3339(),
                elapsed_secs: 30,
            };
            dash.update_scan_progress(progress).await;
            dash.complete_scan(&format!("scan-{}", i)).await;
        }
        let history = dash.get_scan_history(Some(3)).await;
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_build_heatmap() {
        let events = vec![
            sample_event("1"),
            sample_event("2"),
            {
                let mut e = sample_event("3");
                e.event_type = "network".to_string();
                e
            },
        ];
        let heatmap = LiveDashboard::build_heatmap(&events);
        assert_eq!(heatmap.total_findings, 3);
        assert_eq!(heatmap.categories.len(), 2);
    }

    #[test]
    fn test_format_event() {
        let event = sample_event("1");
        let formatted = LiveDashboard::format_event(&event);
        assert!(formatted.contains("SQL Injection"));
        assert!(formatted.contains("Critical"));
    }

    #[test]
    fn test_render_heatmap_text() {
        let events = vec![sample_event("1")];
        let heatmap = LiveDashboard::build_heatmap(&events);
        let text = LiveDashboard::render_heatmap_text(&heatmap);
        assert!(text.contains("Heatmap"));
        assert!(text.contains("vulnerability"));
    }

    #[test]
    fn test_heatmap_empty() {
        let heatmap = LiveDashboard::build_heatmap(&[]);
        assert_eq!(heatmap.total_findings, 0);
        assert!(heatmap.categories.is_empty());
    }

    #[test]
    fn test_websocket_message_serialization() {
        let msg = WebSocketMessage {
            msg_type: "event".to_string(),
            payload: "test".to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("event"));
    }
}