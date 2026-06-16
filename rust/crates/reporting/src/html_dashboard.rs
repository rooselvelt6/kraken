use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetric {
    pub label: String,
    pub value: String,
    pub color: String,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardEntry {
    pub timestamp: String,
    pub event: String,
    pub detail: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtmlDashboard {
    pub title: String,
    pub metrics: Vec<DashboardMetric>,
    pub entries: Vec<DashboardEntry>,
    pub refresh_interval_secs: u32,
    pub theme: String,
}

impl HtmlDashboard {
    pub fn new(title: String) -> Self {
        Self {
            title,
            metrics: Vec::new(),
            entries: Vec::new(),
            refresh_interval_secs: 30,
            theme: "dark".into(),
        }
    }

    pub fn add_metric(&mut self, metric: DashboardMetric) {
        self.metrics.push(metric);
    }

    pub fn add_entry(&mut self, entry: DashboardEntry) {
        self.entries.push(entry);
    }

    pub fn set_refresh_interval(&mut self, secs: u32) {
        self.refresh_interval_secs = secs;
    }

    pub fn set_theme(&mut self, theme: String) {
        self.theme = theme;
    }

    pub fn render_html(&self) -> String {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let is_dark = self.theme == "dark";

        let bg = if is_dark { "#0d1117" } else { "#ffffff" };
        let fg = if is_dark { "#c9d1d9" } else { "#24292f" };
        let card_bg = if is_dark { "#161b22" } else { "#f6f8fa" };
        let border = if is_dark { "#30363d" } else { "#d0d7de" };
        let heading = if is_dark { "#f0f6fc" } else { "#1f2328" };

        let mut metrics_html = String::new();
        for m in &self.metrics {
            metrics_html.push_str(&format!(
                r#"<div class="metric-card"><div class="metric-icon">{icon}</div><div class="metric-value" style="color:{color}">{value}</div><div class="metric-label">{label}</div></div>"#,
                icon = m.icon,
                value = m.value,
                color = m.color,
                label = m.label,
            ));
        }

        let mut table_rows = String::new();
        for e in &self.entries {
            let sev_color = match e.severity.as_str() {
                "Critical" => "#dc3545",
                "High" => "#fd7e14",
                "Medium" => "#ffc107",
                "Low" => "#0dcaf0",
                _ => "#20c997",
            };
            table_rows.push_str(&format!(
                r#"<tr><td>{ts}</td><td>{event}</td><td>{detail}</td><td><span class="sev-badge" style="background:{sev_color}">{sev}</span></td></tr>"#,
                ts = e.timestamp,
                event = html_escape(&e.event),
                detail = html_escape(&e.detail),
                sev = e.severity,
                sev_color = sev_color,
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — Live Dashboard</title>
<meta http-equiv="refresh" content="{refresh}">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,sans-serif;background:{bg};color:{fg};line-height:1.6}}
.header{{background:{card_bg};border-bottom:1px solid {border};padding:1.5rem 2rem;display:flex;justify-content:space-between;align-items:center}}
.header h1{{font-size:1.5rem;color:{heading}}}
.header .ts{{color:#8b949e;font-size:0.85rem}}
.metrics-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;padding:1.5rem 2rem}}
.metric-card{{background:{card_bg};border:1px solid {border};border-radius:8px;padding:1.25rem;text-align:center}}
.metric-icon{{font-size:1.5rem;margin-bottom:0.5rem}}
.metric-value{{font-size:1.8rem;font-weight:700}}
.metric-label{{font-size:0.8rem;color:#8b949e;margin-top:0.25rem}}
.section{{padding:0 2rem 2rem}}
.section h2{{font-size:1.2rem;color:{heading};margin-bottom:1rem;border-bottom:1px solid {border};padding-bottom:0.5rem}}
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:0.9rem}}
th,td{{padding:0.5rem 0.75rem;text-align:left;border-bottom:1px solid {border}}}
th{{background:{card_bg};color:#8b949e;font-weight:600;position:sticky;top:0}}
tr:hover td{{background:rgba(255,255,255,0.03)}}
.sev-badge{{display:inline-block;padding:0.15rem 0.5rem;border-radius:4px;font-size:0.75rem;font-weight:600;color:#fff}}
.status-dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:0.4rem;background:#3fb950}}
.footer{{text-align:center;padding:1.5rem;color:#8b949e;font-size:0.8rem;border-top:1px solid {border}}}
@media(max-width:768px){{.metrics-grid{{grid-template-columns:repeat(2,1fr)}}.section{{padding:0 1rem}}}}
</style>
</head>
<body>
<div class="header">
<h1>🔬 {title}</h1>
<span class="ts">Last updated: {now} | Auto-refresh: {refresh}s</span>
</div>
<div class="metrics-grid">
{metrics}
</div>
<div class="section">
<h2>Recent Events</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Timestamp</th><th>Event</th><th>Detail</th><th>Severity</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>
<div class="footer">
<span class="status-dot"></span> System Online — Generated by Kraken Security Platform
</div>
</body>
</html>"#,
            title = html_escape(&self.title),
            refresh = self.refresh_interval_secs,
            now = now,
            metrics = metrics_html,
            rows = table_rows,
        )
    }

    pub fn export_html(&self) -> String {
        self.render_html()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_dashboard() {
        let d = HtmlDashboard::new("Test Scan".into());
        assert_eq!(d.title, "Test Scan");
        assert_eq!(d.metrics.len(), 0);
        assert_eq!(d.refresh_interval_secs, 30);
    }

    #[test]
    fn test_add_metric() {
        let mut d = HtmlDashboard::new("Scan".into());
        d.add_metric(DashboardMetric {
            label: "Findings".into(),
            value: "42".into(),
            color: "#ffc107".into(),
            icon: "🔍".into(),
        });
        assert_eq!(d.metrics.len(), 1);
    }

    #[test]
    fn test_add_entry() {
        let mut d = HtmlDashboard::new("Scan".into());
        d.add_entry(DashboardEntry {
            timestamp: "2026-01-01 12:00".into(),
            event: "SQLi Found".into(),
            detail: "/login.php".into(),
            severity: "Critical".into(),
        });
        assert_eq!(d.entries.len(), 1);
    }

    #[test]
    fn test_render_html_contains_title() {
        let d = HtmlDashboard::new("Nightly Scan".into());
        let html = d.render_html();
        assert!(html.contains("Nightly Scan"));
    }

    #[test]
    fn test_render_html_contains_metrics() {
        let mut d = HtmlDashboard::new("Scan".into());
        d.add_metric(DashboardMetric {
            label: "Hosts".into(),
            value: "10".into(),
            color: "#3fb950".into(),
            icon: "🖥".into(),
        });
        let html = d.render_html();
        assert!(html.contains("10"));
        assert!(html.contains("Hosts"));
    }

    #[test]
    fn test_render_html_entries_table() {
        let mut d = HtmlDashboard::new("Scan".into());
        d.add_entry(DashboardEntry {
            timestamp: "now".into(),
            event: "test-event".into(),
            detail: "details".into(),
            severity: "High".into(),
        });
        let html = d.render_html();
        assert!(html.contains("test-event"));
    }

    #[test]
    fn test_set_refresh() {
        let mut d = HtmlDashboard::new("S".into());
        d.set_refresh_interval(60);
        assert_eq!(d.refresh_interval_secs, 60);
    }
}
