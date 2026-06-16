use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotResult {
    pub url: String,
    pub title: String,
    pub status_code: u16,
    pub content_hash: String,
    pub content_length: usize,
    pub captured_at: DateTime<Utc>,
    pub screenshot_path: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotCapture {
    pub results: Vec<ScreenshotResult>,
    pub total_captured: usize,
    pub total_failed: usize,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub viewport_width: u32,
    pub viewport_height: u32,
}

impl ScreenshotCapture {
    pub fn new(viewport_width: u32, viewport_height: u32) -> Self {
        Self {
            results: Vec::new(),
            total_captured: 0,
            total_failed: 0,
            started_at: Utc::now(),
            completed_at: None,
            viewport_width,
            viewport_height,
        }
    }

    pub fn capture_url(url: &str, title: &str, status_code: u16, body: &str) -> ScreenshotResult {
        let mut hasher = Sha256::new();
        hasher.update(body.as_bytes());
        let hash = hex::encode(hasher.finalize());

        ScreenshotResult {
            url: url.to_string(),
            title: title.to_string(),
            status_code,
            content_hash: hash,
            content_length: body.len(),
            captured_at: Utc::now(),
            screenshot_path: None,
            error: None,
        }
    }

    pub fn add_result(&mut self, result: ScreenshotResult) {
        if result.error.is_some() {
            self.total_failed += 1;
        } else {
            self.total_captured += 1;
        }
        self.results.push(result);
    }

    pub fn complete(&mut self) {
        self.completed_at = Some(Utc::now());
    }

    pub fn set_screenshot_path(&mut self, index: usize, path: String) {
        if let Some(result) = self.results.get_mut(index) {
            result.screenshot_path = Some(path);
        }
    }

    pub fn summary(&self) -> String {
        let failed_str = if self.total_failed > 0 {
            format!(", {} failed", self.total_failed)
        } else {
            String::new()
        };
        format!(
            "Captured {} pages{} — viewport {}x{}",
            self.total_captured, failed_str, self.viewport_width, self.viewport_height
        )
    }

    pub fn generate_html_report(&self) -> String {
        let mut items = String::new();
        for r in &self.results {
            let status_color = if r.error.is_some() {
                "#dc3545"
            } else if r.status_code < 400 {
                "#3fb950"
            } else {
                "#fd7e14"
            };
            let thumbnail = if let Some(path) = &r.screenshot_path {
                format!(
                    r#"<img src="{path}" alt="{title}" class="thumb" loading="lazy">"#,
                    path = html_escape(path),
                    title = html_escape(&r.title),
                )
            } else {
                r#"<div class="no-thumb">No Screenshot</div>"#.into()
            };

            items.push_str(&format!(
                r#"<div class="card"><div class="thumb-wrap">{thumb}</div><div class="card-body"><h3>{title}</h3><p class="url">{url}</p><p>Status: <span class="status" style="color:{status_color}">{code}</span> | Size: {size} bytes</p><p class="hash">SHA-256: <code>{hash}</code></p></div></div>"#,
                thumb = thumbnail,
                title = html_escape(&r.title),
                url = html_escape(&r.url),
                code = r.status_code,
                size = r.content_length,
                hash = &r.content_hash[..16],
            ));
        }

        let now = Utc::now().format("%Y-%m-%d %H:%M UTC");
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Screenshot Report — {total} pages</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}}
h1{{color:#f0f6fc;margin-bottom:0.5rem}}
.summary{{color:#8b949e;margin-bottom:2rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:1.5rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}}
.thumb-wrap{{width:100%;height:220px;background:#21262d;overflow:hidden}}
.thumb{{width:100%;height:100%;object-fit:cover}}
.no-thumb{{display:flex;align-items:center;justify-content:center;height:100%;color:#8b949e;font-size:0.9rem}}
.card-body{{padding:1rem}}
.card-body h3{{font-size:1rem;color:#f0f6fc;margin-bottom:0.3rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.card-body .url{{font-size:0.8rem;color:#58a6ff;margin-bottom:0.5rem;word-break:break-all}}
.card-body p{{font-size:0.85rem;color:#8b949e;margin-bottom:0.25rem}}
.card-body .hash{{font-size:0.75rem}}
.card-body .hash code{{background:#21262d;padding:0.1rem 0.3rem;border-radius:3px}}
.footer{{text-align:center;padding:2rem;color:#8b949e;font-size:0.85rem;margin-top:2rem;border-top:1px solid #30363d}}
@media(max-width:768px){{.grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<h1>📸 Web Screenshot Report</h1>
<p class="summary">{summary}</p>
<div class="grid">
{items}
</div>
<div class="footer">Generated by Kraken — {now}</div>
</body>
</html>"#,
            total = self.results.len(),
            summary = html_escape(&self.summary()),
            items = items,
            now = now,
        )
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
    fn test_new_capture() {
        let sc = ScreenshotCapture::new(1920, 1080);
        assert_eq!(sc.viewport_width, 1920);
        assert_eq!(sc.results.len(), 0);
    }

    #[test]
    fn test_capture_url() {
        let result = ScreenshotCapture::capture_url(
            "https://example.com",
            "Example",
            200,
            "<html>Hello</html>",
        );
        assert_eq!(result.url, "https://example.com");
        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_hash.len(), 64);
    }

    #[test]
    fn test_add_result() {
        let mut sc = ScreenshotCapture::new(800, 600);
        sc.add_result(ScreenshotCapture::capture_url("https://a.com", "A", 200, "body"));
        sc.add_result(ScreenshotCapture::capture_url("https://b.com", "B", 404, "not found"));
        assert_eq!(sc.total_captured, 2);
    }

    #[test]
    fn test_add_failed() {
        let mut sc = ScreenshotCapture::new(800, 600);
        sc.add_result(ScreenshotResult {
            url: "https://bad.com".into(),
            title: "Error".into(),
            status_code: 0,
            content_hash: "".into(),
            content_length: 0,
            captured_at: Utc::now(),
            screenshot_path: None,
            error: Some("Connection refused".into()),
        });
        assert_eq!(sc.total_failed, 1);
        assert_eq!(sc.total_captured, 0);
    }

    #[test]
    fn test_summary() {
        let mut sc = ScreenshotCapture::new(1024, 768);
        sc.add_result(ScreenshotCapture::capture_url("https://a.com", "A", 200, "ok"));
        assert!(sc.summary().contains("Captured 1 pages"));
    }

    #[test]
    fn test_generate_html_report() {
        let mut sc = ScreenshotCapture::new(1280, 720);
        sc.add_result(ScreenshotCapture::capture_url("https://x.com", "X", 200, "ok"));
        let html = sc.generate_html_report();
        assert!(html.contains("Screenshot Report"));
        assert!(html.contains("X"));
    }

    #[test]
    fn test_complete() {
        let mut sc = ScreenshotCapture::new(800, 600);
        assert!(sc.completed_at.is_none());
        sc.complete();
        assert!(sc.completed_at.is_some());
    }
}
