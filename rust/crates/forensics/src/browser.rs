use std::collections::HashMap;
use std::path::Path;

use kraken_errors::ForensicsError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserArtifact {
    pub browser_type: String,
    pub artifact_type: String,
    pub source_path: String,
    pub entries: Vec<BrowserEntry>,
    pub total_entries: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserEntry {
    pub url: Option<String>,
    pub title: Option<String>,
    pub visit_time: Option<String>,
    pub visit_count: Option<u32>,
    pub typed_count: Option<u32>,
    pub last_visit: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cookie_name: Option<String>,
    pub cookie_value: Option<String>,
    pub cookie_domain: Option<String>,
    pub cookie_expiry: Option<String>,
    pub download_path: Option<String>,
    pub download_url: Option<String>,
    pub download_size: Option<u64>,
    pub download_mime: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserCredential {
    pub browser: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub created: Option<String>,
    pub last_used: Option<String>,
}

pub struct BrowserForensics;

impl Default for BrowserForensics {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserForensics {
    pub fn new() -> Self {
        BrowserForensics
    }

    pub fn analyze_history(browser_path: &str) -> Result<BrowserArtifact, ForensicsError> {
        let path = Path::new(browser_path);
        if !path.exists() {
            return Err(ForensicsError::NotFound(browser_path.to_string()));
        }
        let browser_type = Self::detect_browser(browser_path);

        let mut entries = Vec::new();
        let sqlite_paths = Self::find_sqlite_files(browser_path, &["history", "History", "places"]);

        for sqlite_path in &sqlite_paths {
            if let Ok(sqlite_entries) = Self::parse_sqlite_history(sqlite_path) {
                entries.extend(sqlite_entries);
            }
        }

        if entries.is_empty() {
            entries = Self::parse_history_json(browser_path);
        }

        let total = entries.len();
        Ok(BrowserArtifact {
            browser_type,
            artifact_type: "history".to_string(),
            source_path: browser_path.to_string(),
            entries,
            total_entries: total,
        })
    }

    pub fn analyze_cookies(browser_path: &str) -> Result<BrowserArtifact, ForensicsError> {
        let path = Path::new(browser_path);
        if !path.exists() {
            return Err(ForensicsError::NotFound(browser_path.to_string()));
        }
        let browser_type = Self::detect_browser(browser_path);

        let mut entries = Vec::new();
        let cookie_paths = Self::find_sqlite_files(browser_path, &["cookies", "Cookies", "Network"]);

        for cookie_path in &cookie_paths {
            if let Ok(mut cookie_entries) = Self::parse_sqlite_cookies(cookie_path) {
                entries.append(&mut cookie_entries);
            }
        }

        let total_entries = entries.len();
        Ok(BrowserArtifact {
            browser_type,
            artifact_type: "cookies".to_string(),
            source_path: browser_path.to_string(),
            entries,
            total_entries,
        })
    }

    pub fn analyze_downloads(browser_path: &str) -> Result<BrowserArtifact, ForensicsError> {
        let path = Path::new(browser_path);
        if !path.exists() {
            return Err(ForensicsError::NotFound(browser_path.to_string()));
        }
        let browser_type = Self::detect_browser(browser_path);

        let mut entries = Vec::new();
        let download_paths = Self::find_sqlite_files(browser_path, &["downloads", "Downloads", "history"]);

        for dl_path in &download_paths {
            if let Ok(mut dl_entries) = Self::parse_sqlite_downloads(dl_path) {
                entries.append(&mut dl_entries);
            }
        }

        let total_entries = entries.len();
        Ok(BrowserArtifact {
            browser_type,
            artifact_type: "downloads".to_string(),
            source_path: browser_path.to_string(),
            entries,
            total_entries,
        })
    }

    pub fn analyze_credentials(browser_path: &str) -> Result<Vec<BrowserCredential>, ForensicsError> {
        let mut credentials = Vec::new();
        let login_paths = Self::find_sqlite_files(browser_path, &[
            "Login Data", "logins", "key4.db", "signons.sqlite"
        ]);

        for login_path in &login_paths {
            if let Ok(mut creds) = Self::parse_login_data(login_path) {
                credentials.append(&mut creds);
            }
        }

        Ok(credentials)
    }

    fn detect_browser(path: &str) -> String {
        let lower = path.to_lowercase();
        if lower.contains("chrome") || lower.contains("chromium") || lower.contains("brave") || lower.contains("edge") {
            "chrome".to_string()
        } else if lower.contains("firefox") || lower.contains("mozilla") {
            "firefox".to_string()
        } else if lower.contains("safari") {
            "safari".to_string()
        } else if lower.contains("opera") || lower.contains("vivaldi") {
            "chromium".to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn find_sqlite_files(root: &str, names: &[&str]) -> Vec<String> {
        let mut results = Vec::new();
        let root_path = Path::new(root);
        if !root_path.exists() { return results; }

        let walker = walkdir::WalkDir::new(root_path)
            .follow_links(false)
            .max_depth(10);
        for entry in walker.into_iter().flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if names.contains(&fname.as_str()) {
                results.push(entry.path().to_string_lossy().to_string());
            }
        }
        results
    }

    fn parse_sqlite_history(db_path: &str) -> Result<Vec<BrowserEntry>, ForensicsError> {
        let mut entries = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(db_path) {
            let tables: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")
                .ok()
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| row.get(0)).ok()
                        .map(|rows| rows.flatten().collect())
                })
                .unwrap_or_default();

            if tables.contains(&"urls".to_string()) || tables.contains(&"moz_places".to_string()) {
                let query = if tables.contains(&"moz_places".to_string()) {
                    "SELECT url, title, last_visit_date, visit_count FROM moz_places LIMIT 100"
                } else {
                    "SELECT url, title, last_visit_time, visit_count FROM urls LIMIT 100"
                };
                if let Ok(mut stmt) = conn.prepare(query) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        let url: String = row.get(0).unwrap_or_default();
                        let title: Option<String> = row.get(1).ok();
                        let visit_time: Option<i64> = row.get(2).ok();
                        let count: Option<u32> = row.get(3).ok();
                        Ok((url, title, visit_time, count))
                    }) {
                        for row in rows.flatten() {
                            let (url, title, visit_time, count) = row;
                            let ts = visit_time.and_then(|t| {
                                let secs = (t / 1000000) - 11644473600i64;
                                chrono::DateTime::from_timestamp(secs, 0)
                                    .map(|d| d.to_rfc3339())
                            });
                            entries.push(BrowserEntry {
                                url: Some(url),
                                title,
                                visit_time: ts,
                                visit_count: count,
                                typed_count: None,
                                last_visit: None,
                                username: None,
                                password: None,
                                cookie_name: None,
                                cookie_value: None,
                                cookie_domain: None,
                                cookie_expiry: None,
                                download_path: None,
                                download_url: None,
                                download_size: None,
                                download_mime: None,
                            });
                        }
                    }
                }
            }
        }
        Ok(entries)
    }

    fn parse_sqlite_cookies(db_path: &str) -> Result<Vec<BrowserEntry>, ForensicsError> {
        let mut entries = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(db_path) {
            let query = "SELECT name, value, host_key, expires_utc FROM cookies LIMIT 100";
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    let name: String = row.get(0).unwrap_or_default();
                    let value: String = row.get(1).unwrap_or_default();
                    let domain: String = row.get(2).unwrap_or_default();
                    let expires: Option<i64> = row.get(3).ok();
                    Ok((name, value, domain, expires))
                }) {
                    for row in rows.flatten() {
                        let (name, value, domain, expires) = row;
                        let expiry = expires.and_then(|t| {
                            let secs = (t / 1000000) - 11644473600i64;
                            chrono::DateTime::from_timestamp(secs, 0)
                                .map(|d| d.to_rfc3339())
                        });
                        entries.push(BrowserEntry {
                            url: None,
                            title: None,
                            visit_time: None,
                            visit_count: None,
                            typed_count: None,
                            last_visit: None,
                            username: None,
                            password: None,
                            cookie_name: Some(name),
                            cookie_value: Some(value),
                            cookie_domain: Some(domain),
                            cookie_expiry: expiry,
                            download_path: None,
                            download_url: None,
                            download_size: None,
                            download_mime: None,
                        });
                    }
                }
            }
        }
        Ok(entries)
    }

    fn parse_sqlite_downloads(db_path: &str) -> Result<Vec<BrowserEntry>, ForensicsError> {
        let mut entries = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(db_path) {
            let query = "SELECT target_path, source_url, total_bytes, mime_type FROM downloads LIMIT 100";
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    let target: String = row.get(0).unwrap_or_default();
                    let url: String = row.get(1).unwrap_or_default();
                    let size: Option<u64> = row.get(2).ok();
                    let mime: Option<String> = row.get(3).ok();
                    Ok((target, url, size, mime))
                }) {
                    for row in rows.flatten() {
                        let (target, url, size, mime) = row;
                        entries.push(BrowserEntry {
                            url: None,
                            title: None,
                            visit_time: None,
                            visit_count: None,
                            typed_count: None,
                            last_visit: None,
                            username: None,
                            password: None,
                            cookie_name: None,
                            cookie_value: None,
                            cookie_domain: None,
                            cookie_expiry: None,
                            download_path: Some(target),
                            download_url: Some(url),
                            download_size: size,
                            download_mime: mime,
                        });
                    }
                }
            }
        }
        Ok(entries)
    }

    fn parse_login_data(db_path: &str) -> Result<Vec<BrowserCredential>, ForensicsError> {
        let mut credentials = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(db_path) {
            let tables: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")
                .ok()
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| row.get(0)).ok()
                        .map(|rows| rows.flatten().collect())
                })
                .unwrap_or_default();

            let query = if tables.contains(&"logins".to_string()) {
                "SELECT hostname, encryptedUsername, encryptedPassword FROM logins LIMIT 100"
            } else {
                "SELECT origin_url, username_value, password_value FROM logins LIMIT 100"
            };
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    let url: String = row.get(0).unwrap_or_default();
                    let user: String = row.get(1).unwrap_or_default();
                    let pass: String = row.get(2).unwrap_or_default();
                    Ok((url, user, pass))
                }) {
                    for row in rows.flatten() {
                        let (url, user, pass) = row;
                        credentials.push(BrowserCredential {
                            browser: "unknown".to_string(),
                            url,
                            username: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, user.as_bytes()),
                            password: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pass.as_bytes()),
                            created: None,
                            last_used: None,
                        });
                    }
                }
            }
        }
        Ok(credentials)
    }

    fn parse_history_json(browser_path: &str) -> Vec<BrowserEntry> {
        let mut entries = Vec::new();
        let path = Path::new(browser_path);
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(json) = serde_json::from_str::<Vec<HashMap<String, serde_json::Value>>>(&content) {
                    for item in json {
                        entries.push(BrowserEntry {
                            url: item.get("url").and_then(|v| v.as_str().map(String::from)),
                            title: item.get("title").and_then(|v| v.as_str().map(String::from)),
                            visit_time: item.get("visit_time").and_then(|v| v.as_str().map(String::from)),
                            visit_count: item.get("visit_count").and_then(|v| v.as_u64().map(|n| n as u32)),
                            typed_count: None,
                            last_visit: None,
                            username: None,
                            password: None,
                            cookie_name: None,
                            cookie_value: None,
                            cookie_domain: None,
                            cookie_expiry: None,
                            download_path: None,
                            download_url: None,
                            download_size: None,
                            download_mime: None,
                        });
                    }
                }
            }
        }
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_browser() {
        assert_eq!(BrowserForensics::detect_browser("/home/user/.config/google-chrome"), "chrome");
        assert_eq!(BrowserForensics::detect_browser("/home/user/.mozilla/firefox"), "firefox");
        assert_eq!(BrowserForensics::detect_browser("/home/user/.config/opera"), "chromium");
        assert_eq!(BrowserForensics::detect_browser("/random/path"), "unknown");
    }

    #[test]
    fn test_find_sqlite_files_nonexistent() {
        let files = BrowserForensics::find_sqlite_files("/nonexistent/path", &["history"]);
        assert!(files.is_empty());
    }

    #[test]
    fn test_analyze_history_nonexistent() {
        let result = BrowserForensics::analyze_history("/nonexistent/browser/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_cookies_nonexistent() {
        let result = BrowserForensics::analyze_cookies("/nonexistent/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_browser_entry() {
        let entry = BrowserEntry {
            url: Some("https://example.com".to_string()),
            title: Some("Example".to_string()),
            visit_time: Some("2026-01-15T10:00:00Z".to_string()),
            visit_count: Some(5),
            typed_count: None,
            last_visit: None,
            username: None,
            password: None,
            cookie_name: None,
            cookie_value: None,
            cookie_domain: None,
            cookie_expiry: None,
            download_path: None,
            download_url: None,
            download_size: None,
            download_mime: None,
        };
        assert_eq!(entry.url.unwrap(), "https://example.com");
    }

    #[test]
    fn test_browser_artifact() {
        let artifact = BrowserArtifact {
            browser_type: "chrome".to_string(),
            artifact_type: "history".to_string(),
            source_path: "/path/to/history".to_string(),
            entries: vec![],
            total_entries: 0,
        };
        let json = serde_json::to_string_pretty(&artifact).unwrap();
        assert!(json.contains("chrome"));
    }

    #[test]
    fn test_browser_credential() {
        let cred = BrowserCredential {
            browser: "chrome".to_string(),
            url: "https://login.example.com".to_string(),
            username: "dXNlcg==".to_string(),
            password: "cGFzcw==".to_string(),
            created: None,
            last_used: None,
        };
        assert_eq!(cred.url, "https://login.example.com");
    }

    #[test]
    fn test_parse_history_json_invalid() {
        let tmp = std::env::temp_dir().join("bad_history.json");
        std::fs::write(&tmp, "not json").unwrap();
        let entries = BrowserForensics::parse_history_json(tmp.to_str().unwrap());
        assert!(entries.is_empty());
        std::fs::remove_file(&tmp).ok();
    }
}
