use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailInfo {
    pub file_path: String,
    pub file_size: u64,
    pub format: String,
    pub headers: HashMap<String, String>,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: Option<String>,
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub content_types: Vec<String>,
    pub attachments: Vec<EmailAttachment>,
    pub body_preview: String,
    pub suspicious_indicators: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub size: usize,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailAddress {
    pub address: String,
    pub name: Option<String>,
}

pub struct EmailForensics;

impl Default for EmailForensics {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailForensics {
    pub fn new() -> Self {
        EmailForensics
    }

    pub fn analyze(path: &str) -> Result<EmailInfo, String> {
        let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;

        let format = Self::detect_format(&data, path);
        let content = String::from_utf8_lossy(&data).to_string();

        let headers = Self::parse_headers(&content);
        let (from, to, cc, bcc) = Self::extract_addresses(&headers);
        let subject = headers.get("Subject").cloned();
        let date = headers.get("Date").cloned()
            .or_else(|| headers.get("Date:").cloned());
        let message_id = headers.get("Message-ID").cloned()
            .or_else(|| headers.get("Message-Id").cloned());
        let content_types = Self::extract_content_types(&content);
        let attachments = Self::extract_attachments(&content);
        let body_preview = Self::extract_body_preview(&content);
        let suspicious_indicators = Self::detect_suspicious(&content, &headers);

        Ok(EmailInfo {
            file_path: path.to_string(),
            file_size: data.len() as u64,
            format,
            headers,
            from,
            to,
            cc,
            bcc,
            subject,
            date,
            message_id,
            content_types,
            attachments,
            body_preview,
            suspicious_indicators,
        })
    }

    fn detect_format(data: &[u8], path: &str) -> String {
        let text = String::from_utf8_lossy(data);
        if text.starts_with("From ") && text.contains("Subject:") {
            return "mbox".to_string();
        }
        if text.contains("MIME-Version:") && text.contains("Content-Type:") {
            return "eml".to_string();
        }
        if path.ends_with(".msg") || path.ends_with(".MSG") {
            return "msg".to_string();
        }
        if text.starts_with("Return-Path:") || text.starts_with("Delivered-To:") {
            return "email".to_string();
        }
        "unknown".to_string()
    }

    fn parse_headers(content: &str) -> HashMap<String, String> {
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut last_key: Option<String> = None;

        for line in content.lines() {
            if line.is_empty() {
                break;
            }

            if line.starts_with(char::is_whitespace) && last_key.is_some() {
                if let Some(ref key) = last_key {
                    if let Some(val) = headers.get_mut(key) {
                        val.push(' ');
                        val.push_str(line.trim());
                    }
                }
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let k = key.trim().to_string();
                let v = value.trim().to_string();
                headers.insert(k.clone(), v);
                last_key = Some(k);
            }
        }

        headers
    }

    fn extract_addresses(headers: &HashMap<String, String>) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
        let from = Self::parse_address_field(headers.get("From").map(String::as_str).unwrap_or(""));
        let to = Self::parse_address_field(headers.get("To").map(String::as_str).unwrap_or(""));
        let cc = Self::parse_address_field(headers.get("Cc").map(String::as_str).unwrap_or(""));
        let bcc = Self::parse_address_field(headers.get("Bcc").map(String::as_str).unwrap_or(""));
        (from, to, cc, bcc)
    }

    fn parse_address_field(field: &str) -> Vec<String> {
        let mut addresses = Vec::new();
        for part in field.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() { continue; }
            if let Some((_, email)) = trimmed.split_once('<') {
                if let Some(addr) = email.split('>').next() {
                    addresses.push(addr.trim().to_string());
                }
            } else {
                addresses.push(trimmed.to_string());
            }
        }
        addresses
    }

    fn extract_content_types(content: &str) -> Vec<String> {
        let mut types = Vec::new();
        let re = regex::Regex::new(r"Content-Type:\s*([^;\n]+)").ok();
        if let Some(re) = re {
            for cap in re.captures_iter(content) {
                types.push(cap[1].trim().to_string());
            }
        }
        types
    }

    fn extract_attachments(content: &str) -> Vec<EmailAttachment> {
        let mut attachments = Vec::new();
        let boundary_re = regex::Regex::new(r#"boundary="([^"]+)""#).ok();

        if let Some(boundary_re) = boundary_re {
            if let Some(boundary) = boundary_re.captures(content) {
                let b = &boundary[1];
                let sections: Vec<&str> = content.split(&format!("--{}", b)).collect();
                for section in sections.iter().skip(1) {
                    if section.contains("Content-Disposition: attachment") || section.contains("Content-Disposition: inline") {
                        let filename = Self::extract_filename(section);
                        let content_type = Self::extract_part_content_type(section);
                        let size = section.len();
                        let encoding = if section.contains("Content-Transfer-Encoding: base64") {
                            Some("base64".to_string())
                        } else if section.contains("Content-Transfer-Encoding: quoted-printable") {
                            Some("quoted-printable".to_string())
                        } else {
                            None
                        };
                        attachments.push(EmailAttachment {
                            filename,
                            content_type,
                            size,
                            encoding,
                        });
                    }
                }
            }
        }
        attachments
    }

    fn extract_filename(section: &str) -> String {
        let re = regex::Regex::new(r#"filename[^=]*=\s*"?([^";\n]+)"#).ok();
        if let Some(re) = re {
            if let Some(cap) = re.captures(section) {
                return cap[1].to_string();
            }
        }
        "unknown".to_string()
    }

    fn extract_part_content_type(section: &str) -> String {
        let re = regex::Regex::new(r"Content-Type:\s*([^;\n]+)").ok();
        if let Some(re) = re {
            if let Some(cap) = re.captures(section) {
                return cap[1].trim().to_string();
            }
        }
        "text/plain".to_string()
    }

    fn extract_body_preview(content: &str) -> String {
        let parts: Vec<&str> = content.split("\n\n").collect();
        if parts.len() > 1 {
            parts[1..].join("\n\n")
                .chars().take(200).collect()
        } else {
            String::new()
        }
    }

    fn detect_suspicious(content: &str, headers: &HashMap<String, String>) -> Vec<String> {
        let mut indicators = Vec::new();

        let suspicious_patterns = [
            (r"\bphishing\b", "Contains phishing references"),
            (r"\bmalware\b", "Contains malware references"),
            (r"\bpassword\b", "Contains password references"),
            (r"\baccount\b.*\bverify\b", "Account verification request"),
            (r"\burgent\b", "Urgency language detected"),
            (r"\bclick here\b", "Clickbait detected"),
            (r"\bfree\b.*\bwin\b", "Free/win offer detected"),
            (r"\bbank\b.*\bdetail\b", "Bank detail request"),
        ];

        let lower = content.to_lowercase();
        for (pattern, indicator) in &suspicious_patterns {
            let re = regex::Regex::new(pattern).ok();
            if let Some(re) = re {
                if re.is_match(&lower) {
                    indicators.push(indicator.to_string());
                }
            }
        }

        if let Some(from) = headers.get("From") {
            if from.contains("=?") {
                indicators.push("Encoded From header".to_string());
            }
        }

        let spf_headers: Vec<_> = headers.keys().filter(|k| {
            let kl = k.to_lowercase();
            kl.contains("spf") || kl.contains("dkim") || kl.contains("dmarc")
        }).collect();
        if spf_headers.is_empty() {
            indicators.push("Missing authentication headers".to_string());
        }

        indicators
    }

    pub fn extract_body_text(content: &str) -> String {
        let mut body = String::new();
        let mut in_header = true;

        for line in content.lines() {
            if in_header && line.is_empty() {
                in_header = false;
                continue;
            }
            if in_header { continue; }
            if !line.trim().is_empty() && !line.starts_with("--") && !line.starts_with("Content-") {
                body.push_str(line.trim());
                body.push(' ');
            }
        }

        body.truncate(500);
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_email() -> String {
        let mut email = String::new();
        email.push_str("From: sender@example.com\n");
        email.push_str("To: recipient@example.com\n");
        email.push_str("Cc: cc@example.com\n");
        email.push_str("Subject: Test Email\n");
        email.push_str("Date: Mon, 15 Jun 2026 10:00:00 +0000\n");
        email.push_str("Message-ID: <12345@example.com>\n");
        email.push_str("MIME-Version: 1.0\n");
        email.push_str("Content-Type: multipart/mixed; boundary=\"---boundary\"\n");
        email.push_str("\n");
        email.push_str("This is the body\n");
        email.push_str("-----boundary\n");
        email.push_str("Content-Type: text/plain\n");
        email.push_str("Content-Disposition: attachment; filename=\"test.txt\"\n");
        email.push_str("\n");
        email.push_str("attachment content\n");
        email.push_str("-----boundary--\n");
        email
    }

    #[test]
    fn test_analyze_email() {
        let tmp = std::env::temp_dir().join("test.eml");
        std::fs::write(&tmp, create_test_email()).unwrap();
        let result = EmailForensics::analyze(tmp.to_str().unwrap());
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.from, vec!["sender@example.com"]);
        assert_eq!(info.subject.unwrap(), "Test Email");
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_parse_headers() {
        let content = "From: user@test.com\nTo: admin@test.com\nSubject: Hello\n\nBody";
        let headers = EmailForensics::parse_headers(content);
        assert_eq!(headers.get("From").unwrap(), "user@test.com");
        assert_eq!(headers.get("Subject").unwrap(), "Hello");
    }

    #[test]
    fn test_parse_headers_with_folding() {
        let content = "Subject: A very long\n subject line\nDate: Today\n\nBody";
        let headers = EmailForensics::parse_headers(content);
        assert_eq!(headers.get("Subject").unwrap(), "A very long subject line");
    }

    #[test]
    fn test_parse_addresses() {
        let mut headers = HashMap::new();
        headers.insert("From".to_string(), "\"Sender\" <sender@test.com>".to_string());
        headers.insert("To".to_string(), "user1@test.com, user2@test.com".to_string());
        let (from, to, _, _) = EmailForensics::extract_addresses(&headers);
        assert_eq!(from, vec!["sender@test.com"]);
        assert_eq!(to.len(), 2);
    }

    #[test]
    fn test_extract_attachments() {
        let content = create_test_email();
        let attachments = EmailForensics::extract_attachments(&content);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].filename, "test.txt");
    }

    #[test]
    fn test_detect_suspicious() {
        let headers = HashMap::new();
        let content = "Please click here to verify your account urgently";
        let indicators = EmailForensics::detect_suspicious(content, &headers);
        assert!(indicators.contains(&"Clickbait detected".to_string()));
    }

    #[test]
    fn test_detect_format_eml() {
        let data = b"MIME-Version: 1.0\nContent-Type: text/plain\nSubject: Test";
        assert_eq!(EmailForensics::detect_format(data, "test.eml"), "eml");
    }

    #[test]
    fn test_email_info() {
        let info = EmailInfo {
            file_path: "test.eml".to_string(),
            file_size: 100,
            format: "eml".to_string(),
            headers: HashMap::new(),
            from: vec!["a@b.com".to_string()],
            to: vec!["c@d.com".to_string()],
            cc: vec![],
            bcc: vec![],
            subject: Some("Test".to_string()),
            date: None,
            message_id: Some("<id@host>".to_string()),
            content_types: vec!["text/plain".to_string()],
            attachments: vec![],
            body_preview: "body".to_string(),
            suspicious_indicators: vec![],
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("a@b.com"));
    }
}
