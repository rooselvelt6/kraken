use crate::dissectors;
use crate::packet::PacketInfo;

#[derive(Debug, Clone)]
pub struct CapturedCredential {
    pub timestamp: String,
    pub service: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub raw_data: Option<String>,
}

pub struct CredSniffer {
    pub credentials: Vec<CapturedCredential>,
    pub service_filters: Vec<String>,
}

impl Default for CredSniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl CredSniffer {
    pub fn new() -> Self {
        CredSniffer {
            credentials: Vec::new(),
            service_filters: vec![
                "HTTP".to_string(), "FTP".to_string(),
                "IMAP".to_string(), "POP3".to_string(),
                "SMTP".to_string(),
            ],
        }
    }

    pub fn analyze(&mut self, packet: &PacketInfo) -> Option<CapturedCredential> {
        if packet.protocol != Some(6) {
            return None;
        }

        let service = match packet.dst_port.or(packet.src_port) {
            Some(80) | Some(8080) => "HTTP",
            Some(21) => "FTP",
            Some(143) | Some(993) => "IMAP",
            Some(110) | Some(995) => "POP3",
            Some(25) | Some(587) => "SMTP",
            _ => return None,
        };

        if let Some(ref payload_str) = try_utf8(&packet.payload) {
            match service {
                "HTTP" => {
                    if let Some((user, pass)) = dissectors::extract_credentials_from_http(&packet.payload) {
                        let cred = CapturedCredential {
                            timestamp: packet.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                            service: "HTTP".to_string(),
                            src_ip: packet.src_ip.clone().unwrap_or_default(),
                            dst_ip: packet.dst_ip.clone().unwrap_or_default(),
                            src_port: packet.src_port.unwrap_or(0),
                            dst_port: packet.dst_port.unwrap_or(0),
                            username: user,
                            password: pass,
                            url: Some(payload_str.lines().next().unwrap_or("").to_string()),
                            raw_data: Some(payload_str.clone()),
                        };
                        self.credentials.push(cred.clone());
                        return Some(cred);
                    }
                }
                "FTP" => {
                    if let Some((user, pass)) = extract_ftp_creds(payload_str) {
                        let cred = CapturedCredential {
                            timestamp: packet.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                            service: "FTP".to_string(),
                            src_ip: packet.src_ip.clone().unwrap_or_default(),
                            dst_ip: packet.dst_ip.clone().unwrap_or_default(),
                            src_port: packet.src_port.unwrap_or(0),
                            dst_port: packet.dst_port.unwrap_or(0),
                            username: user,
                            password: pass,
                            url: None,
                            raw_data: Some(payload_str.clone()),
                        };
                        self.credentials.push(cred.clone());
                        return Some(cred);
                    }
                }
                "IMAP" | "POP3" | "SMTP" => {
                    if let Some((user, pass)) = extract_mail_creds(payload_str, service) {
                        let cred = CapturedCredential {
                            timestamp: packet.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                            service: service.to_string(),
                            src_ip: packet.src_ip.clone().unwrap_or_default(),
                            dst_ip: packet.dst_ip.clone().unwrap_or_default(),
                            src_port: packet.src_port.unwrap_or(0),
                            dst_port: packet.dst_port.unwrap_or(0),
                            username: user,
                            password: pass,
                            url: None,
                            raw_data: Some(payload_str.clone()),
                        };
                        self.credentials.push(cred.clone());
                        return Some(cred);
                    }
                }
                _ => {}
            }
        }

        None
    }
}

fn try_utf8(data: &[u8]) -> Option<String> {
    String::from_utf8(data.to_vec()).ok()
}

fn extract_ftp_creds(data: &str) -> Option<(String, String)> {
    let mut user = String::new();
    let mut pass = String::new();

    for line in data.lines() {
        let line = line.trim();
        if line.to_uppercase().starts_with("USER ") {
            user = line[5..].trim().to_string();
        } else if line.to_uppercase().starts_with("PASS ") {
            pass = line[5..].trim().to_string();
        }
    }

    if !user.is_empty() && !pass.is_empty() {
        Some((user, pass))
    } else {
        None
    }
}

fn extract_mail_creds(data: &str, service: &str) -> Option<(String, String)> {
    let mut user = String::new();
    let mut pass = String::new();

    match service {
        "IMAP" => {
            let re = regex::Regex::new(r"(?i)(LOGIN|AUTHENTICATE)\s+(\S+)\s+(\S+)").ok()?;
            if let Some(caps) = re.captures(data) {
                user = caps.get(2)?.as_str().trim_matches('"').to_string();
                pass = caps.get(3)?.as_str().trim_matches('"').to_string();
            }
        }
        "POP3" => {
            for line in data.lines() {
                let line = line.trim();
                if line.to_uppercase().starts_with("USER ") {
                    user = line[5..].trim().to_string();
                } else if line.to_uppercase().starts_with("PASS ") {
                    pass = line[5..].trim().to_string();
                }
            }
        }
        "SMTP" => {
            let re = regex::Regex::new(r"(?i)AUTH\s+(LOGIN|PLAIN)\s+(\S+)").ok()?;
            if let Some(caps) = re.captures(data) {
                let auth_data = caps.get(2)?.as_str();
                if let Ok(decoded) = base64_decode(auth_data) {
                    let parts: Vec<&str> = decoded.split('\0').collect();
                    if parts.len() >= 3 {
                        user = parts[1].to_string();
                        pass = parts[2].to_string();
                    }
                }
            }
        }
        _ => return None,
    }

    if !user.is_empty() && !pass.is_empty() {
        Some((user, pass))
    } else {
        None
    }
}

fn base64_decode(input: &str) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine.decode(input.trim()).map_err(|e| format!("Base64 error: {}", e))?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_http_packet(auth: &str) -> PacketInfo {
        let mut pkt = PacketInfo::default();
        pkt.protocol = Some(6);
        pkt.src_port = Some(12345);
        pkt.dst_port = Some(80);
        pkt.src_ip = Some("192.168.1.2".to_string());
        pkt.dst_ip = Some("10.0.0.1".to_string());
        pkt.payload = format!("GET / HTTP/1.1\r\nAuthorization: Basic {}\r\nHost: example.com\r\n\r\n", auth).into_bytes();
        pkt
    }

    #[test]
    fn test_ftp_creds_extract() {
        let data = "USER admin\r\nPASS secret123\r\n";
        let creds = extract_ftp_creds(data);
        assert_eq!(creds, Some(("admin".to_string(), "secret123".to_string())));
    }

    #[test]
    fn test_ftp_creds_case_insensitive() {
        let data = "user admin\r\npass secret\r\n";
        let creds = extract_ftp_creds(data);
        assert_eq!(creds, Some(("admin".to_string(), "secret".to_string())));
    }

    #[test]
    fn test_cred_sniffer_http_basic() {
        let auth = base64_encode("admin:secret");
        let pkt = make_http_packet(&auth);
        let mut sniffer = CredSniffer::new();
        let cred = sniffer.analyze(&pkt);
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "secret");
        assert_eq!(cred.service, "HTTP");
    }

    #[test]
    fn test_cred_sniffer_non_http() {
        let mut pkt = PacketInfo::default();
        pkt.protocol = Some(6);
        pkt.dst_port = Some(22);
        let mut sniffer = CredSniffer::new();
        assert!(sniffer.analyze(&pkt).is_none());
    }

    #[test]
    fn test_cred_sniffer_empty() {
        let sniffer = CredSniffer::new();
        assert!(sniffer.credentials.is_empty());
    }

    #[test]
    fn test_mail_creds_imap() {
        let data = "a001 LOGIN user@example.com mypassword\r\n";
        let creds = extract_mail_creds(data, "IMAP");
        assert_eq!(creds, Some(("user@example.com".to_string(), "mypassword".to_string())));
    }

    #[test]
    fn test_mail_creds_pop3() {
        let data = "USER testuser\r\nPASS testpass\r\n";
        let creds = extract_mail_creds(data, "POP3");
        assert_eq!(creds, Some(("testuser".to_string(), "testpass".to_string())));
    }

    fn base64_encode(input: &str) -> String {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(input)
    }
}
