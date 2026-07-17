use crate::dissectors;
use crate::packet::PacketInfo;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpSession {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub cookie: Option<String>,
    pub set_cookie: Option<String>,
    pub user_agent: Option<String>,
    pub auth_token: Option<String>,
    pub is_authenticated: bool,
    pub packets_count: u64,
}

pub struct SessionHunter {
    pub sessions: HashMap<String, HttpSession>,
    pub hijacked_cookies: Vec<HijackedCookie>,
}

#[derive(Debug, Clone)]
pub struct HijackedCookie {
    pub cookie: String,
    pub host: String,
    pub uri: String,
    pub src_ip: String,
    pub timestamp: String,
}

impl Default for SessionHunter {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionHunter {
    pub fn new() -> Self {
        SessionHunter {
            sessions: HashMap::new(),
            hijacked_cookies: Vec::new(),
        }
    }

    pub fn analyze(&mut self, pkt: &PacketInfo) -> Option<&HttpSession> {
        if pkt.protocol != Some(6) {
            return None;
        }
        let dst_port = pkt.dst_port.unwrap_or(0);
        if dst_port != 80 && dst_port != 8080 {
            return None;
        }

        let key = format!("{}:{}->{}:{}",
            pkt.src_ip.as_deref().unwrap_or("?"),
            pkt.src_port.unwrap_or(0),
            pkt.dst_ip.as_deref().unwrap_or("?"),
            dst_port,
        );

        let session = self.sessions.entry(key.clone()).or_insert_with(|| {
            let src_ip = pkt.src_ip.clone().unwrap_or_default();
            let dst_ip = pkt.dst_ip.clone().unwrap_or_default();
            HttpSession {
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                src_port: pkt.src_port.unwrap_or(0),
                dst_port,
                host: None,
                uri: None,
                cookie: None,
                set_cookie: None,
                user_agent: None,
                auth_token: None,
                is_authenticated: false,
                packets_count: 0,
            }
        });

        session.packets_count += 1;

        if dst_port == 80 || dst_port == 8080 {
            if let Some(req) = dissectors::dissect_http_request(&pkt.payload) {
                session.host = req.host;
                session.uri = Some(req.uri.clone());
                session.user_agent = req.user_agent;
                session.cookie = req.cookie.clone();
                session.auth_token = req.authorization.clone();

                if let Some(cookie) = &req.cookie {
                    if !self.hijacked_cookies.iter().any(|h| h.cookie == *cookie && h.host == session.host.as_deref().unwrap_or("")) {
                        self.hijacked_cookies.push(HijackedCookie {
                            cookie: cookie.clone(),
                            host: session.host.clone().unwrap_or_default(),
                            uri: req.uri.clone(),
                            src_ip: session.src_ip.clone(),
                            timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        });
                    }
                }

                if req.cookie.is_some() || req.authorization.is_some() {
                    session.is_authenticated = true;
                }
            }
        }

        if let Some(resp) = dissectors::dissect_http_response(&pkt.payload) {
            session.set_cookie = resp.set_cookie.clone();
            if let Some(cookie) = &resp.set_cookie {
                if !self.hijacked_cookies.iter().any(|h| h.cookie == *cookie && h.host == session.host.as_deref().unwrap_or("")) {
                    self.hijacked_cookies.push(HijackedCookie {
                        cookie: cookie.clone(),
                        host: session.host.clone().unwrap_or_default(),
                        uri: session.uri.clone().unwrap_or_default(),
                        src_ip: session.src_ip.clone(),
                        timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    });
                }
            }
        }

        Some(session)
    }

    pub fn hijacked_cookies(&self) -> &[HijackedCookie] {
        &self.hijacked_cookies
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn authenticated_sessions(&self) -> Vec<&HttpSession> {
        self.sessions.values().filter(|s| s.is_authenticated).collect()
    }

    pub fn clear(&mut self) {
        self.sessions.clear();
        self.hijacked_cookies.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use crate::packet::PacketInfo;

    fn make_http_pkt(cookie: Option<&str>, auth: Option<&str>) -> PacketInfo {
        let mut pkt = PacketInfo::default();
        pkt.protocol = Some(6);
        pkt.src_port = Some(54321);
        pkt.dst_port = Some(80);
        pkt.src_ip = Some("10.0.0.2".to_string());
        pkt.dst_ip = Some("93.184.216.34".to_string());

        let mut data = format!("GET /dashboard HTTP/1.1\r\nHost: example.com\r\n");
        if let Some(c) = cookie {
            data.push_str(&format!("Cookie: {}\r\n", c));
        }
        if let Some(a) = auth {
            data.push_str(&format!("Authorization: Basic {}\r\n", a));
        }
        data.push_str("\r\n");
        pkt.payload = data.into_bytes();
        pkt
    }

    #[test]
    fn test_session_hunter_new() {
        let hunter = SessionHunter::new();
        assert_eq!(hunter.session_count(), 0);
    }

    #[test]
    fn test_session_detection() {
        let mut hunter = SessionHunter::new();
        let pkt = make_http_pkt(Some("session=abc123"), None);
        hunter.analyze(&pkt);
        assert_eq!(hunter.session_count(), 1);
    }

    #[test]
    fn test_hijacked_cookie_collected() {
        let mut hunter = SessionHunter::new();
        let pkt = make_http_pkt(Some("session=abc123"), None);
        hunter.analyze(&pkt);
        assert_eq!(hunter.hijacked_cookies().len(), 1);
        assert_eq!(hunter.hijacked_cookies()[0].cookie, "session=abc123");
    }

    #[test]
    fn test_authenticated_session() {
        let mut hunter = SessionHunter::new();
        let auth = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        let pkt = make_http_pkt(None, Some(&auth));
        hunter.analyze(&pkt);
        assert_eq!(hunter.authenticated_sessions().len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut hunter = SessionHunter::new();
        let pkt = make_http_pkt(Some("test=1"), None);
        hunter.analyze(&pkt);
        assert_eq!(hunter.session_count(), 1);
        hunter.clear();
        assert_eq!(hunter.session_count(), 0);
    }

    #[test]
    fn test_non_http_ignored() {
        let mut hunter = SessionHunter::new();
        let mut pkt = PacketInfo::default();
        pkt.protocol = Some(6);
        pkt.dst_port = Some(22);
        hunter.analyze(&pkt);
        assert_eq!(hunter.session_count(), 0);
    }

    #[test]
    fn test_dedup_cookies() {
        let mut hunter = SessionHunter::new();
        let pkt1 = make_http_pkt(Some("session=abc"), None);
        let pkt2 = make_http_pkt(Some("session=abc"), None);
        hunter.analyze(&pkt1);
        hunter.analyze(&pkt2);
        assert_eq!(hunter.hijacked_cookies().len(), 1);
    }
}
