use crate::packet::{DnsHeader, parse_dns_questions};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub host: Option<String>,
    pub cookie: Option<String>,
    pub user_agent: Option<String>,
    pub authorization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub set_cookie: Option<String>,
    pub location: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<String>,
    pub answers: Vec<DnsRecord>,
    pub transaction_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpMessage {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: String,
    pub yiaddr: String,
    pub siaddr: String,
    pub giaddr: String,
    pub chaddr: String,
    pub message_type: String,
    pub options: HashMap<u8, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpMessage {
    pub type_code: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: Vec<u8>,
}

pub fn dissect_http_request(data: &[u8]) -> Option<HttpRequest> {
    let text = String::from_utf8_lossy(data);
    let parts: Vec<&str> = text.splitn(2, "\r\n\r\n").collect();
    if parts.len() < 2 { return None; }
    let header_part = parts.first()?;
    let body = parts.get(1).unwrap_or(&"").to_string();

    let lines: Vec<&str> = header_part.lines().collect();
    let request_line = lines.first()?;
    let req_parts: Vec<&str> = request_line.split_whitespace().collect();
    if req_parts.len() < 3 { return None; }

    let mut req = HttpRequest {
        method: req_parts[0].to_string(),
        uri: req_parts[1].to_string(),
        version: req_parts[2].to_string(),
        headers: Vec::new(),
        body,
        host: None,
        cookie: None,
        user_agent: None,
        authorization: None,
    };

    for line in lines.iter().skip(1) {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_string();
            let value = line[idx + 1..].trim().to_string();
            req.headers.push((key.clone(), value.clone()));
            match key.to_lowercase().as_str() {
                "host" => req.host = Some(value),
                "cookie" => req.cookie = Some(value),
                "user-agent" => req.user_agent = Some(value),
                "authorization" => req.authorization = Some(value),
                _ => {}
            }
        }
    }

    Some(req)
}

pub fn dissect_http_response(data: &[u8]) -> Option<HttpResponse> {
    let text = String::from_utf8_lossy(data);
    let parts: Vec<&str> = text.splitn(2, "\r\n\r\n").collect();
    let header_part = parts.first()?;
    let body = parts.get(1).unwrap_or(&"").to_string();

    let lines: Vec<&str> = header_part.lines().collect();
    let status_line = lines.first()?;
    let status_parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if status_parts.len() < 2 { return None; }

    let mut resp = HttpResponse {
        version: status_parts[0].to_string(),
        status_code: status_parts[1].parse().unwrap_or(0),
        reason: status_parts.get(2).unwrap_or(&"").to_string(),
        headers: Vec::new(),
        body,
        set_cookie: None,
        location: None,
        content_type: None,
    };

    for line in lines.iter().skip(1) {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_string();
            let value = line[idx + 1..].trim().to_string();
            resp.headers.push((key.clone(), value.clone()));
            match key.to_lowercase().as_str() {
                "set-cookie" => resp.set_cookie = Some(value),
                "location" => resp.location = Some(value),
                "content-type" => resp.content_type = Some(value),
                _ => {}
            }
        }
    }

    Some(resp)
}

pub fn dissect_dns(data: &[u8]) -> Option<DnsMessage> {
    let (dns, _) = DnsHeader::parse(data)?;
    let questions = parse_dns_questions(&data[12..], dns.questions);

    let mut answers = Vec::new();
    let mut offset = 12;
    for _ in 0..dns.questions {
        let mut name_end = offset;
        loop {
            if name_end >= data.len() { return None; }
            let len = data[name_end] as usize;
            if len == 0 { name_end += 1; break; }
            if len & 0xc0 == 0xc0 { name_end += 2; break; }
            name_end += 1 + len;
        }
        offset = name_end + 4;
    }

    for _ in 0..dns.answers {
        if offset + 12 > data.len() { break; }
        let mut rname_end = offset;
        loop {
            if rname_end >= data.len() { break; }
            let len = data[rname_end] as usize;
            if len == 0 { rname_end += 1; break; }
            if len & 0xc0 == 0xc0 { rname_end += 2; break; }
            rname_end += 1 + len;
        }
        if rname_end + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[rname_end], data[rname_end + 1]]);
        let rclass = u16::from_be_bytes([data[rname_end + 2], data[rname_end + 3]]);
        let ttl = u32::from_be_bytes([data[rname_end + 4], data[rname_end + 5], data[rname_end + 6], data[rname_end + 7]]);
        let rdlength = u16::from_be_bytes([data[rname_end + 8], data[rname_end + 9]]) as usize;
        if rname_end + 10 + rdlength > data.len() { break; }

        let rdata = match rtype {
            1 => {
                if rdlength == 4 {
                    format!("{}.{}.{}.{}", data[rname_end + 10], data[rname_end + 11], data[rname_end + 12], data[rname_end + 13])
                } else {
                    hex::encode(&data[rname_end + 10..rname_end + 10 + rdlength])
                }
            }
            5 | 2 | 15 => {
                let (name, _) = crate::packet::parse_dns_name(data, rname_end + 10).unwrap_or_default();
                name
            }
            16 => {
                let txt_data = &data[rname_end + 10..rname_end + 10 + rdlength];
                let mut txt = String::new();
                let mut tpos = 0;
                while tpos < txt_data.len() {
                    let tlen = txt_data[tpos] as usize;
                    tpos += 1;
                    if tpos + tlen <= txt_data.len() {
                        if !txt.is_empty() { txt.push(';'); }
                        txt.push_str(&String::from_utf8_lossy(&txt_data[tpos..tpos + tlen]));
                        tpos += tlen;
                    } else {
                        break;
                    }
                }
                txt
            }
            28 => {
                if rdlength == 16 {
                    let mut hex_str = String::new();
                    for i in 0..8 {
                        if i > 0 { hex_str.push(':'); }
                        hex_str.push_str(&hex::encode(&data[rname_end + 10 + i * 2..rname_end + 12 + i * 2]));
                    }
                    hex_str
                } else {
                    hex::encode(&data[rname_end + 10..rname_end + 10 + rdlength])
                }
            }
            _ => hex::encode(&data[rname_end + 10..rname_end + 10 + rdlength]),
        };

        answers.push(DnsRecord {
            name: String::new(),
            rtype,
            rclass,
            ttl,
            rdata,
        });
        offset = rname_end + 10 + rdlength;
    }

    Some(DnsMessage {
        id: dns.id,
        is_response: dns.is_response(),
        opcode: dns.opcode(),
        rcode: dns.rcode(),
        questions,
        answers,
        transaction_id: dns.id,
    })
}

pub fn dissect_dhcp(data: &[u8]) -> Option<DhcpMessage> {
    if data.len() < 240 { return None; }
    let op = data[0];
    let options = &data[240..];
    let mut msg_type = String::from("unknown");
    let mut parsed_opts: HashMap<u8, Vec<u8>> = HashMap::new();

    let mut i = 0;
    while i < options.len() {
        if options[i] == 255 { break; }
        if options[i] == 0 { i += 1; continue; }
        if i + 1 >= options.len() { break; }
        let opt_type = options[i];
        let opt_len = options[i + 1] as usize;
        if i + 2 + opt_len > options.len() { break; }
        if opt_type == 53 && opt_len > 0 {
            msg_type = match options[i + 2] {
                1 => "DISCOVER",
                2 => "OFFER",
                3 => "REQUEST",
                4 => "DECLINE",
                5 => "ACK",
                6 => "NAK",
                7 => "RELEASE",
                8 => "INFORM",
                _ => "UNKNOWN",
            }.to_string();
        }
        parsed_opts.insert(opt_type, options[i + 2..i + 2 + opt_len].to_vec());
        i += 2 + opt_len;
    }

    Some(DhcpMessage {
        op,
        htype: data[1],
        hlen: data[2],
        hops: data[3],
        xid: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        secs: u16::from_be_bytes([data[8], data[9]]),
        flags: u16::from_be_bytes([data[10], data[11]]),
        ciaddr: format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]),
        yiaddr: format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]),
        siaddr: format!("{}.{}.{}.{}", data[20], data[21], data[22], data[23]),
        giaddr: format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]),
        chaddr: (0..6).map(|i| format!("{:02x}", data[28 + i])).collect::<Vec<_>>().join(":"),
        message_type: msg_type,
        options: parsed_opts,
    })
}

pub fn dissect_icmp(data: &[u8]) -> Option<IcmpMessage> {
    if data.len() < 4 { return None; }
    Some(IcmpMessage {
        type_code: data[0],
        code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
        rest: data[4..].to_vec(),
    })
}

pub fn extract_credentials_from_http(data: &[u8]) -> Option<(String, String)> {
    if let Some(req) = dissect_http_request(data) {
        if let Some(auth) = &req.authorization {
            if let Some(encoded) = auth.strip_prefix("Basic ") {
                if let Ok(decoded) = base64_decode(encoded) {
                    if let Some(idx) = decoded.find(':') {
                        return Some((decoded[..idx].to_string(), decoded[idx + 1..].to_string()));
                    }
                }
            }
        }
        let body_lower = req.body.to_lowercase();
        if body_lower.contains("password") || body_lower.contains("passwd") || body_lower.contains("pwd") {
            let fields: Vec<&str> = req.body.split('&').collect();
            for field in fields {
                let kv: Vec<&str> = field.splitn(2, '=').collect();
                if kv.len() == 2 {
                    let k = kv[0].to_lowercase();
                    if k == "password" || k == "passwd" || k == "pwd" || k == "pass" {
                        let v = url_decode(kv[1]);
                        if !v.is_empty() {
                            let user = req.body.split('&')
                                .filter_map(|f| {
                                    let kv: Vec<&str> = f.splitn(2, '=').collect();
                                    if kv.len() == 2 {
                                        let k = kv[0].to_lowercase();
                                        if k == "username" || k == "user" || k == "email" || k == "login" || k == "userid" {
                                            Some(url_decode(kv[1]))
                                        } else { None }
                                    } else { None }
                                })
                                .next()
                                .unwrap_or_default();
                            return Some((user, v));
                        }
                    }
                }
            }
        }
    }
    None
}

fn base64_decode(input: &str) -> Result<String, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine.decode(input.trim()).map_err(|e| format!("Base64 decode error: {}", e))?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn url_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            '+' => result.push(' '),
            '%' => {
                let hi = chars.next().and_then(|c| c.to_digit(16)).unwrap_or(0);
                let lo = chars.next().and_then(|c| c.to_digit(16)).unwrap_or(0);
                result.push((hi as u8 * 16 + lo as u8) as char);
            }
            _ => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dissect_http_get() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let req = dissect_http_request(data).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.host, Some("example.com".to_string()));
        assert_eq!(req.user_agent, Some("test".to_string()));
    }

    #[test]
    fn test_dissect_http_post() {
        let data = b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret";
        let req = dissect_http_request(data).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.uri, "/login");
        assert_eq!(req.body, "username=admin&password=secret");
    }

    #[test]
    fn test_dissect_http_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=abc123\r\n\r\n<body>ok</body>";
        let resp = dissect_http_response(data).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.set_cookie, Some("session=abc123".to_string()));
        assert_eq!(resp.content_type, Some("text/html".to_string()));
    }

    #[test]
    fn test_dissect_dns_query() {
        let mut data = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(b"\x03www\x07example\x03com\x00");
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let dns = dissect_dns(&data).unwrap();
        assert!(!dns.is_response);
        assert_eq!(dns.questions.len(), 1);
    }

    #[test]
    fn test_dissect_dhcp_discover() {
        let mut data = vec![0x00; 240];
        data[0] = 1; // op = BOOTREQUEST
        data.extend_from_slice(&[53, 1, 1]); // DHCP DISCOVER
        data.push(255); // end
        let dhcp = dissect_dhcp(&data).unwrap();
        assert_eq!(dhcp.message_type, "DISCOVER");
    }

    #[test]
    fn test_dissect_icmp() {
        let data = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let icmp = dissect_icmp(&data).unwrap();
        assert_eq!(icmp.type_code, 8);
        assert_eq!(icmp.code, 0);
    }

    #[test]
    fn test_extract_basic_auth() {
        let data = b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
        let creds = extract_credentials_from_http(data);
        assert_eq!(creds, Some(("admin".to_string(), "secret".to_string())));
    }

    #[test]
    fn test_extract_form_creds() {
        let data = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret123";
        let creds = extract_credentials_from_http(data);
        assert_eq!(creds, Some(("admin".to_string(), "secret123".to_string())));
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world%21"), "hello world!");
    }

    #[test]
    fn test_http_response_redirect() {
        let data = b"HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\n\r\n";
        let resp = dissect_http_response(data).unwrap();
        assert_eq!(resp.status_code, 302);
        assert_eq!(resp.location, Some("https://example.com/login".to_string()));
    }

    #[test]
    fn test_dns_response() {
        let mut data = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
        data.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04");
        data.extend_from_slice(&[192, 168, 1, 1]);
        let dns = dissect_dns(&data).unwrap();
        assert!(dns.is_response);
        assert_eq!(dns.answers.len(), 1);
    }

    #[test]
    fn test_dissect_http_request_partial() {
        let data = b"GET / HTTP/1.1\r\n";
        assert!(dissect_http_request(data).is_none());
    }
}
