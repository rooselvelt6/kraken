use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkLogEntry {
    pub timestamp: String,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: String,
    pub length: usize,
    pub info: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkCaptureInfo {
    pub file_path: String,
    pub file_size: u64,
    pub format: String,
    pub packet_count: usize,
    pub entries: Vec<NetworkLogEntry>,
    pub unique_ips: Vec<String>,
    pub unique_ports: Vec<u16>,
    pub protocols: HashMap<String, usize>,
    pub suspicious_connections: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsQuery {
    pub timestamp: String,
    pub query: String,
    pub query_type: String,
    pub response: Option<String>,
    pub response_code: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionInfo {
    pub timestamp: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

pub struct NetworkForensics;

impl NetworkForensics {
    pub fn new() -> Self {
        NetworkForensics
    }

    pub fn analyze_capture(path: &str) -> Result<NetworkCaptureInfo, String> {
        let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;
        let format = Self::detect_format(&data, path);

        let (entries, packet_count) = match format.as_str() {
            "pcap" => Self::parse_pcap(&data),
            "pcapng" => Self::parse_pcapng(&data),
            "pcap_stream" => Self::parse_pcap_stream(&data),
            _ => Self::parse_text_log(&data),
        };

        let unique_ips = Self::extract_unique_ips(&entries);
        let unique_ports = Self::extract_unique_ports(&entries);
        let protocols = Self::count_protocols(&entries);
        let suspicious_connections = Self::detect_suspicious(&entries);

        Ok(NetworkCaptureInfo {
            file_path: path.to_string(),
            file_size: data.len() as u64,
            format,
            packet_count,
            entries,
            unique_ips,
            unique_ports,
            protocols,
            suspicious_connections,
        })
    }

    pub fn analyze_pcap(data: &[u8]) -> NetworkCaptureInfo {
        let (entries, packet_count) = Self::parse_pcap(data);
        let unique_ips = Self::extract_unique_ips(&entries);
        let unique_ports = Self::extract_unique_ports(&entries);
        let protocols = Self::count_protocols(&entries);
        let suspicious_connections = Self::detect_suspicious(&entries);

        NetworkCaptureInfo {
            file_path: "stream".to_string(),
            file_size: data.len() as u64,
            format: "pcap".to_string(),
            packet_count,
            entries,
            unique_ips,
            unique_ports,
            protocols,
            suspicious_connections,
        }
    }

    pub fn extract_connections(data: &[u8]) -> Vec<ConnectionInfo> {
        let mut connections = Vec::new();
        let text = String::from_utf8_lossy(data);

        if let Ok(entries) = serde_json::from_str::<Vec<NetworkLogEntry>>(&text) {
            for entry in entries {
                if let (Some(src), Some(dst), Some(sp), Some(dp)) =
                    (entry.source_ip, entry.dest_ip, entry.source_port, entry.dest_port)
                {
                    connections.push(ConnectionInfo {
                        timestamp: entry.timestamp,
                        protocol: entry.protocol,
                        local_addr: src.clone(),
                        local_port: sp,
                        remote_addr: dst.clone(),
                        remote_port: dp,
                        state: "established".to_string(),
                        pid: None,
                        process_name: None,
                    });
                }
            }
        }
        connections
    }

    pub fn parse_dns(data: &[u8]) -> Vec<DnsQuery> {
        let mut queries = Vec::new();
        let text = String::from_utf8_lossy(&data);
        let re = regex::Regex::new(r"(?i)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}").ok();

        if let Some(re) = re {
            let now = chrono::Utc::now().to_rfc3339();
            for cap in re.find_iter(&text) {
                let query = cap.as_str().to_string();
                if query.len() > 4 {
                    queries.push(DnsQuery {
                        timestamp: now.clone(),
                        query,
                        query_type: "A".to_string(),
                        response: None,
                        response_code: "NOERROR".to_string(),
                    });
                }
            }
        }
        queries
    }

    fn detect_format(data: &[u8], path: &str) -> String {
        if data.starts_with(b"\xd4\xc3\xb2\xa1") || data.starts_with(b"\xa1\xb2\xc3\xd4") {
            return "pcap".to_string();
        }
        if data.starts_with(b"\x0a\x0d\x0d\x0a") {
            return "pcapng".to_string();
        }
        if data.len() > 24 && data[0..4] == [0xa1, 0xb2, 0xc3, 0xd4] {
            return "pcap".to_string();
        }
        if path.ends_with(".pcap") || path.ends_with(".cap") {
            return "pcap".to_string();
        }
        if path.ends_with(".pcapng") {
            return "pcapng".to_string();
        }
        "text".to_string()
    }

    fn parse_pcap(data: &[u8]) -> (Vec<NetworkLogEntry>, usize) {
        let mut entries = Vec::new();
        if data.len() < 24 { return (entries, 0); }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let swap = magic == 0xd4c3b2a1;
        let _ = swap;

        let packet_count = data.len() / 100;
        let mut offset = 24;

        let re = regex::Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").ok();

        for _ in 0..packet_count.min(200) {
            if offset + 16 > data.len() { break; }

            let incl_len = u32::from_le_bytes([
                data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]
            ]) as usize;

            offset += 16;
            if offset + incl_len > data.len() { break; }

            let pkt = &data[offset..offset + incl_len];
            offset += incl_len;

            if let Some(ref re) = re {
                if let Ok(text) = std::str::from_utf8(pkt) {
                    if let Some(_ip_match) = re.find(text) {
                        let ips: Vec<&str> = text.split_whitespace()
                            .filter(|w| re.is_match(w))
                            .collect();

                        let (src_ip, dst_ip) = if ips.len() >= 2 {
                            (Some(ips[0].to_string()), Some(ips[1].to_string()))
                        } else if ips.len() == 1 {
                            (Some(ips[0].to_string()), None)
                        } else {
                            (None, None)
                        };

                        let protocol = if text.contains("TCP") || text.contains("tcp") {
                            "TCP"
                        } else if text.contains("UDP") || text.contains("udp") {
                            "UDP"
                        } else if text.contains("ICMP") || text.contains("icmp") {
                            "ICMP"
                        } else if text.contains("HTTP") || text.contains("http") {
                            "HTTP"
                        } else if text.contains("DNS") || text.contains("dns") {
                            "DNS"
                        } else {
                            "IP"
                        };

                        entries.push(NetworkLogEntry {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            source_ip: src_ip,
                            dest_ip: dst_ip,
                            source_port: None,
                            dest_port: None,
                            protocol: protocol.to_string(),
                            length: incl_len,
                            info: text.chars().take(80).collect(),
                            flags: vec![],
                        });
                    }
                }
            }
        }

        (entries, packet_count)
    }

    fn parse_pcapng(data: &[u8]) -> (Vec<NetworkLogEntry>, usize) {
        Self::parse_pcap(data)
    }

    fn parse_pcap_stream(data: &[u8]) -> (Vec<NetworkLogEntry>, usize) {
        Self::parse_pcap(data)
    }

    fn parse_text_log(data: &[u8]) -> (Vec<NetworkLogEntry>, usize) {
        let mut entries = Vec::new();
        let text = String::from_utf8_lossy(data);

        let re = regex::Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").ok();
        let port_re = regex::Regex::new(r":(\d{1,5})").ok();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }

            let ips: Vec<String> = re.as_ref()
                .map(|r| r.find_iter(trimmed).map(|m| m.as_str().to_string()).collect())
                .unwrap_or_default();

            let ports: Vec<u16> = port_re.as_ref()
                .map(|r| {
                    r.captures_iter(trimmed)
                        .filter_map(|c| c[1].parse().ok())
                        .collect()
                })
                .unwrap_or_default();

            let (src_ip, dst_ip) = if ips.len() >= 2 {
                (Some(ips[0].clone()), Some(ips[1].clone()))
            } else if ips.len() == 1 {
                (Some(ips[0].clone()), None)
            } else {
                (None, None)
            };

            let (src_port, dst_port) = if ports.len() >= 2 {
                (Some(ports[0]), Some(ports[1]))
            } else if ports.len() == 1 {
                (Some(ports[0]), None)
            } else {
                (None, None)
            };

            let protocol = if trimmed.contains("TCP") || trimmed.contains("SYN") {
                "TCP"
            } else if trimmed.contains("UDP") {
                "UDP"
            } else if trimmed.contains("ICMP") || trimmed.contains("ping") {
                "ICMP"
            } else if trimmed.contains("HTTP") || trimmed.contains("GET") || trimmed.contains("POST") {
                "HTTP"
            } else if trimmed.contains("DNS") {
                "DNS"
            } else if trimmed.contains("TLS") || trimmed.contains("SSL") {
                "TLS"
            } else if trimmed.contains("HTTPS") {
                "HTTPS"
            } else {
                "IP"
            };

            entries.push(NetworkLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source_ip: src_ip,
                dest_ip: dst_ip,
                source_port: src_port,
                dest_port: dst_port,
                protocol: protocol.to_string(),
                length: trimmed.len(),
                info: trimmed.chars().take(80).collect(),
                flags: vec![],
            });
        }

        let count = entries.len();
        (entries, count)
    }

    fn extract_unique_ips(entries: &[NetworkLogEntry]) -> Vec<String> {
        let mut ips = Vec::new();
        for entry in entries {
            if let Some(ref ip) = entry.source_ip {
                ips.push(ip.clone());
            }
            if let Some(ref ip) = entry.dest_ip {
                ips.push(ip.clone());
            }
        }
        ips.sort();
        ips.dedup();
        ips
    }

    fn extract_unique_ports(entries: &[NetworkLogEntry]) -> Vec<u16> {
        let mut ports: Vec<u16> = entries.iter()
            .filter_map(|e| e.source_port.or(e.dest_port))
            .collect();
        ports.sort();
        ports.dedup();
        ports
    }

    fn count_protocols(entries: &[NetworkLogEntry]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for entry in entries {
            *counts.entry(entry.protocol.clone()).or_default() += 1;
        }
        counts
    }

    fn detect_suspicious(entries: &[NetworkLogEntry]) -> Vec<String> {
        let mut alerts = Vec::new();

        let high_ports: Vec<u16> = entries.iter()
            .filter_map(|e| e.dest_port)
            .filter(|&p| p < 1024 && p != 80 && p != 443 && p != 53)
            .collect();
        if !high_ports.is_empty() {
            alerts.push(format!("Connections to privileged ports: {:?}", high_ports));
        }

        let port_counts: HashMap<u16, usize> = entries.iter()
            .filter_map(|e| e.dest_port)
            .fold(HashMap::new(), |mut acc, p| {
                *acc.entry(p).or_default() += 1;
                acc
            });
        for (&port, &count) in &port_counts {
            if count > 100 {
                alerts.push(format!("Port scan detected on port {}: {} connections", port, count));
            }
        }

        let ip_counts: HashMap<&str, usize> = entries.iter()
            .filter_map(|e| e.source_ip.as_deref())
            .fold(HashMap::new(), |mut acc, ip| {
                *acc.entry(ip).or_default() += 1;
                acc
            });
        for (ip, &count) in &ip_counts {
            if count > 50 {
                alerts.push(format!("High traffic from {}: {} packets", ip, count));
            }
        }

        let private_ranges = ["10.", "172.16.", "192.168.", "169.254."];
        let external_ips: Vec<&str> = entries.iter()
            .filter_map(|e| e.dest_ip.as_deref())
            .filter(|ip| !private_ranges.iter().any(|r| ip.starts_with(r)) && !ip.starts_with("127."))
            .collect();
        if !external_ips.is_empty() {
            alerts.push(format!("External connections: {:?}", &external_ips[..external_ips.len().min(5)]));
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format_pcap() {
        let data = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00";
        let detected = NetworkForensics::detect_format(data, "test.pcap");
        assert!(detected == "pcap");
    }

    #[test]
    fn test_detect_format_text() {
        let data = b"192.168.1.1:80 10.0.0.1:443 TCP";
        let detected = NetworkForensics::detect_format(data, "test.log");
        assert_eq!(detected, "text");
    }

    #[test]
    fn test_parse_text_log() {
        let data = b"192.168.1.1:8080 10.0.0.1:443 TCP SYN\n192.168.1.2:53 8.8.8.8:53 DNS query\n";
        let (entries, _) = NetworkForensics::parse_text_log(data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].source_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(entries[0].protocol, "TCP");
    }

    #[test]
    fn test_parse_text_log_http() {
        let data = b"GET /index.html HTTP/1.1";
        let (entries, _) = NetworkForensics::parse_text_log(data);
        assert!(!entries.is_empty());
        assert_eq!(entries[0].protocol, "HTTP");
    }

    #[test]
    fn test_extract_unique_ips() {
        let entries = vec![
            NetworkLogEntry {
                timestamp: String::new(), source_ip: Some("10.0.0.1".to_string()),
                dest_ip: Some("10.0.0.2".to_string()), source_port: None, dest_port: None,
                protocol: "TCP".to_string(), length: 0, info: String::new(), flags: vec![],
            },
            NetworkLogEntry {
                timestamp: String::new(), source_ip: Some("10.0.0.1".to_string()),
                dest_ip: Some("10.0.0.3".to_string()), source_port: None, dest_port: None,
                protocol: "UDP".to_string(), length: 0, info: String::new(), flags: vec![],
            },
        ];
        let ips = NetworkForensics::extract_unique_ips(&entries);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn test_count_protocols() {
        let entries = vec![
            NetworkLogEntry {
                timestamp: String::new(), source_ip: None, dest_ip: None,
                source_port: None, dest_port: None,
                protocol: "TCP".to_string(), length: 0, info: String::new(), flags: vec![],
            },
            NetworkLogEntry {
                timestamp: String::new(), source_ip: None, dest_ip: None,
                source_port: None, dest_port: None,
                protocol: "TCP".to_string(), length: 0, info: String::new(), flags: vec![],
            },
            NetworkLogEntry {
                timestamp: String::new(), source_ip: None, dest_ip: None,
                source_port: None, dest_port: None,
                protocol: "UDP".to_string(), length: 0, info: String::new(), flags: vec![],
            },
        ];
        let counts = NetworkForensics::count_protocols(&entries);
        assert_eq!(counts.get("TCP").unwrap(), &2);
        assert_eq!(counts.get("UDP").unwrap(), &1);
    }

    #[test]
    fn test_parse_dns() {
        let data = b"Query: example.com Type: A Response: 93.184.216.34";
        let queries = NetworkForensics::parse_dns(data);
        assert!(!queries.is_empty());
        assert!(queries.iter().any(|q| q.query == "example.com"));
    }

    #[test]
    fn test_capture_info() {
        let info = NetworkCaptureInfo {
            file_path: "capture.pcap".to_string(),
            file_size: 1024,
            format: "pcap".to_string(),
            packet_count: 10,
            entries: vec![],
            unique_ips: vec!["10.0.0.1".to_string()],
            unique_ports: vec![80, 443],
            protocols: HashMap::from([("TCP".to_string(), 5), ("UDP".to_string(), 3)]),
            suspicious_connections: vec!["High traffic".to_string()],
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("capture.pcap"));
        assert!(json.contains("10.0.0.1"));
    }

    #[test]
    fn test_connection_info() {
        let conn = ConnectionInfo {
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            protocol: "TCP".to_string(),
            local_addr: "192.168.1.1".to_string(),
            local_port: 12345,
            remote_addr: "93.184.216.34".to_string(),
            remote_port: 443,
            state: "ESTABLISHED".to_string(),
            pid: Some(1234),
            process_name: Some("chrome".to_string()),
        };
        assert_eq!(conn.remote_port, 443);
    }

    #[test]
    fn test_extract_connections() {
        let entries = vec![
            NetworkLogEntry {
                timestamp: "now".to_string(),
                source_ip: Some("10.0.0.1".to_string()),
                dest_ip: Some("10.0.0.2".to_string()),
                source_port: Some(12345),
                dest_port: Some(80),
                protocol: "TCP".to_string(),
                length: 100,
                info: String::new(),
                flags: vec![],
            }
        ];
        let json = serde_json::to_string(&entries).unwrap();
        let connections = NetworkForensics::extract_connections(json.as_bytes());
        assert_eq!(connections.len(), 1);
    }

    #[test]
    fn test_nonexistent_capture() {
        let result = NetworkForensics::analyze_capture("/nonexistent/capture.pcap");
        assert!(result.is_err());
    }
}
