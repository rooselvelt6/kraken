use crate::dissectors::{self, DnsMessage, HttpRequest, HttpResponse};
use crate::packet::{parse_packet, PacketInfo};
use kraken_errors::NetworkError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PcapAnalysis {
    pub file_path: String,
    pub total_packets: usize,
    pub duration_secs: f64,
    pub protocols: HashMap<String, usize>,
    pub conversations: Vec<Conversation>,
    pub http_requests: Vec<HttpRequest>,
    pub http_responses: Vec<HttpResponse>,
    pub dns_queries: Vec<DnsMessage>,
    pub top_talkers: Vec<(String, usize)>,
    pub port_stats: HashMap<u16, usize>,
    pub ipv4_packets: usize,
    pub ipv6_packets: usize,
    pub arp_packets: usize,
    pub tcp_packets: usize,
    pub udp_packets: usize,
    pub icmp_packets: usize,
    pub total_bytes: u64,
    pub avg_packet_size: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packets: usize,
    pub bytes: u64,
}

pub struct PcapAnalyzer {
    pub analysis: PcapAnalysis,
    pub packets: Vec<PacketInfo>,
}

impl Default for PcapAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapAnalyzer {
    pub fn new() -> Self {
        PcapAnalyzer {
            analysis: PcapAnalysis::default(),
            packets: Vec::new(),
        }
    }

    pub fn analyze_file<P: AsRef<Path>>(&mut self, path: P) -> Result<&PcapAnalysis, NetworkError> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        self.analysis.file_path = path_str.clone();

        let cap = pcap::Capture::from_file(path)
            .map_err(|e| NetworkError::Other(format!("Cannot open pcap: {}", e)))?;

        let mut cap = cap;
        let mut first_ts = None;
        let mut last_ts = None;

        while let Ok(pkt) = cap.next_packet() {
            let info = parse_packet(pkt.data, pkt.header.len as usize);

            if first_ts.is_none() {
                first_ts = Some(pkt.header.ts.tv_sec as f64 + pkt.header.ts.tv_usec as f64 / 1_000_000.0);
            }
            last_ts = Some(pkt.header.ts.tv_sec as f64 + pkt.header.ts.tv_usec as f64 / 1_000_000.0);

            self.analysis.total_packets += 1;
            self.analysis.total_bytes += pkt.header.len as u64;

            let proto = info.protocol_name.clone();
            *self.analysis.protocols.entry(proto.clone()).or_insert(0) += 1;

            match proto.as_str() {
                "TCP" | "HTTP" | "SSH" | "FTP" | "SMTP" | "POP3" | "IMAP" | "HTTPS" => {
                    self.analysis.tcp_packets += 1;
                }
                "UDP" | "DNS" | "DHCP" | "SNMP" | "NTP" => {
                    self.analysis.udp_packets += 1;
                }
                "ICMP" => {
                    self.analysis.icmp_packets += 1;
                }
                "ARP" => {
                    self.analysis.arp_packets += 1;
                }
                "IPv6" => {
                    self.analysis.ipv6_packets += 1;
                }
                _ => {
                    if info.protocol == Some(6) {
                        self.analysis.tcp_packets += 1;
                    }
                }
            }

            if info.protocol == Some(6) || info.protocol == Some(17) {
                if let Some(port) = info.src_port.or(info.dst_port) {
                    *self.analysis.port_stats.entry(port).or_insert(0) += 1;
                }
            }

            let proto_name = info.protocol_name.clone();
            let src_ip = info.src_ip.clone().unwrap_or_default();
            let dst_ip = info.dst_ip.clone().unwrap_or_default();
            let src_port = info.src_port.unwrap_or(0);
            let dst_port = info.dst_port.unwrap_or(0);

            let existing = self.analysis.conversations.iter_mut()
                .find(|c: &&mut Conversation| {
                    (c.src_ip == src_ip && c.dst_ip == dst_ip && c.src_port == src_port && c.dst_port == dst_port)
                    || (c.src_ip == dst_ip && c.dst_ip == src_ip && c.src_port == dst_port && c.dst_port == src_port)
                });

            match existing {
                Some(conv) => {
                    conv.packets += 1;
                    conv.bytes += pkt.header.len as u64;
                }
                None => {
                    self.analysis.conversations.push(Conversation {
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        src_port,
                        dst_port,
                        protocol: proto_name,
                        packets: 1,
                        bytes: pkt.header.len as u64,
                    });
                }
            }

            if info.dst_port == Some(80) || info.src_port == Some(80) {
                if let Some(req) = dissectors::dissect_http_request(&info.payload) {
                    self.analysis.http_requests.push(req);
                }
                if let Some(resp) = dissectors::dissect_http_response(&info.payload) {
                    self.analysis.http_responses.push(resp);
                }
            }

            if info.dst_port == Some(53) || info.src_port == Some(53) {
                if let Some(dns) = dissectors::dissect_dns(&info.payload) {
                    self.analysis.dns_queries.push(dns);
                }
            }

            self.packets.push(info);
        }

        if let (Some(first), Some(last)) = (first_ts, last_ts) {
            self.analysis.duration_secs = last - first;
        }

        if self.analysis.total_packets > 0 {
            self.analysis.avg_packet_size = self.analysis.total_bytes as f64 / self.analysis.total_packets as f64;
        }

        let mut talkers: HashMap<String, usize> = HashMap::new();
        for pkt in &self.packets {
            if let Some(ref ip) = pkt.src_ip {
                *talkers.entry(ip.clone()).or_insert(0) += 1;
            }
            if let Some(ref ip) = pkt.dst_ip {
                *talkers.entry(ip.clone()).or_insert(0) += 1;
            }
        }
        let mut talkers_vec: Vec<(String, usize)> = talkers.into_iter().collect();
        talkers_vec.sort_by_key(|x| std::cmp::Reverse(x.1));
        self.analysis.top_talkers = talkers_vec.into_iter().take(10).collect();

        Ok(&self.analysis)
    }

    pub fn get_packets(&self) -> &[PacketInfo] {
        &self.packets
    }

    pub fn filter_protocol(&self, protocol: &str) -> Vec<&PacketInfo> {
        self.packets.iter().filter(|p| p.protocol_name == protocol).collect()
    }

    pub fn filter_ip(&self, ip: &str) -> Vec<&PacketInfo> {
        self.packets.iter().filter(|p| {
            p.src_ip.as_deref() == Some(ip) || p.dst_ip.as_deref() == Some(ip)
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_new() {
        let analyzer = PcapAnalyzer::new();
        assert_eq!(analyzer.analysis.total_packets, 0);
    }

    #[test]
    fn test_nonexistent_pcap() {
        let mut analyzer = PcapAnalyzer::new();
        let result = analyzer.analyze_file("/tmp/nonexistent.pcap");
        assert!(result.is_err());
    }

    #[test]
    fn test_analysis_defaults() {
        let analysis = PcapAnalysis::default();
        assert_eq!(analysis.total_packets, 0);
        assert!(analysis.protocols.is_empty());
    }

    #[test]
    fn test_filter_empty() {
        let analyzer = PcapAnalyzer::new();
        assert!(analyzer.filter_protocol("HTTP").is_empty());
        assert!(analyzer.filter_ip("1.2.3.4").is_empty());
    }

    #[test]
    fn test_create_pcap_from_packets() {
        let mut analyzer = PcapAnalyzer::new();
        let pkt = PacketInfo::default();
        analyzer.packets.push(pkt);
        assert_eq!(analyzer.packets.len(), 1);
    }

    #[test]
    fn test_conversation_dedup() {
        let mut analysis = PcapAnalysis::default();
        analysis.conversations.push(Conversation {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP".to_string(),
            packets: 1,
            bytes: 100,
        });
        assert_eq!(analysis.conversations.len(), 1);
    }
}
