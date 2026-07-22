use crate::packet::{parse_packet, PacketInfo};
use kraken_errors::NetworkError;
use pcap::{Capture, Device};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub bpf_filter: String,
    pub promisc: bool,
    pub snaplen: i32,
    pub timeout_ms: i32,
    pub max_packets: usize,
    pub buffer_size: i32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            interface: None,
            bpf_filter: String::new(),
            promisc: true,
            snaplen: 65535,
            timeout_ms: 1000,
            max_packets: 0,
            buffer_size: 1024 * 1024,
        }
    }
}

pub struct Sniffer {
    pub config: CaptureConfig,
    pub packets: Vec<PacketInfo>,
    running: Arc<AtomicBool>,
}

impl Sniffer {
    pub fn new(config: CaptureConfig) -> Self {
        Sniffer {
            config,
            packets: Vec::new(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn list_interfaces() -> Vec<Device> {
        Device::list().unwrap_or_default()
    }

    pub fn default_interface() -> Option<String> {
        Device::list().ok()?.into_iter().find(|d| !d.addresses.is_empty())
            .map(|d| d.name)
    }

    pub fn start(&mut self) -> Result<(), NetworkError> {
        let dev_name = self.config.interface.clone()
            .or_else(Self::default_interface)
            .ok_or_else(|| NetworkError::Other("No interface found".to_string()))?;

        let mut cap = Capture::from_device(dev_name.as_str())
            .map_err(|e| NetworkError::Other(format!("Device error: {}", e)))?
            .promisc(self.config.promisc)
            .snaplen(self.config.snaplen)
            .timeout(self.config.timeout_ms)
            .buffer_size(self.config.buffer_size)
            .open()
            .map_err(|e| NetworkError::Other(format!("Capture open error: {}", e)))?;

        if !self.config.bpf_filter.is_empty() {
            cap.filter(&self.config.bpf_filter, true)
                .map_err(|e| NetworkError::Protocol(format!("BPF error: {}", e)))?;
        }

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        let max_packets = self.config.max_packets;

        while running.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(pkt) => {
                    let info = parse_packet(pkt.data, pkt.header.len as usize);
                    self.packets.push(info);
                    if max_packets > 0 && self.packets.len() >= max_packets {
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    if running.load(Ordering::SeqCst) {
                        eprintln!("Capture error: {}", e);
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn start_async(&'static mut self) -> Result<(), NetworkError> {
        self.running.store(true, Ordering::SeqCst);
        thread::spawn(move || {
            let _ = self.start();
        });
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn capture_once(count: usize) -> Vec<PacketInfo> {
        let config = CaptureConfig {
            max_packets: count,
            ..Default::default()
        };
        let mut sniffer = Sniffer::new(config);
        let _ = sniffer.start();
        sniffer.packets
    }

    pub fn capture_with_filter(filter: &str, count: usize) -> Vec<PacketInfo> {
        let config = CaptureConfig {
            bpf_filter: filter.to_string(),
            max_packets: count,
            ..Default::default()
        };
        let mut sniffer = Sniffer::new(config);
        let _ = sniffer.start();
        sniffer.packets
    }

    pub fn packets(&self) -> &[PacketInfo] {
        &self.packets
    }

    pub fn clear(&mut self) {
        self.packets.clear();
    }
}

pub fn get_default_interface() -> Option<String> {
    Sniffer::default_interface()
}

pub fn list_ifaces() -> Vec<String> {
    Sniffer::list_interfaces().into_iter().map(|d| d.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert!(config.interface.is_none());
        assert!(config.bpf_filter.is_empty());
        assert!(config.promisc);
        assert_eq!(config.snaplen, 65535);
    }

    #[test]
    fn test_list_interfaces() {
        let ifaces = Sniffer::list_interfaces();
        assert!(!ifaces.is_empty());
    }

    #[test]
    fn test_default_interface() {
        let iface = Sniffer::default_interface();
        assert!(iface.is_some());
    }

    #[test]
    fn test_sniffer_new() {
        let config = CaptureConfig::default();
        let sniffer = Sniffer::new(config);
        assert!(sniffer.packets.is_empty());
    }

    #[test]
    fn test_list_ifaces() {
        let names = list_ifaces();
        assert!(!names.is_empty());
        assert!(names.iter().any(|n| !n.is_empty()));
    }
}
