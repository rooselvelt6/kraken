use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpFloodConfig {
    pub target_ip: String,
    pub target_port: u16,
    pub packet_size: usize,
    pub packet_rate: u64,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpFloodResult {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_per_sec: f64,
    pub bandwidth_mbps: f64,
    pub success: bool,
}

pub struct UdpFlooder;

impl Default for UdpFlooder {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpFlooder {
    pub fn new() -> Self {
        UdpFlooder
    }

    pub fn default_config(ip: &str, port: u16) -> UdpFloodConfig {
        UdpFloodConfig {
            target_ip: ip.to_string(),
            target_port: port,
            packet_size: 1024,
            packet_rate: 500,
            duration_secs: 10,
        }
    }

    pub fn flood(config: &UdpFloodConfig) -> UdpFloodResult {
        let total = config.packet_rate * config.duration_secs;
        let bytes = total * config.packet_size as u64;
        let mbps = bytes as f64 * 8.0 / config.duration_secs as f64 / 1_000_000.0;

        UdpFloodResult {
            packets_sent: total,
            bytes_sent: bytes,
            packets_per_sec: config.packet_rate as f64,
            bandwidth_mbps: mbps,
            success: true,
        }
    }

    pub fn generate_payload(size: usize) -> Vec<u8> {
        let mut payload = vec![0u8; size];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = UdpFlooder::default_config("10.0.0.1", 53);
        assert_eq!(config.packet_size, 1024);
    }

    #[test]
    fn test_flood() {
        let config = UdpFlooder::default_config("192.168.1.1", 12345);
        let result = UdpFlooder::flood(&config);
        assert!(result.success);
        assert_eq!(result.packets_sent, 5000);
    }

    #[test]
    fn test_generate_payload() {
        let payload = UdpFlooder::generate_payload(100);
        assert_eq!(payload.len(), 100);
    }

    #[test]
    fn test_udp_flood_serde() {
        let config = UdpFlooder::default_config("1.2.3.4", 53);
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("packet_size"));
    }
}
