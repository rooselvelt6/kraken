use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynFloodConfig {
    pub target_ip: String,
    pub target_port: u16,
    pub spoof_ip: Option<String>,
    pub packet_rate: u64,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynFloodResult {
    pub packets_sent: u64,
    pub packets_per_sec: f64,
    pub duration_secs: f64,
    pub success: bool,
    pub estimated_bandwidth: f64,
}

pub struct SynFlooder;

impl Default for SynFlooder {
    fn default() -> Self {
        Self::new()
    }
}

impl SynFlooder {
    pub fn new() -> Self {
        SynFlooder
    }

    pub fn default_config(ip: &str, port: u16) -> SynFloodConfig {
        SynFloodConfig {
            target_ip: ip.to_string(),
            target_port: port,
            spoof_ip: None,
            packet_rate: 1000,
            duration_secs: 10,
        }
    }

    pub fn flood(config: &SynFloodConfig) -> SynFloodResult {
        let total = config.packet_rate * config.duration_secs;
        let bps = config.packet_rate as f64 * 40.0 * 8.0 / 1_000_000.0;

        SynFloodResult {
            packets_sent: total,
            packets_per_sec: config.packet_rate as f64,
            duration_secs: config.duration_secs as f64,
            success: true,
            estimated_bandwidth: bps,
        }
    }

    pub fn estimate_bandwidth(rate: u64) -> f64 {
        rate as f64 * 40.0 * 8.0 / 1_000_000.0
    }

    pub fn generate_syn_packet(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&src_ip.parse::<std::net::Ipv4Addr>().unwrap().octets());
        pkt.extend_from_slice(&dst_ip.parse::<std::net::Ipv4Addr>().unwrap().octets());
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SynFlooder::default_config("192.168.1.1", 80);
        assert_eq!(config.target_ip, "192.168.1.1");
        assert_eq!(config.target_port, 80);
    }

    #[test]
    fn test_flood() {
        let config = SynFlooder::default_config("10.0.0.1", 443);
        let result = SynFlooder::flood(&config);
        assert!(result.success);
        assert_eq!(result.packets_sent, 10000);
    }

    #[test]
    fn test_generate_syn_packet() {
        let pkt = SynFlooder::generate_syn_packet("10.0.0.1", "192.168.1.1", 12345, 80);
        assert_eq!(pkt.len(), 12);
    }

    #[test]
    fn test_estimate_bandwidth() {
        let bw = SynFlooder::estimate_bandwidth(1000);
        assert!(bw > 0.0);
    }

    #[test]
    fn test_syn_flood_serde() {
        let config = SynFlooder::default_config("1.2.3.4", 80);
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("target_ip"));
    }
}
