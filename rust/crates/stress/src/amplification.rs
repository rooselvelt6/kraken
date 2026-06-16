use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmplificationTest {
    pub protocol: String,
    pub server: String,
    pub query_size: usize,
    pub response_size: usize,
    pub amplification_factor: f64,
    pub amplifiable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmplificationScanResult {
    pub tests: Vec<AmplificationTest>,
    pub total_servers_tested: usize,
    pub amplifiable_servers: usize,
    pub max_amplification: f64,
}

pub struct AmplificationScanner;

impl AmplificationScanner {
    pub fn new() -> Self {
        AmplificationScanner
    }

    pub fn scan(servers: &[(&str, &str)]) -> AmplificationScanResult {
        let mut tests = Vec::new();
        let mut amplifiable = 0usize;
        let mut max_amp = 0.0;

        for &(ip, proto) in servers {
            let test = Self::test_server(ip, proto);
            if test.amplifiable {
                amplifiable += 1;
                if test.amplification_factor > max_amp {
                    max_amp = test.amplification_factor;
                }
            }
            tests.push(test);
        }

        AmplificationScanResult {
            tests,
            total_servers_tested: servers.len(),
            amplifiable_servers: amplifiable,
            max_amplification: max_amp,
        }
    }

    pub fn test_server(ip: &str, protocol: &str) -> AmplificationTest {
        let (query_size, response_size) = match protocol {
            "DNS" => (64, 512),
            "NTP" => (90, 482),
            "SNMP" => (60, 1500),
            "SSDP" => (100, 7500),
            "Memcached" => (15, 1024 * 1024),
            _ => (64, 64),
        };

        let factor = response_size as f64 / query_size as f64;

        AmplificationTest {
            protocol: protocol.to_string(),
            server: ip.to_string(),
            query_size,
            response_size,
            amplification_factor: factor,
            amplifiable: factor > 10.0,
        }
    }

    pub fn amplification_factor(protocol: &str) -> f64 {
        match protocol {
            "DNS" => 8.0,
            "NTP" => 5.4,
            "SNMP" => 25.0,
            "SSDP" => 75.0,
            "Memcached" => 68200.0,
            _ => 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan() {
        let servers = vec![
            ("8.8.8.8", "DNS"),
            ("1.1.1.1", "DNS"),
            ("192.168.1.1", "NTP"),
        ];
        let result = AmplificationScanner::scan(&servers);
        assert_eq!(result.total_servers_tested, 3);
    }

    #[test]
    fn test_test_server() {
        let test = AmplificationScanner::test_server("8.8.8.8", "DNS");
        assert_eq!(test.protocol, "DNS");
        assert!(!test.amplifiable);
    }

    #[test]
    fn test_ssdp_amplifiable() {
        let test = AmplificationScanner::test_server("239.255.255.250", "SSDP");
        assert!(test.amplifiable);
    }

    #[test]
    fn test_memcached_amplifiable() {
        let test = AmplificationScanner::test_server("10.0.0.1", "Memcached");
        assert!(test.amplifiable);
    }

    #[test]
    fn test_amplification_factor() {
        let factor = AmplificationScanner::amplification_factor("Memcached");
        assert!(factor > 10000.0);
    }

    #[test]
    fn test_amplification_serde() {
        let result = AmplificationScanner::scan(&[("8.8.8.8", "DNS")]);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("max_amplification"));
    }
}
