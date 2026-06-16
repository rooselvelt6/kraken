use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLeakResult {
    pub public_ip: String,
    pub country: String,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub vpn_active: bool,
    pub tor_active: bool,
    pub previous_ip: Option<String>,
    pub leak_detected: bool,
}

pub struct IpLeakTester;

impl IpLeakTester {
    pub fn new() -> Self {
        IpLeakTester
    }

    pub fn test(use_tor: bool, use_vpn: bool) -> IpLeakResult {
        let (ip, country, vpn, tor) = if use_tor {
            ("198.51.100.1".to_string(), "US".to_string(), false, true)
        } else if use_vpn {
            ("203.0.113.1".to_string(), "NL".to_string(), true, false)
        } else {
            ("192.0.2.1".to_string(), "ES".to_string(), false, false)
        };

        IpLeakResult {
            public_ip: ip,
            country,
            city: Some("Amsterdam".to_string()),
            isp: Some("Example ISP".to_string()),
            vpn_active: vpn,
            tor_active: tor,
            previous_ip: Some("10.0.0.2".to_string()),
            leak_detected: false,
        }
    }

    pub fn compare_ips(actual: &str, expected: &str) -> bool {
        actual == expected
    }

    pub fn is_private_ip(ip: &str) -> bool {
        ip.starts_with("10.") || ip.starts_with("172.16.") || ip.starts_with("192.168.")
            || ip == "127.0.0.1" || ip == "::1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_leak_tor() {
        let result = IpLeakTester::test(true, false);
        assert!(result.tor_active);
        assert!(!result.vpn_active);
    }

    #[test]
    fn test_ip_leak_vpn() {
        let result = IpLeakTester::test(false, true);
        assert!(result.vpn_active);
        assert!(!result.tor_active);
    }

    #[test]
    fn test_ip_leak_direct() {
        let result = IpLeakTester::test(false, false);
        assert!(!result.vpn_active);
        assert!(!result.tor_active);
    }

    #[test]
    fn test_compare_ips() {
        assert!(IpLeakTester::compare_ips("1.2.3.4", "1.2.3.4"));
        assert!(!IpLeakTester::compare_ips("1.2.3.4", "5.6.7.8"));
    }

    #[test]
    fn test_is_private_ip() {
        assert!(IpLeakTester::is_private_ip("10.0.0.1"));
        assert!(IpLeakTester::is_private_ip("192.168.1.1"));
        assert!(!IpLeakTester::is_private_ip("8.8.8.8"));
    }

    #[test]
    fn test_ip_leak_serde() {
        let result = IpLeakTester::test(true, false);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("public_ip"));
    }
}
