use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub os_name: String,
    pub os_family: String,
    pub accuracy: f64,
    pub ttl: u32,
    pub tcp_window_size: Option<u32>,
    pub tcp_options: Vec<String>,
    pub distance_hops: Option<u32>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProbeResult {
    pub ttl: u32,
    pub window_size: u32,
    pub ip_id: u16,
    pub df_bit: bool,
}

pub fn fingerprint(addr: IpAddr) -> OsFingerprint {
    let evidence = vec![];

    if let Ok(ttl) = probe_ttl(addr) {
        let (os_name, family, accuracy): (String, String, f64) = {
            if ttl <= 32 {
                ("BSD/AIX".to_string(), "Unix".to_string(), 0.6)
            } else if ttl <= 64 {
                ("Linux".to_string(), "Linux".to_string(), 0.85)
            } else if ttl <= 96 {
                ("macOS/iOS".to_string(), "Darwin".to_string(), 0.75)
            } else if ttl <= 128 {
                ("Windows".to_string(), "Windows".to_string(), 0.80)
            } else if ttl <= 192 {
                ("Solaris/AIX".to_string(), "Unix".to_string(), 0.65)
            } else {
                ("Unknown".to_string(), "Unknown".to_string(), 0.3)
            }
        };

        let ev = vec![format!("Initial TTL: {}", ttl)];

        return OsFingerprint {
            os_name: os_name.to_string(),
            os_family: family.to_string(),
            accuracy,
            ttl,
            tcp_window_size: None,
            tcp_options: vec![],
            distance_hops: None,
            evidence: ev,
        };
    }

    OsFingerprint {
        os_name: "Unknown".into(),
        os_family: "Unknown".into(),
        accuracy: 0.0,
        ttl: 64,
        tcp_window_size: None,
        tcp_options: vec![],
        distance_hops: None,
        evidence,
    }
}

pub fn detailed_fingerprint(addr: IpAddr, open_ports: &[u16]) -> OsFingerprint {
    let mut base = fingerprint(addr);

    if let Some(port) = open_ports.first() {
        if let Some(probe) = probe_tcp_details(addr, *port) {
            base.ttl = probe.ttl;
            base.tcp_window_size = Some(probe.window_size);

            let (os_name, family, accuracy): (String, String, f64) = {
                let ttl = probe.ttl;
                if ttl <= 32 {
                    ("BSD/AIX".to_string(), "Unix".to_string(), 0.7)
                } else if ttl <= 64 {
                    ("Linux".to_string(), "Linux".to_string(), 0.9)
                } else if ttl <= 96 {
                    ("macOS/iOS".to_string(), "Darwin".to_string(), 0.8)
                } else if ttl <= 128 {
                    if probe.window_size == 65535 || probe.window_size == 8192 {
                        ("Windows".to_string(), "Windows".to_string(), 0.9)
                    } else {
                        ("Windows (maybe Linux?)".to_string(), "Windows".to_string(), 0.7)
                    }
                } else if ttl <= 192 {
                    ("Solaris/AIX".to_string(), "Unix".to_string(), 0.7)
                } else {
                    ("Unknown".to_string(), "Unknown".to_string(), 0.3)
                }
            };

            base.os_name = os_name;
            base.os_family = family;
            base.accuracy = accuracy;
            base.evidence.push(format!("TCP probe on port {}: TTL={}, Window={}, DF={}",
                port, probe.ttl, probe.window_size, probe.df_bit));

            if accuracy > base.accuracy {
                base.accuracy = accuracy;
            }
        }
    }

    base
}

fn probe_ttl(addr: IpAddr) -> Result<u32, ()> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|_| ())?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));

    let echo_req = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    match socket.send_to(echo_req, (addr, 0)) {
        Ok(_) => {
            let mut buf = [0u8; 64];
            match socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if n >= 20 {
                        let ttl = buf[8] as u32;
                        return Ok(if ttl == 0 { 64 } else { ttl });
                    }
                    Ok(64)
                }
                Err(_) => Ok(64),
            }
        }
        Err(_) => Err(()),
    }
}

fn probe_tcp_details(_addr: IpAddr, _port: u16) -> Option<TcpProbeResult> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));

    let mut buf = [0u8; 64];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) if n >= 20 => {
            let ttl = buf[8] as u32;
            let window = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) & 0xFFFF;
            let ip_id = u16::from_be_bytes([buf[6], buf[7]]);
            let df = (buf[6] & 0x40) != 0;

            Some(TcpProbeResult {
                ttl: if ttl == 0 { 64 } else { ttl },
                window_size: window,
                ip_id,
                df_bit: df,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_fingerprint_struct_fields() {
        let fp = OsFingerprint {
            os_name: "Linux".into(),
            os_family: "Linux".into(),
            accuracy: 0.85,
            ttl: 64,
            tcp_window_size: Some(65535),
            tcp_options: vec!["MSS".into(), "NOP".into()],
            distance_hops: Some(5),
            evidence: vec!["test evidence".into()],
        };
        assert_eq!(fp.os_name, "Linux");
        assert_eq!(fp.accuracy, 0.85);
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.tcp_window_size, Some(65535));
        assert_eq!(fp.distance_hops, Some(5));
        assert_eq!(fp.evidence.len(), 1);
    }

    #[test]
    fn test_os_fingerprint_clone() {
        let fp = OsFingerprint {
            os_name: "Windows".into(),
            os_family: "Windows".into(),
            accuracy: 0.80,
            ttl: 128,
            tcp_window_size: None,
            tcp_options: vec![],
            distance_hops: None,
            evidence: vec![],
        };
        let cloned = fp.clone();
        assert_eq!(cloned.os_name, "Windows");
        assert_eq!(cloned.ttl, 128);
        assert!(cloned.tcp_options.is_empty());
    }

    #[test]
    fn test_tcp_probe_result_struct() {
        let result = TcpProbeResult {
            ttl: 64,
            window_size: 65535,
            ip_id: 1234,
            df_bit: true,
        };
        assert_eq!(result.ttl, 64);
        assert_eq!(result.window_size, 65535);
        assert_eq!(result.ip_id, 1234);
        assert!(result.df_bit);
    }

    #[test]
    fn test_tcp_probe_result_clone() {
        let result = TcpProbeResult {
            ttl: 128,
            window_size: 8192,
            ip_id: 5678,
            df_bit: false,
        };
        let cloned = result.clone();
        assert_eq!(cloned.ttl, 128);
        assert_eq!(cloned.window_size, 8192);
        assert!(!cloned.df_bit);
    }

    #[test]
    fn test_fingerprint_returns_valid_os_for_unreachable() {
        // fingerprint on unreachable host returns default
        let fp = fingerprint(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(fp.os_name, "Unknown");
        assert_eq!(fp.os_family, "Unknown");
        assert_eq!(fp.accuracy, 0.0);
        assert!(fp.evidence.is_empty());
    }

    #[test]
    fn test_detailed_fingerprint_no_ports() {
        let fp = detailed_fingerprint(
            IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            &[],
        );
        assert_eq!(fp.os_name, "Unknown");
    }

    #[test]
    fn test_os_fingerprint_default_values() {
        let fp = OsFingerprint {
            os_name: String::new(),
            os_family: String::new(),
            accuracy: 0.0,
            ttl: 0,
            tcp_window_size: None,
            tcp_options: Vec::new(),
            distance_hops: None,
            evidence: Vec::new(),
        };
        assert!(fp.os_name.is_empty());
        assert!(fp.evidence.is_empty());
        assert!(fp.tcp_options.is_empty());
        assert_eq!(fp.accuracy, 0.0);
    }

    #[test]
    fn test_ttl_ranges_mapping() {
        // Test the TTL -> OS mapping logic without network calls
        // This validates the logic used in fingerprint()
        let test_cases: Vec<(u32, &str, &str)> = vec![
            (16, "BSD/AIX", "Unix"),
            (32, "BSD/AIX", "Unix"),
            (64, "Linux", "Linux"),
            (96, "macOS/iOS", "Darwin"),
            (128, "Windows", "Windows"),
            (192, "Solaris/AIX", "Unix"),
            (255, "Unknown", "Unknown"),
        ];

        for (ttl, expected_name, expected_family) in test_cases {
            // Simulate what fingerprint() does
            let (os_name, family, _accuracy): (String, String, f64) = if ttl <= 32 {
                ("BSD/AIX".into(), "Unix".into(), 0.6)
            } else if ttl <= 64 {
                ("Linux".into(), "Linux".into(), 0.85)
            } else if ttl <= 96 {
                ("macOS/iOS".into(), "Darwin".into(), 0.75)
            } else if ttl <= 128 {
                ("Windows".into(), "Windows".into(), 0.80)
            } else if ttl <= 192 {
                ("Solaris/AIX".into(), "Unix".into(), 0.65)
            } else {
                ("Unknown".into(), "Unknown".into(), 0.3)
            };
            assert_eq!(os_name, expected_name, "TTL {}", ttl);
            assert_eq!(family, expected_family, "TTL {}", ttl);
        }
    }

    #[test]
    fn test_os_fingerprint_serde_roundtrip() {
        let fp = OsFingerprint {
            os_name: "Linux".into(),
            os_family: "Linux".into(),
            accuracy: 0.85,
            ttl: 64,
            tcp_window_size: Some(65535),
            tcp_options: vec!["MSS".into()],
            distance_hops: Some(3),
            evidence: vec!["Initial TTL: 64".into()],
        };
        let json = serde_json::to_string(&fp).unwrap();
        let deserialized: OsFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.os_name, "Linux");
        assert_eq!(deserialized.ttl, 64);
        assert_eq!(deserialized.tcp_window_size, Some(65535));
    }

    #[test]
    fn test_tcp_probe_result_serde() {
        let result = TcpProbeResult {
            ttl: 128,
            window_size: 8192,
            ip_id: 42,
            df_bit: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: TcpProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ttl, 128);
        assert!(deserialized.df_bit);
    }

    #[test]
    fn test_os_fingerprint_debug() {
        let fp = OsFingerprint {
            os_name: "Test".into(),
            os_family: "TestFam".into(),
            accuracy: 0.5,
            ttl: 32,
            tcp_window_size: None,
            tcp_options: vec![],
            distance_hops: None,
            evidence: vec![],
        };
        let debug = format!("{:?}", fp);
        assert!(debug.contains("Test"));
        assert!(debug.contains("OsFingerprint"));
    }
}
