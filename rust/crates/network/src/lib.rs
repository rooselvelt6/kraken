pub mod port;
pub mod dns;
pub mod service;
pub mod os;
pub mod masscan;
pub mod web;
pub mod web_exploit;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_CONCURRENCY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub addr: IpAddr,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout: Duration,
    pub scan_type: ScanType,
}

/// Default configuration for network scans.
///
/// # Examples
///
/// ```
/// use network::ScanConfig;
/// use std::time::Duration;
///
/// let config = ScanConfig::default();
/// assert!(config.ports.is_empty());
/// assert_eq!(config.concurrency, 256);
/// assert_eq!(config.timeout, Duration::from_secs(3));
/// ```
impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ports: vec![],
            concurrency: DEFAULT_CONCURRENCY,
            timeout: DEFAULT_TIMEOUT,
            scan_type: ScanType::TcpConnect,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    TcpConnect,
    SynStealth,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target: ScanTarget,
    pub total_ports: usize,
    pub open_ports: Vec<PortResult>,
    pub filtered_ports: Vec<PortResult>,
    pub closed_ports: Vec<PortResult>,
    pub scan_duration: std::time::Duration,
    pub os_fingerprint: Option<os::OsFingerprint>,
    pub dns_records: Option<dns::DnsRecords>,
}

impl ScanSummary {
    /// Creates an empty scan summary for the given target.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::IpAddr;
    /// use network::{ScanTarget, ScanSummary};
    ///
    /// let target = ScanTarget {
    ///     addr: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    ///     hostname: None,
    /// };
    /// let summary = ScanSummary::new(target);
    /// assert_eq!(summary.total_ports, 0);
    /// assert!(summary.open_ports.is_empty());
    /// assert!(summary.os_fingerprint.is_none());
    /// ```
    pub fn new(target: ScanTarget) -> Self {
        Self {
            target,
            total_ports: 0,
            open_ports: vec![],
            filtered_ports: vec![],
            closed_ports: vec![],
            scan_duration: std::time::Duration::default(),
            os_fingerprint: None,
            dns_records: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert!(config.ports.is_empty());
        assert_eq!(config.concurrency, 256);
        assert_eq!(config.timeout, Duration::from_secs(3));
        assert!(matches!(config.scan_type, ScanType::TcpConnect));
    }

    #[test]
    fn test_scan_type_variants() {
        assert!(matches!(ScanType::TcpConnect, ScanType::TcpConnect));
        assert!(matches!(ScanType::SynStealth, ScanType::SynStealth));
        assert!(matches!(ScanType::Udp, ScanType::Udp));
        assert_ne!(ScanType::TcpConnect, ScanType::Udp);
    }

    #[test]
    fn test_scan_type_debug() {
        assert_eq!(format!("{:?}", ScanType::TcpConnect), "TcpConnect");
        assert_eq!(format!("{:?}", ScanType::SynStealth), "SynStealth");
        assert_eq!(format!("{:?}", ScanType::Udp), "Udp");
    }

    #[test]
    fn test_scan_type_clone_copy() {
        let st = ScanType::TcpConnect;
        let copied: ScanType = st;
        let cloned = st.clone();
        assert_eq!(copied, st);
        assert_eq!(cloned, st);
    }

    #[test]
    fn test_port_state_all_variants() {
        let states = [PortState::Open, PortState::Closed, PortState::Filtered, PortState::Unfiltered];
        for state in &states {
            let _ = format!("{:?}", state);
            let _ = state.clone();
        }
    }

    #[test]
    fn test_port_state_eq() {
        assert_eq!(PortState::Open, PortState::Open);
        assert_ne!(PortState::Open, PortState::Closed);
        assert_ne!(PortState::Filtered, PortState::Unfiltered);
    }

    #[test]
    fn test_port_result_struct() {
        let pr = PortResult {
            port: 22,
            protocol: "tcp".into(),
            state: PortState::Open,
            service: Some(ServiceInfo {
                name: "SSH".into(),
                product: None,
                version: None,
                banner: None,
            }),
        };
        assert_eq!(pr.port, 22);
        assert_eq!(pr.protocol, "tcp");
        assert!(pr.service.is_some());
    }

    #[test]
    fn test_port_result_no_service() {
        let pr = PortResult {
            port: 80,
            protocol: "tcp".into(),
            state: PortState::Closed,
            service: None,
        };
        assert!(pr.service.is_none());
    }

    #[test]
    fn test_service_info_all_fields() {
        let si = ServiceInfo {
            name: "HTTP".into(),
            product: Some("nginx".into()),
            version: Some("1.24.0".into()),
            banner: Some("HTTP/1.1 200 OK".into()),
        };
        assert_eq!(si.name, "HTTP");
        assert!(si.product.is_some());
        assert!(si.version.is_some());
        assert!(si.banner.is_some());
    }

    #[test]
    fn test_scan_target_struct() {
        let target = ScanTarget {
            addr: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            hostname: Some("router.local".into()),
        };
        assert_eq!(target.addr, IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(target.hostname, Some("router.local".into()));
    }

    #[test]
    fn test_scan_target_no_hostname() {
        let target = ScanTarget {
            addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            hostname: None,
        };
        assert!(target.hostname.is_none());
    }

    #[test]
    fn test_scan_summary_new() {
        let target = ScanTarget {
            addr: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            hostname: None,
        };
        let summary = ScanSummary::new(target.clone());
        assert_eq!(summary.total_ports, 0);
        assert!(summary.open_ports.is_empty());
        assert!(summary.filtered_ports.is_empty());
        assert!(summary.closed_ports.is_empty());
        assert_eq!(summary.scan_duration, Duration::default());
        assert!(summary.os_fingerprint.is_none());
        assert!(summary.dns_records.is_none());
        assert_eq!(summary.target.addr, target.addr);
    }

    #[test]
    fn test_default_timeout_value() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(3));
    }

    #[test]
    fn test_default_concurrency_value() {
        assert_eq!(DEFAULT_CONCURRENCY, 256);
    }

    #[test]
    fn test_scan_config_with_ports() {
        let config = ScanConfig {
            ports: vec![22, 80, 443],
            concurrency: 100,
            timeout: Duration::from_secs(5),
            scan_type: ScanType::Udp,
        };
        assert_eq!(config.ports.len(), 3);
        assert_eq!(config.concurrency, 100);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert!(matches!(config.scan_type, ScanType::Udp));
    }

    #[test]
    fn test_port_state_serde() {
        let states = vec![PortState::Open, PortState::Closed, PortState::Filtered, PortState::Unfiltered];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let deserialized: PortState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, deserialized);
        }
    }

    #[test]
    fn test_scan_type_serde() {
        let types = vec![ScanType::TcpConnect, ScanType::SynStealth, ScanType::Udp];
        for st in &types {
            let json = serde_json::to_string(st).unwrap();
            let deserialized: ScanType = serde_json::from_str(&json).unwrap();
            assert_eq!(*st, deserialized);
        }
    }

    #[test]
    fn test_port_result_clone() {
        let pr = PortResult {
            port: 443,
            protocol: "tcp".into(),
            state: PortState::Open,
            service: None,
        };
        let cloned = pr.clone();
        assert_eq!(cloned.port, 443);
        assert!(matches!(cloned.state, PortState::Open));
    }

    #[test]
    fn test_scan_summary_with_data() {
        let target = ScanTarget {
            addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            hostname: Some("test".into()),
        };
        let mut summary = ScanSummary::new(target);
        summary.total_ports = 100;
        summary.open_ports.push(PortResult {
            port: 80,
            protocol: "tcp".into(),
            state: PortState::Open,
            service: None,
        });
        summary.closed_ports.push(PortResult {
            port: 22,
            protocol: "tcp".into(),
            state: PortState::Closed,
            service: None,
        });
        summary.scan_duration = Duration::from_millis(500);

        assert_eq!(summary.total_ports, 100);
        assert_eq!(summary.open_ports.len(), 1);
        assert_eq!(summary.closed_ports.len(), 1);
        assert_eq!(summary.scan_duration, Duration::from_millis(500));
    }
}
