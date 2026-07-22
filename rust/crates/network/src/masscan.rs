use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use kraken_errors::NetworkError;
use crate::{PortResult, PortState, ScanTarget};

#[derive(Debug, Clone)]
pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct MasscanConfig {
    pub targets: Vec<IpRange>,
    pub ports: Vec<PortRange>,
    pub concurrency: usize,
    pub timeout: Duration,
    pub rate_limit: Option<u64>,
}

impl Default for MasscanConfig {
    fn default() -> Self {
        Self {
            targets: vec![],
            ports: vec![PortRange { start: 1, end: 1024 }],
            concurrency: 10000,
            timeout: Duration::from_secs(3),
            rate_limit: None,
        }
    }
}

impl MasscanConfig {
    /// Adds a CIDR range to scan.
    ///
    /// # Examples
    ///
    /// ```
    /// use network::masscan::MasscanConfig;
    ///
    /// let mut config = MasscanConfig::default();
    /// config.add_cidr("192.168.1.0/30").unwrap();
    /// config.ports.clear();
    /// config.add_port(80);
    /// config.add_port(443);
    ///
    /// assert_eq!(config.total_ips(), 2);
    /// assert_eq!(config.total_ports(), 2);
    /// assert_eq!(config.total_probes(), 4);
    /// ```
    pub fn add_cidr(&mut self, cidr: &str) -> Result<(), NetworkError> {
        let range = parse_cidr(cidr)?;
        self.targets.push(range);
        Ok(())
    }

    pub fn add_port_range(&mut self, start: u16, end: u16) {
        self.ports.push(PortRange { start, end });
    }

    pub fn add_port(&mut self, port: u16) {
        self.ports.push(PortRange { start: port, end: port });
    }

    pub fn total_ips(&self) -> u64 {
        self.targets.iter().map(|r| ip_count(r.start, r.end)).sum()
    }

    pub fn total_ports(&self) -> u64 {
        self.ports.iter().map(|r| (r.end - r.start + 1) as u64).sum()
    }

    pub fn total_probes(&self) -> u64 {
        self.total_ips() * self.total_ports()
    }
}

#[derive(Debug, Clone)]
pub struct MasscanResult {
    pub target: ScanTarget,
    pub results: Vec<PortResult>,
    pub scan_duration: Duration,
    pub ips_scanned: u64,
    pub total_probes: u64,
}

pub fn scan(config: &MasscanConfig) -> Vec<MasscanResult> {
    let start = Instant::now();
    let all_ips = expand_ranges(&config.targets);
    let all_ports = expand_port_ranges(&config.ports);
    let mut results = Vec::new();

    for ip in all_ips {
        let target = ScanTarget { addr: ip, hostname: None };
        let mut open_ports = Vec::new();

        for &port in &all_ports {
            let state = probe_port(ip, port, config.timeout);
            if matches!(state, PortState::Open) {
                let service = crate::port::grab_banner(&ip, port, config.timeout);
                open_ports.push(PortResult {
                    port,
                    protocol: "tcp".to_string(),
                    state,
                    service,
                });
            }
        }

        results.push(MasscanResult {
            target,
            results: open_ports,
            scan_duration: start.elapsed(),
            ips_scanned: 1,
            total_probes: all_ports.len() as u64,
        });
    }

    results
}

fn probe_port(addr: IpAddr, port: u16, timeout: Duration) -> PortState {
    let sock_addr = (addr, port);
    match std::net::TcpStream::connect_timeout(&sock_addr.into(), timeout) {
        Ok(_) => PortState::Open,
        Err(e) => {
            if let Some(io_err) = e.raw_os_error() {
                match io_err {
                    11 | 111 | 61 | 146 => PortState::Closed,
                    110 | 60 | 78 | 113 | 148 => PortState::Filtered,
                    _ => PortState::Filtered,
                }
            } else {
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                    std::io::ErrorKind::TimedOut => PortState::Filtered,
                    std::io::ErrorKind::ConnectionReset => PortState::Closed,
                    _ => PortState::Filtered,
                }
            }
        }
    }
}

fn parse_cidr(cidr: &str) -> Result<IpRange, NetworkError> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(NetworkError::Other(format!("Invalid CIDR: {}", cidr)));
    }

    let ip: Ipv4Addr = parts[0].parse().map_err(|e| NetworkError::Other(format!("Invalid IP: {}", e)))?;
    let prefix: u8 = parts[1].parse().map_err(|_| NetworkError::Other("Invalid prefix".to_string()))?;

    if prefix > 32 {
        return Err(NetworkError::Other(format!("Invalid prefix length: {}", prefix)));
    }

    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    let (start, end) = match prefix {
        32 => (network, broadcast),
        31 => (network, broadcast),
        _ => (network + 1, broadcast - 1),
    };

    if start > end {
        return Err(NetworkError::Other(format!("No usable hosts in CIDR: {}", cidr)));
    }

    Ok(IpRange {
        start: IpAddr::V4(Ipv4Addr::from(start)),
        end: IpAddr::V4(Ipv4Addr::from(end)),
    })
}

fn ip_count(start: IpAddr, end: IpAddr) -> u64 {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => (u32::from(e) - u32::from(s) + 1) as u64,
        (IpAddr::V6(_), IpAddr::V6(_)) => 0,
        _ => 0,
    }
}

fn expand_ranges(ranges: &[IpRange]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for range in ranges {
        if let (IpAddr::V4(start), IpAddr::V4(end)) = (range.start, range.end) {
            let s = u32::from(start);
            let e = u32::from(end);
            for ip in s..=e {
                ips.push(IpAddr::V4(Ipv4Addr::from(ip)));
            }
        }
    }
    ips
}

fn expand_port_ranges(ranges: &[PortRange]) -> Vec<u16> {
    let mut ports = Vec::new();
    for range in ranges {
        for port in range.start..=range.end {
            ports.push(port);
        }
    }
    ports
}

pub fn scan_range(cidr: &str, ports: &[u16]) -> Result<Vec<MasscanResult>, NetworkError> {
    let mut config = MasscanConfig::default();
    config.add_cidr(cidr)?;
    for &port in ports {
        config.add_port(port);
    }
    Ok(scan(&config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_small() {
        let range = parse_cidr("192.168.1.0/30").unwrap();
        assert_eq!(range.start, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(range.end, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn test_parse_cidr_single() {
        let range = parse_cidr("10.0.0.1/32").unwrap();
        assert_eq!(range.start, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(range.end, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("invalid").is_err());
        assert!(parse_cidr("10.0.0.1/33").is_err());
    }

    #[test]
    fn test_expand_ranges() {
        let range = IpRange {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        };
        let ips = expand_ranges(&[range]);
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ips[2], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    }

    #[test]
    fn test_port_range() {
        let ports = expand_port_ranges(&[PortRange { start: 80, end: 85 }]);
        assert!(ports.contains(&80));
        assert!(ports.contains(&85));
        assert_eq!(ports.len(), 6);
    }

    #[test]
    fn test_total_probes() {
        let mut config = MasscanConfig::default();
        config.ports = vec![PortRange { start: 80, end: 81 }];
        config.add_cidr("10.0.0.0/30").unwrap();
        assert_eq!(config.total_probes(), 4);
    }

    #[test]
    fn test_masscan_config_default() {
        let config = MasscanConfig::default();
        assert!(config.targets.is_empty());
        assert_eq!(config.ports.len(), 1);
        assert_eq!(config.ports[0].start, 1);
        assert_eq!(config.ports[0].end, 1024);
        assert_eq!(config.concurrency, 10000);
        assert!(config.rate_limit.is_none());
    }

    #[test]
    fn test_add_port() {
        let mut config = MasscanConfig::default();
        config.add_port(80);
        assert_eq!(config.ports.len(), 2); // default + 80
        assert_eq!(config.ports[1].start, 80);
        assert_eq!(config.ports[1].end, 80);
    }

    #[test]
    fn test_add_port_range() {
        let mut config = MasscanConfig::default();
        config.add_port_range(1000, 2000);
        assert_eq!(config.ports.len(), 2);
        assert_eq!(config.ports[1].start, 1000);
        assert_eq!(config.ports[1].end, 2000);
    }

    #[test]
    fn test_total_ips_single_host() {
        let mut config = MasscanConfig::default();
        config.add_cidr("10.0.0.1/32").unwrap();
        assert_eq!(config.total_ips(), 1);
    }

    #[test]
    fn test_total_ips_slash24() {
        let mut config = MasscanConfig::default();
        config.add_cidr("10.0.0.0/30").unwrap();
        assert_eq!(config.total_ips(), 2); // network+1, broadcast-1
    }

    #[test]
    fn test_total_ports_empty() {
        let config = MasscanConfig {
            targets: vec![],
            ports: vec![],
            concurrency: 100,
            timeout: Duration::from_secs(1),
            rate_limit: None,
        };
        assert_eq!(config.total_ports(), 0);
    }

    #[test]
    fn test_total_probes_zero() {
        let config = MasscanConfig {
            targets: vec![],
            ports: vec![],
            concurrency: 100,
            timeout: Duration::from_secs(1),
            rate_limit: None,
        };
        assert_eq!(config.total_probes(), 0);
    }

    #[test]
    fn test_ip_count_single() {
        let count = ip_count(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn test_ip_count_range() {
        let count = ip_count(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        );
        assert_eq!(count, 5);
    }

    #[test]
    fn test_expand_port_ranges_multiple() {
        let ranges = vec![
            PortRange { start: 80, end: 82 },
            PortRange { start: 443, end: 443 },
        ];
        let ports = expand_port_ranges(&ranges);
        assert_eq!(ports.len(), 4);
        assert!(ports.contains(&80));
        assert!(ports.contains(&82));
        assert!(ports.contains(&443));
    }

    #[test]
    fn test_expand_ranges_empty() {
        let ips = expand_ranges(&[]);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_expand_port_ranges_empty() {
        let ports = expand_port_ranges(&[]);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_cidr_various_invalid() {
        assert!(parse_cidr("").is_err());
        assert!(parse_cidr("10.0.0.1").is_err());
        assert!(parse_cidr("10.0.0.0/abc").is_err());
        assert!(parse_cidr("not-an-ip/24").is_err());
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("10.0.0.0/-1").is_err());
    }

    #[test]
    fn test_parse_cidr_slash_31() {
        let range = parse_cidr("10.0.0.0/31").unwrap();
        assert_eq!(range.start, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(range.end, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_parse_cidr_slash_24() {
        let range = parse_cidr("192.168.1.0/30").unwrap();
        assert_eq!(range.start, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(range.end, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn test_add_cidr_to_config() {
        let mut config = MasscanConfig::default();
        config.add_cidr("192.168.1.0/30").unwrap();
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.total_ips(), 2);
    }

    #[test]
    fn test_masscan_result_struct() {
        let result = MasscanResult {
            target: ScanTarget {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                hostname: Some("test.local".into()),
            },
            results: vec![],
            scan_duration: Duration::from_secs(1),
            ips_scanned: 1,
            total_probes: 10,
        };
        assert_eq!(result.ips_scanned, 1);
        assert_eq!(result.total_probes, 10);
        assert!(result.results.is_empty());
    }

    #[test]
    fn test_scan_range_invalid_cidr() {
        let result = scan_range("invalid", &[80]);
        assert!(result.is_err());
    }
}
