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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
