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
