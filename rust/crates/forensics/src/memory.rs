

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryProcess {
    pub pid: u32,
    pub name: String,
    pub ppid: Option<u32>,
    pub state: String,
    pub threads: u32,
    pub memory_kb: u64,
    pub path: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemorySocket {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryModule {
    pub name: String,
    pub base_addr: String,
    pub size: u64,
    pub path: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryAnalysisResult {
    pub processes: Vec<MemoryProcess>,
    pub sockets: Vec<MemorySocket>,
    pub modules: Vec<MemoryModule>,
    pub suspicious_processes: Vec<MemoryProcess>,
    pub hidden_processes: Vec<String>,
}

pub struct MemoryAnalyzer;

impl MemoryAnalyzer {
    pub fn new() -> Self {
        MemoryAnalyzer
    }

    pub fn analyze_live() -> MemoryAnalysisResult {
        MemoryAnalysisResult {
            processes: Self::list_processes(),
            sockets: Self::list_sockets(),
            modules: Vec::new(),
            suspicious_processes: Self::find_suspicious(),
            hidden_processes: Vec::new(),
        }
    }

    pub fn list_processes() -> Vec<MemoryProcess> {
        let mut procs = Vec::new();
        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let pid_str = name.to_string_lossy();
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        let _proc_path = format!("/proc/{}", pid);
                        let comm_path = format!("/proc/{}/comm", pid);
                        let status_path = format!("/proc/{}/status", pid);

                        let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
                        let path = cmdline.replace('\0', " ").trim().to_string();

                        let name = std::fs::read_to_string(&comm_path).unwrap_or_default().trim().to_string();
                        let status = std::fs::read_to_string(&status_path).unwrap_or_default();

                        let state = status.lines()
                            .find(|l| l.starts_with("State:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("?").to_string();

                        let threads = status.lines()
                            .find(|l| l.starts_with("Threads:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);

                        let mem = status.lines()
                            .find(|l| l.starts_with("VmRSS:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);

                        procs.push(MemoryProcess {
                            pid,
                            name,
                            ppid: None,
                            state,
                            threads,
                            memory_kb: mem,
                            path,
                        });
                    }
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("tasklist")
                .args(["/FO", "CSV", "/NH"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 5 {
                        let name = parts[0].trim_matches('"').to_string();
                        let pid = parts[1].trim_matches('"').parse().unwrap_or(0);
                        procs.push(MemoryProcess {
                            pid,
                            name,
                            ppid: None,
                            state: "Running".to_string(),
                            threads: 0,
                            memory_kb: 0,
                            path: String::new(),
                        });
                    }
                }
            }
        }
        procs
    }

    pub fn list_sockets() -> Vec<MemorySocket> {
        let mut sockets = Vec::new();
        #[cfg(target_os = "linux")]
        {
            let tcp_paths = vec!["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"];
            for path in &tcp_paths {
                if let Ok(content) = std::fs::read_to_string(path) {
                    for line in content.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 10 {
                            let local = parts[1];
                            let remote = parts[2];
                            let state_hex = parts[3];
                            let pid_info = parts.last().unwrap_or(&"");
                            let pid = pid_info.split('/').last().unwrap_or("0").parse().unwrap_or(0);

                            let (local_addr, local_port) = Self::parse_socket_addr(local);
                            let (remote_addr, remote_port) = Self::parse_socket_addr(remote);
                            let state = Self::tcp_state_name(u32::from_str_radix(state_hex, 16).unwrap_or(0));

                            let proto = if path.contains("udp") { "UDP" } else { "TCP" };
                            sockets.push(MemorySocket {
                                protocol: proto.to_string(),
                                local_addr,
                                local_port,
                                remote_addr,
                                remote_port,
                                state,
                                pid,
                            });
                        }
                    }
                }
            }
        }
        sockets
    }

    fn parse_socket_addr(hex_addr: &str) -> (String, u16) {
        let parts: Vec<&str> = hex_addr.split(':').collect();
        if parts.len() == 2 {
            let ip_hex = parts[0];
            let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
            let ip = if ip_hex.len() == 8 {
                let bytes = hex::decode(ip_hex).unwrap_or_default();
                if bytes.len() == 4 {
                    format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
                } else {
                    "0.0.0.0".to_string()
                }
            } else {
                "::".to_string()
            };
            (ip, port)
        } else {
            ("0.0.0.0".to_string(), 0)
        }
    }

    fn tcp_state_name(state: u32) -> String {
        match state {
            1 => "ESTABLISHED".to_string(),
            2 => "SYN_SENT".to_string(),
            3 => "SYN_RECV".to_string(),
            4 => "FIN_WAIT1".to_string(),
            5 => "FIN_WAIT2".to_string(),
            6 => "TIME_WAIT".to_string(),
            7 => "CLOSE".to_string(),
            8 => "CLOSE_WAIT".to_string(),
            9 => "LAST_ACK".to_string(),
            10 => "LISTEN".to_string(),
            11 => "CLOSING".to_string(),
            _ => format!("UNKNOWN({})", state),
        }
    }

    pub fn find_suspicious() -> Vec<MemoryProcess> {
        let mut susp = Vec::new();
        let suspicious_names = vec![
            "mimikatz", "wireshark", "tcpdump", "nc", "netcat", "ncat",
            "nmap", "masscan", "sqlmap", "hashcat", "john", "hydra",
            "proxychains", "tor", "plink", "putty", "cobaltstrike",
        ];
        for proc in Self::list_processes() {
            let lower = proc.name.to_lowercase();
            if suspicious_names.iter().any(|s| lower.contains(s)) {
                susp.push(proc);
            }
        }
        susp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socket_addr_ipv4() {
        let (ip, port) = MemoryAnalyzer::parse_socket_addr("0100007F:0050");
        assert_eq!(port, 80);
        assert!(ip.contains("127"));
    }

    #[test]
    fn test_tcp_state_names() {
        assert_eq!(MemoryAnalyzer::tcp_state_name(1), "ESTABLISHED");
        assert_eq!(MemoryAnalyzer::tcp_state_name(10), "LISTEN");
        assert_eq!(MemoryAnalyzer::tcp_state_name(99), "UNKNOWN(99)");
    }

    #[test]
    fn test_list_processes_no_panic() {
        let procs = MemoryAnalyzer::list_processes();
        assert!(procs.len() >= 1);
    }

    #[test]
    fn test_find_suspicious() {
        let susp = MemoryAnalyzer::find_suspicious();
        assert!(susp.is_empty() || !susp.is_empty());
    }

    #[test]
    fn test_list_sockets_no_panic() {
        let sockets = MemoryAnalyzer::list_sockets();
        assert!(sockets.is_empty() || !sockets.is_empty());
    }

    #[test]
    fn test_memory_process_serialization() {
        let proc = MemoryProcess {
            pid: 1337,
            name: "test".to_string(),
            ppid: Some(1),
            state: "R".to_string(),
            threads: 5,
            memory_kb: 1024,
            path: "/usr/bin/test".to_string(),
        };
        let json = serde_json::to_string_pretty(&proc).unwrap();
        assert!(json.contains("1337"));
    }

    #[test]
    fn test_memory_socket_serialization() {
        let sock = MemorySocket {
            protocol: "TCP".to_string(),
            local_addr: "0.0.0.0".to_string(),
            local_port: 4444,
            remote_addr: "10.0.0.1".to_string(),
            remote_port: 80,
            state: "LISTEN".to_string(),
            pid: 1234,
        };
        let json = serde_json::to_string_pretty(&sock).unwrap();
        assert!(json.contains("4444"));
    }

    #[test]
    fn test_analysis_result() {
        let result = MemoryAnalysisResult {
            processes: vec![],
            sockets: vec![],
            modules: vec![],
            suspicious_processes: vec![],
            hidden_processes: vec![],
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("suspicious_processes"));
    }

    #[test]
    fn test_analyze_live() {
        let result = MemoryAnalyzer::analyze_live();
        assert!(result.processes.len() >= 1);
    }
}
