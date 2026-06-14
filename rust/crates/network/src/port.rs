use std::net::{IpAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::{PortResult, PortState, ScanConfig, ScanTarget, ScanType, ServiceInfo};

pub fn scan_ports(target: &ScanTarget, config: &ScanConfig) -> Vec<PortResult> {
    match config.scan_type {
        ScanType::TcpConnect => tcp_connect_scan(target, config),
        ScanType::SynStealth => {
            log::warn!("SYN scan requires raw socket privileges, falling back to TCP connect");
            tcp_connect_scan(target, config)
        }
        ScanType::Udp => udp_scan(target, config),
    }
}

fn tcp_connect_scan(target: &ScanTarget, config: &ScanConfig) -> Vec<PortResult> {
    let ports = if config.ports.is_empty() {
        common_ports()
    } else {
        config.ports.clone()
    };

    let total = ports.len();
    let completed = Arc::new(AtomicUsize::new(0));
    let results = std::sync::Mutex::new(Vec::with_capacity(total));

    let start = Instant::now();

    std::thread::scope(|s| {
        for chunk in ports.chunks(config.concurrency) {
            let chunk = chunk.to_vec();
            let results_ref = &results;
            let completed_ref = Arc::clone(&completed);
            let target_addr = target.addr;
            let timeout = config.timeout;

            s.spawn(move || {
                for port in chunk {
                    let state = probe_tcp_port(target_addr, port, timeout);
                    let service = if matches!(state, PortState::Open) {
                        grab_banner(&target_addr, port, timeout)
                    } else {
                        None
                    };

                    let mut results = results_ref.lock().unwrap();
                    results.push(PortResult {
                        port,
                        protocol: "tcp".to_string(),
                        state,
                        service,
                    });
                    let done = completed_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    if done.is_multiple_of(100) || done == total {
                        log::info!("TCP scan progress: {}/{} ports", done, total);
                    }
                }
            });
        }
    });

    let _elapsed = start.elapsed();
    log::info!("TCP scan finished: {} ports in {:?}", total, _elapsed);

    results.into_inner().unwrap()
}

fn probe_tcp_port(addr: IpAddr, port: u16, timeout: Duration) -> PortState {
    let sock_addr = (addr, port);
    match TcpStream::connect_timeout(&sock_addr.into(), timeout) {
        Ok(_) => PortState::Open,
        Err(e) => {
            if let Some(io_err) = e.raw_os_error() {
                match io_err {
                    11 | 111 | 61 | 146 => PortState::Closed,
                    110 | 60 | 78 => PortState::Filtered,
                    113 | 148 => PortState::Filtered,
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

pub fn grab_banner(addr: &IpAddr, port: u16, timeout: Duration) -> Option<ServiceInfo> {
    let sock_addr = (*addr, port);
    if let Ok(stream) = TcpStream::connect_timeout(&sock_addr.into(), timeout) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        let mut buf = vec![0u8; 1024];
        match stream.peek(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                let banner = String::from_utf8_lossy(&buf).to_string();
                let info = identify_service(port, &banner);
                Some(ServiceInfo {
                    name: info.0,
                    product: info.1,
                    version: info.2,
                    banner: Some(banner),
                })
            }
            _ => {
                let name = known_service_name(port);
                Some(ServiceInfo {
                    name: name.to_string(),
                    product: None,
                    version: None,
                    banner: None,
                })
            }
        }
    } else {
        let name = known_service_name(port);
        Some(ServiceInfo {
            name: name.to_string(),
            product: None,
            version: None,
            banner: None,
        })
    }
}

fn udp_scan(target: &ScanTarget, config: &ScanConfig) -> Vec<PortResult> {
    let ports = if config.ports.is_empty() {
        common_udp_ports()
    } else {
        config.ports.clone()
    };

    let results: Vec<PortResult> = ports
        .into_iter()
        .map(|port| {
            let state = probe_udp_port(target.addr, port, config.timeout);
            PortResult {
                port,
                protocol: "udp".to_string(),
                state,
                service: None,
            }
        })
        .collect();

    results
}

fn probe_udp_port(addr: IpAddr, port: u16, timeout: Duration) -> PortState {
    let sock_addr = (addr, port);
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            let _ = socket.set_read_timeout(Some(timeout));
            match socket.connect(sock_addr) {
                Ok(_) => {
                    let _ = socket.send(&[0u8; 1]);
                    let mut buf = [0u8; 1];
                    match socket.recv(&mut buf) {
                        Ok(_) => PortState::Open,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => PortState::Open,
                        Err(_) => PortState::Filtered,
                    }
                }
                Err(_) => PortState::Filtered,
            }
        }
        Err(_) => PortState::Filtered,
    }
}

fn identify_service(port: u16, banner: &str) -> (String, Option<String>, Option<String>) {
    let banner_lower = banner.to_lowercase();

    if banner_lower.contains("ssh") || banner_lower.contains("openssh") {
        let ver = extract_version(&banner_lower, "openssh");
        return ("SSH".to_string(), Some("OpenSSH".to_string()), ver);
    }
    if banner_lower.contains("http") || banner_lower.contains("nginx") || banner_lower.contains("apache") {
        let product: Option<String> = if banner_lower.contains("nginx") {
            Some("nginx".to_string())
        } else if banner_lower.contains("apache") {
            Some("Apache".to_string())
        } else {
            None
        };
        let ver = product.as_deref().and_then(|p| extract_version(&banner_lower, p));
        return ("HTTP".to_string(), product, ver);
    }
    if banner_lower.contains("ftp") || banner_lower.contains("220") {
        return ("FTP".to_string(), None, None);
    }
    if banner_lower.contains("smtp") || banner_lower.contains("esmtp") {
        return ("SMTP".to_string(), None, None);
    }
    if banner_lower.contains("pop3") {
        return ("POP3".to_string(), None, None);
    }
    if banner_lower.contains("imap") {
        return ("IMAP".to_string(), None, None);
    }
    if banner_lower.contains("mysql") {
        return ("MySQL".to_string(), None, None);
    }
    if banner_lower.contains("postgresql") || banner_lower.contains("psql") {
        return ("PostgreSQL".to_string(), None, None);
    }
    if banner_lower.contains("mongodb") {
        return ("MongoDB".to_string(), None, None);
    }
    if banner_lower.contains("redis") {
        return ("Redis".to_string(), None, None);
    }
    if banner_lower.contains("https") || port == 443 {
        return ("HTTPS".to_string(), None, None);
    }

    (known_service_name(port).to_string(), None, None)
}

fn extract_version(text: &str, product: &str) -> Option<String> {
    let re = regex::Regex::new(&format!(r"(?i){}\s*[ /-]?\s*v?(\d+\.\d+(?:\.\d+)?)", regex::escape(product))).ok()?;
    re.captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

pub fn known_service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        123 => "NTP",
        135 => "MS-RPC",
        137..=139 => "NetBIOS",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        500 => "IKE",
        514 => "Syslog",
        587 => "SMTP Submission",
        593 => "HTTP-RPC",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS Proxy",
        1194 => "OpenVPN",
        1352 => "Lotus Notes",
        1433 | 1434 => "MSSQL",
        1521 => "Oracle DB",
        1701 => "L2TP",
        1723 => "PPTP",
        2049 => "NFS",
        2082 | 2083 => "cPanel",
        2181 => "ZooKeeper",
        2222 => "DirectAdmin",
        2375 | 2376 => "Docker",
        2443 => "HTTPS Alt",
        2483 | 2484 => "Oracle DB",
        3128 => "Squid Proxy",
        3306 => "MySQL",
        3389 => "RDP",
        3478 => "STUN/TURN",
        3541 => "SIP",
        3689 => "DAAP",
        3690 => "SVN",
        4000 | 4040 => "HTTP Alt",
        4369 => "Erlang Port Mapper",
        4444 => "Metasploit Default",
        4500 => "IPsec NAT-T",
        4567 => "Sinatra",
        4647 => "TeamSpeak",
        4848 => "GlassFish",
        5000 => "HTTP Alt",
        5001 => "HTTP Alt",
        5003 => "FileMaker",
        5060 | 5061 => "SIP",
        5143 => "Bluetooth",
        5353 => "mDNS",
        5432 => "PostgreSQL",
        5555 => "Android ADB",
        5591 => "Oracle EM",
        5631 => "VNC",
        5666 => "NRPE",
        5672 => "AMQP",
        5800 | 5900 | 5901 => "VNC",
        5984 => "CouchDB",
        5985 | 5986 => "WinRM",
        6000 | 6001 => "X11",
        6379 => "Redis",
        6380 => "Redis TLS",
        6443 => "Kubernetes API",
        6580 => "Parrot",
        6660..=6669 => "IRC",
        6881..=6889 => "BitTorrent",
        7001 | 7002 => "WebLogic",
        7070 => "RTMP",
        8000 => "HTTP Alt",
        8008 => "HTTP Alt",
        8042 => "Asterisk",
        8069 => "Odoo",
        8080 => "HTTP Proxy",
        8081 => "HTTP Alt",
        8086 => "InfluxDB",
        8087 => "HTTP Alt",
        8088 => "HTTP Alt",
        8090 => "HTTP Alt",
        8118 => "Privoxy",
        8140 => "Puppet",
        8172 => "IIS",
        8200 => "Elasticsearch",
        8222 => "VMware",
        8333 => "Bitcoin",
        8403 => "CommFort",
        8443 => "HTTPS Alt",
        8500 => "Consul",
        8600 => "Consul DNS",
        8649 => "Ganglia",
        8888 => "HTTP Alt",
        9000 => "HTTP Alt",
        9001 => "HTTP Alt",
        9042 | 9043 => "Cassandra",
        9050 => "Tor SOCKS",
        9051 => "Tor Control",
        9090 => "Prometheus",
        9092 => "Kafka",
        9100 => "Print Server",
        9119 => "Syncthing",
        9200 => "Elasticsearch",
        9300 => "Elasticsearch Cluster",
        9418 => "Git",
        9443 => "HTTPS Alt",
        9999 => "HTTP Alt",
        10000 => "Webmin",
        10050 | 10051 => "Zabbix",
        10161 => "SNMP Alt",
        11211 => "Memcached",
        11214 => "Memcached SSL",
        12000 => "Cube",
        12345 => "NetBus",
        13722 => "BackupPC",
        14000 => "HTTP Alt",
        16010 => "HBase",
        16161 => "SNMP Alt",
        17000 => "HTTP Alt",
        18091 => "HTTP Alt",
        18092 => "HTTP Alt",
        19000 => "HTTP Alt",
        19200 => "Elasticsearch Alt",
        20000 => "Usermin",
        20080 => "HTTP Alt",
        20547 => "Proxmox",
        21025 => "Minecraft",
        21320 => "D-Bus",
        22000 => "Syncthing Alt",
        22222 => "SSH Alt",
        23073 => "Soldat",
        23399 => "Skype",
        24554 => "BGP",
        24800 => "Synergy",
        25565 => "Minecraft",
        26000 => "ZigBee",
        26257 => "CockroachDB",
        27015..=27017 => "Steam",
        27036 => "Steam",
        27374 => "Sub7",
        28015 => "Rust",
        28017 => "MongoDB Alt",
        28240 => "SIP Alt",
        28642 => "OpenVPN Alt",
        30718 => "Lantronix",
        31337 => "BackOrifice",
        32400 => "Plex",
        32764 => "Linksys",
        32822 => "SSH Alt",
        33434 => "Traceroute",
        33435 => "Traceroute",
        33848 => "Jenkins",
        34012 => "WebDAV",
        34443 => "HTTPS Alt",
        37777 => "Unreal",
        38865 => "SAP",
        39222 => "ETag",
        39779 => "Oozie",
        39821 => "OpenVPN Alt",
        41121 => "TerraMaster",
        41523 => "RouterOS",
        44334 => "HTTPS Alt",
        44818 => "EtherNet/IP",
        47808 => "BACnet",
        49152..=49156 => "Windows RPC",
        50000 => "SAP",
        50001 => "SAP",
        50070 => "Hadoop",
        50075 => "Hadoop",
        50090 => "Hadoop",
        50100 => "SAP Alt",
        50200 => "SAP Alt",
        50389 => "IIS",
        51103 => "SAP Alt",
        51234 => "SAP Alt",
        51400 => "SAP Alt",
        51515 => "SAP Alt",
        51820 => "WireGuard",
        53413 => "Netcore",
        54321 => "PostgreSQL Alt",
        55055 => "SAP Alt",
        55553 => "SAP Alt",
        55554 => "SAP Alt",
        56000 => "SAP Alt",
        56001 => "SAP Alt",
        57000 => "SAP Alt",
        57100 => "SAP Alt",
        57200 => "SAP Alt",
        57300 => "SAP Alt",
        57400 => "SAP Alt",
        57500 => "SAP Alt",
        57600 => "SAP Alt",
        57700 => "SAP Alt",
        57800 => "SAP Alt",
        57900 => "SAP Alt",
        58000 => "SAP Alt",
        58100 => "SAP Alt",
        58200 => "SAP Alt",
        58300 => "SAP Alt",
        58400 => "SAP Alt",
        58500 => "SAP Alt",
        58600 => "SAP Alt",
        58700 => "SAP Alt",
        58800 => "SAP Alt",
        58900 => "SAP Alt",
        59000 => "SAP Alt",
        59100 => "SAP Alt",
        59200 => "SAP Alt",
        59300 => "SAP Alt",
        59400 => "SAP Alt",
        59500 => "SAP Alt",
        59600 => "SAP Alt",
        59700 => "SAP Alt",
        59800 => "SAP Alt",
        59900 => "SAP Alt",
        60000 => "SAP Alt",
        60100 => "SAP Alt",
        60200 => "SAP Alt",
        60300 => "SAP Alt",
        60400 => "SAP Alt",
        60500 => "SAP Alt",
        60600 => "SAP Alt",
        60700 => "SAP Alt",
        60800 => "SAP Alt",
        60900 => "SAP Alt",
        61000 => "SAP Alt",
        61613 => "STOMP",
        61616 => "ActiveMQ",
        62078 => "iPhone Sync",
        63737 => "HTTP Alt",
        64738 => "Mumble",
        65000 => "SAP Alt",
        65100 => "SAP Alt",
        65200 => "SAP Alt",
        65300 => "SAP Alt",
        65301 => "SAP Alt",
        65302 => "SAP Alt",
        65303 => "SAP Alt",
        65304 => "SAP Alt",
        65305 => "SAP Alt",
        65306 => "SAP Alt",
        65307 => "SAP Alt",
        65308 => "SAP Alt",
        65309 => "SAP Alt",
        65310 => "SAP Alt",
        65535 => "Unknown",
        _ => "Unknown",
    }
}

fn common_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 162, 389,
        443, 445, 465, 500, 514, 587, 593, 636, 993, 995, 1080, 1194, 1352,
        1433, 1434, 1521, 1701, 1723, 2049, 2082, 2083, 2181, 2222, 2375,
        2376, 2443, 3128, 3306, 3389, 3478, 3541, 3690, 4000, 4040, 4369,
        4444, 4500, 4848, 5000, 5001, 5060, 5061, 5143, 5353, 5432, 5555,
        5631, 5666, 5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6379,
        6380, 6443, 6580, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667,
        6668, 6669, 7001, 7070, 7777, 7778, 8000, 8008, 8069, 8080, 8081,
        8086, 8087, 8088, 8090, 8118, 8140, 8172, 8200, 8222, 8333, 8403,
        8443, 8500, 8600, 8649, 8888, 9000, 9001, 9042, 9050, 9051, 9090,
        9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10050, 10051,
        11211, 12345, 13722, 16010, 20000, 21025, 22000, 22222, 23073,
        23399, 24800, 25565, 26000, 26257, 27015, 27016, 27017, 27036,
        27374, 28015, 28017, 30718, 31337, 32400, 32764, 32822, 33434,
        33435, 33848, 34443, 39222, 41121, 41523, 44818, 47808, 49152,
        49153, 49154, 49155, 49156, 50000, 50001, 50070, 50075, 50090,
        51820, 53413, 54321, 61613, 61616, 62078, 64738, 65535,
    ]
}

fn common_udp_ports() -> Vec<u16> {
    vec![
        53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 389, 445,
        500, 514, 520, 521, 524, 546, 547, 560, 563, 587, 623,
        631, 636, 993, 995, 1025, 1026, 1027, 1028, 1029,
        1112, 1194, 1381, 1433, 1434, 1474, 1571, 1645, 1646,
        1701, 1718, 1719, 1812, 1813, 1900, 1935, 1985, 1991,
        2000, 2002, 2030, 2048, 2049, 2051, 2101, 2200, 2222,
        2356, 3074, 3153, 3283, 3456, 3478, 3479, 3480, 3540,
        3541, 3542, 3543, 3544, 3659, 3691, 3702, 3723, 3784,
        4000, 4045, 4155, 4165, 4259, 4500, 4567, 4660, 4661,
        4662, 4664, 4665, 4672, 5000, 5050, 5060, 5093, 5190,
        5222, 5223, 5248, 5351, 5353, 5355, 5432, 5500, 5555,
        5631, 5632, 5678, 5679, 5681, 5683, 5684, 5696, 5700,
        5800, 5801, 5900, 5901, 6000, 6001, 6002, 6003, 6004,
        6010, 6039, 6050, 6060, 6070, 6080, 6090, 6100, 6110,
        6112, 6129, 6257, 6346, 6347, 6464, 6471, 6522, 6566,
        6588, 6670, 6671, 6699, 6700, 6701, 6726, 6771, 6788,
        6790, 6831, 6841, 6842, 6881, 6900, 6901, 6969, 6970,
        6971, 6994, 7000, 7001, 7002, 7003, 7004, 7005, 7006,
        7007, 7015, 7016, 7100, 7123, 7127, 7145, 7171, 7173,
        7174, 7200, 7202, 7252, 7300, 7306, 7307, 7308, 7310,
        7314, 7326, 7391, 7392, 7393, 7394, 7395, 7396, 7397,
        7398, 7399, 7400, 7401, 7402, 7420, 7421, 7435, 7441,
        7451, 7471, 7473, 7542, 7544, 7546, 7547, 7548, 7549,
        7550, 7551, 7560, 7563, 7566, 7569, 7570, 7571, 7574,
        7578, 7579, 7580, 7581, 7582, 7583, 7588, 7589, 7590,
        7591, 7592, 7593, 7594, 7595, 7596, 7597, 7598, 7599,
        8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008,
        8009, 8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017,
        8018, 8019, 8020, 8021, 8022, 8023, 8024, 8025, 8026,
        8027, 8028, 8029, 8030, 8173, 8190, 8191, 8200, 8300,
        8399, 8400, 8401, 8402, 8403, 8775, 8855, 8863, 8864,
        8875, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007,
        9008, 9009, 9010, 9011, 9012, 9013, 9014, 9015, 9016,
        9017, 9018, 9019, 9020, 9021, 9022, 9023, 9024, 9025,
        9026, 9027, 9028, 9029, 9030, 9050, 9051, 9100, 9101,
        9102, 9103, 9119, 9200, 9300, 9418, 10000, 10050, 10051,
        11211, 12345, 13722, 16010, 17000, 17185, 20000, 20031,
        21025, 22000, 22222, 23399, 24800, 25565, 26000, 27015,
        27016, 27017, 27018, 27019, 27020, 27374, 28015, 30718,
        31337, 32400, 32764, 32822, 34443, 39222, 41121, 41523,
        44818, 47808, 50000, 51820, 54321, 61613, 61616, 64738,
    ]
}
