use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use network::masscan::{IpRange, MasscanConfig, MasscanResult, PortRange};
use network::os::{OsFingerprint, TcpProbeResult};
use network::port::known_service_name;
use network::web::*;
use network::web_exploit::*;
use network::dns::*;
use network::*;

fn target_v4() -> ScanTarget {
    ScanTarget {
        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        hostname: Some("test.local".into()),
    }
}

fn target_v4_no_host() -> ScanTarget {
    ScanTarget {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        hostname: None,
    }
}

#[test]
fn scan_config_default_ports_empty() {
    let c = ScanConfig::default();
    assert!(c.ports.is_empty());
}

#[test]
fn scan_config_default_concurrency() {
    assert_eq!(ScanConfig::default().concurrency, 256);
}

#[test]
fn scan_config_default_timeout() {
    assert_eq!(ScanConfig::default().timeout, Duration::from_secs(3));
}

#[test]
fn scan_config_default_scan_type() {
    assert!(matches!(ScanConfig::default().scan_type, ScanType::TcpConnect));
}

#[test]
fn scan_config_custom() {
    let c = ScanConfig {
        ports: vec![22, 80, 443],
        concurrency: 100,
        timeout: Duration::from_secs(10),
        scan_type: ScanType::Udp,
    };
    assert_eq!(c.ports, vec![22, 80, 443]);
    assert_eq!(c.concurrency, 100);
    assert_eq!(c.timeout, Duration::from_secs(10));
    assert!(matches!(c.scan_type, ScanType::Udp));
}

#[test]
fn scan_type_tcp_connect_eq() {
    assert_eq!(ScanType::TcpConnect, ScanType::TcpConnect);
}

#[test]
fn scan_type_ne() {
    assert_ne!(ScanType::TcpConnect, ScanType::SynStealth);
}

#[test]
fn scan_type_clone() {
    let s = ScanType::Udp;
    let c = s.clone();
    assert_eq!(s, c);
}

#[test]
fn scan_type_copy() {
    let s = ScanType::SynStealth;
    let c: ScanType = s;
    assert_eq!(s, c);
}

#[test]
fn scan_type_debug() {
    assert_eq!(format!("{:?}", ScanType::TcpConnect), "TcpConnect");
    assert_eq!(format!("{:?}", ScanType::SynStealth), "SynStealth");
    assert_eq!(format!("{:?}", ScanType::Udp), "Udp");
}

#[test]
fn port_state_all_variants() {
    let _ = PortState::Open;
    let _ = PortState::Closed;
    let _ = PortState::Filtered;
    let _ = PortState::Unfiltered;
}

#[test]
fn port_state_eq() {
    assert_eq!(PortState::Open, PortState::Open);
    assert_ne!(PortState::Open, PortState::Closed);
}

#[test]
fn port_state_clone() {
    let s = PortState::Filtered;
    assert_eq!(s.clone(), PortState::Filtered);
}

#[test]
fn port_state_debug() {
    assert_eq!(format!("{:?}", PortState::Open), "Open");
}

#[test]
fn scan_target_with_hostname() {
    let t = target_v4();
    assert_eq!(t.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(t.hostname, Some("test.local".into()));
}

#[test]
fn scan_target_no_hostname() {
    let t = target_v4_no_host();
    assert!(t.hostname.is_none());
}

#[test]
fn scan_target_clone() {
    let t = target_v4();
    let c = t.clone();
    assert_eq!(c.addr, t.addr);
    assert_eq!(c.hostname, t.hostname);
}

#[test]
fn port_result_with_service() {
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
    assert!(pr.service.is_some());
}

#[test]
fn port_result_without_service() {
    let pr = PortResult {
        port: 80,
        protocol: "udp".into(),
        state: PortState::Closed,
        service: None,
    };
    assert!(pr.service.is_none());
}

#[test]
fn port_result_clone() {
    let pr = PortResult {
        port: 443,
        protocol: "tcp".into(),
        state: PortState::Open,
        service: None,
    };
    let c = pr.clone();
    assert_eq!(c.port, 443);
}

#[test]
fn service_info_all_fields() {
    let si = ServiceInfo {
        name: "HTTP".into(),
        product: Some("nginx".into()),
        version: Some("1.24.0".into()),
        banner: Some("HTTP/1.1 200 OK".into()),
    };
    assert_eq!(si.name, "HTTP");
    assert_eq!(si.product.as_deref(), Some("nginx"));
    assert_eq!(si.version.as_deref(), Some("1.24.0"));
    assert!(si.banner.is_some());
}

#[test]
fn service_info_no_optionals() {
    let si = ServiceInfo {
        name: "Unknown".into(),
        product: None,
        version: None,
        banner: None,
    };
    assert!(si.product.is_none());
    assert!(si.version.is_none());
    assert!(si.banner.is_none());
}

#[test]
fn service_info_clone() {
    let si = ServiceInfo { name: "SSH".into(), product: None, version: None, banner: None };
    let c = si.clone();
    assert_eq!(c.name, "SSH");
}

#[test]
fn scan_summary_new() {
    let s = ScanSummary::new(target_v4());
    assert_eq!(s.total_ports, 0);
    assert!(s.open_ports.is_empty());
    assert!(s.filtered_ports.is_empty());
    assert!(s.closed_ports.is_empty());
    assert_eq!(s.scan_duration, Duration::default());
    assert!(s.os_fingerprint.is_none());
    assert!(s.dns_records.is_none());
}

#[test]
fn scan_summary_new_target_addr() {
    let t = target_v4();
    let s = ScanSummary::new(t.clone());
    assert_eq!(s.target.addr, t.addr);
}

#[test]
fn scan_summary_modification() {
    let mut s = ScanSummary::new(target_v4());
    s.total_ports = 1000;
    s.open_ports.push(PortResult {
        port: 80,
        protocol: "tcp".into(),
        state: PortState::Open,
        service: None,
    });
    s.scan_duration = Duration::from_secs(5);
    assert_eq!(s.total_ports, 1000);
    assert_eq!(s.open_ports.len(), 1);
    assert_eq!(s.scan_duration, Duration::from_secs(5));
}

#[test]
fn default_timeout() {
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(3));
}

#[test]
fn default_concurrency() {
    assert_eq!(DEFAULT_CONCURRENCY, 256);
}

#[test]
fn known_service_ssh() {
    assert_eq!(known_service_name(22), "SSH");
}

#[test]
fn known_service_http() {
    assert_eq!(known_service_name(80), "HTTP");
}

#[test]
fn known_service_https() {
    assert_eq!(known_service_name(443), "HTTPS");
}

#[test]
fn known_service_ftp() {
    assert_eq!(known_service_name(21), "FTP");
}

#[test]
fn known_service_smtp() {
    assert_eq!(known_service_name(25), "SMTP");
}

#[test]
fn known_service_dns() {
    assert_eq!(known_service_name(53), "DNS");
}

#[test]
fn known_service_mysql() {
    assert_eq!(known_service_name(3306), "MySQL");
}

#[test]
fn known_service_postgres() {
    assert_eq!(known_service_name(5432), "PostgreSQL");
}

#[test]
fn known_service_redis() {
    assert_eq!(known_service_name(6379), "Redis");
}

#[test]
fn known_service_mongodb_range() {
    assert_eq!(known_service_name(27015), "Steam");
}

#[test]
fn known_service_rdp() {
    assert_eq!(known_service_name(3389), "RDP");
}

#[test]
fn known_service_netbios_range() {
    assert_eq!(known_service_name(137), "NetBIOS");
    assert_eq!(known_service_name(138), "NetBIOS");
    assert_eq!(known_service_name(139), "NetBIOS");
}

#[test]
fn known_service_irc_range() {
    assert_eq!(known_service_name(6660), "IRC");
    assert_eq!(known_service_name(6669), "IRC");
}

#[test]
fn known_service_bittorrent_range() {
    assert_eq!(known_service_name(6881), "BitTorrent");
    assert_eq!(known_service_name(6889), "BitTorrent");
}

#[test]
fn known_service_windows_rpc_range() {
    assert_eq!(known_service_name(49152), "Windows RPC");
    assert_eq!(known_service_name(49156), "Windows RPC");
}

#[test]
fn known_service_unknown() {
    assert_eq!(known_service_name(65535), "Unknown");
}

#[test]
fn known_service_ldap() {
    assert_eq!(known_service_name(389), "LDAP");
}

#[test]
fn known_service_kubernetes() {
    assert_eq!(known_service_name(6443), "Kubernetes API");
}

#[test]
fn known_service_docker() {
    assert_eq!(known_service_name(2375), "Docker");
}

#[test]
fn known_service_wireguard() {
    assert_eq!(known_service_name(51820), "WireGuard");
}

#[test]
fn known_service_zookeeper() {
    assert_eq!(known_service_name(2181), "ZooKeeper");
}

#[test]
fn known_service_kafka() {
    assert_eq!(known_service_name(9092), "Kafka");
}

#[test]
fn known_service_elasticsearch() {
    assert_eq!(known_service_name(9200), "Elasticsearch");
}

#[test]
fn known_service_prometheus() {
    assert_eq!(known_service_name(9090), "Prometheus");
}

#[test]
fn known_service_bitcoin() {
    assert_eq!(known_service_name(8333), "Bitcoin");
}

#[test]
fn known_service_plex() {
    assert_eq!(known_service_name(32400), "Plex");
}

#[test]
fn known_service_minecraft() {
    assert_eq!(known_service_name(25565), "Minecraft");
}

#[test]
fn known_service_pop3() {
    assert_eq!(known_service_name(110), "POP3");
}

#[test]
fn known_service_imap() {
    assert_eq!(known_service_name(143), "IMAP");
}

#[test]
fn known_service_telnet() {
    assert_eq!(known_service_name(23), "Telnet");
}

#[test]
fn known_service_ntp() {
    assert_eq!(known_service_name(123), "NTP");
}

#[test]
fn known_service_smb() {
    assert_eq!(known_service_name(445), "SMB");
}

#[test]
fn known_service_oracle() {
    assert_eq!(known_service_name(1521), "Oracle DB");
}

#[test]
fn known_service_memcached() {
    assert_eq!(known_service_name(11211), "Memcached");
}

#[test]
fn masscan_config_default_targets_empty() {
    let c = MasscanConfig::default();
    assert!(c.targets.is_empty());
}

#[test]
fn masscan_config_default_ports() {
    let c = MasscanConfig::default();
    assert_eq!(c.ports.len(), 1);
    assert_eq!(c.ports[0].start, 1);
    assert_eq!(c.ports[0].end, 1024);
}

#[test]
fn masscan_config_default_concurrency() {
    assert_eq!(MasscanConfig::default().concurrency, 10000);
}

#[test]
fn masscan_config_default_timeout() {
    assert_eq!(MasscanConfig::default().timeout, Duration::from_secs(3));
}

#[test]
fn masscan_config_default_rate_limit() {
    assert!(MasscanConfig::default().rate_limit.is_none());
}

#[test]
fn masscan_add_cidr_30() {
    let mut c = MasscanConfig::default();
    c.add_cidr("192.168.1.0/30").unwrap();
    assert_eq!(c.targets.len(), 1);
    assert_eq!(c.total_ips(), 2);
}

#[test]
fn masscan_add_cidr_32() {
    let mut c = MasscanConfig::default();
    c.add_cidr("10.0.0.1/32").unwrap();
    assert_eq!(c.total_ips(), 1);
}

#[test]
fn masscan_add_cidr_invalid() {
    let mut c = MasscanConfig::default();
    assert!(c.add_cidr("invalid").is_err());
}

#[test]
fn masscan_add_cidr_bad_prefix() {
    let mut c = MasscanConfig::default();
    assert!(c.add_cidr("10.0.0.0/33").is_err());
}

#[test]
fn masscan_add_port() {
    let mut c = MasscanConfig::default();
    c.add_port(80);
    assert_eq!(c.ports.len(), 2);
    assert_eq!(c.ports[1].start, 80);
    assert_eq!(c.ports[1].end, 80);
}

#[test]
fn masscan_add_port_range() {
    let mut c = MasscanConfig::default();
    c.add_port_range(1000, 2000);
    assert_eq!(c.ports.len(), 2);
    assert_eq!(c.ports[1].start, 1000);
    assert_eq!(c.ports[1].end, 2000);
}

#[test]
fn masscan_total_ports() {
    let mut c = MasscanConfig::default();
    c.ports.clear();
    c.add_port_range(80, 85);
    assert_eq!(c.total_ports(), 6);
}

#[test]
fn masscan_total_ports_empty() {
    let c = MasscanConfig { targets: vec![], ports: vec![], concurrency: 100, timeout: Duration::from_secs(1), rate_limit: None };
    assert_eq!(c.total_ports(), 0);
}

#[test]
fn masscan_total_ips() {
    let mut c = MasscanConfig::default();
    c.add_cidr("10.0.0.0/30").unwrap();
    assert_eq!(c.total_ips(), 2);
}

#[test]
fn masscan_total_probes() {
    let mut c = MasscanConfig::default();
    c.ports.clear();
    c.add_port(80);
    c.add_port(443);
    c.add_cidr("10.0.0.0/30").unwrap();
    assert_eq!(c.total_probes(), 4);
}

#[test]
fn masscan_total_probes_zero() {
    let c = MasscanConfig { targets: vec![], ports: vec![], concurrency: 100, timeout: Duration::from_secs(1), rate_limit: None };
    assert_eq!(c.total_probes(), 0);
}

#[test]
fn masscan_result_struct() {
    let r = MasscanResult {
        target: target_v4(),
        results: vec![],
        scan_duration: Duration::from_secs(1),
        ips_scanned: 1,
        total_probes: 10,
    };
    assert_eq!(r.ips_scanned, 1);
    assert_eq!(r.total_probes, 10);
    assert!(r.results.is_empty());
}

#[test]
fn masscan_result_clone() {
    let r = MasscanResult {
        target: target_v4(),
        results: vec![],
        scan_duration: Duration::from_millis(500),
        ips_scanned: 5,
        total_probes: 50,
    };
    let c = r.clone();
    assert_eq!(c.ips_scanned, 5);
}

#[test]
fn masscan_ip_range_struct() {
    let r = IpRange {
        start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
    };
    assert_eq!(r.start, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(r.end, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
}

#[test]
fn masscan_port_range_struct() {
    let r = PortRange { start: 80, end: 443 };
    assert_eq!(r.start, 80);
    assert_eq!(r.end, 443);
}

#[test]
fn masscan_port_range_clone() {
    let r = PortRange { start: 22, end: 22 };
    let c = r.clone();
    assert_eq!(c.start, 22);
    assert_eq!(c.end, 22);
}

#[test]
fn masscan_scan_range_invalid_cidr() {
    let result = network::masscan::scan_range("invalid", &[80]);
    assert!(result.is_err());
}

#[test]
fn os_fingerprint_struct() {
    let fp = OsFingerprint {
        os_name: "Linux".into(),
        os_family: "Linux".into(),
        accuracy: 0.85,
        ttl: 64,
        tcp_window_size: Some(65535),
        tcp_options: vec!["MSS".into()],
        distance_hops: Some(3),
        evidence: vec!["test".into()],
    };
    assert_eq!(fp.os_name, "Linux");
    assert_eq!(fp.accuracy, 0.85);
    assert_eq!(fp.ttl, 64);
    assert_eq!(fp.tcp_window_size, Some(65535));
}

#[test]
fn os_fingerprint_clone() {
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
    let c = fp.clone();
    assert_eq!(c.os_name, "Windows");
    assert_eq!(c.ttl, 128);
}

#[test]
fn os_fingerprint_empty() {
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
}

#[test]
fn tcp_probe_result_struct() {
    let r = TcpProbeResult {
        ttl: 64,
        window_size: 65535,
        ip_id: 42,
        df_bit: true,
    };
    assert_eq!(r.ttl, 64);
    assert_eq!(r.window_size, 65535);
    assert_eq!(r.ip_id, 42);
    assert!(r.df_bit);
}

#[test]
fn tcp_probe_result_clone() {
    let r = TcpProbeResult { ttl: 128, window_size: 8192, ip_id: 100, df_bit: false };
    let c = r.clone();
    assert_eq!(c.ttl, 128);
    assert!(!c.df_bit);
}

#[test]
fn tcp_probe_result_false_df() {
    let r = TcpProbeResult { ttl: 100, window_size: 4096, ip_id: 0, df_bit: false };
    assert!(!r.df_bit);
}

#[test]
fn dns_records_struct() {
    let dr = DnsRecords {
        domain: "example.com".into(),
        a_records: vec!["1.2.3.4".into()],
        aaaa_records: vec![],
        mx_records: vec![MxRecord { preference: 10, exchange: "mail.example.com".into() }],
        ns_records: vec!["ns1.example.com".into()],
        txt_records: vec!["v=spf1 include:_spf.google.com ~all".into()],
        cname_records: vec![],
        soa_record: None,
        subdomains: vec![],
    };
    assert_eq!(dr.domain, "example.com");
    assert_eq!(dr.a_records.len(), 1);
    assert!(dr.aaaa_records.is_empty());
    assert_eq!(dr.mx_records.len(), 1);
    assert_eq!(dr.ns_records.len(), 1);
    assert_eq!(dr.txt_records.len(), 1);
    assert!(dr.soa_record.is_none());
}

#[test]
fn dns_records_clone() {
    let dr = DnsRecords {
        domain: "test.com".into(),
        a_records: vec![],
        aaaa_records: vec![],
        mx_records: vec![],
        ns_records: vec![],
        txt_records: vec![],
        cname_records: vec![],
        soa_record: None,
        subdomains: vec![],
    };
    let c = dr.clone();
    assert_eq!(c.domain, "test.com");
}

#[test]
fn mx_record_struct() {
    let mx = MxRecord { preference: 10, exchange: "mx1.example.com".into() };
    assert_eq!(mx.preference, 10);
    assert_eq!(mx.exchange, "mx1.example.com");
}

#[test]
fn mx_record_clone() {
    let mx = MxRecord { preference: 20, exchange: "mx2.example.com".into() };
    let c = mx.clone();
    assert_eq!(c.preference, 20);
}

#[test]
fn soa_record_struct() {
    let soa = SoaRecord {
        mname: "ns1.example.com".into(),
        rname: "admin.example.com".into(),
        serial: 2023100101,
        refresh: 3600,
        retry: 900,
        expire: 604800,
        minimum: 86400,
    };
    assert_eq!(soa.serial, 2023100101);
    assert_eq!(soa.refresh, 3600);
}

#[test]
fn soa_record_clone() {
    let soa = SoaRecord {
        mname: "ns1.example.com".into(),
        rname: "admin.example.com".into(),
        serial: 1,
        refresh: 1,
        retry: 1,
        expire: 1,
        minimum: 1,
    };
    let c = soa.clone();
    assert_eq!(c.serial, 1);
}

#[test]
fn subdomain_result_struct() {
    let sr = SubdomainResult {
        name: "api.example.com".into(),
        ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        is_alive: true,
        takeover: None,
    };
    assert_eq!(sr.name, "api.example.com");
    assert!(sr.is_alive);
    assert!(sr.takeover.is_none());
}

#[test]
fn subdomain_result_with_takeover() {
    let sr = SubdomainResult {
        name: "old.example.com".into(),
        ip_addresses: vec![],
        is_alive: false,
        takeover: Some(TakeoverInfo {
            service: "GitHub Pages".into(),
            vulnerable: true,
            evidence: "CNAME points to github.io".into(),
        }),
    };
    let t = sr.takeover.unwrap();
    assert!(t.vulnerable);
    assert_eq!(t.service, "GitHub Pages");
}

#[test]
fn takeover_info_struct() {
    let t = TakeoverInfo {
        service: "Heroku".into(),
        vulnerable: true,
        evidence: "herokuapp.com".into(),
    };
    assert_eq!(t.service, "Heroku");
    assert!(t.vulnerable);
}

#[test]
fn takeover_info_clone() {
    let t = TakeoverInfo {
        service: "Netlify".into(),
        vulnerable: false,
        evidence: "none".into(),
    };
    let c = t.clone();
    assert!(!c.vulnerable);
}

#[test]
fn web_scan_config_default_base_url() {
    assert!(WebScanConfig::default().base_url.is_empty());
}

#[test]
fn web_scan_config_default_wordlist() {
    assert!(WebScanConfig::default().wordlist.is_empty());
}

#[test]
fn web_scan_config_default_extensions_not_empty() {
    assert!(!WebScanConfig::default().extensions.is_empty());
}

#[test]
fn web_scan_config_default_concurrency() {
    assert_eq!(WebScanConfig::default().concurrency, 32);
}

#[test]
fn web_scan_config_default_follow_redirects() {
    assert!(!WebScanConfig::default().follow_redirects);
}

#[test]
fn web_scan_config_default_cookies() {
    assert!(WebScanConfig::default().cookies.is_empty());
}

#[test]
fn web_scan_config_default_user_agent() {
    assert!(!WebScanConfig::default().user_agent.is_empty());
}

#[test]
fn web_scan_config_custom() {
    let mut cookies = HashMap::new();
    cookies.insert("session".into(), "abc123".into());
    let c = WebScanConfig {
        base_url: "http://example.com".into(),
        wordlist: vec!["admin".into()],
        extensions: vec![".php".into()],
        concurrency: 10,
        timeout: Duration::from_secs(5),
        follow_redirects: true,
        user_agent: "test".into(),
        cookies,
    };
    assert_eq!(c.base_url, "http://example.com");
    assert_eq!(c.wordlist.len(), 1);
    assert_eq!(c.extensions.len(), 1);
    assert_eq!(c.concurrency, 10);
    assert!(c.follow_redirects);
    assert_eq!(c.cookies.len(), 1);
}

#[test]
fn fuzz_result_struct() {
    let fr = FuzzResult {
        url: "http://example.com/admin".into(),
        status: 200,
        size: 1024,
        content_type: Some("text/html".into()),
        title: Some("Admin".into()),
        is_directory: true,
        redirected_to: None,
    };
    assert_eq!(fr.status, 200);
    assert!(fr.is_directory);
}

#[test]
fn fuzz_result_clone() {
    let fr = FuzzResult {
        url: "test".into(),
        status: 404,
        size: 0,
        content_type: None,
        title: None,
        is_directory: false,
        redirected_to: None,
    };
    let c = fr.clone();
    assert_eq!(c.status, 404);
}

#[test]
fn fuzz_result_with_redirect() {
    let fr = FuzzResult {
        url: "http://example.com/old".into(),
        status: 301,
        size: 0,
        content_type: None,
        title: None,
        is_directory: false,
        redirected_to: Some("http://example.com/new".into()),
    };
    assert_eq!(fr.redirected_to.as_deref(), Some("http://example.com/new"));
}

#[test]
fn vhost_result_struct() {
    let vr = VHostResult {
        host: "admin.example.com".into(),
        status: 200,
        size: 512,
        content_type: Some("text/html".into()),
        different_from_base: true,
        serves_same_content: false,
    };
    assert!(vr.different_from_base);
    assert!(!vr.serves_same_content);
}

#[test]
fn vhost_result_clone() {
    let vr = VHostResult {
        host: "test".into(),
        status: 200,
        size: 0,
        content_type: None,
        different_from_base: false,
        serves_same_content: true,
    };
    let c = vr.clone();
    assert!(c.serves_same_content);
}

#[test]
fn param_result_struct() {
    let pr = ParamResult {
        parameter: "id".into(),
        url: "http://example.com/?id=1".into(),
        status: 200,
        response_time_ms: 50,
        reflected: true,
        size_diff: 100,
    };
    assert!(pr.reflected);
    assert_eq!(pr.response_time_ms, 50);
}

#[test]
fn param_result_clone() {
    let pr = ParamResult {
        parameter: "q".into(),
        url: "test".into(),
        status: 200,
        response_time_ms: 0,
        reflected: false,
        size_diff: 0,
    };
    let c = pr.clone();
    assert!(!c.reflected);
}

#[test]
fn waf_info_struct() {
    let wi = WafInfo {
        detected: true,
        name: Some("Cloudflare".into()),
        evidence: vec!["server header".into()],
    };
    assert!(wi.detected);
    assert_eq!(wi.name.as_deref(), Some("Cloudflare"));
}

#[test]
fn waf_info_not_detected() {
    let wi = WafInfo { detected: false, name: None, evidence: vec![] };
    assert!(!wi.detected);
}

#[test]
fn waf_info_clone() {
    let wi = WafInfo { detected: true, name: None, evidence: vec![] };
    let c = wi.clone();
    assert!(c.detected);
}

#[test]
fn tech_entry_struct() {
    let te = TechEntry {
        name: "nginx".into(),
        version: Some("1.24".into()),
        category: "Web server".into(),
        confidence: 0.9,
        evidence: "Server header".into(),
    };
    assert_eq!(te.confidence, 0.9);
    assert!(te.version.is_some());
}

#[test]
fn tech_entry_clone() {
    let te = TechEntry {
        name: "PHP".into(),
        version: None,
        category: "Language".into(),
        confidence: 0.7,
        evidence: "test".into(),
    };
    let c = te.clone();
    assert!(c.version.is_none());
}

#[test]
fn cms_info_struct() {
    let ci = CmsInfo {
        name: Some("WordPress".into()),
        version: Some("6.4".into()),
        plugins: vec![("akismet".into(), Some("5.1".into()))],
        themes: vec![("flavor".into(), None)],
        confidence: 0.9,
    };
    assert_eq!(ci.name.as_deref(), Some("WordPress"));
    assert_eq!(ci.plugins.len(), 1);
    assert_eq!(ci.themes.len(), 1);
}

#[test]
fn cms_info_no_name() {
    let ci = CmsInfo { name: None, version: None, plugins: vec![], themes: vec![], confidence: 0.0 };
    assert!(ci.name.is_none());
    assert_eq!(ci.confidence, 0.0);
}

#[test]
fn cms_info_clone() {
    let ci = CmsInfo { name: None, version: None, plugins: vec![], themes: vec![], confidence: 0.0 };
    let c = ci.clone();
    assert!(c.name.is_none());
}

#[test]
fn js_endpoint_struct() {
    let je = JsEndpoint {
        url: "http://example.com/app.js".into(),
        endpoint: "/api/v1/users".into(),
        context: Some("API endpoint".into()),
    };
    assert!(je.context.is_some());
}

#[test]
fn js_endpoint_no_context() {
    let je = JsEndpoint { url: "test".into(), endpoint: "/test".into(), context: None };
    assert!(je.context.is_none());
}

#[test]
fn js_endpoint_clone() {
    let je = JsEndpoint { url: "a".into(), endpoint: "b".into(), context: None };
    let c = je.clone();
    assert_eq!(c.url, "a");
}

#[test]
fn robots_info_exists() {
    let ri = RobotsInfo {
        exists: true,
        sitemaps: vec!["http://example.com/sitemap.xml".into()],
        allowed: vec!["/public".into()],
        disallowed: vec!["/admin".into()],
        crawl_delay: Some(10),
    };
    assert!(ri.exists);
    assert_eq!(ri.sitemaps.len(), 1);
    assert_eq!(ri.disallowed.len(), 1);
    assert_eq!(ri.crawl_delay, Some(10));
}

#[test]
fn robots_info_not_exists() {
    let ri = RobotsInfo {
        exists: false,
        sitemaps: vec![],
        allowed: vec![],
        disallowed: vec![],
        crawl_delay: None,
    };
    assert!(!ri.exists);
}

#[test]
fn robots_info_clone() {
    let ri = RobotsInfo { exists: true, sitemaps: vec![], allowed: vec![], disallowed: vec![], crawl_delay: None };
    let c = ri.clone();
    assert!(c.exists);
}

#[test]
fn severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn severity_not_equal() {
    assert_ne!(Severity::High, Severity::Low);
}

#[test]
fn severity_clone() {
    let s = Severity::Critical;
    let c = s.clone();
    assert_eq!(c, Severity::Critical);
}

#[test]
fn severity_copy() {
    let s = Severity::Medium;
    let c: Severity = s;
    assert_eq!(c, Severity::Medium);
}

#[test]
fn severity_debug() {
    assert_eq!(format!("{:?}", Severity::Info), "Info");
    assert_eq!(format!("{:?}", Severity::Critical), "Critical");
}

#[test]
fn vuln_result_struct() {
    let vr = VulnResult {
        vuln_type: "SQL Injection".into(),
        parameter: "id".into(),
        url: "http://example.com/page".into(),
        severity: Severity::Critical,
        payload: "' OR 1=1--".into(),
        evidence: "SQL error".into(),
        confidence: 0.85,
        cwe: Some("CWE-89".into()),
    };
    assert_eq!(vr.severity, Severity::Critical);
    assert_eq!(vr.confidence, 0.85);
}

#[test]
fn vuln_result_no_cwe() {
    let vr = VulnResult {
        vuln_type: "Info Leak".into(),
        parameter: "".into(),
        url: "test".into(),
        severity: Severity::Info,
        payload: "".into(),
        evidence: "".into(),
        confidence: 0.5,
        cwe: None,
    };
    assert!(vr.cwe.is_none());
}

#[test]
fn vuln_result_clone() {
    let vr = VulnResult {
        vuln_type: "XSS".into(),
        parameter: "q".into(),
        url: "test".into(),
        severity: Severity::High,
        payload: "<script>".into(),
        evidence: "reflected".into(),
        confidence: 0.8,
        cwe: Some("CWE-79".into()),
    };
    let c = vr.clone();
    assert_eq!(c.severity, Severity::High);
}

#[test]
fn sqli_result_struct() {
    let sr = SqliResult {
        vulnerable: true,
        injection_type: "Error-based".into(),
        parameter: "id".into(),
        payload: "'".into(),
        evidence: "MySQL error".into(),
        confidence: 0.85,
    };
    assert!(sr.vulnerable);
}

#[test]
fn sqli_result_not_vulnerable() {
    let sr = SqliResult {
        vulnerable: false,
        injection_type: "".into(),
        parameter: "".into(),
        payload: "".into(),
        evidence: "".into(),
        confidence: 0.0,
    };
    assert!(!sr.vulnerable);
}

#[test]
fn sqli_result_clone() {
    let sr = SqliResult {
        vulnerable: true,
        injection_type: "Union".into(),
        parameter: "q".into(),
        payload: "UNION".into(),
        evidence: "evidence".into(),
        confidence: 0.7,
    };
    let c = sr.clone();
    assert!(c.vulnerable);
}

#[test]
fn nosqli_result_struct() {
    let nr = NoSqliResult {
        vulnerable: true,
        db_type: "MongoDB $ne".into(),
        parameter: "user".into(),
        payload: "[$ne]=1".into(),
        evidence: "Response changed".into(),
    };
    assert!(nr.vulnerable);
    assert!(nr.db_type.contains("MongoDB"));
}

#[test]
fn nosqli_result_clone() {
    let nr = NoSqliResult {
        vulnerable: false,
        db_type: "".into(),
        parameter: "".into(),
        payload: "".into(),
        evidence: "".into(),
    };
    let c = nr.clone();
    assert!(!c.vulnerable);
}

#[test]
fn xss_result_struct() {
    let xr = XssResult {
        vulnerable: true,
        xss_type: "Reflected XSS".into(),
        parameter: "q".into(),
        payload: "<script>alert(1)</script>".into(),
        evidence: "reflected".into(),
        confidence: 0.85,
    };
    assert!(xr.vulnerable);
    assert!(xr.xss_type.contains("XSS"));
}

#[test]
fn xss_result_clone() {
    let xr = XssResult {
        vulnerable: false,
        xss_type: "".into(),
        parameter: "".into(),
        payload: "".into(),
        evidence: "".into(),
        confidence: 0.0,
    };
    let c = xr.clone();
    assert!(!c.vulnerable);
}

#[test]
fn cmd_injection_result_struct() {
    let cr = CmdInjectionResult {
        vulnerable: true,
        parameter: "cmd".into(),
        payload: "; ls".into(),
        evidence: "file listing".into(),
        os_type: Some("Linux/Unix".into()),
    };
    assert!(cr.vulnerable);
    assert_eq!(cr.os_type.as_deref(), Some("Linux/Unix"));
}

#[test]
fn cmd_injection_result_no_os() {
    let cr = CmdInjectionResult {
        vulnerable: false,
        parameter: "".into(),
        payload: "".into(),
        evidence: "".into(),
        os_type: None,
    };
    assert!(cr.os_type.is_none());
}

#[test]
fn cmd_injection_result_clone() {
    let cr = CmdInjectionResult {
        vulnerable: true,
        parameter: "p".into(),
        payload: "p".into(),
        evidence: "e".into(),
        os_type: Some("Windows".into()),
    };
    let c = cr.clone();
    assert!(c.vulnerable);
}

#[test]
fn lfi_result_struct() {
    let lr = LfiResult {
        vulnerable: true,
        lfi_type: "Local File Inclusion".into(),
        parameter: "file".into(),
        payload: "../../../../etc/passwd".into(),
        evidence: "root: found".into(),
    };
    assert!(lr.vulnerable);
    assert!(lr.evidence.contains("root"));
}

#[test]
fn lfi_result_clone() {
    let lr = LfiResult {
        vulnerable: false,
        lfi_type: "".into(),
        parameter: "".into(),
        payload: "".into(),
        evidence: "".into(),
    };
    let c = lr.clone();
    assert!(!c.vulnerable);
}

#[test]
fn ssti_result_struct() {
    let sr = SstiResult {
        vulnerable: true,
        engine: "Jinja2".into(),
        parameter: "name".into(),
        payload: "{{7*7}}".into(),
        evidence: "49 in response".into(),
    };
    assert!(sr.vulnerable);
    assert!(sr.engine.contains("Jinja"));
}

#[test]
fn ssti_result_clone() {
    let sr = SstiResult {
        vulnerable: false,
        engine: "".into(),
        parameter: "".into(),
        payload: "".into(),
        evidence: "".into(),
    };
    let c = sr.clone();
    assert!(!c.vulnerable);
}

#[test]
fn csrf_result_struct() {
    let cr = CsrfResult {
        vulnerable: true,
        form_action: "/login".into(),
        evidence: "No CSRF token".into(),
        missing_token: true,
    };
    assert!(cr.vulnerable);
    assert!(cr.missing_token);
}

#[test]
fn csrf_result_not_vulnerable() {
    let cr = CsrfResult {
        vulnerable: false,
        form_action: "".into(),
        evidence: "".into(),
        missing_token: false,
    };
    assert!(!cr.vulnerable);
    assert!(!cr.missing_token);
}

#[test]
fn csrf_result_clone() {
    let cr = CsrfResult {
        vulnerable: true,
        form_action: "/submit".into(),
        evidence: "missing".into(),
        missing_token: true,
    };
    let c = cr.clone();
    assert!(c.missing_token);
}

#[test]
fn exploit_progress_struct() {
    let mut data = HashMap::new();
    data.insert("key".into(), "value".into());
    let ep = ExploitProgress {
        extracted_data: data,
        tables_found: vec!["users".into()],
        row_count: 42,
        is_complete: false,
    };
    assert_eq!(ep.row_count, 42);
    assert!(!ep.is_complete);
}

#[test]
fn exploit_progress_complete() {
    let ep = ExploitProgress {
        extracted_data: HashMap::new(),
        tables_found: vec![],
        row_count: 0,
        is_complete: true,
    };
    assert!(ep.is_complete);
}

#[test]
fn exploit_progress_clone() {
    let ep = ExploitProgress {
        extracted_data: HashMap::new(),
        tables_found: vec!["t1".into()],
        row_count: 1,
        is_complete: false,
    };
    let c = ep.clone();
    assert_eq!(c.row_count, 1);
}

#[test]
fn scan_target_serde_roundtrip() {
    let t = target_v4();
    let json = serde_json::to_string(&t).unwrap();
    let back: ScanTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(back.addr, t.addr);
    assert_eq!(back.hostname, t.hostname);
}

#[test]
fn scan_config_serde_roundtrip() {
    let c = ScanConfig {
        ports: vec![22, 80],
        concurrency: 50,
        timeout: Duration::from_secs(7),
        scan_type: ScanType::SynStealth,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: ScanConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.ports, vec![22, 80]);
    assert_eq!(back.concurrency, 50);
    assert!(matches!(back.scan_type, ScanType::SynStealth));
}

#[test]
fn scan_type_serde_roundtrip() {
    for st in [ScanType::TcpConnect, ScanType::SynStealth, ScanType::Udp] {
        let json = serde_json::to_string(&st).unwrap();
        let back: ScanType = serde_json::from_str(&json).unwrap();
        assert_eq!(st, back);
    }
}

#[test]
fn port_state_serde_roundtrip() {
    for ps in [PortState::Open, PortState::Closed, PortState::Filtered, PortState::Unfiltered] {
        let json = serde_json::to_string(&ps).unwrap();
        let back: PortState = serde_json::from_str(&json).unwrap();
        assert_eq!(ps, back);
    }
}

#[test]
fn port_result_serde_roundtrip() {
    let pr = PortResult {
        port: 80,
        protocol: "tcp".into(),
        state: PortState::Open,
        service: Some(ServiceInfo {
            name: "HTTP".into(),
            product: Some("nginx".into()),
            version: None,
            banner: None,
        }),
    };
    let json = serde_json::to_string(&pr).unwrap();
    let back: PortResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.port, 80);
    assert_eq!(back.state, PortState::Open);
}

#[test]
fn service_info_serde_roundtrip() {
    let si = ServiceInfo {
        name: "SSH".into(),
        product: Some("OpenSSH".into()),
        version: Some("9.3".into()),
        banner: Some("SSH-2.0".into()),
    };
    let json = serde_json::to_string(&si).unwrap();
    let back: ServiceInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, "SSH");
    assert_eq!(back.product.as_deref(), Some("OpenSSH"));
}

#[test]
fn scan_summary_serde_roundtrip() {
    let s = ScanSummary::new(target_v4());
    let json = serde_json::to_string(&s).unwrap();
    let back: ScanSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_ports, 0);
    assert!(back.open_ports.is_empty());
}

#[test]
fn os_fingerprint_serde_roundtrip() {
    let fp = OsFingerprint {
        os_name: "Linux".into(),
        os_family: "Linux".into(),
        accuracy: 0.85,
        ttl: 64,
        tcp_window_size: Some(65535),
        tcp_options: vec!["MSS".into()],
        distance_hops: Some(3),
        evidence: vec!["test".into()],
    };
    let json = serde_json::to_string(&fp).unwrap();
    let back: OsFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(back.os_name, "Linux");
    assert_eq!(back.ttl, 64);
    assert_eq!(back.tcp_window_size, Some(65535));
}

#[test]
fn tcp_probe_result_serde_roundtrip() {
    let r = TcpProbeResult { ttl: 128, window_size: 8192, ip_id: 42, df_bit: true };
    let json = serde_json::to_string(&r).unwrap();
    let back: TcpProbeResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.ttl, 128);
    assert!(back.df_bit);
}

#[test]
fn dns_records_serde_roundtrip() {
    let dr = DnsRecords {
        domain: "example.com".into(),
        a_records: vec!["1.1.1.1".into()],
        aaaa_records: vec!["::1".into()],
        mx_records: vec![MxRecord { preference: 10, exchange: "mx.com".into() }],
        ns_records: vec!["ns1.com".into()],
        txt_records: vec!["v=spf1".into()],
        cname_records: vec!["alias.com".into()],
        soa_record: Some(SoaRecord {
            mname: "ns1.com".into(),
            rname: "admin.com".into(),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 86400,
        }),
        subdomains: vec![SubdomainResult {
            name: "sub.example.com".into(),
            ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            is_alive: true,
            takeover: Some(TakeoverInfo {
                service: "GitHub Pages".into(),
                vulnerable: true,
                evidence: "CNAME".into(),
            }),
        }],
    };
    let json = serde_json::to_string(&dr).unwrap();
    let back: DnsRecords = serde_json::from_str(&json).unwrap();
    assert_eq!(back.domain, "example.com");
    assert_eq!(back.a_records.len(), 1);
    assert!(back.soa_record.is_some());
    assert_eq!(back.subdomains.len(), 1);
}

#[test]
fn mx_record_serde_roundtrip() {
    let mx = MxRecord { preference: 10, exchange: "mx.com".into() };
    let json = serde_json::to_string(&mx).unwrap();
    let back: MxRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.preference, 10);
}

#[test]
fn soa_record_serde_roundtrip() {
    let soa = SoaRecord {
        mname: "ns".into(),
        rname: "admin".into(),
        serial: 1,
        refresh: 2,
        retry: 3,
        expire: 4,
        minimum: 5,
    };
    let json = serde_json::to_string(&soa).unwrap();
    let back: SoaRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.serial, 1);
    assert_eq!(back.minimum, 5);
}

#[test]
fn subdomain_result_serde_roundtrip() {
    let sr = SubdomainResult {
        name: "sub.test.com".into(),
        ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        is_alive: true,
        takeover: None,
    };
    let json = serde_json::to_string(&sr).unwrap();
    let back: SubdomainResult = serde_json::from_str(&json).unwrap();
    assert!(back.is_alive);
}

#[test]
fn takeover_info_serde_roundtrip() {
    let t = TakeoverInfo {
        service: "Heroku".into(),
        vulnerable: true,
        evidence: "evidence".into(),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: TakeoverInfo = serde_json::from_str(&json).unwrap();
    assert!(back.vulnerable);
}

#[test]
fn web_scan_config_serde_roundtrip() {
    let c = WebScanConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: WebScanConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.concurrency, 32);
    assert!(!back.follow_redirects);
}

#[test]
fn fuzz_result_serde_roundtrip() {
    let fr = FuzzResult {
        url: "http://test.com".into(),
        status: 200,
        size: 100,
        content_type: Some("text/html".into()),
        title: Some("Test".into()),
        is_directory: false,
        redirected_to: None,
    };
    let json = serde_json::to_string(&fr).unwrap();
    let back: FuzzResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, 200);
}

#[test]
fn vhost_result_serde_roundtrip() {
    let vr = VHostResult {
        host: "admin.test.com".into(),
        status: 200,
        size: 512,
        content_type: None,
        different_from_base: true,
        serves_same_content: false,
    };
    let json = serde_json::to_string(&vr).unwrap();
    let back: VHostResult = serde_json::from_str(&json).unwrap();
    assert!(back.different_from_base);
}

#[test]
fn param_result_serde_roundtrip() {
    let pr = ParamResult {
        parameter: "id".into(),
        url: "http://test.com".into(),
        status: 200,
        response_time_ms: 42,
        reflected: true,
        size_diff: -10,
    };
    let json = serde_json::to_string(&pr).unwrap();
    let back: ParamResult = serde_json::from_str(&json).unwrap();
    assert!(back.reflected);
    assert_eq!(back.size_diff, -10);
}

#[test]
fn waf_info_serde_roundtrip() {
    let wi = WafInfo {
        detected: true,
        name: Some("Cloudflare".into()),
        evidence: vec!["header".into()],
    };
    let json = serde_json::to_string(&wi).unwrap();
    let back: WafInfo = serde_json::from_str(&json).unwrap();
    assert!(back.detected);
}

#[test]
fn tech_entry_serde_roundtrip() {
    let te = TechEntry {
        name: "nginx".into(),
        version: Some("1.24".into()),
        category: "Web server".into(),
        confidence: 0.9,
        evidence: "Server header".into(),
    };
    let json = serde_json::to_string(&te).unwrap();
    let back: TechEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.confidence, 0.9);
}

#[test]
fn cms_info_serde_roundtrip() {
    let ci = CmsInfo {
        name: Some("WordPress".into()),
        version: Some("6.4".into()),
        plugins: vec![],
        themes: vec![],
        confidence: 0.75,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: CmsInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back.confidence, 0.75);
}

#[test]
fn js_endpoint_serde_roundtrip() {
    let je = JsEndpoint {
        url: "http://test.com/app.js".into(),
        endpoint: "/api/v1".into(),
        context: None,
    };
    let json = serde_json::to_string(&je).unwrap();
    let back: JsEndpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back.endpoint, "/api/v1");
}

#[test]
fn robots_info_serde_roundtrip() {
    let ri = RobotsInfo {
        exists: true,
        sitemaps: vec!["http://test.com/sitemap.xml".into()],
        allowed: vec![],
        disallowed: vec!["/admin".into()],
        crawl_delay: Some(5),
    };
    let json = serde_json::to_string(&ri).unwrap();
    let back: RobotsInfo = serde_json::from_str(&json).unwrap();
    assert!(back.exists);
    assert_eq!(back.crawl_delay, Some(5));
}

#[test]
fn severity_serde_roundtrip() {
    for s in [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
        let json = serde_json::to_string(&s).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn vuln_result_serde_roundtrip() {
    let vr = VulnResult {
        vuln_type: "SQLi".into(),
        parameter: "id".into(),
        url: "http://test.com".into(),
        severity: Severity::High,
        payload: "' OR 1=1--".into(),
        evidence: "error".into(),
        confidence: 0.85,
        cwe: Some("CWE-89".into()),
    };
    let json = serde_json::to_string(&vr).unwrap();
    let back: VulnResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.severity, Severity::High);
}

#[test]
fn exploit_progress_serde_roundtrip() {
    let mut data = HashMap::new();
    data.insert("k".into(), "v".into());
    let ep = ExploitProgress {
        extracted_data: data,
        tables_found: vec!["users".into()],
        row_count: 10,
        is_complete: false,
    };
    let json = serde_json::to_string(&ep).unwrap();
    let back: ExploitProgress = serde_json::from_str(&json).unwrap();
    assert_eq!(back.row_count, 10);
}

#[test]
fn sqli_result_serde_roundtrip() {
    let sr = SqliResult {
        vulnerable: true,
        injection_type: "Error".into(),
        parameter: "id".into(),
        payload: "'".into(),
        evidence: "error".into(),
        confidence: 0.8,
    };
    let json = serde_json::to_string(&sr).unwrap();
    let back: SqliResult = serde_json::from_str(&json).unwrap();
    assert!(back.vulnerable);
}

#[test]
fn nosqli_result_serde_roundtrip() {
    let nr = NoSqliResult {
        vulnerable: true,
        db_type: "MongoDB".into(),
        parameter: "user".into(),
        payload: "[$ne]=1".into(),
        evidence: "changed".into(),
    };
    let json = serde_json::to_string(&nr).unwrap();
    let back: NoSqliResult = serde_json::from_str(&json).unwrap();
    assert!(back.vulnerable);
}

#[test]
fn xss_result_serde_roundtrip() {
    let xr = XssResult {
        vulnerable: true,
        xss_type: "Reflected".into(),
        parameter: "q".into(),
        payload: "<script>".into(),
        evidence: "reflected".into(),
        confidence: 0.85,
    };
    let json = serde_json::to_string(&xr).unwrap();
    let back: XssResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.confidence, 0.85);
}

#[test]
fn cmd_injection_result_serde_roundtrip() {
    let cr = CmdInjectionResult {
        vulnerable: true,
        parameter: "cmd".into(),
        payload: "; ls".into(),
        evidence: "output".into(),
        os_type: Some("Linux".into()),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: CmdInjectionResult = serde_json::from_str(&json).unwrap();
    assert!(back.os_type.is_some());
}

#[test]
fn lfi_result_serde_roundtrip() {
    let lr = LfiResult {
        vulnerable: true,
        lfi_type: "LFI".into(),
        parameter: "file".into(),
        payload: "/etc/passwd".into(),
        evidence: "root:".into(),
    };
    let json = serde_json::to_string(&lr).unwrap();
    let back: LfiResult = serde_json::from_str(&json).unwrap();
    assert!(back.vulnerable);
}

#[test]
fn ssti_result_serde_roundtrip() {
    let sr = SstiResult {
        vulnerable: true,
        engine: "Jinja2".into(),
        parameter: "name".into(),
        payload: "{{7*7}}".into(),
        evidence: "49".into(),
    };
    let json = serde_json::to_string(&sr).unwrap();
    let back: SstiResult = serde_json::from_str(&json).unwrap();
    assert!(back.vulnerable);
}

#[test]
fn csrf_result_serde_roundtrip() {
    let cr = CsrfResult {
        vulnerable: true,
        form_action: "/login".into(),
        evidence: "missing token".into(),
        missing_token: true,
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: CsrfResult = serde_json::from_str(&json).unwrap();
    assert!(back.missing_token);
}

#[test]
fn masscan_add_multiple_cidrs() {
    let mut c = MasscanConfig::default();
    c.add_cidr("10.0.0.0/30").unwrap();
    c.add_cidr("192.168.1.0/30").unwrap();
    assert_eq!(c.targets.len(), 2);
    assert_eq!(c.total_ips(), 4);
}

#[test]
fn masscan_add_multiple_ports() {
    let mut c = MasscanConfig::default();
    c.ports.clear();
    c.add_port(80);
    c.add_port(443);
    c.add_port(8080);
    assert_eq!(c.total_ports(), 3);
}

#[test]
fn masscan_rate_limit() {
    let mut c = MasscanConfig::default();
    c.rate_limit = Some(1000);
    assert_eq!(c.rate_limit, Some(1000));
}

#[test]
fn scan_summary_os_fingerprint_set() {
    let mut s = ScanSummary::new(target_v4());
    s.os_fingerprint = Some(OsFingerprint {
        os_name: "Linux".into(),
        os_family: "Linux".into(),
        accuracy: 0.9,
        ttl: 64,
        tcp_window_size: None,
        tcp_options: vec![],
        distance_hops: None,
        evidence: vec![],
    });
    assert!(s.os_fingerprint.is_some());
}

#[test]
fn scan_summary_dns_records_set() {
    let mut s = ScanSummary::new(target_v4());
    s.dns_records = Some(DnsRecords {
        domain: "test.com".into(),
        a_records: vec![],
        aaaa_records: vec![],
        mx_records: vec![],
        ns_records: vec![],
        txt_records: vec![],
        cname_records: vec![],
        soa_record: None,
        subdomains: vec![],
    });
    assert!(s.dns_records.is_some());
}

#[test]
fn port_result_all_states() {
    for state in [PortState::Open, PortState::Closed, PortState::Filtered, PortState::Unfiltered] {
        let pr = PortResult {
            port: 80,
            protocol: "tcp".into(),
            state,
            service: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let back: PortResult = serde_json::from_str(&json).unwrap();
        assert_eq!(pr.state, back.state);
    }
}

#[test]
fn service_info_all_none_options_serde() {
    let si = ServiceInfo {
        name: "Test".into(),
        product: None,
        version: None,
        banner: None,
    };
    let json = serde_json::to_string(&si).unwrap();
    let back: ServiceInfo = serde_json::from_str(&json).unwrap();
    assert!(back.product.is_none());
    assert!(back.version.is_none());
    assert!(back.banner.is_none());
}

#[test]
fn severity_all_variants_eq() {
    assert_eq!(Severity::Info, Severity::Info);
    assert_eq!(Severity::Critical, Severity::Critical);
}

#[test]
fn scan_type_all_variants_serialize() {
    let variants = vec![
        ("TcpConnect", ScanType::TcpConnect),
        ("SynStealth", ScanType::SynStealth),
        ("Udp", ScanType::Udp),
    ];
    for (name, variant) in variants {
        let json = serde_json::to_string(&variant).unwrap();
        assert!(json.contains(name));
    }
}

#[test]
fn known_service_port_0() {
    assert_eq!(known_service_name(0), "Unknown");
}

#[test]
fn known_service_port_8080() {
    assert_eq!(known_service_name(8080), "HTTP Proxy");
}

#[test]
fn known_service_port_8443() {
    assert_eq!(known_service_name(8443), "HTTPS Alt");
}

#[test]
fn known_service_port_5432() {
    assert_eq!(known_service_name(5432), "PostgreSQL");
}

#[test]
fn known_service_port_6379_tls() {
    assert_eq!(known_service_name(6380), "Redis TLS");
}

#[test]
fn known_service_port_27017_steam() {
    assert_eq!(known_service_name(27017), "Steam");
}

#[test]
fn known_service_port_27017_mongo_alt() {
    assert_eq!(known_service_name(28017), "MongoDB Alt");
}

#[test]
fn known_service_port_cassandra() {
    assert_eq!(known_service_name(9042), "Cassandra");
}

#[test]
fn known_service_port_git() {
    assert_eq!(known_service_name(9418), "Git");
}

#[test]
fn known_service_port_webmin() {
    assert_eq!(known_service_name(10000), "Webmin");
}
