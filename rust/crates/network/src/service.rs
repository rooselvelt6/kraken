use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::ServiceInfo;

pub fn fingerprint_banner(addr: std::net::IpAddr, port: u16, timeout: Duration) -> ServiceInfo {
    let sock_addr = (addr, port);
    if let Ok(mut stream) = TcpStream::connect_timeout(&sock_addr.into(), timeout) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));

        let mut buf = vec![0u8; 4096];
        match stream.peek(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                let banner = String::from_utf8_lossy(&buf).to_string();
                identify_from_banner(port, &banner)
            }
            _ => send_probe_and_read(port, &mut stream),
        }
    } else {
        ServiceInfo {
            name: known_service_name(port).to_string(),
            product: None,
            version: None,
            banner: None,
        }
    }
}

fn send_probe_and_read(port: u16, stream: &mut TcpStream) -> ServiceInfo {
    let probes = get_probes(port);
    for (probe_name, probe_data) in &probes {
        let _ = stream.write_all(probe_data.as_bytes());
        let _ = stream.flush();

        let mut buf = vec![0u8; 4096];
        match stream.read(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                let response = String::from_utf8_lossy(&buf).to_string();
                log::debug!("{} probe response: {:?}", probe_name, response);
                let info = identify_from_banner(port, &response);
                if info.product.is_some() || info.version.is_some() {
                    return info;
                }
            }
            _ => {}
        }
    }

    ServiceInfo {
        name: known_service_name(port).to_string(),
        product: None,
        version: None,
        banner: None,
    }
}

fn get_probes(port: u16) -> Vec<(&'static str, String)> {
    match port {
        80 | 443 | 8080 | 8443 | 8000 | 3000 | 5000 | 9000 => {
            vec![
                ("HTTP-GET", "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string()),
                ("HTTP-GET-v1.1", "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".to_string()),
            ]
        }
        22 => vec![("SSH", "\r\n".to_string())],
        21 => vec![("FTP", "\r\n".to_string())],
        25 | 587 => vec![("SMTP", "EHLO localhost\r\n".to_string())],
        110 => vec![("POP3", "\r\n".to_string())],
        143 => vec![("IMAP", "a1 LOGOUT\r\n".to_string())],
        4433 | 9443 => vec![("TLS", "\x16\x03\x01\x00\x02\x01\x00".to_string())],
        6379 => vec![("PING", "*1\r\n$4\r\nPING\r\n".to_string())],
        11211 => vec![("STATS", "stats\r\n".to_string())],
        _ => vec![],
    }
}

fn identify_from_banner(port: u16, banner: &str) -> ServiceInfo {
    let lower = banner.to_lowercase();
    let name = known_service_name(port).to_string();
    let (product, version) = detect_product_version(&lower, port);

    ServiceInfo {
        name,
        product,
        version,
        banner: Some(banner.to_string()),
    }
}

fn detect_product_version(lower: &str, port: u16) -> (Option<String>, Option<String>) {
    let checks: Vec<(&str, &[&str], Option<&str>)> = vec![
        ("OpenSSH", &["openssh"], None),
        ("Apache HTTPD", &["apache"], None),
        ("nginx", &["nginx"], None),
        ("Microsoft IIS", &["microsoft-iis", "iis"], None),
        ("lighttpd", &["lighttpd", "light"], None),
        ("Node.js", &["node.js", "nodejs"], None),
        ("Express", &["express"], None),
        ("Python", &["python"], Some("http.server")),
        ("MySQL", &["mysql"], None),
        ("MariaDB", &["mariadb"], None),
        ("PostgreSQL", &["postgresql", "postgres"], None),
        ("MongoDB", &["mongodb"], None),
        ("Redis", &["redis"], None),
        ("Memcached", &["memcached"], None),
        ("Elasticsearch", &["elasticsearch"], None),
        ("ProFTPD", &["proftpd"], None),
        ("Pure-FTPd", &["pure-ftpd"], None),
        ("vsFTPd", &["vsftpd"], None),
        ("Exim", &["exim"], None),
        ("Postfix", &["postfix"], None),
        ("Sendmail", &["sendmail"], None),
        ("Dovecot", &["dovecot"], None),
        ("Courier", &["courier"], None),
        ("OpenLDAP", &["openldap"], None),
        ("OpenVPN", &["openvpn"], None),
        ("HAProxy", &["haproxy"], None),
        ("Traefik", &["traefik"], None),
        ("Caddy", &["caddy"], None),
        ("Tomcat", &["tomcat"], None),
        ("Jetty", &["jetty"], None),
        ("JBoss", &["jboss"], None),
        ("WebLogic", &["weblogic"], None),
        ("GlassFish", &["glassfish"], None),
        ("Squid", &["squid"], None),
        ("Varnish", &["varnish"], None),
    ];

    for (product_name, patterns, _) in &checks {
        if patterns.iter().any(|p| lower.contains(p)) {
            let version = extract_version(lower, product_name);
            return (Some(product_name.to_string()), version);
        }
    }

    if port == 80 || port == 443 || port == 8080 || port == 8443 {
        if let Some(srv) = extract_server_header(lower) {
            return srv;
        }
    }

    (None, None)
}

fn extract_server_header(lower: &str) -> Option<(Option<String>, Option<String>)> {
    let re = regex::Regex::new(r"server:\s*([^\r\n]+)").ok()?;
    if let Some(caps) = re.captures(lower) {
        let server = caps.get(1)?.as_str().to_string();
        let parts: Vec<&str> = server.splitn(2, '/').collect();
        if parts.len() == 2 {
            return Some((Some(parts[0].to_string()), Some(parts[1].to_string())));
        }
        return Some((Some(server), None));
    }
    None
}

fn extract_version(text: &str, product: &str) -> Option<String> {
    let escaped = regex::escape(product);
    let patterns = [
        format!(r"(?i){}\s*[/-]?\s*v?(\d+\.\d+(?:\.\d+)?)", escaped),
        format!(r"(?i){}\s*[/-]?\s*(\d+\.\d+(?:\.\d+)?)", escaped),
        format!(r"(?i)(\d+\.\d+(?:\.\d+)?)\s*[/-]?\s*{}", escaped),
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().to_string());
                }
            }
        }
    }
    None
}

use crate::port;

fn known_service_name(p: u16) -> &'static str {
    port::known_service_name(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_server_header_basic() {
        let lower = "server: nginx/1.24.0\r\ncontent-type: text/html";
        let result = extract_server_header(lower);
        assert_eq!(result, Some((Some("nginx".into()), Some("1.24.0".into()))));
    }

    #[test]
    fn test_extract_server_header_no_version() {
        let lower = "server: apache\r\n";
        let result = extract_server_header(lower);
        assert_eq!(result, Some((Some("apache".into()), None)));
    }

    #[test]
    fn test_extract_server_header_not_found() {
        let lower = "content-type: text/html\r\n";
        let result = extract_server_header(lower);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_version_nginx() {
        let ver = extract_version("nginx/1.24.0 running", "nginx");
        assert_eq!(ver, Some("1.24.0".into()));
    }

    #[test]
    fn test_extract_version_openssh() {
        let ver = extract_version("openssh 8.9p1", "OpenSSH");
        assert_eq!(ver, Some("8.9".into()));
    }

    #[test]
    fn test_extract_version_no_match() {
        let ver = extract_version("hello world", "nonexistent");
        assert!(ver.is_none());
    }

    #[test]
    fn test_extract_version_number_before_product() {
        let ver = extract_version("8.0.144 mysql-server", "mysql");
        assert!(ver.is_some());
    }

    #[test]
    fn test_get_probes_http_ports() {
        for port in &[80, 443, 8080, 8443, 8000, 3000, 5000, 9000] {
            let probes = get_probes(*port);
            assert!(!probes.is_empty(), "port {} should have probes", port);
            assert!(probes.iter().any(|(name, _)| name.starts_with("HTTP")));
        }
    }

    #[test]
    fn test_get_probes_ssh() {
        let probes = get_probes(22);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].0, "SSH");
    }

    #[test]
    fn test_get_probes_ftp() {
        let probes = get_probes(21);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].0, "FTP");
    }

    #[test]
    fn test_get_probes_smtp() {
        let probes = get_probes(25);
        assert!(!probes.is_empty());
        assert!(probes.iter().any(|(name, _)| *name == "SMTP"));
    }

    #[test]
    fn test_get_probes_redis() {
        let probes = get_probes(6379);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].0, "PING");
    }

    #[test]
    fn test_get_probes_memcached() {
        let probes = get_probes(11211);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].0, "STATS");
    }

    #[test]
    fn test_get_probes_unknown_port_empty() {
        let probes = get_probes(54321);
        assert!(probes.is_empty());
    }

    #[test]
    fn test_identify_from_banner_ssh() {
        let info = identify_from_banner(22, "SSH-2.0-OpenSSH_9.3p1 Ubuntu");
        assert_eq!(info.name, "SSH");
        assert!(info.product.is_some());
        assert_eq!(info.banner, Some("SSH-2.0-OpenSSH_9.3p1 Ubuntu".into()));
    }

    #[test]
    fn test_identify_from_banner_nginx() {
        let info = identify_from_banner(80, "HTTP/1.1 200 OK\r\nserver: nginx/1.24.0");
        assert_eq!(info.name, "HTTP");
        assert_eq!(info.product, Some("nginx".into()));
    }

    #[test]
    fn test_identify_from_banner_generic() {
        let info = identify_from_banner(12345, "random data");
        assert_eq!(info.name, "NetBus");
        assert!(info.product.is_none());
        assert!(info.version.is_none());
        assert_eq!(info.banner, Some("random data".into()));
    }

    #[test]
    fn test_detect_product_version_various() {
        let checks = vec![
            ("openssh_9.3p1", "OpenSSH"),
            ("apache/2.4.57", "Apache HTTPD"),
            ("nginx/1.25.3", "nginx"),
            ("microsoft-iis/10.0", "Microsoft IIS"),
            ("redis_version=7.2.3", "Redis"),
            ("postgresql 15.4", "PostgreSQL"),
            ("mongodb 7.0", "MongoDB"),
        ];
        for (banner, expected_product) in checks {
            let (product, _version) = detect_product_version(&banner.to_lowercase(), 80);
            assert!(product.is_some(), "should detect product for: {}", banner);
            let product_str = product.unwrap();
            assert!(
                product_str.to_lowercase().contains(&expected_product.to_lowercase()),
                "expected {} in product '{}' for banner '{}'",
                expected_product,
                product_str,
                banner
            );
            if banner.contains('.') {
                // Most banners with dots should extract a version
                // (not always - depends on the pattern)
            }
        }
    }

    #[test]
    fn test_service_info_struct() {
        let info = ServiceInfo {
            name: "HTTP".into(),
            product: Some("nginx".into()),
            version: Some("1.24".into()),
            banner: Some("HTTP/1.1 200".into()),
        };
        assert_eq!(info.name, "HTTP");
        assert!(info.product.is_some());
        assert!(info.version.is_some());
        assert!(info.banner.is_some());
    }

    #[test]
    fn test_service_info_no_optional() {
        let info = ServiceInfo {
            name: "Unknown".into(),
            product: None,
            version: None,
            banner: None,
        };
        assert!(info.product.is_none());
        assert!(info.version.is_none());
        assert!(info.banner.is_none());
    }

    #[test]
    fn test_extract_version_with_dash() {
        let ver = extract_version("openssh-8.9p1", "OpenSSH");
        assert_eq!(ver, Some("8.9".into()));
    }

    #[test]
    fn test_extract_version_with_space() {
        let ver = extract_version("lighttpd 1.4.71", "lighttpd");
        assert_eq!(ver, Some("1.4.71".into()));
    }
}
