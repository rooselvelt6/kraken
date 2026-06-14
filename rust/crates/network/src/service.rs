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
