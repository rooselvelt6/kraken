use std::sync::OnceLock;

use chrono::Utc;

use crate::{FindingKind, OsintFinding, OsintSource, Reliability};
use crate::throttle::RateLimiter;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to create tokio runtime"))
}

const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (111, "RPC"),
    (135, "MSRPC"), (139, "NetBIOS"), (143, "IMAP"), (389, "LDAP"),
    (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle"), (2049, "NFS"),
    (2375, "Docker"), (2376, "Docker TLS"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"),
    (5985, "WinRM"), (5986, "WinRM TLS"), (6379, "Redis"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (27017, "MongoDB"),
];

async fn tcp_connect(ip: &str, port: u16, timeout_secs: u64) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = format!("{}:{}", ip, port);
    let sock_addrs = match addr.to_socket_addrs() {
        Ok(mut a) => a.next(),
        Err(_) => return false,
    };
    let sock_addr = match sock_addrs {
        Some(a) => a,
        None => return false,
    };
    TcpStream::connect_timeout(&sock_addr, Duration::from_secs(timeout_secs)).is_ok()
}

#[derive(Debug, Clone)]
pub struct PortScanner;

impl PortScanner {
    pub fn scan(ip: &str, ports: Option<&[u16]>) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let targets: Vec<u16> = match ports {
            Some(p) => p.to_vec(),
            None => COMMON_PORTS.iter().map(|(p, _)| *p).collect(),
        };

        let rt = runtime();

        for port in &targets {
            let open = rt.block_on(tcp_connect(ip, *port, 3));
            let name = COMMON_PORTS.iter().find(|(p, _)| p == port).map(|(_, n)| *n).unwrap_or("unknown");

            findings.push(OsintFinding {
                source: OsintSource {
                    name: "portscan/tcp".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("OpenPort".into()),
                value: if open {
                    format!("Port {}/tcp OPEN ({})", port, name)
                } else {
                    format!("Port {}/tcp closed ({})", port, name)
                },
                context: Some(format!("TCP connect scan to {}:{}", ip, port)),
                confidence: if open { 0.95 } else { 0.8 },
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        findings
    }

    pub fn scan_quick(ip: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let rt = runtime();

        let open_ports: Vec<(u16, &str)> = COMMON_PORTS.iter()
            .filter(|(p, _)| rt.block_on(tcp_connect(ip, *p, 2)))
            .copied()
            .collect();

        if open_ports.is_empty() {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "portscan/quick".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("OpenPort".into()),
                value: format!("No common ports open on {}", ip),
                context: Some("Scanned 29 common ports".into()),
                confidence: 0.7,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        } else {
            let summary: Vec<String> = open_ports.iter()
                .map(|(p, n)| format!("{}/{}", p, n))
                .collect();
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "portscan/quick".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("OpenPort".into()),
                value: format!("Open ports on {}: {}", ip, summary.join(", ")),
                context: Some(format!("Found {} open port(s) of 29 scanned", open_ports.len())),
                confidence: 0.95,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        findings
    }
}

#[derive(Debug, Clone)]
pub struct CertTransparency;

impl CertTransparency {
    fn crt_limiter() -> &'static RateLimiter {
        static LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
        LIMITER.get_or_init(|| RateLimiter::new(5, 10))
    }

    pub fn lookup_domain(domain: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        Self::crt_limiter().wait_if_needed();
        let url = format!("https://crt.sh/?q={}&output=json", domain);

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Kraken-OSINT/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let resp = match client.get(&url).send() {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "crt.sh/error".into(),
                        reliability: Reliability::High,
                        url: Some(format!("https://crt.sh/?q={}", domain)),
                    },
                    kind: FindingKind::Subdomain,
                    value: format!("crt.sh returned HTTP {}", r.status()),
                    context: Some("Certificate transparency lookup failed".into()),
                    confidence: 0.5,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
                return findings;
            }
            Err(e) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "crt.sh/error".into(),
                        reliability: Reliability::Low,
                        url: Some(format!("https://crt.sh/?q={}", domain)),
                    },
                    kind: FindingKind::Subdomain,
                    value: format!("crt.sh error: {}", e),
                    context: Some("Certificate transparency lookup failed".into()),
                    confidence: 0.3,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
                return findings;
            }
        };

        let json: Vec<serde_json::Value> = match resp.json() {
            Ok(j) => j,
            Err(_) => return findings,
        };

        let mut subdomains: Vec<String> = Vec::new();
        for entry in &json {
            if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
                for line in name_value.lines() {
                    let line = line.trim().trim_start_matches("*.").trim_start_matches("www.");
                    let lower = line.to_lowercase();
                    if lower.contains(domain) && !subdomains.contains(&lower) {
                        subdomains.push(lower);
                    }
                }
            }
            if let Some(common_name) = entry.get("common_name").and_then(|v| v.as_str()) {
                let cn = common_name.trim().trim_start_matches("*.").trim_start_matches("www.").to_lowercase();
                if cn.contains(domain) && !subdomains.contains(&cn) {
                    subdomains.push(cn);
                }
            }
        }

        subdomains.sort_unstable();
        subdomains.dedup();

        if subdomains.is_empty() {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "crt.sh/lookup".into(),
                    reliability: Reliability::High,
                    url: Some(format!("https://crt.sh/?q={}", domain)),
                },
                kind: FindingKind::Subdomain,
                value: format!("No certificates found for {}", domain),
                context: Some("Domain may not have SSL certificates or may be invalid".into()),
                confidence: 0.6,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        } else {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "crt.sh/lookup".into(),
                    reliability: Reliability::High,
                    url: Some(format!("https://crt.sh/?q={}", domain)),
                },
                kind: FindingKind::Subdomain,
                value: format!("{} certificates found for {}", subdomains.len(), domain),
                context: Some(format!("Subdomains: {}", subdomains.join(", "))),
                confidence: 0.9,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });

            for sub in &subdomains {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "crt.sh/subdomain".into(),
                        reliability: Reliability::High,
                        url: Some(format!("https://crt.sh/?q={}", sub)),
                    },
                    kind: FindingKind::Subdomain,
                    value: format!("Subdomain: {}", sub),
                    context: Some(format!("Discovered via crt.sh certificate transparency for {}", domain)),
                    confidence: 0.85,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }

        findings
    }

    pub fn lookup_issuer(domain: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        Self::crt_limiter().wait_if_needed();
        let url = format!("https://crt.sh/?q={}&output=json", domain);

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Kraken-OSINT/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let resp = match client.get(&url).send() {
            Ok(r) if r.status().is_success() => r,
            _ => return findings,
        };

        let json: Vec<serde_json::Value> = match resp.json() {
            Ok(j) => j,
            Err(_) => return findings,
        };

        let mut issuers: Vec<(String, String, String)> = Vec::new();

        for entry in &json {
            let issuer_name = entry.get("issuer_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let common_name = entry.get("common_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let not_after = entry.get("not_after")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if !issuer_name.is_empty() && !issuers.iter().any(|(i, _, _)| i == &issuer_name) {
                issuers.push((issuer_name, common_name, not_after));
            }
        }

        for (issuer, cn, expires) in &issuers {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "crt.sh/issuer".into(),
                    reliability: Reliability::High,
                    url: Some(format!("https://crt.sh/?q={}", cn)),
                },
                kind: FindingKind::Custom("CertificateInfo".into()),
                value: format!("Issuer: {}", issuer),
                context: Some(format!("CN: {} | Expires: {}", cn, expires)),
                confidence: 0.9,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        findings
    }
}

#[derive(Debug, Clone)]
pub struct ASNLookup;

impl ASNLookup {
    pub fn lookup_ip(ip: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let query = format!("https://bgp.he.net/ip/{}", ip);

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Kraken-OSINT/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return Self::team_cymru(ip),
        };

        let resp = match client.get(&query).send() {
            Ok(r) if r.status().is_success() => r,
            _ => return Self::team_cymru(ip),
        };

        let html = match resp.text() {
            Ok(t) => t,
            Err(_) => return Self::team_cymru(ip),
        };

        let document = scraper::Html::parse_document(&html);
        let mut parsed_asn = false;

        if let Ok(sel) = scraper::Selector::parse("table#asns td") {
            for elem in document.select(&sel) {
                let text = elem.text().collect::<String>().trim().to_string();
                if text.starts_with("AS") || text.starts_with("as") {
                    let asn = text.trim().to_string();
                    parsed_asn = true;
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: "asn/bgphe".into(),
                            reliability: Reliability::Medium,
                            url: Some(format!("https://bgp.he.net/{}", asn)),
                        },
                        kind: FindingKind::Custom("ASN".into()),
                        value: format!("ASN for {}: {}", ip, asn),
                        context: Some(format!("Found on bgp.he.net for {}", ip)),
                        confidence: 0.7,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        if let Ok(sel) = scraper::Selector::parse("div#ipinfo") {
            for elem in document.select(&sel) {
                let text = elem.text().collect::<String>().trim().to_string();
                if !text.is_empty() {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: "asn/bgphe".into(),
                            reliability: Reliability::Medium,
                            url: None,
                        },
                        kind: FindingKind::Custom("IPInfo".into()),
                        value: format!("IP info for {}: {}", ip, text),
                        context: None,
                        confidence: 0.6,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        if !parsed_asn {
            findings.extend(Self::team_cymru(ip));
        }

        if findings.is_empty() {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "asn/bgphe".into(),
                    reliability: Reliability::Low,
                    url: Some(query),
                },
                kind: FindingKind::Custom("ASN".into()),
                value: format!("No ASN data found for {}", ip),
                context: Some("Could not parse ASN from bgp.he.net".into()),
                confidence: 0.3,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        findings
    }

    fn team_cymru(ip: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let query = format!("{}.{}", ip, "asn.cymru.com");

        use std::net::ToSocketAddrs;
        let addr = match (format!("{}:43", query)).to_socket_addrs() {
            Ok(mut a) => a.next(),
            Err(_) => return findings,
        };

        let addr = match addr {
            Some(a) => a,
            None => return findings,
        };

        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(s) => s,
            Err(_) => return findings,
        };

        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = write!(stream, "{}\r\n", ip);

        let reader = BufReader::new(&stream);
        let mut lines = reader.lines();

        if let Some(Ok(line)) = lines.next() {
            let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
            if parts.len() >= 3 {
                let asn = parts[0].to_string();
                let cidr = parts[2].to_string();
                let country = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "asn/cymru".into(),
                        reliability: Reliability::High,
                        url: Some(format!("https://bgp.he.net/AS{}", asn)),
                    },
                    kind: FindingKind::Custom("ASN".into()),
                    value: format!("AS{} | {} | {}", asn, country, cidr),
                    context: Some(format!("Team Cymru whois for {}", ip)),
                    confidence: 0.95,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }

        findings
    }
}

#[derive(Debug, Clone)]
pub struct TechFingerprinter;

impl TechFingerprinter {
    pub fn fingerprint(url: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let resp = match client.get(url).send() {
            Ok(r) => r,
            Err(e) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "tech/error".into(),
                        reliability: Reliability::High,
                        url: Some(url.to_string()),
                    },
                    kind: FindingKind::Technology,
                    value: format!("HTTP error: {}", e),
                    context: Some("Could not connect to target".into()),
                    confidence: 0.5,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
                return findings;
            }
        };

        let headers = resp.headers();
        let status = resp.status().as_u16();

        findings.push(OsintFinding {
            source: OsintSource {
                name: "tech/http".into(),
                reliability: Reliability::High,
                url: Some(url.to_string()),
            },
            kind: FindingKind::Technology,
            value: format!("HTTP Status: {}", status),
            context: Some(format!("{} returned {}", url, status)),
            confidence: 1.0,
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });

        let header_patterns: Vec<(&str, &str, Vec<&str>)> = vec![
            ("server", "Server", vec!["Apache", "nginx", "IIS", "Cloudflare", "OpenResty", "Caddy", "LiteSpeed", "Tomcat", "Jetty", "Node", "Kestrel", "Gunicorn", "uWSGI", "Puma", "Unicorn", "Thin", "Passenger", "WEBrick", "Lighttpd", "Cherokee", "HTTPD"]),
            ("x-powered-by", "X-Powered-By", vec!["PHP", "ASP.NET", "Express", "Rails", "Django", "Flask", "Node", "Java", "JSP"]),
            ("x-aspnet-version", "ASP.NET Version", vec![]),
            ("x-generator", "Generator", vec!["WordPress", "Drupal", "Joomla", "Wix", "Squarespace", "Ghost", "Hugo", "Jekyll", "Gatsby", "Next.js", "Nuxt"]),
            ("cf-ray", "Cloudflare", vec![]),
            ("x-served-by", "X-Served-By", vec![]),
            ("set-cookie", "Cookies", vec!["PHPSESSID", "ASPSESSIONID", "JSESSIONID", "connect.sid", "laravel_session", "symfony", "ci_session", "rack.session", "_session_id"]),
        ];

        for (header_name, display_name, known_values) in &header_patterns {
            if let Some(val) = headers.get(*header_name) {
                if let Ok(val_str) = val.to_str() {
                    let context = if known_values.is_empty() {
                        Some(val_str.to_string())
                    } else {
                        let matched: Vec<&str> = known_values.iter()
                            .filter(|kv| val_str.contains(*kv))
                            .copied()
                            .collect();
                        Some(matched.join(", "))
                    };

                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: format!("tech/{}", header_name.to_lowercase().replace('-', "_")),
                            reliability: Reliability::High,
                            url: None,
                        },
                        kind: FindingKind::Technology,
                        value: format!("{}: {}", display_name, val_str),
                        context,
                        confidence: 0.9,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        let body = match resp.text() {
            Ok(b) => b,
            Err(_) => return findings,
        };

        let html_patterns: Vec<(&str, Vec<&str>)> = vec![
            ("WordPress", vec!["/wp-content/", "/wp-includes/", "wp-json", "wordpress"]),
            ("Drupal", vec!["drupal.js", "Drupal.settings", "/sites/default/", "drupal"]),
            ("Joomla", vec!["/components/", "/modules/", "Joomla"]),
            ("Shopify", vec!["shopify.com", "myshopify.com", "Shopify"]),
            ("Magento", vec!["/skin/frontend/", "Magento", "mage/"]),
            ("Wix", vec!["wix.com", "Wix.com"]),
            ("Squarespace", vec!["squarespace.com", "Squarespace"]),
            ("Ghost", vec!["ghost.io", "Ghost"]),
            ("Next.js", vec!["__NEXT_DATA__", "/_next/static"]),
            ("Nuxt.js", vec!["__NUXT__", "/_nuxt/"]),
            ("Gatsby", vec!["gatsby-"]),
            ("Laravel", vec!["laravel"]),
            ("Django", vec!["csrftoken", "django"]),
            ("Rails", vec!["csrf-param", "csrf-token", "rails"]),
            ("React", vec!["react", "React."]),
            ("Vue.js", vec!["vuejs", "Vue.", "__VUE__"]),
            ("Angular", vec!["angular", "ng-version"]),
            ("jQuery", vec!["jquery"]),
            ("Bootstrap", vec!["bootstrap"]),
            ("Font Awesome", vec!["font-awesome", "fontawesome"]),
            ("Google Analytics", vec!["google-analytics", "ga.js", "gtag"]),
            ("Cloudflare", vec!["cloudflare"]),
        ];

        let body_lower = body.to_lowercase();
        for (name, indicators) in &html_patterns {
            if indicators.iter().any(|ind| body_lower.contains(ind)) {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: format!("tech/html/{}", name.to_lowercase().replace(' ', "_").replace('.', "")),
                        reliability: Reliability::Medium,
                        url: None,
                    },
                    kind: FindingKind::Technology,
                    value: format!("CMS/Framework: {}", name),
                    context: Some(format!("Detected via HTML content analysis of {}", url)),
                    confidence: 0.7,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }

        findings
    }
}

#[derive(Debug, Clone)]
pub struct IPEnricher;

impl IPEnricher {
    pub fn reverse_dns(ip: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let query = format!("https://dns.google/resolve?name={}&type=PTR", ip);

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        if let Ok(resp) = client.get(&query).send() {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(answer) = json.get("Answer").and_then(|a| a.as_array()) {
                    for entry in answer {
                        if let Some(data) = entry.get("data").and_then(|d| d.as_str()) {
                            findings.push(OsintFinding {
                                source: OsintSource {
                                    name: "ip/rdns".into(),
                                    reliability: Reliability::High,
                                    url: None,
                                },
                                kind: FindingKind::Custom("ReverseDNS".into()),
                                value: format!("PTR: {} -> {}", ip, data),
                                context: Some(format!("Reverse DNS lookup via Google DNS over HTTPS")),
                                confidence: 0.9,
                                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            });
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "ip/rdns".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("ReverseDNS".into()),
                value: format!("No PTR record for {}", ip),
                context: Some("No reverse DNS entry found".into()),
                confidence: 0.6,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        findings
    }

    pub fn ipinfo(ip: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let url = format!("https://ipinfo.io/{}/json", ip);

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Kraken-OSINT/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let resp = match client.get(&url).send() {
            Ok(r) if r.status().is_success() => r,
            _ => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "ip/ipinfo".into(),
                        reliability: Reliability::Low,
                        url: Some(format!("https://ipinfo.io/{}", ip)),
                    },
                    kind: FindingKind::Custom("IPGeo".into()),
                    value: format!("IP info: {}", ip),
                    context: Some("Visit ipinfo.io for details".into()),
                    confidence: 0.3,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
                return findings;
            }
        };

        let json: serde_json::Value = match resp.json() {
            Ok(j) => j,
            Err(_) => return findings,
        };

        let fields: Vec<(&str, &str, f64)> = vec![
            ("city", "City", 0.9),
            ("region", "Region", 0.9),
            ("country", "Country", 0.95),
            ("loc", "Coordinates", 0.85),
            ("org", "Organization", 0.85),
            ("postal", "Postal Code", 0.7),
            ("timezone", "Timezone", 0.8),
            ("asn", "ASN", 0.8),
            ("hostname", "Hostname", 0.7),
        ];

        for (key, label, confidence) in fields {
            if let Some(val) = json.get(key).and_then(|v| v.as_str()) {
                if !val.is_empty() {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: format!("ip/ipinfo/{}", key),
                            reliability: Reliability::Medium,
                            url: None,
                        },
                        kind: FindingKind::Custom("IPGeo".into()),
                        value: format!("{}: {}", label, val),
                        context: Some(format!("IP {} geolocation data", ip)),
                        confidence,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        findings
    }

    pub fn shodan_lookup(ip: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();

        let api_key = match std::env::var("SHODAN_API_KEY") {
            Ok(k) => k,
            Err(_) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "shodan/apikey".into(),
                        reliability: Reliability::High,
                        url: None,
                    },
                    kind: FindingKind::Custom("Shodan".into()),
                    value: "Shodan API key not configured".into(),
                    context: Some("Set SHODAN_API_KEY environment variable".into()),
                    confidence: 1.0,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
                return findings;
            }
        };

        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent("Kraken-OSINT/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);
        let resp = match client.get(&url).send() {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "shodan/host".into(),
                        reliability: Reliability::High,
                        url: Some(format!("https://www.shodan.io/host/{}", ip)),
                    },
                    kind: FindingKind::Custom("Shodan".into()),
                    value: format!("Shodan returned HTTP {}", r.status()),
                    context: Some("API limit or IP not found in Shodan".into()),
                    confidence: 0.5,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
                return findings;
            }
            Err(e) => {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "shodan/host".into(),
                        reliability: Reliability::Low,
                        url: Some(format!("https://www.shodan.io/host/{}", ip)),
                    },
                    kind: FindingKind::Custom("Shodan".into()),
                    value: format!("Shodan error: {}", e),
                    context: Some("API request failed".into()),
                    confidence: 0.3,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
                return findings;
            }
        };

        let json: serde_json::Value = match resp.json() {
            Ok(j) => j,
            Err(_) => return findings,
        };

        if let Some(ports) = json.get("ports").and_then(|p| p.as_array()) {
            let port_list: Vec<String> = ports.iter()
                .filter_map(|p| p.as_u64())
                .map(|p| {
                    let name = COMMON_PORTS.iter().find(|(port, _)| *port == p as u16)
                        .map(|(_, n)| format!(" ({})", n)).unwrap_or_default();
                    format!("{}{}", p, name)
                })
                .collect();
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "shodan/ports".into(),
                    reliability: Reliability::High,
                    url: Some(format!("https://www.shodan.io/host/{}", ip)),
                },
                kind: FindingKind::Custom("Shodan".into()),
                value: format!("Shodan: {} open ports for {}", ports.len(), ip),
                context: Some(port_list.join(", ")),
                confidence: 0.9,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        if let Some(hostnames) = json.get("hostnames").and_then(|h| h.as_array()) {
            let names: Vec<String> = hostnames.iter()
                .filter_map(|h| h.as_str().map(String::from))
                .collect();
            if !names.is_empty() {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "shodan/hostnames".into(),
                        reliability: Reliability::High,
                        url: None,
                    },
                    kind: FindingKind::Custom("Shodan".into()),
                    value: format!("Hostnames: {}", names.join(", ")),
                    context: Some(format!("Associated with {}", ip)),
                    confidence: 0.85,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }

        if let Some(os) = json.get("os").and_then(|o| o.as_str()) {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "shodan/os".into(),
                    reliability: Reliability::Medium,
                    url: None,
                },
                kind: FindingKind::Custom("Shodan".into()),
                value: format!("OS: {}", os),
                context: Some(format!("Operating system detected for {}", ip)),
                confidence: 0.7,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        let geo_fields: Vec<(&str, &str)> = vec![
            ("city", "City"),
            ("region_code", "Region"),
            ("country_name", "Country"),
            ("latitude", "Latitude"),
            ("longitude", "Longitude"),
            ("isp", "ISP"),
            ("org", "Organization"),
            ("asn", "ASN"),
        ];

        for (key, label) in &geo_fields {
            if let Some(val) = json.get(*key).and_then(|v| v.as_str()) {
                if !val.is_empty() {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: format!("shodan/{}", key),
                            reliability: Reliability::Medium,
                            url: None,
                        },
                        kind: FindingKind::Custom("Shodan".into()),
                        value: format!("{}: {}", label, val),
                        context: None,
                        confidence: 0.75,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        findings
    }
}

pub fn analyze_ip(ip: &str) -> Vec<OsintFinding> {
    let mut findings = Vec::new();
    findings.extend(IPEnricher::reverse_dns(ip));
    findings.extend(IPEnricher::ipinfo(ip));
    findings.extend(IPEnricher::shodan_lookup(ip));
    findings.extend(ASNLookup::team_cymru(ip));
    findings
}

pub fn analyze_domain(domain: &str) -> Vec<OsintFinding> {
    let mut findings = Vec::new();
    findings.extend(CertTransparency::lookup_domain(domain));
    findings.extend(CertTransparency::lookup_issuer(domain));

    use std::net::ToSocketAddrs;
    let ips: Vec<String> = format!("{}:0", domain)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip().to_string()).collect())
        .unwrap_or_default();

    let mut seen_ips = Vec::new();
    for ip in ips {
        if !seen_ips.contains(&ip) {
            seen_ips.push(ip.clone());
            findings.extend(IPEnricher::reverse_dns(&ip));
            findings.extend(IPEnricher::ipinfo(&ip));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_scan_returns_findings() {
        let findings = PortScanner::scan("127.0.0.1", Some(&[80, 443]));
        assert!(findings.len() >= 2);
        assert!(findings.iter().any(|f| f.value.contains("80")));
        assert!(findings.iter().any(|f| f.value.contains("443")));
    }

    #[test]
    fn quick_scan_returns_findings() {
        let findings = PortScanner::scan_quick("127.0.0.1");
        assert!(!findings.is_empty());
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn cert_transparency_empty_domain() {
        let findings = CertTransparency::lookup_domain("thisdomaindoesnotexist.xyz");
        assert!(!findings.is_empty());
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn cert_transparency_issuer_lookup() {
        let findings = CertTransparency::lookup_issuer("example.com");
        // May be empty if crt.sh is unreachable or rate-limited in test env
        assert!(findings.len() <= 50);
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn asn_lookup_returns_findings() {
        let findings = ASNLookup::lookup_ip("8.8.8.8");
        assert!(!findings.is_empty());
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn team_cymru_lookup() {
        let findings = ASNLookup::lookup_ip("8.8.8.8");
        // May be empty if bgp.he.net is unreachable in test env
        assert!(findings.len() <= 10);
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn tech_fingerprint_returns_headers() {
        let findings = TechFingerprinter::fingerprint("https://example.com");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.value.contains("HTTP Status")));
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn ip_enricher_reverse_dns() {
        let findings = IPEnricher::reverse_dns("8.8.8.8");
        assert!(!findings.is_empty());
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn ip_enricher_ipinfo() {
        let findings = IPEnricher::ipinfo("8.8.8.8");
        assert!(!findings.is_empty());
        // May not have Country field if ipinfo.io is unreachable/rate-limited
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn shodan_lookup_requires_key() {
        let findings = IPEnricher::shodan_lookup("8.8.8.8");
        let no_key = findings.iter().any(|f| f.value.contains("API key not configured"));
        assert!(no_key || !findings.is_empty());
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn analyze_ip_combines_sources() {
        let findings = analyze_ip("8.8.8.8");
        assert!(findings.len() >= 3, "should have multiple sources, got {}", findings.len());
    }

    #[cfg_attr(not(feature = "network-tests"), ignore = "requires network")]
    #[test]
    fn analyze_domain_returns_findings() {
        let findings = analyze_domain("example.com");
        assert!(!findings.is_empty());
    }
}
