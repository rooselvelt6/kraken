use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::Utc;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};

use crate::{FindingKind, OsintFinding, OsintSource, Reliability};

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to create tokio runtime"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    pub domain: String,
    pub records: Vec<DnsRecord>,
    pub resolved_ips: Vec<String>,
    pub whois: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RecordType {
    A,
    AAAA,
    MX,
    TXT,
    NS,
    SOA,
    CNAME,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::NS => "NS",
            Self::SOA => "SOA",
            Self::CNAME => "CNAME",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(Self::A),
            "AAAA" => Some(Self::AAAA),
            "MX" => Some(Self::MX),
            "TXT" => Some(Self::TXT),
            "NS" => Some(Self::NS),
            "SOA" => Some(Self::SOA),
            "CNAME" => Some(Self::CNAME),
            _ => None,
        }
    }

    fn to_hickory(&self) -> hickory_resolver::proto::rr::RecordType {
        match self {
            Self::A => hickory_resolver::proto::rr::RecordType::A,
            Self::AAAA => hickory_resolver::proto::rr::RecordType::AAAA,
            Self::MX => hickory_resolver::proto::rr::RecordType::MX,
            Self::TXT => hickory_resolver::proto::rr::RecordType::TXT,
            Self::NS => hickory_resolver::proto::rr::RecordType::NS,
            Self::SOA => hickory_resolver::proto::rr::RecordType::SOA,
            Self::CNAME => hickory_resolver::proto::rr::RecordType::CNAME,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsResolver;

impl DnsResolver {
    pub fn resolve_a(domain: &str) -> Vec<String> {
        use std::net::ToSocketAddrs;
        let addr = format!("{}:0", domain);
        match addr.to_socket_addrs() {
            Ok(addrs) => {
                let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                ips.sort_unstable();
                ips.dedup();
                ips
            }
            Err(_) => vec![],
        }
    }

    pub fn resolve_all(domain: &str, record_types: &[RecordType]) -> Vec<OsintFinding> {
        let mut findings = Vec::new();

        for rt in record_types {
            match rt {
                RecordType::A => {
                    for ip in Self::resolve_a(domain) {
                        findings.push(Self::make_finding(domain, "A", &ip));
                    }
                }
                _ => {
                    if let Ok(records) = Self::resolve_with_hickory(domain, rt) {
                        for r in records {
                            findings.push(Self::make_finding(domain, rt.as_str(), &r));
                        }
                    }
                }
            }
        }

        findings
    }

    fn resolve_with_hickory(domain: &str, record_type: &RecordType) -> Result<Vec<String>, String> {
        let rt = runtime();
        rt.block_on(async {
            let resolver = TokioResolver::builder_tokio()
                .map_err(|e| format!("dns builder: {e}"))?
                .build()
                .map_err(|e| format!("dns build: {e}"))?;

            if matches!(record_type, RecordType::CNAME) {
                return Self::lookup_cname(&resolver, domain).await;
            }

            let response = resolver
                .lookup(domain, record_type.to_hickory())
                .await
                .map_err(|e| format!("dns lookup {}: {e}", record_type.as_str()))?;

            let values: Vec<String> = response
                .answers()
                .iter()
                .filter_map(|record| Self::rdata_to_string(&record.data, record_type))
                .collect();

            Ok(values)
        })
    }

    async fn lookup_cname(resolver: &TokioResolver, domain: &str) -> Result<Vec<String>, String> {
        let response = resolver
            .lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
            .map_err(|e| format!("dns lookup CNAME: {e}"))?;

        let values: Vec<String> = response
            .answers()
            .iter()
            .filter_map(|record| {
                let rdata = &record.data;
                match rdata {
                    RData::CNAME(name) => Some(name.to_string()),
                    _ => None,
                }
            })
            .collect();

        Ok(values)
    }

    fn rdata_to_string(rdata: &RData, rt: &RecordType) -> Option<String> {
        match rt {
            RecordType::A => match rdata {
                RData::A(ip) => Some(ip.to_string()),
                _ => None,
            },
            RecordType::AAAA => match rdata {
                RData::AAAA(ip) => Some(ip.to_string()),
                _ => None,
            },
            RecordType::MX => match rdata {
                RData::MX(mx) => {
                    Some(format!("{} pref={}", mx.exchange, mx.preference))
                }
                _ => None,
            },
            RecordType::TXT => match rdata {
                RData::TXT(txt) => {
                    let text: String = txt.txt_data.iter()
                        .map(|t| String::from_utf8_lossy(t).into_owned())
                        .collect();
                    Some(text)
                }
                _ => None,
            },
            RecordType::NS => match rdata {
                RData::NS(name) => Some(name.to_string()),
                _ => None,
            },
            RecordType::SOA => match rdata {
                RData::SOA(soa) => {
                    Some(format!(
                        "mname={} rname={} serial={} refresh={} retry={} expire={} minimum={}",
                        soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum,
                    ))
                }
                _ => None,
            },
            RecordType::CNAME => None,
        }
    }

    fn make_finding(domain: &str, record_type: &str, value: &str) -> OsintFinding {
        OsintFinding {
            source: OsintSource {
                name: format!("dns/{}", record_type),
                reliability: Reliability::High,
                url: None,
            },
            kind: FindingKind::DnsRecord,
            value: format!("{} {} {}", domain, record_type, value),
            context: None,
            confidence: 0.95,
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }
    }

    pub fn whois_lookup(domain: &str) -> Result<String, String> {
        let whois_server = Self::find_whois_server(domain)?;
        let query = if domain.ends_with(".com") || domain.ends_with(".net") || domain.ends_with(".org") {
            domain.to_string()
        } else {
            format!("={}", domain)
        };

        use std::net::ToSocketAddrs;
        let mut stream = TcpStream::connect_timeout(
            &format!("{}:43", whois_server.as_str())
                .to_socket_addrs()
                .map_err(|e| format!("failed to resolve whois server: {e}"))?
                .next()
                .ok_or("no address for whois server")?,
            Duration::from_secs(10),
        )
        .map_err(|e| format!("whois connection failed: {e}"))?;

        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

        write!(stream, "{}\r\n", query).map_err(|e| format!("whois write failed: {e}"))?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader
            .read_to_string(&mut response)
            .map_err(|e| format!("whois read failed: {e}"))?;

        Ok(response)
    }

    fn find_whois_server(domain: &str) -> Result<String, String> {
        let tld = domain.rsplit('.').next().unwrap_or("");
        let iana_url = format!("https://www.iana.org/whois?q={}", tld);
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .get(&iana_url)
            .send()
            .map_err(|e| format!("iana whois query: {e}"))?
            .text()
            .map_err(|e| format!("iana response: {e}"))?;

        for line in resp.lines() {
            let lower = line.to_lowercase();
            if lower.contains("whois.") && lower.contains(tld) {
                if let Some(server) = line.split_whitespace().find(|w| w.contains("whois.")) {
                    return Ok(server.trim_end_matches('.').to_string());
                }
            }
        }

        Err(format!("no whois server found for TLD .{}", tld))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_google_a_records() {
        let ips = DnsResolver::resolve_a("google.com");
        assert!(!ips.is_empty(), "should resolve at least one IP for google.com");
    }

    #[test]
    fn record_type_roundtrip() {
        for name in &["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"] {
            let rt = RecordType::parse_str(name).unwrap();
            assert_eq!(rt.as_str(), *name);
        }
    }

    #[test]
    fn invalid_record_type_returns_none() {
        assert!(RecordType::parse_str("INVALID").is_none());
    }

    #[test]
    fn record_type_case_insensitive() {
        assert!(RecordType::parse_str("a").is_some());
        assert!(RecordType::parse_str("aaaa").is_some());
        assert!(RecordType::parse_str("Mx").is_some());
    }

    #[test]
    fn record_type_all_variants_as_str() {
        for rt in [RecordType::A, RecordType::AAAA, RecordType::MX, RecordType::TXT, RecordType::NS, RecordType::SOA, RecordType::CNAME] {
            assert!(!rt.as_str().is_empty());
        }
    }

    #[test]
    fn dns_record_struct() {
        let r = DnsRecord {
            name: "example.com".into(),
            record_type: "A".into(),
            value: "93.184.216.34".into(),
            ttl: Some(300),
        };
        assert_eq!(r.record_type, "A");
        assert!(r.ttl.is_some());
    }

    #[test]
    fn dns_result_struct() {
        let r = DnsResult {
            domain: "example.com".into(),
            records: vec![],
            resolved_ips: vec!["1.2.3.4".into()],
            whois: None,
        };
        assert_eq!(r.resolved_ips.len(), 1);
        assert!(r.whois.is_none());
    }

    #[test]
    fn record_type_parse_all_invalid() {
        for invalid in &["", "PTR", "MXIP", "123", "SOAX"] {
            assert!(RecordType::parse_str(invalid).is_none(), "should be None for: {}", invalid);
        }
    }

    #[test]
    fn dns_result_with_whois() {
        let r = DnsResult {
            domain: "test.com".into(),
            records: vec![DnsRecord { name: "test.com".into(), record_type: "A".into(), value: "1.1.1.1".into(), ttl: Some(60) }],
            resolved_ips: vec!["1.1.1.1".into()],
            whois: Some("Registrar: Example".into()),
        };
        assert!(r.whois.is_some());
        assert!(!r.records.is_empty());
    }

    #[test]
    fn dns_record_no_ttl() {
        let r = DnsRecord {
            name: "test.com".into(),
            record_type: "TXT".into(),
            value: "v=spf1 include:_spf.google.com ~all".into(),
            ttl: None,
        };
        assert!(r.ttl.is_none());
    }
}
