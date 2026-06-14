use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use hickory_resolver::config::ResolverOpts;
use hickory_resolver::proto::rr::{Name as HickoryName, RData, RecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecords {
    pub domain: String,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<MxRecord>,
    pub ns_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub soa_record: Option<SoaRecord>,
    pub subdomains: Vec<SubdomainResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub name: String,
    pub ip_addresses: Vec<IpAddr>,
    pub is_alive: bool,
    pub takeover: Option<TakeoverInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverInfo {
    pub service: String,
    pub vulnerable: bool,
    pub evidence: String,
}

fn build_resolver(opts: ResolverOpts) -> Result<TokioResolver, String> {
    TokioResolver::builder_tokio()
        .map_err(|e| e.to_string())?
        .with_options(opts)
        .build()
        .map_err(|e| e.to_string())
}

pub fn enumerate(domain: &str) -> Result<DnsRecords, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    rt.block_on(async {
        let mut opts = ResolverOpts::default();
        opts.timeout = DNS_TIMEOUT;
        opts.attempts = 2;

        let resolver = build_resolver(opts)?;
        let domain_name = HickoryName::from_utf8(domain).map_err(|e| e.to_string())?;

        let a_records = lookup_a(&resolver, domain_name.clone()).await;
        let aaaa_records = lookup_aaaa(&resolver, domain_name.clone()).await;
        let mx_records = lookup_mx(&resolver, domain_name.clone()).await;
        let ns_records = lookup_ns(&resolver, domain_name.clone()).await;
        let txt_records = lookup_txt(&resolver, domain_name.clone()).await;
        let cname_records = lookup_cname(&resolver, domain_name.clone()).await;
        let soa_record = lookup_soa(&resolver, domain_name.clone()).await;

        Ok(DnsRecords {
            domain: domain.to_string(),
            a_records,
            aaaa_records,
            mx_records,
            ns_records,
            txt_records,
            cname_records,
            soa_record,
            subdomains: vec![],
        })
    })
}

pub fn brute_force(domain: &str, wordlist: &[String]) -> Result<Vec<SubdomainResult>, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    rt.block_on(async {
        let mut opts = ResolverOpts::default();
        opts.timeout = DNS_TIMEOUT;
        opts.attempts = 1;

        let resolver = build_resolver(opts)?;
        let total = wordlist.len();
        let completed = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(Mutex::new(Vec::new()));

        let concurrency = 64;
        let mut handles = vec![];

        for chunk in wordlist.chunks(concurrency) {
            let chunk = chunk.to_vec();
            let domain = domain.to_string();
            let resolver = resolver.clone();
            let results = Arc::clone(&results);
            let completed_ref = Arc::clone(&completed);

            let handle = tokio::spawn(async move {
                for sub in &chunk {
                    let fqdn = format!("{}.{}", sub, domain);
                    if let Ok(name) = HickoryName::from_utf8(&fqdn) {
                        if let Ok(response) = resolver.lookup_ip(name).await {
                            let ips: Vec<IpAddr> = response.iter().collect();
                            if !ips.is_empty() {
                                let takeover = check_takeover(&fqdn).await;
                                let mut results = results.lock().unwrap();
                                results.push(SubdomainResult {
                                    name: fqdn,
                                    ip_addresses: ips,
                                    is_alive: true,
                                    takeover,
                                });
                            }
                        }
                    }
                    let done = completed_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    if done.is_multiple_of(100) || done == total {
                        log::info!("DNS brute-force: {}/{} subdomains", done, total);
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        let mut all = results.lock().unwrap().clone();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all)
    })
}

pub fn reverse_lookup(ip: IpAddr) -> Result<Vec<String>, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    rt.block_on(async {
        let opts = ResolverOpts::default();
        let resolver = build_resolver(opts)?;

        match resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let results: Vec<String> = lookup.answers().iter().filter_map(|record| {
                    if let RData::PTR(name) = &record.data {
                        Some(name.to_string())
                    } else {
                        None
                    }
                }).collect();
                Ok(results)
            }
            Err(e) => Err(format!("Reverse DNS lookup failed: {}", e)),
        }
    })
}

async fn lookup_a(resolver: &TokioResolver, name: HickoryName) -> Vec<String> {
    resolver.lookup_ip(name).await
        .map(|r| r.iter().map(|ip| ip.to_string()).collect())
        .unwrap_or_default()
}

async fn lookup_aaaa(resolver: &TokioResolver, name: HickoryName) -> Vec<String> {
    resolver.lookup_ip(name).await
        .map(|r| r.iter().filter(|ip| ip.is_ipv6()).map(|ip| ip.to_string()).collect())
        .unwrap_or_default()
}

async fn lookup_ns(resolver: &TokioResolver, name: HickoryName) -> Vec<String> {
    resolver.ns_lookup(name).await
        .map(|r| {
            r.answers().iter().filter_map(|record| {
                if let RData::NS(ns) = &record.data {
                    Some(ns.to_string())
                } else {
                    None
                }
            }).collect()
        })
        .unwrap_or_default()
}

async fn lookup_txt(resolver: &TokioResolver, name: HickoryName) -> Vec<String> {
    resolver.txt_lookup(name).await
        .map(|r| {
            r.answers().iter().filter_map(|record| {
                if let RData::TXT(txt) = &record.data {
                    Some(txt.txt_data.iter().map(|s| String::from_utf8_lossy(s).to_string()).collect::<Vec<_>>().join(" "))
                } else {
                    None
                }
            }).collect()
        })
        .unwrap_or_default()
}

async fn lookup_cname(resolver: &TokioResolver, name: HickoryName) -> Vec<String> {
    resolver.lookup(name, RecordType::CNAME).await
        .map(|r| {
            r.answers().iter().filter_map(|record| {
                if let RData::CNAME(cname) = &record.data {
                    Some(cname.to_string())
                } else {
                    None
                }
            }).collect()
        })
        .unwrap_or_default()
}

async fn lookup_mx(resolver: &TokioResolver, name: HickoryName) -> Vec<MxRecord> {
    resolver.mx_lookup(name).await
        .map(|r| {
            r.answers().iter().filter_map(|record| {
                if let RData::MX(mx) = &record.data {
                    Some(MxRecord {
                        preference: mx.preference,
                        exchange: mx.exchange.to_string(),
                    })
                } else {
                    None
                }
            }).collect()
        })
        .unwrap_or_default()
}

async fn lookup_soa(resolver: &TokioResolver, name: HickoryName) -> Option<SoaRecord> {
    resolver.soa_lookup(name).await.ok().and_then(|r| {
        r.answers().iter().find_map(|record| {
            if let RData::SOA(soa) = &record.data {
                Some(SoaRecord {
                    mname: soa.mname.to_string(),
                    rname: soa.rname.to_string(),
                    serial: soa.serial,
                    refresh: soa.refresh,
                    retry: soa.retry,
                    expire: soa.expire,
                    minimum: soa.minimum,
                })
            } else {
                None
            }
        })
    })
}

async fn check_takeover(domain: &str) -> Option<TakeoverInfo> {
    let cname_check = check_cname_takeover(domain).await;
    if let Some(info) = cname_check {
        return Some(info);
    }

    let http_check = check_http_takeover(domain).await;
    if let Some(info) = http_check {
        return Some(info);
    }

    None
}

async fn check_cname_takeover(domain: &str) -> Option<TakeoverInfo> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;

    let resolver = TokioResolver::builder_tokio()
        .ok()?
        .with_options(opts)
        .build()
        .ok()?;
    let name = HickoryName::from_utf8(domain).ok()?;

    let lookup = resolver.lookup(name, RecordType::CNAME).await.ok()?;
    for record in lookup.answers() {
        let target = if let RData::CNAME(c) = &record.data { c.to_string().to_lowercase() } else { continue };
        for &(service, patterns) in KNOWN_TAKEOVER_SERVICES {
            if patterns.iter().any(|p| target.contains(p)) {
                return Some(TakeoverInfo {
                    service: service.to_string(),
                    vulnerable: true,
                    evidence: format!("CNAME points to {}: {}", service, target),
                });
            }
        }
    }
    None
}

async fn check_http_takeover(domain: &str) -> Option<TakeoverInfo> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    for scheme in &["https", "http"] {
        let url = format!("{}://{}", scheme, domain);
        if let Ok(response) = client.get(&url).send() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default().to_lowercase();

            for &(service, indicators) in KNOWN_TAKEOVER_INDICATORS {
                if indicators.iter().any(|i| body.contains(i)) && (status == 404 || status == 403 || status == 500) {
                    return Some(TakeoverInfo {
                        service: service.to_string(),
                        vulnerable: true,
                        evidence: format!("HTTP {} at {} with {} indicators", status, url, service),
                    });
                }
            }
        }
    }
    None
}

const KNOWN_TAKEOVER_SERVICES: &[(&str, &[&str])] = &[
    ("AWS S3", &["s3.amazonaws.com", "s3-website"]),
    ("AWS CloudFront", &["cloudfront.net"]),
    ("GitHub Pages", &["github.io"]),
    ("Heroku", &["herokuapp.com", "herokussl.com"]),
    ("Netlify", &["netlify.app", "netlify.com"]),
    ("Shopify", &["myshopify.com"]),
    ("WordPress", &["wordpress.com"]),
    ("Tumblr", &["tumblr.com"]),
    ("Surge", &["surge.sh"]),
    ("Bitbucket", &["bitbucket.io"]),
    ("Pantheon", &["pantheonsite.io"]),
    ("Fastly", &["fastly.net", "fastlylb.net"]),
    ("Azure", &["azurewebsites.net", "azureedge.net", "trafficmanager.net"]),
    ("GCP", &["appspot.com", "storage.googleapis.com", "firebaseio.com"]),
    ("Kinsta", &["kinsta.cloud"]),
    ("Fly.io", &["fly.dev"]),
    ("Vercel", &["vercel.app", "now.sh"]),
    ("Render", &["onrender.com"]),
    ("GitLab", &["gitlab.io"]),
    ("ReadTheDocs", &["readthedocs.io", "readthedocs.org"]),
    ("Strikingly", &["strikingly.com", "strikinglydns.com"]),
    ("Unbounce", &["unbouncepages.com"]),
    ("Tilda", &["tilda.ws"]),
    ("Cargo Collective", &["cargocollective.com"]),
    ("Helpjuice", &["helpjuice.com"]),
    ("Freshdesk", &["freshdesk.com"]),
    ("Zendesk", &["zendesk.com"]),
    ("Atlassian", &["atlassian.net"]),
    ("Campaign Monitor", &["createsend.com", "campaignmonitor.com"]),
    ("Acquia", &["acquia-test.co", "acquia-qa.com"]),
];

const KNOWN_TAKEOVER_INDICATORS: &[(&str, &[&str])] = &[
    ("AWS S3", &["no such bucket", "the specified bucket does not exist", "s3://"]),
    ("AWS CloudFront", &["distribution is not configured to serve this request", "cloudfront distribution"]),
    ("GitHub Pages", &["there isn't a github pages site here", "repository not found"]),
    ("Heroku", &["no such app", "there's nothing here, yet", "heroku"]),
    ("Netlify", &["not found - request id:", "page not found"]),
    ("Shopify", &["sorry, this shop is currently unavailable"]),
    ("WordPress", &["do you want to register", "che peccato!"]),
    ("Tumblr", &["there's nothing here", "the page you requested was not found"]),
    ("Surge", &["project not found", "surge"]),
    ("Bitbucket", &["repository not found"]),
    ("Pantheon", &["the gods are angry", "pantheon"]),
    ("Azure", &["app service is in the process of being set up", "azurewebsites"]),
    ("GCP", &["not found", "can't connect to the server"]),
    ("Vercel", &["the deployment could not be found", "vercel"]),
    ("Render", &["render", "page not found"]),
    ("GitLab", &["project not found"]),
    ("ReadTheDocs", &["read the docs", "the page you specified does not exist"]),
    ("Helpjuice", &["helpjuice"]),
    ("Freshdesk", &["freshdesk"]),
    ("Zendesk", &["zendesk"]),
    ("Atlassian", &["atlassian"]),
    ("Campaign Monitor", &["campaign monitor"]),
];
