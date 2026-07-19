use std::collections::HashMap;
use std::time::Duration;

use regex::Regex;
use reqwest::blocking::{Client, ClientBuilder};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};

use crate::DEFAULT_TIMEOUT;

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Kraken Security Scanner)";
const FUZZ_CONCURRENCY: usize = 32;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScanConfig {
    pub base_url: String,
    pub wordlist: Vec<String>,
    pub extensions: Vec<String>,
    pub concurrency: usize,
    pub timeout: Duration,
    pub follow_redirects: bool,
    pub user_agent: String,
    pub cookies: HashMap<String, String>,
}

impl Default for WebScanConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            wordlist: vec![],
            extensions: vec![
                ".php".into(),
                ".asp".into(),
                ".aspx".into(),
                ".jsp".into(),
                ".do".into(),
                ".html".into(),
                ".htm".into(),
                ".txt".into(),
                ".bak".into(),
                ".old".into(),
                ".env".into(),
                ".git".into(),
                ".svn".into(),
                ".json".into(),
                ".xml".into(),
                ".config".into(),
                ".inc".into(),
                ".sql".into(),
                ".tar".into(),
                ".gz".into(),
                ".zip".into(),
                ".log".into(),
            ],
            concurrency: FUZZ_CONCURRENCY,
            timeout: DEFAULT_TIMEOUT,
            follow_redirects: false,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            cookies: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub url: String,
    pub status: u16,
    pub size: usize,
    pub content_type: Option<String>,
    pub title: Option<String>,
    pub is_directory: bool,
    pub redirected_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VHostResult {
    pub host: String,
    pub status: u16,
    pub size: usize,
    pub content_type: Option<String>,
    pub different_from_base: bool,
    pub serves_same_content: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamResult {
    pub parameter: String,
    pub url: String,
    pub status: u16,
    pub response_time_ms: u64,
    pub reflected: bool,
    pub size_diff: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafInfo {
    pub detected: bool,
    pub name: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechEntry {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: f64,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub plugins: Vec<(String, Option<String>)>,
    pub themes: Vec<(String, Option<String>)>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsEndpoint {
    pub url: String,
    pub endpoint: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotsInfo {
    pub exists: bool,
    pub sitemaps: Vec<String>,
    pub allowed: Vec<String>,
    pub disallowed: Vec<String>,
    pub crawl_delay: Option<u64>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_client(config: &WebScanConfig) -> Client {
    let mut builder = ClientBuilder::new()
        .timeout(config.timeout)
        .user_agent(&config.user_agent)
        .danger_accept_invalid_certs(true);

    if !config.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if !config.cookies.is_empty() {
        let mut headers = reqwest::header::HeaderMap::new();
        let cookie_str: String = config
            .cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&cookie_str) {
            headers.insert(reqwest::header::COOKIE, val);
        }
        builder = builder.default_headers(headers);
    }

    builder.build().unwrap_or_default()
}

fn extract_title(body: &str) -> Option<String> {
    let re = Regex::new(r"(?i)<title[^>]*>([^<]+)</title>").ok()?;
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn normalize_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{}", path) };
    format!("{}{}", base, path)
}

// ---------------------------------------------------------------------------
// 1. Directory / File Fuzzer
// ---------------------------------------------------------------------------

pub fn fuzz_directories(config: &WebScanConfig) -> Vec<FuzzResult> {
    let client = build_client(config);
    let mut results = Vec::new();

    for path in &config.wordlist {
        let url = normalize_url(&config.base_url, path);
        if let Ok(resp) = client.get(&url).send() {
            let status = resp.status().as_u16();
            if status != 404 {
                let content_type = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let redirected_to = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let body = resp.text().unwrap_or_default();
                let size = body.len();
                let title = extract_title(&body);
                let is_dir = status == 301
                    || status == 302
                    || url.ends_with('/')
                    || content_type.as_deref().unwrap_or("").starts_with("text/html");

                results.push(FuzzResult {
                    url,
                    status,
                    size,
                    content_type,
                    title,
                    is_directory: is_dir,
                    redirected_to,
                });
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// 2. Extension Fuzzer
// ---------------------------------------------------------------------------

pub fn fuzz_extensions(config: &WebScanConfig) -> Vec<FuzzResult> {
    let client = build_client(config);
    let mut results = Vec::new();

    for base_path in &config.wordlist {
        for ext in &config.extensions {
            let path = format!("{}{}", base_path, ext);
            let url = normalize_url(&config.base_url, &path);
            if let Ok(resp) = client.get(&url).send() {
                let status = resp.status().as_u16();
                if status != 404 {
                    let content_type = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let redirected_to = resp
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let body = resp.text().unwrap_or_default();
                    let title = extract_title(&body);

                    results.push(FuzzResult {
                        url,
                        status,
                        size: body.len(),
                        content_type,
                        title,
                        is_directory: false,
                        redirected_to,
                    });
                }
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// 3. Recursive Scan
// ---------------------------------------------------------------------------

pub fn recursive_scan(config: &WebScanConfig, max_depth: usize) -> Vec<FuzzResult> {
    let mut all = Vec::new();
    let mut dirs_to_scan: Vec<String> = vec![config.base_url.trim_end_matches('/').to_string()];
    let mut visited = std::collections::HashSet::new();

    for depth in 0..max_depth {
        let current_batch = std::mem::take(&mut dirs_to_scan);
        if current_batch.is_empty() {
            break;
        }

        for base in &current_batch {
            if !visited.insert(base.clone()) {
                continue;
            }

            let mut cfg = config.clone();
            cfg.base_url = base.clone();
            let found = fuzz_directories(&cfg);
            for r in &found {
                if r.is_directory && depth + 1 < max_depth {
                    dirs_to_scan.push(r.url.trim_end_matches('/').to_string());
                }
            }
            all.extend(found);
        }

        log::info!(
            "Recursive scan depth {}: {} dirs discovered, {} total results",
            depth + 1,
            dirs_to_scan.len(),
            all.len()
        );
    }

    all
}

// ---------------------------------------------------------------------------
// 4. VHost Discovery
// ---------------------------------------------------------------------------

pub fn discover_vhosts(
    ip: &str,
    base_domain: &str,
    subdomains: &[String],
) -> Vec<VHostResult> {
    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();

    let base_url = format!("http://{}", ip);
    let base_resp = client.get(&base_url).send();
    let base_size = base_resp
        .ok()
        .and_then(|r| r.text().ok())
        .map(|b| b.len())
        .unwrap_or(0);

    let mut results = Vec::new();

    for sub in subdomains {
        let host = if sub.is_empty() {
            base_domain.to_string()
        } else {
            format!("{}.{}", sub, base_domain)
        };

        if let Ok(resp) = client
            .get(&base_url)
            .header(reqwest::header::HOST, &host)
            .send()
        {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let body = resp.text().unwrap_or_default();
            let size = body.len();

            let different = size != base_size;
            let same = (size as i64 - base_size as i64).abs() < 100;

            if different {
                results.push(VHostResult {
                    host,
                    status,
                    size,
                    content_type,
                    different_from_base: true,
                    serves_same_content: same,
                });
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// 5. Parameter Fuzzer
// ---------------------------------------------------------------------------

pub fn fuzz_parameters(
    base_url: &str,
    params: &[String],
    method: &str,
) -> Vec<ParamResult> {
    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .build()
        .unwrap_or_default();

    let baseline = send_base_request(&client, base_url, method);
    let base_size = baseline.0;

    let mut results = Vec::new();
    let test_value = "kraken1337";

    for param in params {
        let url = format!("{}?{}= {}", base_url, param, test_value);
        let start = std::time::Instant::now();
        if let Ok(resp) = client.get(&url).send() {
            let elapsed = start.elapsed().as_millis() as u64;
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            let reflected = body.contains(test_value);
            let size_diff = body.len() as i64 - base_size as i64;

            results.push(ParamResult {
                parameter: param.clone(),
                url,
                status,
                response_time_ms: elapsed,
                reflected,
                size_diff,
            });
        }
    }

    results
}

fn send_base_request(client: &Client, url: &str, method: &str) -> (usize, u64) {
    let start = std::time::Instant::now();
    let resp = match method.to_uppercase().as_str() {
        "POST" => client.post(url).send(),
        _ => client.get(url).send(),
    };
    let elapsed = start.elapsed().as_millis() as u64;
    let size = resp
        .ok()
        .and_then(|r| r.text().ok())
        .map(|b| b.len())
        .unwrap_or(0);
    (size, elapsed)
}

// ---------------------------------------------------------------------------
// 6. WAF Detection
// ---------------------------------------------------------------------------

pub fn detect_waf(url: &str) -> WafInfo {
    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut evidence = Vec::new();
    let mut waf_name: Option<String> = None;

    // Request with a malicious-looking payload
    let attack_url = format!("{}/?q=<script>alert(1)</script>", url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&attack_url).send() {
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.text().unwrap_or_default().to_lowercase();

        // Check response headers for WAF signatures
        if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
            let server_lower = server.to_lowercase();
            for (name, patterns) in WAF_HEADER_SIGNATURES {
                if patterns.iter().any(|p| server_lower.contains(p)) {
                    evidence.push(format!("Server header: {}", server));
                    waf_name = Some(name.to_string());
                }
            }
        }

        for (key, _) in headers.iter() {
            let key_str = key.as_str().to_lowercase();
            if let Some(val) = headers.get(key).and_then(|v| v.to_str().ok()) {
                let combined = format!("{}: {}", key_str, val.to_lowercase());
                for (name, patterns) in WAF_HEADER_SIGNATURES {
                    if patterns.iter().any(|p| combined.contains(p)) {
                        evidence.push(format!("Header {}: {}", key_str, val));
                        waf_name = Some(name.to_string());
                    }
                }
            }
        }

        // Check status codes typical of WAFs
        if status == 406 || status == 501 || status == 999 {
            evidence.push(format!("Block status code: {}", status));
            if waf_name.is_none() {
                waf_name = Some("Generic WAF".to_string());
            }
        }

        // Check body for WAF block pages
        for (name, patterns) in WAF_BODY_SIGNATURES {
            if patterns.iter().any(|p| body.contains(p)) {
                evidence.push(format!("Block page indicators for {}", name));
                waf_name = Some(name.to_string());
            }
        }
    }

    WafInfo {
        detected: !evidence.is_empty(),
        name: waf_name,
        evidence,
    }
}

const WAF_HEADER_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cloudflare"]),
    ("ModSecurity", &["mod_security", "modsecurity"]),
    ("AWS WAF", &["awswaf"]),
    ("Akamai GHOST", &["akamai"]),
    ("F5 BIG-IP ASM", &["big-ip", "f5"]),
    ("Barracuda WAF", &["barracuda"]),
    ("Imperva Incapsula", &["incapsula", "imperva"]),
    ("Sucuri WAF", &["sucuri"]),
    ("Wordfence", &["wordfence"]),
    ("Fortinet FortiWeb", &["fortiweb"]),
    ("Radware WAF", &["radware"]),
    ("StackPath", &["stackpath"]),
    ("Comodo WAF", &["comodo"]),
];

const WAF_BODY_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cloudflare ray id", "attention required", "cf-ray"]),
    ("ModSecurity", &["modsecurity", "not acceptable", "406 not acceptable"]),
    ("AWS WAF", &["request blocked", "awswaf"]),
    ("Akamai GHOST", &["reference number", "akamai"]),
    ("F5 BIG-IP ASM", &["the requested url was rejected", "f5"]),
    ("Imperva Incapsula", &["incapsula", "blocked because"]),
    ("Sucuri WAF", &["sucuri", "blocked by sucuri"]),
    ("Wordfence", &["wordfence", "blocked by wordfence"]),
    ("Fortinet FortiWeb", &["fortiweb", "fortigate"]),
    ("Radware WAF", &["radware", "captcha"]),
];

// ---------------------------------------------------------------------------
// 7. Tech Fingerprint
// ---------------------------------------------------------------------------

pub fn fingerprint_tech(url: &str) -> Vec<TechEntry> {
    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut entries = Vec::new();
    let Ok(resp) = client.get(url).send() else { return entries };
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().unwrap_or_default();
    let lower = body.to_lowercase();

    // --- Header-based detection ---
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        for (name, patterns) in TECH_HEADER_SIGNATURES {
            if patterns.iter().any(|p| server.to_lowercase().contains(p)) {
                let (product, version) = parse_product_version(server, "/");
                entries.push(TechEntry {
                    name: product.unwrap_or(name.to_string()),
                    version,
                    category: "Web server".to_string(),
                    confidence: 0.9,
                    evidence: format!("Server header: {}", server),
                });
            }
        }
    }

    if let Some(x_powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        let (product, version) = parse_product_version(x_powered, "/");
        entries.push(TechEntry {
            name: product.unwrap_or_else(|| x_powered.to_string()),
            version,
            category: "Framework".to_string(),
            confidence: 0.9,
            evidence: format!("X-Powered-By: {}", x_powered),
        });
    }

    // --- Cookie-based detection ---
    if let Some(set_cookie) = headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
        for (name, patterns) in TECH_COOKIE_SIGNATURES {
            if patterns.iter().any(|p| set_cookie.contains(p)) {
                entries.push(TechEntry {
                    name: name.to_string(),
                    version: None,
                    category: "Web server / Framework".to_string(),
                    confidence: 0.8,
                    evidence: format!("Set-Cookie contains {}", patterns[0]),
                });
            }
        }
    }

    // --- HTML meta-based detection ---
    let doc = Html::parse_document(&body);
    let generator_sel = Selector::parse("meta[name=generator]").ok();
    if let Some(sel) = generator_sel {
        for el in doc.select(&sel) {
            if let Some(content) = el.value().attr("content") {
                let (product, version) = parse_product_version(content, " ");
                entries.push(TechEntry {
                    name: product.unwrap_or_else(|| content.to_string()),
                    version,
                    category: "CMS / Generator".to_string(),
                    confidence: 0.95,
                    evidence: format!("Meta generator: {}", content),
                });
            }
        }
    }

    // --- Body content detection ---
    for (name, category, patterns) in TECH_BODY_SIGNATURES {
        if patterns.iter().any(|p| lower.contains(p)) {
            let version = extract_version_from_body(&lower, name);
            let conf = if version.is_some() { 0.9 } else { 0.7 };
            entries.push(TechEntry {
                name: name.to_string(),
                version,
                category: category.to_string(),
                confidence: conf,
                evidence: format!("Body pattern matched for {}", name),
            });
        }
    }

    // Status-based detection
    if status == 401 || status == 403 {
        if let Some(www_auth) = headers.get("www-authenticate").and_then(|v| v.to_str().ok()) {
            if www_auth.to_lowercase().contains("basic") {
                entries.push(TechEntry {
                    name: "HTTP Basic Auth".to_string(),
                    version: None,
                    category: "Authentication".to_string(),
                    confidence: 0.95,
                    evidence: format!("WWW-Authenticate: {}", www_auth),
                });
            }
        }
    }

    entries
}

fn parse_product_version(input: &str, sep: &str) -> (Option<String>, Option<String>) {
    let parts: Vec<&str> = input.splitn(2, sep).collect();
    if parts.len() == 2 {
        (Some(parts[0].trim().to_string()), Some(parts[1].trim().to_string()))
    } else {
        (Some(input.trim().to_string()), None)
    }
}

fn extract_version_from_body(body: &str, product: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?i){}[\s/]*v?(\d+\.\d+(?:\.\d+)?)"#,
        regex::escape(product)
    ))
    .ok()?;
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

const TECH_HEADER_SIGNATURES: &[(&str, &[&str])] = &[
    ("Apache", &["apache"]),
    ("nginx", &["nginx"]),
    ("Microsoft IIS", &["microsoft-iis", "iis"]),
    ("lighttpd", &["lighttpd"]),
    ("Caddy", &["caddy"]),
    ("Tomcat", &["tomcat"]),
    ("Jetty", &["jetty"]),
    ("Node.js", &["node.js"]),
    ("Python", &["python"]),
    ("Cloudflare", &["cloudflare"]),
];

const TECH_COOKIE_SIGNATURES: &[(&str, &[&str])] = &[
    ("ASP.NET", &["asp.net", "aspnet"]),
    ("PHP", &["phpsessid"]),
    ("Java EE", &["jsessionid"]),
    ("Laravel", &["laravel_session"]),
    ("Symfony", &["symfony"]),
    ("Django", &["csrftoken", "sessionid"]),
    ("Ruby on Rails", &["_session_id"]),
    ("Express", &["connect.sid"]),
    ("WordPress", &["wordpress_logged_in", "wp-settings"]),
];

const TECH_BODY_SIGNATURES: &[(&str, &str, &[&str])] = &[
    ("WordPress", "CMS", &["wp-content", "wp-includes", "wp-json"]),
    ("Joomla", "CMS", &["joomla", "com_content", "com_users"]),
    ("Drupal", "CMS", &["drupal", "sites/default", "core/themes"]),
    ("Magento", "CMS", &["mage-cache", "magento", "static/version"]),
    ("Shopify", "E-commerce", &["shopify", "myshopify"]),
    ("WooCommerce", "E-commerce", &["woocommerce", "wc-"]),
    ("Ghost", "CMS", &["ghost"]),
    ("Umbraco", "CMS", &["umbraco"]),
    ("Concrete5", "CMS", &["concrete5"]),
    ("Laravel", "Framework", &["laravel", "livewire"]),
    ("Symfony", "Framework", &["symfony", "_symfony"]),
    ("Django", "Framework", &["django", "csrfmiddleware"]),
    ("Ruby on Rails", "Framework", &["rails", "ruby on rails"]),
    ("Express", "Framework", &["express", "connect.sid"]),
    ("Flask", "Framework", &["flask"]),
    ("Vue.js", "JS Framework", &["vue.js", "vuejs"]),
    ("React", "JS Framework", &["react", "reactjs"]),
    ("Angular", "JS Framework", &["angular"]),
    ("jQuery", "JS Library", &["jquery"]),
    ("Bootstrap", "CSS Framework", &["bootstrap", "bootstrap.css"]),
    ("Tailwind CSS", "CSS Framework", &["tailwind"]),
    ("Font Awesome", "Icon Library", &["font-awesome", "fontawesome"]),
    ("Google Analytics", "Analytics", &["google-analytics", "ga.js"]),
    ("Cloudflare", "CDN", &["cloudflare"]),
    ("Alpine.js", "JS Library", &["alpine.js"]),
    ("htmx", "JS Library", &["htmx"]),
    ("Stripe", "Payment", &["stripe.com", "stripe.js"]),
    ("reCAPTCHA", "Security", &["recaptcha"]),
    ("hCaptcha", "Security", &["hcaptcha"]),
];

// ---------------------------------------------------------------------------
// 8. CMS Scanner
// ---------------------------------------------------------------------------

pub fn scan_cms(url: &str) -> CmsInfo {
    let techs = fingerprint_tech(url);

    let cms_name = techs.iter().find_map(|t| {
        if t.category == "CMS" {
            Some(t.name.clone())
        } else {
            None
        }
    });

    if let Some(name) = cms_name {
        let version = detect_cms_version(url, &name);
        let conf = if version.is_some() { 0.9 } else { 0.75 };
        let plugins = detect_cms_plugins(url, &name);
        let themes = detect_cms_themes(url, &name);

        CmsInfo {
            name: Some(name.to_string()),
            version,
            plugins,
            themes,
            confidence: conf,
        }
    } else {
        CmsInfo {
            name: None,
            version: None,
            plugins: vec![],
            themes: vec![],
            confidence: 0.0,
        }
    }
}

fn detect_cms_version(url: &str, cms: &str) -> Option<String> {
    let version_paths: &[(&str, &str)] = match cms {
        "WordPress" => &[
            ("/readme.html", r"Version\s+(\d+\.\d+(?:\.\d+)?)"),
            ("/feed/", r"generator>\s*https?://wordpress\.org/\?v=(\d+\.\d+(?:\.\d+)?)"),
            ("/wp-links-opml.php", r##"generator="wordpress/(\d+\.\d+(?:\.\d+)?)"##),
        ],
        "Joomla" => &[
            ("joomla.xml", r"<version>(\d+\.\d+(?:\.\d+)?)"),
            ("en-GB.xml", r"<version>(\d+\.\d+(?:\.\d+)?)"),
        ],
        "Drupal" => &[
            ("CHANGELOG.txt", r"Drupal\s+(\d+\.\d+(?:\.\d+)?)"),
            ("CHANGELOG2.txt", r"Drupal\s+(\d+\.\d+(?:\.\d+)?)"),
        ],
        "Magento" => &[("magento_version", r"(\d+\.\d+(?:\.\d+)?)")],
        _ => &[],
    };
    let version_paths: Vec<(&str, &str)> = version_paths.iter().map(|(p, r)| {
        let full = if cms == "Joomla" && *p == "joomla.xml" {
            "/administrator/manifests/files/joomla.xml"
        } else if cms == "Joomla" && *p == "en-GB.xml" {
            "/language/en-GB/en-GB.xml"
        } else if cms == "Drupal" && *p == "CHANGELOG.txt" {
            "/core/CHANGELOG.txt"
        } else if cms == "Drupal" && *p == "CHANGELOG2.txt" {
            "/CHANGELOG.txt"
        } else if cms == "Magento" && *p == "magento_version" {
            "/magento_version"
        } else {
            *p
        };
        (full, *r)
    }).collect();

    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;

    for (path, pattern) in version_paths {
        let full_url = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&full_url).send() {
            if resp.status().is_success() {
                if let Ok(body) = resp.text() {
                    if let Ok(re) = Regex::new(pattern) {
                        if let Some(caps) = re.captures(&body) {
                            if let Some(m) = caps.get(1) {
                                return Some(m.as_str().to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn detect_cms_plugins(url: &str, cms: &str) -> Vec<(String, Option<String>)> {
    let _ = url;
    match cms {
        "WordPress" => detect_wp_plugins(),
        _ => vec![],
    }
}

fn detect_wp_plugins() -> Vec<(String, Option<String>)> {
    // In a full implementation this would probe /wp-content/plugins/<name>/
    // and parse readme.txt for version numbers
    vec![]
}

fn detect_cms_themes(url: &str, cms: &str) -> Vec<(String, Option<String>)> {
    let _ = url;
    match cms {
        "WordPress" => vec![],
        _ => vec![],
    }
}



// ---------------------------------------------------------------------------
// 9. JS Parser
// ---------------------------------------------------------------------------

pub fn parse_js_endpoints(url: &str) -> Vec<JsEndpoint> {
    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut endpoints = Vec::new();

    // Find script tags in the HTML
    let Ok(resp) = client.get(url).send() else { return endpoints };
    let html = resp.text().unwrap_or_default();

    // Extract script src attributes
    let script_re = Regex::new(r#"(?i)<script[^>]*src=["']([^"']+)["']"#).ok();
    if let Some(re) = script_re {
        for cap in re.captures_iter(&html) {
            if let Some(src) = cap.get(1) {
                let js_url = if src.as_str().starts_with("http") {
                    src.as_str().to_string()
                } else {
                    format!("{}/{}", url.trim_end_matches('/'), src.as_str().trim_start_matches('/'))
                };

                if let Ok(js_resp) = client.get(&js_url).send() {
                    if let Ok(js_body) = js_resp.text() {
                        endpoints.extend(extract_from_js(&js_url, &js_body));
                    }
                }
            }
        }
    }

    // Also extract inline JS
    let inline_re = Regex::new(r"(?i)<script[^>]*>([^<]+)</script>").ok();
    if let Some(re) = inline_re {
        let inline_endpoints = extract_from_js(url, &html);
        endpoints.extend(
            re.captures_iter(&html)
                .filter_map(|cap| cap.get(1))
                .flat_map(|m| extract_from_js(url, m.as_str()))
                .chain(inline_endpoints),
        );
    }

    endpoints
}

fn extract_from_js(js_url: &str, body: &str) -> Vec<JsEndpoint> {
    let mut endpoints = Vec::new();

    // API endpoint patterns (no backreferences; regex crate doesn't support them)
    let patterns = [
        r#"(?i)["'/](/[a-z0-9_/.-]*(?:api|v[1-9]\d*|rest|graphql|endpoint|webhook|hook)[a-z0-9_/.-]*)["'/]"#,
        r#"(?i)["'/](/[a-z0-9_/.-]*/(?:login|signin|signup|register|auth|token|oauth|callback|logout)(?:/[\w-]*)?)["'/]"#,
        r#"(?i)["'/](/[a-z0-9_/.-]*(?:admin|dashboard|config|settings|upload|download|export|import|backup)(?:/[\w-]*)?)["'/]"#,
        r#"(?i)(?:url|href|action|src|fetch|axios|ajax|xhr)\s*[=:]\s*["'`]([^"'`]+)["'`]"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(body) {
                if let Some(m) = cap.get(1) {
                    let endpoint = m.as_str().to_string();
                    if !endpoint.is_empty() && endpoint.len() > 1 {
                        endpoints.push(JsEndpoint {
                            url: js_url.to_string(),
                            endpoint,
                            context: None,
                        });
                    }
                }
            }
        }
    }

    // Secret-like patterns
    let secret_patterns = [
        (r#"(?i)api[_-]?key\s*[=:]\s*["'`]([a-z0-9_\-]{16,})["'`]"#, "API key"),
        (r#"(?i)secret\s*[=:]\s*["'`]([a-z0-9_\-]{16,})["'`]"#, "Secret"),
        (r#"(?i)token\s*[=:]\s*["'`]([a-z0-9_\-]{16,})["'`]"#, "Token"),
        (r#"(?i)password\s*[=:]\s*["'`]([^"'`]{6,})["'`]"#, "Password"),
        (r#"(?i)aws.?secret.?access.?key[=:]\s*["'`]([a-z0-9/+]{40})["'`]"#, "AWS Secret Key"),
        (r#"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}"#, "GitHub Token"),
    ];

    for (pattern, label) in &secret_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(body) {
                let value = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if !value.is_empty() {
                    endpoints.push(JsEndpoint {
                        url: js_url.to_string(),
                        endpoint: format!("[{}] {}", label, value),
                        context: Some(label.to_string()),
                    });
                }
            }
        }
    }

    endpoints
}

// ---------------------------------------------------------------------------
// 10. Robots.txt & Sitemap Analyzer
// ---------------------------------------------------------------------------

pub fn analyze_robots(url: &str) -> RobotsInfo {
    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .build()
        .unwrap_or_default();

    let robots_url = format!("{}/robots.txt", url.trim_end_matches('/'));
    let Ok(resp) = client.get(&robots_url).send() else {
        return RobotsInfo {
            exists: false,
            sitemaps: vec![],
            allowed: vec![],
            disallowed: vec![],
            crawl_delay: None,
        };
    };

    if !resp.status().is_success() {
        return RobotsInfo {
            exists: false,
            sitemaps: vec![],
            allowed: vec![],
            disallowed: vec![],
            crawl_delay: None,
        };
    }

    let body = resp.text().unwrap_or_default();
    let mut sitemaps = Vec::new();
    let mut allowed = Vec::new();
    let mut disallowed = Vec::new();
    let mut crawl_delay: Option<u64> = None;
    let mut in_user_agent_all = false;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let lower = line.to_lowercase();
        if lower.starts_with("user-agent") {
            in_user_agent_all = lower.contains("*");
        } else if in_user_agent_all {
            if let Some(path) = lower.strip_prefix("disallow:").map(|s| s.trim()) {
                if !path.is_empty() {
                    disallowed.push(path.to_string());
                }
            }
            if let Some(path) = lower.strip_prefix("allow:").map(|s| s.trim()) {
                if !path.is_empty() {
                    allowed.push(path.to_string());
                }
            }
        }

        if let Some(url_str) = lower.strip_prefix("sitemap:").map(|s| s.trim()) {
            if !url_str.is_empty() {
                sitemaps.push(url_str.to_string());
            }
        }

        if let Some(sec) = lower.strip_prefix("crawl-delay:").map(|s| s.trim()) {
            if let Ok(delay) = sec.parse::<u64>() {
                crawl_delay = Some(delay);
            }
        }
    }

    RobotsInfo {
        exists: true,
        sitemaps,
        allowed,
        disallowed,
        crawl_delay,
    }
}

pub fn parse_sitemap(url: &str) -> Vec<String> {
    let client = ClientBuilder::new()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(DEFAULT_USER_AGENT)
        .build()
        .unwrap_or_default();

    let Ok(resp) = client.get(url).send() else { return vec![] };
    let body = resp.text().unwrap_or_default();

    let mut urls = Vec::new();
    let re = Regex::new(r"(?i)<loc[^>]*>([^<]+)</loc>").ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&body) {
            if let Some(m) = cap.get(1) {
                urls.push(m.as_str().trim().to_string());
            }
        }
    }

    urls
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_title() {
        assert_eq!(
            extract_title("<html><title>Test Page</title></html>"),
            Some("Test Page".to_string())
        );
        assert_eq!(extract_title("<html></html>"), None);
    }

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("http://example.com", "/admin"),
            "http://example.com/admin"
        );
        assert_eq!(
            normalize_url("http://example.com/", "admin"),
            "http://example.com/admin"
        );
    }

    #[test]
    fn test_parse_product_version() {
        let (product, version) = parse_product_version("Apache/2.4.41", "/");
        assert_eq!(product, Some("Apache".to_string()));
        assert_eq!(version, Some("2.4.41".to_string()));
    }

    #[test]
    fn test_extract_version_from_body() {
        let body = "WordPress 5.8.1 running on nginx";
        assert_eq!(
            extract_version_from_body(body, "WordPress"),
            Some("5.8.1".to_string())
        );
    }

    #[test]
    fn test_analyze_robots_empty() {
        let info = RobotsInfo {
            exists: false,
            sitemaps: vec![],
            allowed: vec![],
            disallowed: vec![],
            crawl_delay: None,
        };
        assert!(!info.exists);
        assert!(info.disallowed.is_empty());
    }

    #[test]
    fn test_js_endpoint_extraction() {
        let js = r#"
            const api = "/api/v2/users";
            fetch('/rest/endpoint');
            const url = "/admin/dashboard";
        "#;
        // Quick check patterns compile and match
        let p = r#"(?i)["'/](/[a-z0-9_/.-]*(?:api|v[1-9]\d*|rest|graphql|endpoint|webhook|hook)[a-z0-9_/.-]*)["'/]"#;
        let re = Regex::new(p).unwrap();
        assert!(re.is_match(js), "Pattern 1 should match at least one URL");

        let endpoints = extract_from_js("test.js", js);
        assert!(!endpoints.is_empty(), "Should find at least one endpoint");
        assert!(endpoints.iter().any(|e| e.endpoint.contains("api")), "Should find /api/v2/users");
    }

    #[test]
    fn test_secret_detection() {
        let js = r#"const apiKey = "sk_live_1234567890abcdefghij";"#;
        let endpoints = extract_from_js("test.js", js);
        assert!(!endpoints.is_empty());
    }

    #[test]
    fn test_parse_sitemap_xml() {
        let xml = r#"<?xml version="1.0"?>
        <urlset>
            <url><loc>https://example.com/</loc></url>
            <url><loc>https://example.com/about</loc></url>
        </urlset>"#;
        let urls = parse_sitemap_with_body(xml);
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn test_waf_signatures() {
        assert!(WAF_HEADER_SIGNATURES.iter().any(|(n, _)| *n == "Cloudflare"));
        assert!(WAF_BODY_SIGNATURES.iter().any(|(n, _)| *n == "ModSecurity"));
    }

    #[test]
    fn test_tech_signatures() {
        assert!(TECH_HEADER_SIGNATURES.iter().any(|(n, _)| *n == "nginx"));
        assert!(TECH_COOKIE_SIGNATURES.iter().any(|(n, _)| *n == "PHP"));
        assert!(TECH_BODY_SIGNATURES.iter().any(|(n, _, _)| *n == "WordPress"));
    }

    #[test]
    fn test_extract_title_case_insensitive() {
        assert_eq!(
            extract_title("<HTML><TITLE>My Page</TITLE></HTML>"),
            Some("My Page".to_string())
        );
        assert_eq!(
            extract_title("<html><title>lowercase</title></html>"),
            Some("lowercase".to_string())
        );
    }

    #[test]
    fn test_extract_title_with_attributes() {
        assert_eq!(
            extract_title(r#"<title lang="en">Test</title>"#),
            Some("Test".to_string())
        );
    }

    #[test]
    fn test_extract_title_whitespace_trimmed() {
        assert_eq!(
            extract_title("<title>  spaces  </title>"),
            Some("spaces".to_string())
        );
    }

    #[test]
    fn test_extract_title_no_closing_tag() {
        assert_eq!(extract_title("<title>open"), None);
    }

    #[test]
    fn test_normalize_url_deep_path() {
        assert_eq!(
            normalize_url("http://example.com", "/a/b/c"),
            "http://example.com/a/b/c"
        );
    }

    #[test]
    fn test_normalize_url_double_slash_base() {
        assert_eq!(
            normalize_url("http://example.com/", "/test"),
            "http://example.com/test"
        );
    }

    #[test]
    fn test_normalize_url_no_path_prefix() {
        assert_eq!(
            normalize_url("http://example.com", "admin"),
            "http://example.com/admin"
        );
    }

    #[test]
    fn test_parse_product_version_no_sep() {
        let (product, version) = parse_product_version("Apache", "/");
        assert_eq!(product, Some("Apache".to_string()));
        assert!(version.is_none());
    }

    #[test]
    fn test_parse_product_version_multiple_sep() {
        let (product, version) = parse_product_version("nginx/1.24.0", "/");
        assert_eq!(product, Some("nginx".to_string()));
        assert_eq!(version, Some("1.24.0".to_string()));
    }

    #[test]
    fn test_extract_version_from_body_not_found() {
        let body = "Hello world, no versions here";
        assert!(extract_version_from_body(body, "NonExistent").is_none());
    }

    #[test]
    fn test_extract_version_from_body_with_version() {
        let body = "jQuery 3.7.1 loaded";
        let ver = extract_version_from_body(body, "jQuery");
        assert_eq!(ver, Some("3.7.1".to_string()));
    }

    #[test]
    fn test_web_scan_config_default() {
        let config = WebScanConfig::default();
        assert!(config.base_url.is_empty());
        assert!(config.wordlist.is_empty());
        assert!(!config.extensions.is_empty());
        assert_eq!(config.concurrency, 32);
        assert!(!config.follow_redirects);
        assert!(config.cookies.is_empty());
    }

    #[test]
    fn test_fuzz_result_struct() {
        let fr = FuzzResult {
            url: "http://example.com/admin".into(),
            status: 200,
            size: 1024,
            content_type: Some("text/html".into()),
            title: Some("Admin Panel".into()),
            is_directory: true,
            redirected_to: None,
        };
        assert_eq!(fr.status, 200);
        assert!(fr.is_directory);
    }

    #[test]
    fn test_vhost_result_struct() {
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
    fn test_param_result_struct() {
        let pr = ParamResult {
            parameter: "id".into(),
            url: "http://example.com/page?id=1".into(),
            status: 200,
            response_time_ms: 50,
            reflected: true,
            size_diff: 100,
        };
        assert!(pr.reflected);
        assert_eq!(pr.response_time_ms, 50);
    }

    #[test]
    fn test_waf_info_struct() {
        let wi = WafInfo {
            detected: true,
            name: Some("Cloudflare".into()),
            evidence: vec!["Server header: cloudflare".into()],
        };
        assert!(wi.detected);
        assert_eq!(wi.name, Some("Cloudflare".into()));
    }

    #[test]
    fn test_tech_entry_struct() {
        let te = TechEntry {
            name: "nginx".into(),
            version: Some("1.24".into()),
            category: "Web server".into(),
            confidence: 0.9,
            evidence: "Server header: nginx/1.24".into(),
        };
        assert_eq!(te.confidence, 0.9);
        assert!(te.version.is_some());
    }

    #[test]
    fn test_cms_info_struct() {
        let ci = CmsInfo {
            name: Some("WordPress".into()),
            version: Some("6.4".into()),
            plugins: vec![("akismet".into(), Some("5.1".into()))],
            themes: vec![("flavor".into(), None)],
            confidence: 0.9,
        };
        assert_eq!(ci.name, Some("WordPress".into()));
        assert_eq!(ci.plugins.len(), 1);
        assert_eq!(ci.themes.len(), 1);
    }

    #[test]
    fn test_js_endpoint_struct() {
        let je = JsEndpoint {
            url: "http://example.com/app.js".into(),
            endpoint: "/api/v1/users".into(),
            context: Some("API endpoint".into()),
        };
        assert!(je.context.is_some());
    }

    #[test]
    fn test_robots_info_struct() {
        let ri = RobotsInfo {
            exists: true,
            sitemaps: vec!["http://example.com/sitemap.xml".into()],
            allowed: vec!["/public".into()],
            disallowed: vec!["/admin".into(), "/private".into()],
            crawl_delay: Some(10),
        };
        assert!(ri.exists);
        assert_eq!(ri.sitemaps.len(), 1);
        assert_eq!(ri.disallowed.len(), 2);
        assert_eq!(ri.crawl_delay, Some(10));
    }

    #[test]
    fn test_robots_info_not_exists() {
        let ri = RobotsInfo {
            exists: false,
            sitemaps: vec![],
            allowed: vec![],
            disallowed: vec![],
            crawl_delay: None,
        };
        assert!(!ri.exists);
        assert!(ri.crawl_delay.is_none());
    }

    #[test]
    fn test_extract_from_js_empty_body() {
        let endpoints = extract_from_js("test.js", "");
        assert!(endpoints.is_empty());
    }

    #[test]
    fn test_extract_from_js_api_endpoint() {
        let js = r#"fetch("/api/v1/data")"#;
        let endpoints = extract_from_js("test.js", js);
        assert!(endpoints.iter().any(|e| e.endpoint.contains("api")));
    }

    #[test]
    fn test_extract_from_js_admin_endpoint() {
        let js = r#"const url = "/admin/dashboard/settings";"#;
        let endpoints = extract_from_js("test.js", js);
        assert!(endpoints.iter().any(|e| e.endpoint.contains("admin")));
    }

    #[test]
    fn test_extract_from_js_auth_endpoint() {
        let js = r#"const loginUrl = "/auth/login";"#;
        let endpoints = extract_from_js("test.js", js);
        assert!(endpoints.iter().any(|e| e.endpoint.contains("login")));
    }

    #[test]
    fn test_extract_from_js_secret_api_key() {
        let js = r#"const apiKey = "sk_test_abcdefghijklmnop";"#;
        let endpoints = extract_from_js("test.js", js);
        assert!(endpoints.iter().any(|e| e.context.as_deref() == Some("API key")));
    }

    #[test]
    fn test_extract_from_js_secret_token() {
        let js = r#"const token = "abcdefghijklmnop12345678";"#;
        let endpoints = extract_from_js("test.js", js);
        assert!(endpoints.iter().any(|e| e.context.as_deref() == Some("Token")));
    }

    #[test]
    fn test_extract_from_js_password() {
        let js = r#"password = "secret123456";"#;
        let endpoints = extract_from_js("test.js", js);
        assert!(endpoints.iter().any(|e| e.context.as_deref() == Some("Password")));
    }

    #[test]
    fn test_waf_header_signature_count() {
        assert!(WAF_HEADER_SIGNATURES.len() > 5);
    }

    #[test]
    fn test_waf_body_signature_count() {
        assert!(WAF_BODY_SIGNATURES.len() > 5);
    }

    #[test]
    fn test_tech_header_signature_count() {
        assert!(TECH_HEADER_SIGNATURES.len() > 5);
    }

    #[test]
    fn test_tech_cookie_signature_count() {
        assert!(TECH_COOKIE_SIGNATURES.len() > 5);
    }

    #[test]
    fn test_tech_body_signature_count() {
        assert!(TECH_BODY_SIGNATURES.len() > 10);
    }

    #[test]
    fn test_parse_sitemap_empty() {
        let urls = parse_sitemap_with_body("");
        assert!(urls.is_empty());
    }

    #[test]
    fn test_parse_sitemap_single_url() {
        let xml = r#"<urlset><url><loc>https://example.com/home</loc></url></urlset>"#;
        let urls = parse_sitemap_with_body(xml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://example.com/home");
    }

    #[test]
    fn test_parse_sitemap_no_loc_tags() {
        let xml = r#"<urlset><url><loc></loc></url></urlset>"#;
        let urls = parse_sitemap_with_body(xml);
        assert!(urls.is_empty());
    }
}

#[cfg(test)]
fn parse_sitemap_with_body(body: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let re = Regex::new(r"(?i)<loc[^>]*>([^<]+)</loc>").ok();
    if let Some(re) = re {
        for cap in re.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                urls.push(m.as_str().trim().to_string());
            }
        }
    }
    urls
}
