use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalleableProfile {
    pub name: String,
    pub description: String,
    pub http_config: HttpProfile,
    pub dns_config: Option<DnsProfile>,
    pub websocket_config: Option<WsProfile>,
    pub encrypted: bool,
    pub jitter_pct: f64,
    pub sleep_time_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProfile {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body_encoding: BodyEncoding,
    pub output_encoding: OutputEncoding,
    pub get_config: HttpGetConfig,
    pub post_config: HttpPostConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpGetConfig {
    pub verb: String,
    pub uri: String,
    pub metadata: Vec<MetadataEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPostConfig {
    pub verb: String,
    pub uri: String,
    pub output: Vec<OutputEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEntry {
    pub name: String,
    pub header: String,
    pub encoder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputEntry {
    pub name: String,
    pub encoder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProfile {
    pub beacon_type: String,
    pub query_type: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsProfile {
    pub path: String,
    pub ping_interval: u32,
    pub frame_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BodyEncoding {
    Binary,
    Base64,
    Hex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputEncoding {
    Raw,
    Base64,
    Netbios,
    Mask,
}

pub struct MalleableEngine;

impl Default for MalleableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MalleableEngine {
    pub fn new() -> Self {
        MalleableEngine
    }

    pub fn default_profile() -> MalleableProfile {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string());
        headers.insert("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string());
        headers.insert("Accept-Language".to_string(), "en-US,en;q=0.5".to_string());

        MalleableProfile {
            name: "default".to_string(),
            description: "Default Kraken C2 profile".to_string(),
            http_config: HttpProfile {
                method: "POST".to_string(),
                uri: "/submit.php".to_string(),
                headers,
                body_encoding: BodyEncoding::Base64,
                output_encoding: OutputEncoding::Base64,
                get_config: HttpGetConfig {
                    verb: "GET".to_string(),
                    uri: "/query.php".to_string(),
                    metadata: vec![
                        MetadataEntry {
                            name: "arch".to_string(),
                            header: "X-Data".to_string(),
                            encoder: "base64".to_string(),
                        },
                    ],
                },
                post_config: HttpPostConfig {
                    verb: "POST".to_string(),
                    uri: "/submit.php".to_string(),
                    output: vec![
                        OutputEntry {
                            name: "output".to_string(),
                            encoder: "base64".to_string(),
                        },
                    ],
                },
            },
            dns_config: None,
            websocket_config: None,
            encrypted: true,
            jitter_pct: 0.2,
            sleep_time_secs: 60,
        }
    }

    pub fn apache_profile() -> MalleableProfile {
        let mut profile = Self::default_profile();
        profile.name = "apache".to_string();
        profile.description = "Apache web server mimicry".to_string();
        profile.http_config.uri = "/wp-admin/admin-ajax.php".to_string();
        profile.http_config.get_config.uri = "/wp-login.php".to_string();
        profile.http_config.post_config.uri = "/wp-admin/admin-ajax.php".to_string();
        profile
    }

    pub fn office365_profile() -> MalleableProfile {
        let mut profile = Self::default_profile();
        profile.name = "office365".to_string();
        profile.description = "Microsoft Office 365 mimicry".to_string();
        profile.http_config.uri = "/_vti_bin/client.svc".to_string();
        profile.http_config.get_config.uri = "/_api/web/site".to_string();
        profile.http_config.post_config.uri = "/_vti_bin/client.svc".to_string();
        profile
    }

    pub fn cloudflare_profile() -> MalleableProfile {
        let mut profile = Self::default_profile();
        profile.name = "cloudflare".to_string();
        profile.description = "Cloudflare CDN mimicry".to_string();
        profile.http_config.uri = "/cdn-cgi/trace".to_string();
        profile.http_config.get_config.uri = "/cdn-cgi/trace".to_string();
        profile.http_config.post_config.uri = "/cdn-cgi/trace".to_string();
        profile
    }

    pub fn dns_profile() -> MalleableProfile {
        let mut profile = Self::default_profile();
        profile.name = "dns-beacon".to_string();
        profile.description = "DNS-based C2 profile".to_string();
        profile.dns_config = Some(DnsProfile {
            beacon_type: "dns".to_string(),
            query_type: "TXT".to_string(),
            ttl: 300,
        });
        profile
    }

    pub fn websocket_profile() -> MalleableProfile {
        let mut profile = Self::default_profile();
        profile.name = "websocket".to_string();
        profile.description = "WebSocket-based C2 profile".to_string();
        profile.websocket_config = Some(WsProfile {
            path: "/ws".to_string(),
            ping_interval: 30,
            frame_size: 65536,
        });
        profile
    }

    pub fn list_profiles() -> Vec<MalleableProfile> {
        vec![
            Self::default_profile(),
            Self::apache_profile(),
            Self::office365_profile(),
            Self::cloudflare_profile(),
            Self::dns_profile(),
            Self::websocket_profile(),
        ]
    }

    pub fn apply_profile(profile: &MalleableProfile, data: &[u8]) -> Vec<u8> {
        match profile.http_config.body_encoding {
            BodyEncoding::Binary => data.to_vec(),
            BodyEncoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(data).into_bytes()
            }
            BodyEncoding::Hex => hex::encode(data).into_bytes(),
        }
    }

    pub fn encode_metadata(profile: &MalleableProfile, metadata: &HashMap<String, String>) -> HashMap<String, String> {
        let mut encoded = HashMap::new();
        for entry in &profile.http_config.get_config.metadata {
            if let Some(value) = metadata.get(&entry.name) {
                let encoded_value = match entry.encoder.as_str() {
                    "base64" => {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.encode(value)
                    }
                    "hex" => hex::encode(value.as_bytes()),
                    _ => value.clone(),
                };
                encoded.insert(entry.header.clone(), encoded_value);
            }
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_profile() {
        let profile = MalleableEngine::default_profile();
        assert_eq!(profile.name, "default");
        assert!(profile.encrypted);
        assert_eq!(profile.jitter_pct, 0.2);
    }

    #[test]
    fn test_apache_profile() {
        let profile = MalleableEngine::apache_profile();
        assert_eq!(profile.name, "apache");
        assert!(profile.http_config.uri.contains("wp-admin"));
    }

    #[test]
    fn test_office365_profile() {
        let profile = MalleableEngine::office365_profile();
        assert_eq!(profile.name, "office365");
        assert!(profile.http_config.uri.contains("client.svc"));
    }

    #[test]
    fn test_cloudflare_profile() {
        let profile = MalleableEngine::cloudflare_profile();
        assert_eq!(profile.name, "cloudflare");
        assert!(profile.http_config.uri.contains("cdn-cgi"));
    }

    #[test]
    fn test_list_profiles() {
        let profiles = MalleableEngine::list_profiles();
        assert!(profiles.len() >= 5);
    }

    #[test]
    fn test_apply_profile_base64() {
        let profile = MalleableEngine::default_profile();
        let data = b"hello world";
        let encoded = MalleableEngine::apply_profile(&profile, data);
        let decoded = String::from_utf8(encoded).unwrap();
        assert!(!decoded.is_empty());
    }

    #[test]
    fn test_apply_profile_hex() {
        let mut profile = MalleableEngine::default_profile();
        profile.http_config.body_encoding = BodyEncoding::Hex;
        let data = b"hello";
        let encoded = MalleableEngine::apply_profile(&profile, data);
        let decoded = String::from_utf8(encoded).unwrap();
        assert!(decoded.contains("68656c6c6f"));
    }

    #[test]
    fn test_apply_profile_binary() {
        let mut profile = MalleableEngine::default_profile();
        profile.http_config.body_encoding = BodyEncoding::Binary;
        let data = b"hello";
        let encoded = MalleableEngine::apply_profile(&profile, data);
        assert_eq!(encoded, data);
    }

    #[test]
    fn test_encode_metadata() {
        let profile = MalleableEngine::default_profile();
        let mut metadata = HashMap::new();
        metadata.insert("arch".to_string(), "x86_64".to_string());
        let encoded = MalleableEngine::encode_metadata(&profile, &metadata);
        assert!(encoded.contains_key("X-Data"));
    }

    #[test]
    fn test_profile_serialization() {
        let profile = MalleableEngine::default_profile();
        let json = serde_json::to_string_pretty(&profile).unwrap();
        assert!(json.contains("default"));
        assert!(json.contains("http_config"));
    }

    #[test]
    fn test_dns_profile() {
        let profile = MalleableEngine::dns_profile();
        assert!(profile.dns_config.is_some());
        assert_eq!(profile.dns_config.unwrap().query_type, "TXT");
    }

    #[test]
    fn test_websocket_profile() {
        let profile = MalleableEngine::websocket_profile();
        assert!(profile.websocket_config.is_some());
    }
}