

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct S3Bucket {
    pub name: String,
    pub region: Option<String>,
    pub public: bool,
    pub files: Vec<S3Object>,
    pub total_size: u64,
    pub acl: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct S3Object {
    pub key: String,
    pub size: u64,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct S3ScanResult {
    pub buckets: Vec<S3Bucket>,
    pub total_buckets: usize,
    pub public_buckets: usize,
    pub total_objects: usize,
    pub scan_time: String,
}

pub struct S3Enumerator;

impl S3Enumerator {
    pub fn new() -> Self {
        S3Enumerator
    }

    pub fn enumerate_bucket(bucket: &str) -> Result<S3Bucket, String> {
        let url = format!("https://{}.s3.amazonaws.com", bucket);
        let resp = reqwest::blocking::get(&url)
            .map_err(|e| format!("s3 request failed: {}", e))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(format!("bucket not found or inaccessible: status {}", status));
        }
        let public = true;

        let body = resp.text().unwrap_or_default();
        let objects = Self::parse_listing(&body);

        let total_size = objects.iter().map(|o| o.size).sum();

        Ok(S3Bucket {
            name: bucket.to_string(),
            region: Self::guess_region(&objects),
            public,
            files: objects.clone(),
            total_size,
            acl: if public { "public-read".to_string() } else { "private".to_string() },
        })
    }

    pub fn scan_buckets(bucket_names: &[&str]) -> S3ScanResult {
        let mut buckets = Vec::new();
        for name in bucket_names {
            if let Ok(bucket) = Self::enumerate_bucket(name) {
                buckets.push(bucket);
            }
        }
        let total_buckets = buckets.len();
        let public_buckets = buckets.iter().filter(|b| b.public).count();
        let total_objects = buckets.iter().map(|b| b.files.len()).sum();

        S3ScanResult {
            buckets,
            total_buckets,
            public_buckets,
            total_objects,
            scan_time: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn generate_names(keyword: &str, domain: &str) -> Vec<String> {
        let mut names = Vec::new();
        let prefixes = ["", "dev-", "test-", "prod-", "staging-", "backup-", "logs-",
            "data-", "media-", "assets-", "static-", "public-", "private-", "uploads-",
            "files-", "config-", "conf-", "bucket-", "s3-", "my-", "the-"];
        let suffixes = ["", "-dev", "-test", "-prod", "-staging", "-backup", "-logs",
            "-data", "-media", "-assets", "-static", "-public", "-private",
            "-uploads", "-files", "-config", "-bucket", "-v2", "-2024", "-2025", "-2026"];

        for prefix in &prefixes {
            for suffix in &suffixes {
                names.push(format!("{}{}{}", prefix, keyword, suffix));
            }
        }

        if !domain.is_empty() {
            let domain_key = domain.replace('.', "-");
            names.push(format!("{}-{}", domain_key, keyword));
            names.push(format!("{}.{}", keyword, domain));
        }

        names.sort();
        names.dedup();
        names
    }

    fn parse_listing(xml: &str) -> Vec<S3Object> {
        let mut objects = Vec::new();
        let lower = xml.to_lowercase();
        let mut pos = 0;

        while let Some(start) = lower[pos..].find("<contents>") {
            let abs = pos + start;
            if let Some(end) = lower[abs..].find("</contents>") {
                let entry = &xml[abs..abs + end + 11];
                let key = Self::extract_xml(entry, "Key");
                let size = Self::extract_xml(entry, "Size").unwrap_or_default().parse::<u64>().unwrap_or(0);
                let last_mod = Self::extract_xml(entry, "LastModified");
                let etag = Self::extract_xml(entry, "ETag");

                objects.push(S3Object {
                    key: key.unwrap_or_default(),
                    size,
                    last_modified: last_mod,
                    etag,
                    public_url: None,
                });
                pos = abs + end + 11;
            } else {
                break;
            }
        }
        objects
    }

    fn extract_xml(xml: &str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        let lower = xml.to_lowercase();
        let search = open.to_lowercase();
        if let Some(start) = lower.find(&search) {
            let val_start = start + search.len();
            if let Some(end) = lower[val_start..].find(&close.to_lowercase()) {
                return Some(xml[val_start..val_start + end].to_string());
            }
        }
        None
    }

    fn guess_region(objects: &[S3Object]) -> Option<String> {
        for obj in objects {
            if let Some(ref etag) = obj.etag {
                if etag.len() > 10 {
                    return Some("us-east-1".to_string());
                }
            }
        }
        None
    }

    pub fn check_permissions(bucket: &str) -> Vec<String> {
        let mut findings = Vec::new();
        let urls = vec![
            format!("https://{}.s3.amazonaws.com", bucket),
            format!("https://{}.s3.us-east-1.amazonaws.com", bucket),
            format!("https://s3.amazonaws.com/{}", bucket),
        ];
        for url in urls {
            if let Ok(resp) = reqwest::blocking::get(&url) {
                if resp.status().is_success() {
                    findings.push(format!("Publicly accessible via: {}", url));
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_names() {
        let names = S3Enumerator::generate_names("myapp", "example.com");
        assert!(names.contains(&"myapp".to_string()));
        assert!(names.contains(&"prod-myapp".to_string()));
    }

    #[test]
    fn test_extract_xml() {
        let xml = "<Key>myfile.txt</Key><Size>1024</Size>";
        assert_eq!(S3Enumerator::extract_xml(xml, "Key"), Some("myfile.txt".to_string()));
        assert_eq!(S3Enumerator::extract_xml(xml, "Size"), Some("1024".to_string()));
    }

    #[test]
    fn test_parse_listing() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult>
<Contents><Key>file1.txt</Key><Size>100</Size><LastModified>2026-01-01</LastModified><ETag>"abc"</ETag></Contents>
<Contents><Key>file2.txt</Key><Size>200</Size><LastModified>2026-01-02</LastModified><ETag>"def"</ETag></Contents>
</ListBucketResult>"#;
        let objects = S3Enumerator::parse_listing(xml);
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].key, "file1.txt");
    }

    #[test]
    fn test_enumerate_nonexistent() {
        let result = S3Enumerator::enumerate_bucket("this-bucket-definitely-does-not-exist-12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_result() {
        let result = S3ScanResult {
            buckets: vec![],
            total_buckets: 0,
            public_buckets: 0,
            total_objects: 0,
            scan_time: "now".to_string(),
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("scan_time"));
    }

    #[test]
    fn test_check_permissions() {
        let findings = S3Enumerator::check_permissions("nonexistent-bucket-xyz");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_s3_bucket() {
        let b = S3Bucket {
            name: "test".to_string(),
            region: None,
            public: true,
            files: vec![],
            total_size: 0,
            acl: "public-read".to_string(),
        };
        let json = serde_json::to_string_pretty(&b).unwrap();
        assert!(json.contains("\"public\": true"));
    }
}
