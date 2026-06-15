

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GcsBucket {
    pub name: String,
    pub location: Option<String>,
    pub storage_class: Option<String>,
    pub public: bool,
    pub uniform_access: bool,
    pub objects: Vec<GcsObject>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GcsObject {
    pub name: String,
    pub size: u64,
    pub content_type: Option<String>,
    pub md5_hash: Option<String>,
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GcpResult {
    pub buckets: Vec<GcsBucket>,
    pub total_buckets: usize,
    pub public_buckets: usize,
}

pub struct GcpEnumerator;

impl GcpEnumerator {
    pub fn new() -> Self {
        GcpEnumerator
    }

    pub fn enumerate_bucket(bucket: &str) -> Result<GcsBucket, String> {
        let url = format!("https://storage.googleapis.com/{}/", bucket);
        let resp = reqwest::blocking::get(&url)
            .map_err(|e| format!("gcs request failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("bucket not found or inaccessible: status {}", resp.status().as_u16()));
        }
        let public = true;

        let mut objects = Vec::new();
        if public {
            let body = resp.text().unwrap_or_default();
            let lower = body.to_lowercase();
            let mut pos = 0;
            while let Some(start) = lower[pos..].find("<contents>") {
                let abs = pos + start;
                if let Some(end) = lower[abs..].find("</contents>") {
                    let entry = &body[abs..abs + end + 11];
                    let name = Self::extract_xml(entry, "Key")
                        .or_else(|| Self::extract_xml(entry, "Name"))
                        .unwrap_or_default();
                    let size = Self::extract_xml(entry, "Size")
                        .unwrap_or_default().parse::<u64>().unwrap_or(0);
                    let ctype = Self::extract_xml(entry, "ContentType");
                    objects.push(GcsObject {
                        name,
                        size,
                        content_type: ctype,
                        md5_hash: None,
                        public_url: None,
                    });
                    pos = abs + end + 11;
                } else {
                    break;
                }
            }
        }

        Ok(GcsBucket {
            name: bucket.to_string(),
            location: None,
            storage_class: None,
            public,
            uniform_access: false,
            objects,
        })
    }

    pub fn scan_buckets(names: &[&str]) -> GcpResult {
        let mut buckets = Vec::new();
        for name in names {
            if let Ok(b) = Self::enumerate_bucket(name) {
                buckets.push(b);
            }
        }
        let total_buckets = buckets.len();
        let public_buckets = buckets.iter().filter(|b| b.public).count();
        GcpResult { buckets, total_buckets, public_buckets }
    }

    pub fn generate_names(keyword: &str, project_id: &str) -> Vec<String> {
        let mut names = Vec::new();
        for prefix in &["", "dev-", "test-", "prod-", "staging-", "data-", "logs-", "assets-"] {
            for suffix in &["", "-dev", "-test", "-prod", "-data", "-logs", "-backup"] {
                names.push(format!("{}{}{}", prefix, keyword, suffix));
            }
        }
        if !project_id.is_empty() {
            names.push(format!("{}-{}", project_id, keyword));
            names.push(format!("{}_{}", project_id, keyword));
        }
        names.sort();
        names.dedup();
        names
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_names() {
        let names = GcpEnumerator::generate_names("my-bucket", "project-123");
        assert!(names.contains(&"my-bucket".to_string()));
        assert!(names.contains(&"project-123-my-bucket".to_string()));
    }

    #[test]
    fn test_enumerate_nonexistent() {
        let result = GcpEnumerator::enumerate_bucket("nonexistent-gcs-bucket-xyz-123");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_xml() {
        assert_eq!(GcpEnumerator::extract_xml("<Name>f.txt</Name>", "Name"), Some("f.txt".to_string()));
        assert_eq!(GcpEnumerator::extract_xml("<Key>f.txt</Key>", "Key"), Some("f.txt".to_string()));
    }

    #[test]
    fn test_gcs_bucket() {
        let b = GcsBucket {
            name: "bucket".to_string(),
            location: Some("US".to_string()),
            storage_class: None,
            public: true,
            uniform_access: false,
            objects: vec![],
        };
        let json = serde_json::to_string_pretty(&b).unwrap();
        assert!(json.contains("US"));
    }

    #[test]
    fn test_gcp_result() {
        let r = GcpResult { buckets: vec![], total_buckets: 0, public_buckets: 0 };
        let json = serde_json::to_string_pretty(&r).unwrap();
        assert!(json.contains("total_buckets"));
    }
}
