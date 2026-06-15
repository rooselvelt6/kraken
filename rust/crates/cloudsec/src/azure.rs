

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AzureContainer {
    pub name: String,
    pub url: String,
    pub public: bool,
    pub blobs: Vec<AzureBlob>,
    pub total_size: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AzureBlob {
    pub name: String,
    pub size: u64,
    pub content_type: Option<String>,
    pub last_modified: Option<String>,
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AzureResult {
    pub containers: Vec<AzureContainer>,
    pub total_containers: usize,
    pub public_containers: usize,
    pub total_blobs: usize,
}

pub struct AzureEnumerator;

impl AzureEnumerator {
    pub fn new() -> Self {
        AzureEnumerator
    }

    pub fn enumerate_container(account: &str, container: &str) -> Result<AzureContainer, String> {
        let url = format!("https://{}.blob.core.windows.net/{}?restype=container&comp=list", account, container);
        let resp = reqwest::blocking::get(&url)
            .map_err(|e| format!("azure request failed: {}", e))?;
        let public = resp.status().is_success();

        let mut blobs = Vec::new();
        if public {
            let body = resp.text().unwrap_or_default();
            let lower = body.to_lowercase();
            let mut pos = 0;
            while let Some(start) = lower[pos..].find("<blob>") {
                let abs = pos + start;
                if let Some(end) = lower[abs..].find("</blob>") {
                    let entry = &body[abs..abs + end + 7];
                    let name = Self::extract_xml(entry, "Name").unwrap_or_default();
                    let size = Self::extract_xml(entry, "Size").unwrap_or_default().parse::<u64>().unwrap_or(0);
                    let ctype = Self::extract_xml(entry, "ContentType");
                    let last_mod = Self::extract_xml(entry, "Last-Modified");
                    blobs.push(AzureBlob {
                        name,
                        size,
                        content_type: ctype,
                        last_modified: last_mod,
                        public_url: None,
                    });
                    pos = abs + end + 7;
                } else {
                    break;
                }
            }
        }

        let total_size: u64 = blobs.iter().map(|b| b.size).sum();
        Ok(AzureContainer {
            name: container.to_string(),
            url: format!("https://{}.blob.core.windows.net/{}", account, container),
            public,
            blobs,
            total_size,
        })
    }

    pub fn scan_containers(account: &str, container_names: &[&str]) -> AzureResult {
        let mut containers = Vec::new();
        for name in container_names {
            if let Ok(c) = Self::enumerate_container(account, name) {
                containers.push(c);
            }
        }
        let total_containers = containers.len();
        let public_containers = containers.iter().filter(|c| c.public).count();
        let total_blobs = containers.iter().map(|c| c.blobs.len()).sum();
        AzureResult { containers, total_containers, public_containers, total_blobs }
    }

    pub fn generate_names(keyword: &str) -> Vec<String> {
        let mut names = Vec::new();
        for prefix in &["", "dev", "test", "prod", "stg", "backup", "data", "logs", "media", "assets", "uploads", "files", "config", "public", "private"] {
            for suffix in &["", "data", "logs", "backup", "files", "media", "assets", "config"] {
                let combined = if suffix.is_empty() {
                    format!("{}{}", prefix, keyword)
                } else {
                    format!("{}{}{}", prefix, keyword, suffix)
                };
                if !combined.is_empty() {
                    names.push(combined);
                }
            }
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
        let names = AzureEnumerator::generate_names("myblob");
        assert!(names.contains(&"myblob".to_string()));
    }

    #[test]
    fn test_enumerate_nonexistent() {
        let result = AzureEnumerator::enumerate_container("nonexistentazureacct", "notacontainer");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_xml() {
        assert_eq!(AzureEnumerator::extract_xml("<Name>blob.txt</Name>", "Name"), Some("blob.txt".to_string()));
    }

    #[test]
    fn test_azure_container() {
        let c = AzureContainer {
            name: "test".to_string(),
            url: "https://test.blob.core.windows.net/test".to_string(),
            public: true,
            blobs: vec![],
            total_size: 0,
        };
        let json = serde_json::to_string_pretty(&c).unwrap();
        assert!(json.contains("test.blob.core.windows.net"));
    }

    #[test]
    fn test_azure_result() {
        let r = AzureResult { containers: vec![], total_containers: 0, public_containers: 0, total_blobs: 0 };
        let json = serde_json::to_string_pretty(&r).unwrap();
        assert!(json.contains("total_containers"));
    }
}
