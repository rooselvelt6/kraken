

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistryEntry {
    pub key_path: String,
    pub value_name: String,
    pub value_type: String,
    pub value_data: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistryHiveInfo {
    pub hive_path: String,
    pub entries: Vec<RegistryEntry>,
    pub last_modified: Option<String>,
    pub parsed_entries: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SamEntry {
    pub username: String,
    pub rid: String,
    pub hash: Option<String>,
    pub account_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemInfo {
    pub computer_name: Option<String>,
    pub os_version: Option<String>,
    pub last_shutdown: Option<String>,
    pub services: Vec<ServiceEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub display_name: String,
    pub start_type: String,
    pub binary_path: String,
}

pub struct RegistryParser;

impl Default for RegistryParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryParser {
    pub fn new() -> Self {
        RegistryParser
    }

    pub fn parse_hive(path: &str) -> Result<RegistryHiveInfo, String> {
        let content = std::fs::read(path).map_err(|e| format!("read hive failed: {}", e))?;

        if !content.starts_with(b"regf") {
            return Err("Not a valid registry hive file".to_string());
        }

        let entries = Self::extract_strings(&content);
        let last_modified = Self::extract_timestamp(&content);
        let parsed_entries = entries.len();

        Ok(RegistryHiveInfo {
            hive_path: path.to_string(),
            entries,
            last_modified,
            parsed_entries,
        })
    }

    pub fn parse_sam(hive_path: &str) -> Result<Vec<SamEntry>, String> {
        let content = std::fs::read(hive_path).map_err(|e| format!("read SAM failed: {}", e))?;
        if !content.starts_with(b"regf") {
            return Err("Not a valid SAM hive".to_string());
        }

        let mut users = Vec::new();
        let strings = Self::extract_strings(&content);
        for entry in &strings {
            if (entry.value_name.contains("SAM") || entry.key_path.contains("SAM"))
                && (entry.value_name == "F" || entry.value_name == "V") {
                    users.push(SamEntry {
                        username: entry.key_path.split('\\').next_back().unwrap_or("?").to_string(),
                        rid: "?".to_string(),
                        hash: Some(entry.value_data.chars().take(32).collect()),
                        account_type: "SAM".to_string(),
                    });
                }
        }

        if users.is_empty() {
            for entry in &strings {
                users.push(SamEntry {
                    username: entry.key_path.split('\\').next_back().unwrap_or("?").to_string(),
                    rid: "?".to_string(),
                    hash: None,
                    account_type: "RegistryString".to_string(),
                });
            }
        }

        Ok(users)
    }

    pub fn parse_system(hive_path: &str) -> Result<SystemInfo, String> {
        let content = std::fs::read(hive_path).map_err(|e| format!("read SYSTEM failed: {}", e))?;
        if !content.starts_with(b"regf") {
            return Err("Not a valid SYSTEM hive".to_string());
        }

        let strings = Self::extract_strings(&content);
        let computer_name = strings.iter()
            .find(|e| e.value_name == "ComputerName" || e.key_path.contains("ComputerName"))
            .map(|e| e.value_data.clone());

        let services = strings.iter()
            .filter(|e| e.key_path.contains("Services\\") && !e.value_type.is_empty())
            .map(|e| ServiceEntry {
                name: e.key_path.split('\\').next_back().unwrap_or("?").to_string(),
                display_name: e.value_data.clone(),
                start_type: e.value_type.clone(),
                binary_path: String::new(),
            })
            .take(50)
            .collect();

        Ok(SystemInfo {
            computer_name,
            os_version: None,
            last_shutdown: None,
            services,
        })
    }

    pub fn extract_strings(data: &[u8]) -> Vec<RegistryEntry> {
        let mut entries = Vec::new();
        let min_len = 4;

        for i in 0..data.len().saturating_sub(min_len) {
            if !data[i].is_ascii_alphanumeric() { continue; }
            let end = data[i..].iter().position(|&b| !b.is_ascii_graphic() && b != b'\\' && b != b'/' && b != b':' && b != b' ' && b != b'_' && b != b'-' && b != b'.')
                .map(|p| i + p)
                .unwrap_or(data.len());
            let s = std::str::from_utf8(&data[i..end]).unwrap_or("");
            if s.len() >= 4 && s.chars().any(|c| c.is_ascii_digit()) && s.contains('\\') {
                let parts: Vec<&str> = s.split('\\').collect();
                let key_path = parts[..parts.len().saturating_sub(1)].join("\\");
                let value = parts.last().unwrap_or(&"");
                if !key_path.is_empty() {
                    entries.push(RegistryEntry {
                        key_path: format!("\\{}", key_path),
                        value_name: String::new(),
                        value_type: "REG_SZ".to_string(),
                        value_data: value.to_string(),
                    });
                }
            }
        }

        entries.sort_by_key(|e| std::cmp::Reverse(e.key_path.len()));
        let mut deduped: Vec<RegistryEntry> = Vec::new();
        for entry in entries {
            let is_sub = deduped.iter().any(|e| e.key_path.ends_with(&entry.key_path));
            if !is_sub {
                deduped.push(entry);
            }
        }
        deduped.sort_by(|a, b| a.key_path.cmp(&b.key_path));
        deduped.truncate(1000);
        deduped
    }

    fn extract_timestamp(data: &[u8]) -> Option<String> {
        if data.len() > 4096 {
            let timestamp_bytes = &data[12..20];
            let timestamp = u64::from_le_bytes(timestamp_bytes.try_into().ok()?);
            if timestamp > 0 {
                let secs = (timestamp / 10000000) as i64 - 11644473600i64;
                return Some(chrono::DateTime::from_timestamp(secs, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hive() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"regf");
        data.extend_from_slice(&[0u8; 4092]);
        data.extend_from_slice(b"SAM\\Domains\\Account\\Users\\000001F4");
        data.extend_from_slice(b"SYSTEM\\CurrentControlSet\\Services\\Tcpip");
        data
    }

    #[test]
    fn test_parse_hive_valid() {
        let tmp = std::env::temp_dir().join("test_hive");
        let data = create_test_hive();
        std::fs::write(&tmp, &data).unwrap();
        let result = RegistryParser::parse_hive(tmp.to_str().unwrap());
        assert!(result.is_ok());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_parse_hive_invalid() {
        let tmp = std::env::temp_dir().join("bad_hive");
        std::fs::write(&tmp, b"not a hive").unwrap();
        let result = RegistryParser::parse_hive(tmp.to_str().unwrap());
        assert!(result.is_err());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_extract_strings() {
        let mut data = vec![0u8; 100];
        data[10..39].copy_from_slice(b"SAM\\Domains\\Account\\Users\\500");
        let entries = RegistryParser::extract_strings(&data);
        assert!(!entries.is_empty());
        let has_sam = entries.iter().any(|e| e.key_path.contains("SAM"));
        assert!(has_sam, "no entry contains SAM in key_path");
    }

    #[test]
    fn test_sam_entry() {
        let entry = SamEntry {
            username: "Administrator".to_string(),
            rid: "500".to_string(),
            hash: Some("aad3b435b51404eeaad3b435b51404ee".to_string()),
            account_type: "SAM".to_string(),
        };
        let json = serde_json::to_string_pretty(&entry).unwrap();
        assert!(json.contains("Administrator"));
    }

    #[test]
    fn test_service_entry() {
        let entry = ServiceEntry {
            name: "Tcpip".to_string(),
            display_name: "TCP/IP Protocol Driver".to_string(),
            start_type: "2".to_string(),
            binary_path: "C:\\Windows\\System32\\drivers\\tcpip.sys".to_string(),
        };
        assert_eq!(entry.name, "Tcpip");
    }

    #[test]
    fn test_system_info() {
        let info = SystemInfo {
            computer_name: Some("DESKTOP-ABC".to_string()),
            os_version: Some("Windows 10 Pro 22H2".to_string()),
            last_shutdown: Some("2026-01-15T03:00:00Z".to_string()),
            services: vec![],
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("DESKTOP-ABC"));
    }

    #[test]
    fn test_registry_entry() {
        let entry = RegistryEntry {
            key_path: "\\SAM\\Domains\\Account\\Users".to_string(),
            value_name: "F".to_string(),
            value_type: "REG_BINARY".to_string(),
            value_data: "01020304".to_string(),
        };
        let json = serde_json::to_string_pretty(&entry).unwrap();
        assert!(json.contains("REG_BINARY"));
    }
}
