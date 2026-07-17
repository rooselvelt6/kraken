use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct KernelConfig {
    pub options: HashMap<String, String>,
    pub is_present: bool,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelConfig {
    pub fn new() -> Self {
        KernelConfig {
            options: HashMap::new(),
            is_present: false,
        }
    }

    pub fn parse(content: &str, _file_path: &Path) -> Self {
        let mut config = KernelConfig::new();
        config.is_present = true;

        for line in content.lines() {
            let trimmed = line.trim();

            if let Some(value) = trimmed.strip_prefix("CONFIG_") {
                if let Some(eq_pos) = value.find('=') {
                    let key = format!("CONFIG_{}", &value[..eq_pos]);
                    let val = value[eq_pos + 1..].trim().to_string();
                    config.options.insert(key, val);
                }
            } else if trimmed.starts_with("# ") && trimmed.contains(" is not set") {
                if let Some(key_start) = trimmed.find("CONFIG_") {
                    let key = trimmed[key_start..]
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    config.options.insert(key, "n".to_string());
                }
            }
        }

        config
    }

    pub fn is_enabled(&self, config: &str) -> bool {
        self.options.get(config).is_some_and(|v| v == "y" || v == "m")
    }

    pub fn is_disabled(&self, config: &str) -> bool {
        self.options.get(config).is_none_or(|v| v == "n" || v.is_empty())
    }

    pub fn value(&self, config: &str) -> Option<&str> {
        self.options.get(config).map(|s| s.as_str())
    }

    pub fn missing_count(&self) -> usize {
        self.options.values().filter(|v| *v == "n").count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_enabled_config() {
        let content = "CONFIG_RANDOMIZE_BASE=y\nCONFIG_X86_SMEP=y\n";
        let p = PathBuf::from(".config");
        let config = KernelConfig::parse(content, &p);
        assert!(config.is_enabled("CONFIG_RANDOMIZE_BASE"));
        assert!(config.is_enabled("CONFIG_X86_SMEP"));
        assert!(config.is_disabled("CONFIG_KASAN"));
    }

    #[test]
    fn test_parse_disabled_config() {
        let content = "# CONFIG_KASAN is not set\nCONFIG_RANDOMIZE_BASE=y\n";
        let p = PathBuf::from(".config");
        let config = KernelConfig::parse(content, &p);
        assert!(config.is_disabled("CONFIG_KASAN"));
        assert_eq!(config.value("CONFIG_KASAN"), Some("n"));
    }

    #[test]
    fn test_empty_config() {
        let config = KernelConfig::new();
        assert!(!config.is_present);
        assert!(config.is_disabled("CONFIG_RANDOMIZE_BASE"));
    }
}
