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

    /// Parses a kernel `.config` file content.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::kconfig::KernelConfig;
    /// use std::path::PathBuf;
    /// let config = KernelConfig::parse(
    ///     "CONFIG_KASAN=y\n# CONFIG_DEBUG_INFO is not set\n",
    ///     &PathBuf::from(".config"),
    /// );
    /// assert!(config.is_enabled("CONFIG_KASAN"));
    /// assert!(config.is_disabled("CONFIG_DEBUG_INFO"));
    /// ```
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

    /// Returns true if the config option is enabled (set to `y` or `m`).
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::kconfig::KernelConfig;
    /// use std::path::PathBuf;
    /// let config = KernelConfig::parse("CONFIG_KASAN=y\n", &PathBuf::from(".config"));
    /// assert!(config.is_enabled("CONFIG_KASAN"));
    /// assert!(!config.is_enabled("CONFIG_KCSAN"));
    /// ```
    pub fn is_enabled(&self, config: &str) -> bool {
        self.options.get(config).is_some_and(|v| v == "y" || v == "m")
    }

    /// Returns true if the config option is disabled or missing.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::kconfig::KernelConfig;
    /// use std::path::PathBuf;
    /// let config = KernelConfig::parse("# CONFIG_KASAN is not set\n", &PathBuf::from(".config"));
    /// assert!(config.is_disabled("CONFIG_KASAN"));
    /// assert!(config.is_disabled("CONFIG_MISSING"));
    /// ```
    pub fn is_disabled(&self, config: &str) -> bool {
        self.options.get(config).is_none_or(|v| v == "n" || v.is_empty())
    }

    /// Returns the raw value of a config option, or None if not present.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::kconfig::KernelConfig;
    /// use std::path::PathBuf;
    /// let config = KernelConfig::parse("CONFIG_DEFAULT_HOSTNAME=(none)\n", &PathBuf::from(".config"));
    /// assert_eq!(config.value("CONFIG_DEFAULT_HOSTNAME"), Some("(none)"));
    /// assert_eq!(config.value("CONFIG_MISSING"), None);
    /// ```
    pub fn value(&self, config: &str) -> Option<&str> {
        self.options.get(config).map(|s| s.as_str())
    }

    /// Returns the count of disabled (`n`) config options.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::kconfig::KernelConfig;
    /// use std::path::PathBuf;
    /// let config = KernelConfig::parse(
    ///     "CONFIG_A=y\n# CONFIG_B is not set\n# CONFIG_C is not set\n",
    ///     &PathBuf::from(".config"),
    /// );
    /// assert_eq!(config.missing_count(), 2);
    /// ```
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

    #[test]
    fn test_module_config_m_value() {
        let content = "CONFIG_USB_SERIAL=m\nCONFIG_BT=m\n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert!(config.is_enabled("CONFIG_USB_SERIAL"), "module (m) should be considered enabled");
        assert!(config.is_enabled("CONFIG_BT"));
    }

    #[test]
    fn test_config_string_value() {
        let content = "CONFIG_DEFAULT_HOSTNAME=(none)\nCONFIG_SYSTEM_TRUSTED_KEYRING=y\n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert_eq!(config.value("CONFIG_DEFAULT_HOSTNAME"), Some("(none)"));
        assert!(config.is_enabled("CONFIG_SYSTEM_TRUSTED_KEYRING"));
    }

    #[test]
    fn test_config_numeric_value() {
        let content = "CONFIG_LOG_BUF_SHIFT=17\nCONFIG_HZ=1000\n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert_eq!(config.value("CONFIG_LOG_BUF_SHIFT"), Some("17"));
        assert_eq!(config.value("CONFIG_HZ"), Some("1000"));
    }

    #[test]
    fn test_missing_count() {
        let content = "CONFIG_A=y\n# CONFIG_B is not set\n# CONFIG_C is not set\n# CONFIG_D is not set\nCONFIG_E=m\n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert_eq!(config.missing_count(), 3);
    }

    #[test]
    fn test_empty_content() {
        let config = KernelConfig::parse("", &PathBuf::from(".config"));
        assert!(config.is_present);
        assert!(config.is_disabled("CONFIG_KASAN"));
    }

    #[test]
    fn test_comment_with_config_not_set() {
        let content = "# CONFIG_DEBUG_INFO is not set\n# CONFIG_KASAN is not set\n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert!(config.is_disabled("CONFIG_DEBUG_INFO"));
        assert!(config.is_disabled("CONFIG_KASAN"));
        assert_eq!(config.value("CONFIG_KASAN"), Some("n"));
    }

    #[test]
    fn test_kasan_enabled_and_disabled() {
        let content = "CONFIG_KASAN=y\nCONFIG_KCSAN=n\n# CONFIG_KMSAN is not set\n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert!(config.is_enabled("CONFIG_KASAN"));
        assert!(!config.is_enabled("CONFIG_KCSAN"));
        assert!(!config.is_enabled("CONFIG_KMSAN"));
    }

    #[test]
    fn test_config_with_quotes() {
        let content = r#"CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_MODULES=y
"#;
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert_eq!(config.value("CONFIG_DEFAULT_HOSTNAME"), Some(r#""(none)""#));
        assert!(config.is_enabled("CONFIG_MODULES"));
    }

    #[test]
    fn test_config_trailing_whitespace() {
        let content = "CONFIG_A=y  \nCONFIG_B=n  \n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert!(config.is_enabled("CONFIG_A"));
        assert!(config.is_disabled("CONFIG_B"));
    }

    #[test]
    fn test_non_config_lines_ignored() {
        let content = "# This is a comment\nCONFIG_A=y\n\n# Another comment\nCONFIG_B=n\n";
        let config = KernelConfig::parse(content, &PathBuf::from(".config"));
        assert!(config.is_enabled("CONFIG_A"));
        assert!(config.is_disabled("CONFIG_B"));
        assert_eq!(config.options.len(), 2);
    }

    #[test]
    fn test_default_trait() {
        let config = KernelConfig::default();
        assert!(!config.is_present);
        assert!(config.options.is_empty());
    }
}
