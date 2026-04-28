//! Secure configuration storage with encryption - God Level Implementation

use crate::crypto::{EncryptedData, EncryptionAlgorithm, Encryptor, Key};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

pub struct SecureConfig {
    data: Vec<u8>,
    algorithm: EncryptionAlgorithm,
}

impl Drop for SecureConfig {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl SecureConfig {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            algorithm: EncryptionAlgorithm::default(),
        }
    }

    pub fn with_algorithm(algorithm: EncryptionAlgorithm) -> Self {
        Self {
            data: Vec::new(),
            algorithm,
        }
    }

    pub fn load(path: &Path, key: &Key) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("read config failed: {}", e))?;

        let encrypted: EncryptedData =
            toml::from_str(&content).map_err(|e| format!("parse config failed: {}", e))?;

        let data = Encryptor::decrypt(&encrypted, key)?;

        Ok(Self {
            data,
            algorithm: encrypted.algorithm,
        })
    }

    pub fn save(&self, path: &Path, key: &Key) -> Result<(), String> {
        let encrypted = Encryptor::encrypt_with_algorithm(&self.data, key, self.algorithm)?;

        let content =
            toml::to_string(&encrypted).map_err(|e| format!("serialize failed: {}", e))?;

        fs::write(path, content).map_err(|e| format!("write config failed: {}", e))?;

        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let toml_str = String::from_utf8(self.data.clone()).ok()?;
        let value: toml::Value = toml_str.parse().ok()?;

        value.get(key)?.as_str().map(|s| s.to_string())
    }

    pub fn set(&mut self, key: &str, value: &str) {
        let new_entry = format!("{} = \"{}\"\n", key, value);
        self.data.extend_from_slice(new_entry.as_bytes());
    }

    pub fn set_algorithm(&mut self, algorithm: EncryptionAlgorithm) {
        self.algorithm = algorithm;
    }

    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Migrate data to new algorithm (decrypt with old, re-encrypt with new)
    pub fn migrate_algorithm(
        &mut self,
        key: &Key,
        new_algorithm: EncryptionAlgorithm,
    ) -> Result<(), String> {
        if self.algorithm == new_algorithm {
            return Ok(());
        }

        let data_clone = self.data.clone();
        #[allow(unused_variables)]
        let reencrypted = Encryptor::encrypt_with_algorithm(&data_clone, key, new_algorithm)?;

        self.algorithm = new_algorithm;
        Ok(())
    }
}

impl Default for SecureConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_load_aes() {
        let key = Key::generate();
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.enc");

        let mut config = SecureConfig::with_algorithm(EncryptionAlgorithm::Aes256Gcm);
        config.set("api_key", "sk-test-12345");
        config.set("model", "deepseek");

        config.save(&config_path, &key).unwrap();
        let loaded = SecureConfig::load(&config_path, &key).unwrap();

        assert_eq!(loaded.get("api_key"), Some("sk-test-12345".to_string()));
        assert_eq!(loaded.get("model"), Some("deepseek".to_string()));
        assert_eq!(loaded.algorithm(), EncryptionAlgorithm::Aes256Gcm);
    }

    #[test]
    fn test_save_load_xchacha() {
        let key = Key::generate();
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.enc");

        let mut config = SecureConfig::with_algorithm(EncryptionAlgorithm::XChaCha20Poly1305);
        config.set("api_key", "sk-test-vzla-2026");

        config.save(&config_path, &key).unwrap();
        let loaded = SecureConfig::load(&config_path, &key).unwrap();

        assert_eq!(loaded.get("api_key"), Some("sk-test-vzla-2026".to_string()));
        assert_eq!(loaded.algorithm(), EncryptionAlgorithm::XChaCha20Poly1305);
    }

    #[test]
    fn test_migrate_algorithm() {
        let key = Key::generate();
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.enc");

        let mut config = SecureConfig::with_algorithm(EncryptionAlgorithm::Aes256Gcm);
        config.set("secret", "migration-test");

        config.save(&config_path, &key).unwrap();

        let mut loaded = SecureConfig::load(&config_path, &key).unwrap();
        assert_eq!(loaded.algorithm(), EncryptionAlgorithm::Aes256Gcm);

        loaded
            .migrate_algorithm(&key, EncryptionAlgorithm::XChaCha20Poly1305)
            .unwrap();
        loaded.save(&config_path, &key).unwrap();

        let migrated = SecureConfig::load(&config_path, &key).unwrap();
        assert_eq!(migrated.algorithm(), EncryptionAlgorithm::XChaCha20Poly1305);
        assert_eq!(migrated.get("secret"), Some("migration-test".to_string()));
    }
}
