//! Security Crate - Encryption, Secure Storage, Secret Redaction, and Hardening
//!
//! Provides encryption, secure credential vault, audit logging, secret redaction,
//! and memory hardening primitives.

pub mod audit;
pub mod config;
pub mod crypto;
pub mod hardening;
pub mod secrets;
pub mod vault;

pub use audit::{AuditAction, AuditEntry, AuditLog, SignedBlock, generate_audit_keypair};
pub use config::SecureConfig;
pub use crypto::{Encryptor, Key};
pub use secrets::{redact_secrets, SecretsRedactor};
pub use vault::{open_credential_vault, CredentialVault, MasterKey, vault_path};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = Key::generate();
        let data = b"secret api key";

        let encrypted = Encryptor::encrypt(data, &key).unwrap();
        let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();

        assert_eq!(data.as_slice(), &decrypted);
    }
}
