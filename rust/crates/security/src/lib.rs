//! Security Crate - Encryption and Secure Storage
//!
//! Provides encryption, secure config storage, and audit logging.

pub mod audit;
pub mod config;
pub mod crypto;

pub use audit::{AuditAction, AuditEntry, AuditLog};
pub use config::SecureConfig;
pub use crypto::{Encryptor, Key};

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
