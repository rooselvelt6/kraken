//! Security Crate - Encryption and Secure Storage
//! 
//! Provides encryption, secure config storage, and audit logging.

pub mod crypto;
pub mod config;
pub mod audit;

pub use crypto::{Encryptor, Key};
pub use config::SecureConfig;
pub use audit::{AuditLog, AuditEntry, AuditAction};

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