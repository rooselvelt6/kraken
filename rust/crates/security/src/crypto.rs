//! Cryptographic utilities for secure storage.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_SIZE]);

impl Key {
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Key(key)
    }
    
    pub fn from_password(password: &str, salt: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&result[..KEY_SIZE]);
        Key(key)
    }
    
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }
    
    pub fn from_base64(encoded: &str) -> Option<Self> {
        let decoded = BASE64.decode(encoded).ok()?;
        if decoded.len() != KEY_SIZE {
            return None;
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&decoded);
        Some(Key(key))
    }
    
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    nonce: String,
    ciphertext: String,
}

pub struct Encryptor;

impl Encryptor {
    pub fn encrypt(data: &[u8], key: &Key) -> Result<EncryptedData, String> {
        let key_bytes: &[u8; KEY_SIZE] = key.as_bytes();
        let cipher = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| format!("cipher init failed: {}", e))?;
        
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| format!("encryption failed: {}", e))?;
        
        Ok(EncryptedData {
            nonce: BASE64.encode(nonce_bytes),
            ciphertext: BASE64.encode(ciphertext),
        })
    }
    
    pub fn decrypt(encrypted: &EncryptedData, key: &Key) -> Result<Vec<u8>, String> {
        let key_bytes: &[u8; KEY_SIZE] = key.as_bytes();
        let cipher = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| format!("cipher init failed: {}", e))?;
        
        let nonce_bytes = BASE64.decode(&encrypted.nonce)
            .map_err(|e| format!("nonce decode failed: {}", e))?;
        let ciphertext = BASE64.decode(&encrypted.ciphertext)
            .map_err(|e| format!("ciphertext decode failed: {}", e))?;
        
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("decryption failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let key = Key::generate();
        let encoded = key.to_base64();
        let decoded = Key::from_base64(&encoded).unwrap();
        assert_eq!(key.to_base64(), decoded.to_base64());
    }
    
    #[test]
    fn test_encrypt_roundtrip() {
        let key = Key::generate();
        let plaintext = b"API_KEY=sk-test-12345";
        
        let encrypted = Encryptor::encrypt(plaintext, &key).unwrap();
        let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext.as_slice(), &decrypted);
    }
}