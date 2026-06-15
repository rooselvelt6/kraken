use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use sha2::Digest;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: String,
    pub nonce: String,
    pub key_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionKey {
    pub key_id: String,
    pub key: Vec<u8>,
    pub created_at: String,
}

pub struct C2Crypto;

impl C2Crypto {
    pub fn generate_key() -> SessionKey {
        let key = Aes256Gcm::generate_key(OsRng);
        SessionKey {
            key_id: uuid::Uuid::new_v4().to_string(),
            key: key.to_vec(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn encrypt(plaintext: &[u8], key: &SessionKey) -> Result<EncryptedMessage, String> {
        let cipher = Aes256Gcm::new_from_slice(&key.key)
            .map_err(|e| format!("key init failed: {}", e))?;
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("encrypt failed: {}", e))?;

        Ok(EncryptedMessage {
            ciphertext: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            key_id: key.key_id.clone(),
        })
    }

    pub fn decrypt(msg: &EncryptedMessage, key: &SessionKey) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(&key.key)
            .map_err(|e| format!("key init failed: {}", e))?;
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(&msg.nonce)
            .map_err(|e| format!("nonce decode failed: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&msg.ciphertext)
            .map_err(|e| format!("ciphertext decode failed: {}", e))?;
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("decrypt failed: {}", e))?;
        Ok(plaintext)
    }

    pub fn derive_key(material: &[u8]) -> SessionKey {
        let mut hasher = sha2::Sha256::new();
        hasher.update(material);
        let hash = hasher.finalize();
        SessionKey {
            key_id: uuid::Uuid::new_v4().to_string(),
            key: hash.to_vec(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn encrypt_json<T: serde::Serialize>(data: &T, key: &SessionKey) -> Result<EncryptedMessage, String> {
        let json = serde_json::to_vec(data).map_err(|e| format!("json serialize failed: {}", e))?;
        Self::encrypt(&json, key)
    }

    pub fn decrypt_json<T: serde::de::DeserializeOwned>(msg: &EncryptedMessage, key: &SessionKey) -> Result<T, String> {
        let plaintext = Self::decrypt(msg, key)?;
        serde_json::from_slice(&plaintext).map_err(|e| format!("json deserialize failed: {}", e))
    }

    pub fn key_exchange_request() -> (SessionKey, Vec<u8>) {
        let key = Self::generate_key();
        let pubkey = key.key.clone();
        (key, pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let key = C2Crypto::generate_key();
        assert_eq!(key.key.len(), 32);
        assert!(!key.key_id.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = C2Crypto::generate_key();
        let msg = b"hello c2 world!";
        let encrypted = C2Crypto::encrypt(msg, &key).unwrap();
        let decrypted = C2Crypto::decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_encrypt_json_roundtrip() {
        let key = C2Crypto::generate_key();
        let data = serde_json::json!({"action": "exec", "cmd": "whoami"});
        let encrypted = C2Crypto::encrypt_json(&data, &key).unwrap();
        let decrypted: serde_json::Value = C2Crypto::decrypt_json(&encrypted, &key).unwrap();
        assert_eq!(decrypted["action"], "exec");
    }

    #[test]
    fn test_derive_key() {
        let key1 = C2Crypto::derive_key(b"shared_secret");
        let key2 = C2Crypto::derive_key(b"shared_secret");
        assert_eq!(key1.key, key2.key);
        assert_ne!(key1.key_id, key2.key_id);
    }

    #[test]
    fn test_different_keys_fail() {
        let key1 = C2Crypto::generate_key();
        let key2 = C2Crypto::generate_key();
        let msg = b"secret";
        let encrypted = C2Crypto::encrypt(msg, &key1).unwrap();
        let result = C2Crypto::decrypt(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_exchange() {
        let (key, pubkey) = C2Crypto::key_exchange_request();
        assert_eq!(key.key, pubkey);
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let key = C2Crypto::generate_key();
        let encrypted = C2Crypto::encrypt(b"test", &key).unwrap();
        let json = serde_json::to_string_pretty(&encrypted).unwrap();
        assert!(json.contains("ciphertext"));
        assert!(json.contains("nonce"));
        assert!(json.contains("key_id"));
    }

    #[test]
    fn test_decrypt_wrong_key_id() {
        let key = C2Crypto::generate_key();
        let mut encrypted = C2Crypto::encrypt(b"test", &key).unwrap();
        encrypted.key_id = "wrong".to_string();
        let result = C2Crypto::decrypt(&encrypted, &key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypt_empty() {
        let key = C2Crypto::generate_key();
        let encrypted = C2Crypto::encrypt(b"", &key).unwrap();
        let decrypted = C2Crypto::decrypt(&encrypted, &key).unwrap();
        assert!(decrypted.is_empty());
    }
}
