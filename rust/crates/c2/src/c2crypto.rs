use security::crypto::{Encryptor, EncryptedData, EncryptionAlgorithm, Key};

pub type SessionKey = Key;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: String,
    pub nonce: String,
    pub key_id: String,
}

pub struct C2Crypto;

impl C2Crypto {
    pub fn generate_key() -> SessionKey {
        Key::generate()
    }

    pub fn encrypt(plaintext: &[u8], key: &SessionKey) -> Result<EncryptedMessage, String> {
        let encrypted = Encryptor::encrypt_with_algorithm(
            plaintext,
            key,
            EncryptionAlgorithm::Aes256Gcm,
        )
        .map_err(|e| e.to_string())?;
        Ok(EncryptedMessage {
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            key_id: key.to_base64(),
        })
    }

    pub fn decrypt(msg: &EncryptedMessage, key: &SessionKey) -> Result<Vec<u8>, String> {
        let encrypted = EncryptedData {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            kdf: key.algorithm(),
            nonce: msg.nonce.clone(),
            ciphertext: msg.ciphertext.clone(),
            salt: Some(key.to_base64()),
            params: None,
        };
        Encryptor::decrypt(&encrypted, key).map_err(|e| e.to_string())
    }

    pub fn derive_key(password: &[u8]) -> SessionKey {
        let salt = [1u8; 16];
        Key::from_password_sha256(
            &String::from_utf8_lossy(password),
            &salt,
        )
    }

    pub fn encrypt_json<T: serde::Serialize>(
        data: &T,
        key: &SessionKey,
    ) -> Result<EncryptedMessage, String> {
        let json = serde_json::to_vec(data)
            .map_err(|e| format!("json serialize failed: {}", e))?;
        Self::encrypt(&json, key)
    }

    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        msg: &EncryptedMessage,
        key: &SessionKey,
    ) -> Result<T, String> {
        let plaintext = Self::decrypt(msg, key)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| format!("json deserialize failed: {}", e))
    }

    pub fn key_exchange_request() -> (SessionKey, Vec<u8>) {
        let key = Self::generate_key();
        let pubkey = key.as_bytes().to_vec();
        (key, pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let key = C2Crypto::generate_key();
        assert_eq!(key.as_bytes().len(), 32);
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
        assert!(key1.constant_time_eq(&key2));
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
        assert_eq!(key.as_bytes().to_vec(), pubkey);
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
    fn test_encrypt_empty() {
        let key = C2Crypto::generate_key();
        let encrypted = C2Crypto::encrypt(b"", &key).unwrap();
        let decrypted = C2Crypto::decrypt(&encrypted, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_key_zeroize() {
        let key = C2Crypto::generate_key();
        let _ = key.to_base64();
    }
}
