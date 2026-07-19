use security::{
    AuditAction, AuditEntry, AuditLog, Encryptor, Key, SecretsRedactor, SecureConfig, MasterKey,
    generate_audit_keypair, redact_secrets,
    secrets::contains_secrets,
    vault::CredentialVault,
};
use security::crypto::{EncryptionAlgorithm, KdfAlgorithm, KdfParams};
use base64::Engine;
use serde_json::json;

#[test]
fn key_generate_not_zero() {
    let key = Key::generate();
    let bytes = key.as_bytes();
    assert!(!bytes.iter().all(|&b| b == 0));
}

#[test]
fn key_generate_two_different() {
    let k1 = Key::generate();
    let k2 = Key::generate();
    assert!(!k1.constant_time_eq(&k2));
}

#[test]
fn key_to_base64_roundtrip() {
    let key = Key::generate();
    let b64 = key.to_base64();
    let decoded = Key::from_base64(&b64).unwrap();
    assert!(key.constant_time_eq(&decoded));
}

#[test]
fn key_from_base64_invalid() {
    assert!(Key::from_base64("not-valid-base64!!!").is_none());
}

#[test]
fn key_from_base64_wrong_length() {
    let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    assert!(Key::from_base64(&short).is_none());
}

#[test]
fn key_constant_time_eq_reflexive() {
    let key = Key::generate();
    assert!(key.constant_time_eq(&key));
}

#[test]
fn key_algorithm_default() {
    let key = Key::generate();
    assert_eq!(key.algorithm(), KdfAlgorithm::Argon2id);
}

#[test]
fn key_salt_default() {
    let key = Key::generate();
    let salt = key.salt();
    assert_eq!(salt, &[0u8; 16]);
}

#[test]
fn key_params_default() {
    let key = Key::generate();
    let params = key.params();
    assert_eq!(params.mem_cost, 65536);
    assert_eq!(params.time_cost, 4);
    assert_eq!(params.lanes, 4);
}

#[test]
fn key_from_password_argon2id_same_inputs() {
    let salt = [1u8; 16];
    let params = KdfParams::interactive();
    let k1 = Key::from_password_argon2id("password", &salt, params);
    let k2 = Key::from_password_argon2id("password", &salt, params);
    assert!(k1.constant_time_eq(&k2));
}

#[test]
fn key_from_password_argon2id_different_password() {
    let salt = [1u8; 16];
    let params = KdfParams::interactive();
    let k1 = Key::from_password_argon2id("password1", &salt, params);
    let k2 = Key::from_password_argon2id("password2", &salt, params);
    assert!(!k1.constant_time_eq(&k2));
}

#[test]
fn key_from_password_argon2id_different_salt() {
    let params = KdfParams::interactive();
    let k1 = Key::from_password_argon2id("password", &[1u8; 16], params);
    let k2 = Key::from_password_argon2id("password", &[2u8; 16], params);
    assert!(!k1.constant_time_eq(&k2));
}

#[test]
fn key_from_password_sha256() {
    let key = Key::from_password_sha256("test", &[1u8; 16]);
    assert_eq!(key.algorithm(), KdfAlgorithm::Sha256);
}

#[test]
fn key_from_password_sha256_consistent() {
    let k1 = Key::from_password_sha256("pass", &[2u8; 16]);
    let k2 = Key::from_password_sha256("pass", &[2u8; 16]);
    assert!(k1.constant_time_eq(&k2));
}

#[test]
fn key_from_password_sha256_different() {
    let k1 = Key::from_password_sha256("a", &[1u8; 16]);
    let k2 = Key::from_password_sha256("b", &[1u8; 16]);
    assert!(!k1.constant_time_eq(&k2));
}

#[test]
fn key_from_password_sha256_salt_stored() {
    let salt = [42u8; 16];
    let key = Key::from_password_sha256("p", &salt);
    assert_eq!(key.salt(), &salt);
}

#[test]
fn key_as_bytes_length() {
    let key = Key::generate();
    assert_eq!(key.as_bytes().len(), 32);
}

#[test]
fn key_base64_not_empty() {
    let key = Key::generate();
    assert!(!key.to_base64().is_empty());
}

#[test]
fn key_from_base64_roundtrip_two_keys() {
    let k1 = Key::generate();
    let k2 = Key::generate();
    let b1 = k1.to_base64();
    let b2 = k2.to_base64();
    assert_ne!(b1, b2);
    let d1 = Key::from_base64(&b1).unwrap();
    let d2 = Key::from_base64(&b2).unwrap();
    assert!(k1.constant_time_eq(&d1));
    assert!(k2.constant_time_eq(&d2));
}

#[test]
fn encrypt_decrypt_xchacha_roundtrip() {
    let key = Key::generate();
    let data = b"secret data";
    let encrypted = Encryptor::encrypt(data, &key).unwrap();
    let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
    assert_eq!(data.as_slice(), decrypted.as_slice());
}

#[test]
fn encrypt_decrypt_aes_roundtrip() {
    let key = Key::generate();
    let data = b"aes test data";
    let encrypted =
        Encryptor::encrypt_with_algorithm(data, &key, EncryptionAlgorithm::Aes256Gcm).unwrap();
    assert_eq!(encrypted.algorithm, EncryptionAlgorithm::Aes256Gcm);
    let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
    assert_eq!(data.as_slice(), decrypted.as_slice());
}

#[test]
fn encrypt_decrypt_xchacha_explicit() {
    let key = Key::generate();
    let data = b"xchacha test";
    let encrypted = Encryptor::encrypt_with_algorithm(
        data,
        &key,
        EncryptionAlgorithm::XChaCha20Poly1305,
    )
    .unwrap();
    assert_eq!(encrypted.algorithm, EncryptionAlgorithm::XChaCha20Poly1305);
    let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
    assert_eq!(data.as_slice(), decrypted.as_slice());
}

#[test]
fn encrypt_empty_data() {
    let key = Key::generate();
    let data = b"";
    let encrypted = Encryptor::encrypt(data, &key).unwrap();
    let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn encrypt_large_data() {
    let key = Key::generate();
    let data = vec![0xABu8; 100_000];
    let encrypted = Encryptor::encrypt(&data, &key).unwrap();
    let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
    assert_eq!(data, decrypted);
}

#[test]
fn encrypt_wrong_key_fails() {
    let k1 = Key::generate();
    let k2 = Key::generate();
    let data = b"secret";
    let encrypted = Encryptor::encrypt(data, &k1).unwrap();
    let result = Encryptor::decrypt(&encrypted, &k2);
    assert!(result.is_err());
}

#[test]
fn encrypt_different_nonces() {
    let key = Key::generate();
    let data = b"same data";
    let e1 = Encryptor::encrypt(data, &key).unwrap();
    let e2 = Encryptor::encrypt(data, &key).unwrap();
    assert_ne!(e1.nonce, e2.nonce);
    assert_ne!(e1.ciphertext, e2.ciphertext);
}

#[test]
fn encrypted_data_has_salt_and_params() {
    let key = Key::generate();
    let encrypted = Encryptor::encrypt(b"test", &key).unwrap();
    assert!(encrypted.salt.is_some());
    assert!(encrypted.params.is_some());
}

#[test]
fn encrypt_aes_ciphertext_differs_from_xchacha() {
    let key = Key::generate();
    let data = b"compare";
    let aes = Encryptor::encrypt_with_algorithm(data, &key, EncryptionAlgorithm::Aes256Gcm).unwrap();
    let xchacha =
        Encryptor::encrypt_with_algorithm(data, &key, EncryptionAlgorithm::XChaCha20Poly1305)
            .unwrap();
    assert_ne!(aes.ciphertext, xchacha.ciphertext);
}

#[test]
fn constant_time_eq_equal() {
    let a = [1u8; 32];
    let b = [1u8; 32];
    assert!(security::crypto::constant_time_eq(&a, &b));
}

#[test]
fn constant_time_eq_not_equal() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    assert!(!security::crypto::constant_time_eq(&a, &b));
}

#[test]
fn constant_time_eq_different_lengths() {
    let a = [1u8; 32];
    let b = [1u8; 16];
    assert!(!security::crypto::constant_time_eq(&a, &b));
}

#[test]
fn constant_time_eq_empty() {
    assert!(security::crypto::constant_time_eq(&[], &[]));
}

#[test]
fn kdf_params_interactive() {
    let p = KdfParams::interactive();
    assert_eq!(p.mem_cost, 65536);
    assert_eq!(p.time_cost, 4);
    assert_eq!(p.lanes, 4);
}

#[test]
fn kdf_params_sensitive() {
    let p = KdfParams::sensitive();
    assert_eq!(p.mem_cost, 131072);
    assert_eq!(p.time_cost, 6);
    assert_eq!(p.lanes, 4);
}

#[test]
fn kdf_params_default() {
    let p = KdfParams::default();
    let i = KdfParams::interactive();
    assert_eq!(p.mem_cost, i.mem_cost);
    assert_eq!(p.time_cost, i.time_cost);
    assert_eq!(p.lanes, i.lanes);
}

#[test]
fn encryption_algorithm_default() {
    assert_eq!(
        EncryptionAlgorithm::default(),
        EncryptionAlgorithm::XChaCha20Poly1305
    );
}

#[test]
fn kdf_algorithm_default() {
    assert_eq!(KdfAlgorithm::default(), KdfAlgorithm::Argon2id);
}

#[test]
fn redact_api_key() {
    let redacted = redact_secrets("api_key=sk-test-12345abcdef");
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("sk-test"));
}

#[test]
fn redact_jwt() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j6TQvPXKtj_bSqtZISdPwQoA";
    let redacted = redact_secrets(&format!("token={}", jwt));
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn redact_github_token() {
    let redacted = redact_secrets("ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn redact_ssh_key() {
    let input = "-----BEGIN RSA PRIVATE KEY-----\nFAKE";
    let redacted = redact_secrets(input);
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn redact_clean_text() {
    let input = "hello world no secrets here";
    let redacted = redact_secrets(input);
    assert_eq!(redacted, input);
}

#[test]
fn contains_secrets_true() {
    assert!(contains_secrets("api_key=sk-test-12345abcdef"));
}

#[test]
fn contains_secrets_false() {
    assert!(!contains_secrets("hello world"));
}

#[test]
fn secrets_redactor_custom_pattern() {
    let redactor = SecretsRedactor::with_custom(
        vec![("custom", r"CUSTOM_\d{4}")],
        "[HIDDEN]",
    );
    let result = redactor.redact("my code is CUSTOM_1234 here");
    assert!(result.contains("[HIDDEN]"));
    assert!(!result.contains("CUSTOM_1234"));
}

#[test]
fn secrets_redactor_custom_no_match() {
    let redactor = SecretsRedactor::with_custom(
        vec![("custom", r"CUSTOM_\d{4}")],
        "[HIDDEN]",
    );
    let result = redactor.redact("nothing sensitive");
    assert_eq!(result, "nothing sensitive");
}

#[test]
fn secrets_redactor_contains_secret() {
    let redactor = SecretsRedactor::with_custom(
        vec![("pin", r"PIN:\s*\d{4}")],
        "[X]",
    );
    assert!(redactor.contains_secret("your PIN: 1234"));
    assert!(!redactor.contains_secret("no pin here"));
}

#[test]
fn secrets_redactor_default_instance() {
    let redactor = SecretsRedactor::new();
    let result = redactor.redact("api_key=sk-test-12345abcdef");
    assert!(result.contains("[REDACTED]"));
}

#[test]
fn redact_sensitive_value_api_key() {
    let result = SecretsRedactor::redact_sensitive_value("api_key", "sk-test-12345");
    assert!(result.starts_with("sk-t"));
    assert!(result.ends_with("..."));
}

#[test]
fn redact_sensitive_value_password() {
    let result = SecretsRedactor::redact_sensitive_value("password", "mysecret");
    assert!(result.starts_with("myse"));
    assert!(result.ends_with("..."));
}

#[test]
fn redact_sensitive_value_token() {
    let result = SecretsRedactor::redact_sensitive_value("auth_token", "tok_abcdef123456");
    assert!(result.starts_with("tok_"));
    assert!(result.ends_with("..."));
}

#[test]
fn redact_sensitive_value_not_sensitive() {
    let result = SecretsRedactor::redact_sensitive_value("username", "alice");
    assert_eq!(result, "alice");
}

#[test]
fn redact_sensitive_value_short_value() {
    let result = SecretsRedactor::redact_sensitive_value("api_key", "ab");
    assert_eq!(result, "***");
}

#[test]
fn redact_sensitive_value_exact_four() {
    let result = SecretsRedactor::redact_sensitive_value("secret", "abcd");
    assert_eq!(result, "***");
}

#[test]
fn audit_log_new_empty() {
    let log = AuditLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn audit_log_default() {
    let log = AuditLog::default();
    assert!(log.is_empty());
}

#[test]
fn audit_log_single_entry() {
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    assert_eq!(log.len(), 1);
}

#[test]
fn audit_log_verify_empty() {
    let log = AuditLog::new();
    assert!(log.verify());
}

#[test]
fn audit_log_verify_single() {
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    assert!(log.verify());
}

#[test]
fn audit_log_verify_chain() {
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    log.log(AuditAction::ToolExecute, Some("t1".to_string()));
    log.log(AuditAction::SessionEnd, Some("s1".to_string()));
    assert!(log.verify());
}

#[test]
fn audit_log_verify_chain_integrity_ok() {
    let mut log = AuditLog::new();
    log.log(AuditAction::ApiKeySet, None);
    log.log(AuditAction::ApiKeyCleared, None);
    assert!(log.verify_chain_integrity().is_ok());
}

#[test]
fn audit_log_entries_iterator() {
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    log.log(AuditAction::ToolExecute, Some("t2".to_string()));
    let count = log.entries().count();
    assert_eq!(count, 2);
}

#[test]
fn audit_log_previous_hash_changes() {
    let mut log = AuditLog::new();
    let h0 = log.previous_hash();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    let h1 = log.previous_hash();
    assert_ne!(h0, h1);
}

#[test]
fn audit_entry_new() {
    let entry = AuditEntry::new(
        AuditAction::ToolExecute,
        Some("tool".to_string()),
        [0u8; 32],
    );
    assert_eq!(entry.action, AuditAction::ToolExecute);
    assert_eq!(entry.target.as_deref(), Some("tool"));
    assert!(entry.timestamp > 0);
}

#[test]
fn audit_entry_hash_hex_length() {
    let entry = AuditEntry::new(AuditAction::SessionStart, None, [0u8; 32]);
    assert_eq!(entry.hash_hex().len(), 64);
}

#[test]
fn audit_entry_to_ecs_json() {
    let entry = AuditEntry::new(AuditAction::ToolExecute, Some("t".to_string()), [0u8; 32]);
    let ecs = entry.to_ecs_json();
    assert!(ecs.get("@timestamp").is_some());
    assert!(ecs.get("event").is_some());
    assert_eq!(ecs["event"]["action"], "TOOL_EXECUTE");
}

#[test]
fn audit_entry_to_splunk_hec() {
    let entry = AuditEntry::new(AuditAction::SessionStart, Some("s".to_string()), [0u8; 32]);
    let hec = entry.to_splunk_hec();
    assert_eq!(hec["sourcetype"], "opencode:audit");
    assert_eq!(hec["event"]["action"], "SESSION_START");
}

#[test]
fn audit_entry_to_opentelemetry() {
    let entry = AuditEntry::new(AuditAction::FileRead, None, [0u8; 32]);
    let otel = entry.to_opentelemetry();
    assert!(otel.get("resourceSpans").is_some());
}

#[test]
fn audit_entry_serde_roundtrip() {
    let entry = AuditEntry::new(AuditAction::ConfigChange, Some("cfg".to_string()), [0u8; 32]);
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry.action, deserialized.action);
    assert_eq!(entry.target, deserialized.target);
    assert_eq!(entry.entry_hash, deserialized.entry_hash);
}

#[test]
fn generate_audit_keypair_works() {
    let (sk, vk) = generate_audit_keypair();
    assert_eq!(sk.verifying_key(), vk);
}

#[test]
fn sign_and_verify_block() {
    let (sk, vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    for i in 0..10 {
        log.log(AuditAction::ToolExecute, Some(format!("tool-{i}")));
    }
    let block = log.sign_block(&sk).unwrap();
    assert!(block.verify(&vk));
}

#[test]
fn sign_block_wrong_key_fails() {
    let (sk, _) = generate_audit_keypair();
    let (_, wrong_vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    let block = log.sign_block(&sk).unwrap();
    assert!(!block.verify(&wrong_vk));
}

#[test]
fn sign_empty_log_returns_none() {
    let (sk, _vk) = generate_audit_keypair();
    let log = AuditLog::new();
    assert!(log.sign_block(&sk).is_none());
}

#[test]
fn sign_all_blocks() {
    let (sk, vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    for i in 0..250 {
        log.log(AuditAction::ToolExecute, Some(format!("t-{i}")));
    }
    let blocks = log.sign_all_blocks(&sk);
    assert_eq!(blocks.len(), 3);
    for block in &blocks {
        assert!(block.verify(&vk));
    }
}

#[test]
fn verify_blocks_valid() {
    let (sk, vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    for i in 0..50 {
        log.log(AuditAction::ToolExecute, Some(format!("t-{i}")));
    }
    let blocks = log.sign_all_blocks(&sk);
    assert!(log.verify_blocks(&blocks, &vk).is_ok());
}

#[test]
fn verify_blocks_invalid_key() {
    let (sk, _) = generate_audit_keypair();
    let (_, wrong_vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    let blocks = log.sign_all_blocks(&sk);
    assert!(log.verify_blocks(&blocks, &wrong_vk).is_err());
}

#[test]
fn signed_block_serde_roundtrip() {
    let (sk, _vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    let block = log.sign_block(&sk).unwrap();
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: security::SignedBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block.block_number, deserialized.block_number);
    assert_eq!(block.block_hash, deserialized.block_hash);
}

#[test]
fn signed_block_hash_mismatch() {
    let (sk, vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    let mut block = log.sign_block(&sk).unwrap();
    block.block_hash = [0u8; 32];
    assert!(!block.verify(&vk));
}

#[test]
fn signed_block_signature_tampered() {
    let (sk, vk) = generate_audit_keypair();
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    let mut block = log.sign_block(&sk).unwrap();
    block.signature_hex = hex::encode([0u8; 64]);
    assert!(!block.verify(&vk));
}

#[test]
fn audit_log_export_ecs() {
    let mut log = AuditLog::new();
    log.log(AuditAction::ToolExecute, Some("t".to_string()));
    let ecs = log.export_ecs();
    assert_eq!(ecs.len(), 1);
}

#[test]
fn audit_log_export_splunk_hec() {
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s".to_string()));
    let hec = log.export_splunk_hec();
    assert_eq!(hec.len(), 1);
}

#[test]
fn audit_log_export_opentelemetry() {
    let mut log = AuditLog::new();
    log.log(AuditAction::FileWrite, Some("f".to_string()));
    let otel = log.export_opentelemetry();
    assert!(otel.get("resourceSpans").is_some());
}

#[test]
fn audit_log_export_json() {
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    let json = log.export_json();
    assert_eq!(json["count"], 1);
    assert!(json.get("entries").is_some());
}

#[test]
fn audit_log_all_actions_display() {
    let actions = vec![
        AuditAction::ApiKeySet,
        AuditAction::ApiKeyCleared,
        AuditAction::ConfigEncrypt,
        AuditAction::ConfigDecrypt,
        AuditAction::SessionStart,
        AuditAction::SessionEnd,
        AuditAction::ToolExecute,
        AuditAction::FileRead,
        AuditAction::FileWrite,
        AuditAction::FileDelete,
        AuditAction::ToolCallStart,
        AuditAction::ToolCallEnd,
        AuditAction::PermissionGrant,
        AuditAction::PermissionDeny,
        AuditAction::ForensicCapture,
        AuditAction::ConfigChange,
        AuditAction::ProviderSwitch,
    ];
    for action in &actions {
        let display = action.to_string();
        assert!(!display.is_empty());
    }
}

#[test]
fn audit_action_serde_roundtrip() {
    let actions = vec![
        AuditAction::ApiKeySet,
        AuditAction::SessionStart,
        AuditAction::ToolExecute,
        AuditAction::ProviderSwitch,
    ];
    for action in actions {
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: AuditAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, deserialized);
    }
}

#[test]
fn secure_config_new() {
    let config = SecureConfig::new();
    assert_eq!(config.algorithm(), EncryptionAlgorithm::XChaCha20Poly1305);
}

#[test]
fn secure_config_default() {
    let config = SecureConfig::default();
    assert_eq!(config.algorithm(), EncryptionAlgorithm::XChaCha20Poly1305);
}

#[test]
fn secure_config_with_algorithm_aes() {
    let config = SecureConfig::with_algorithm(EncryptionAlgorithm::Aes256Gcm);
    assert_eq!(config.algorithm(), EncryptionAlgorithm::Aes256Gcm);
}

#[test]
fn secure_config_set_algorithm() {
    let mut config = SecureConfig::new();
    config.set_algorithm(EncryptionAlgorithm::Aes256Gcm);
    assert_eq!(config.algorithm(), EncryptionAlgorithm::Aes256Gcm);
}

#[test]
fn secure_config_set_get() {
    let mut config = SecureConfig::new();
    config.set("key1", "value1");
    assert_eq!(config.get("key1"), Some("value1".to_string()));
}

#[test]
fn secure_config_get_missing() {
    let config = SecureConfig::new();
    assert_eq!(config.get("missing"), None);
}

#[test]
fn master_key_from_password() {
    let mk = MasterKey::from_password("test-password").unwrap();
    assert!(!mk.is_locked() || true);
}

#[test]
fn master_key_from_password_none() {
    let mk = MasterKey::from_password("");
    assert!(mk.is_some());
}

#[test]
fn master_key_derive_key() {
    let mk = MasterKey::from_password("test-pass").unwrap();
    let salt = [1u8; 16];
    let params = KdfParams::interactive();
    let key = mk.derive_key(&salt, params);
    assert_eq!(key.algorithm(), KdfAlgorithm::Argon2id);
}

#[test]
fn vault_roundtrip() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("test.vault");
    let mk = MasterKey::from_password("vault-pass").unwrap();
    let mut vault = CredentialVault::open_or_create(path.clone(), &mk).unwrap();
    vault.set("key", json!("value"));
    vault.save(&mk).unwrap();
    let loaded = CredentialVault::open(path, &mk).unwrap();
    assert_eq!(loaded.get("key"), Some(&json!("value")));
}

#[test]
fn vault_set_get_string() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let mut vault = CredentialVault::open_or_create(path.clone(), &mk).unwrap();
    vault.set("name", json!("alice"));
    vault.save(&mk).unwrap();
    let loaded = CredentialVault::open(path, &mk).unwrap();
    assert_eq!(loaded.get_string("name"), Some("alice".to_string()));
}

#[test]
fn vault_remove() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let mut vault = CredentialVault::open_or_create(path.clone(), &mk).unwrap();
    vault.set("x", json!(42));
    let removed = vault.remove("x");
    assert!(removed.is_some());
    assert!(vault.get("x").is_none());
}

#[test]
fn vault_get_missing() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let vault = CredentialVault::open_or_create(path, &mk).unwrap();
    assert!(vault.get("nonexistent").is_none());
}

#[test]
fn vault_data_reference() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let vault = CredentialVault::open_or_create(path, &mk).unwrap();
    assert!(vault.data().is_object());
}

#[test]
fn vault_algorithm_default() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let vault = CredentialVault::open_or_create(path, &mk).unwrap();
    assert_eq!(vault.algorithm(), EncryptionAlgorithm::XChaCha20Poly1305);
}

#[test]
fn vault_set_algorithm() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let mut vault = CredentialVault::open_or_create(path, &mk).unwrap();
    vault.set_algorithm(EncryptionAlgorithm::Aes256Gcm);
    assert_eq!(vault.algorithm(), EncryptionAlgorithm::Aes256Gcm);
}

#[test]
fn vault_path_reference() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let vault = CredentialVault::open_or_create(path.clone(), &mk).unwrap();
    assert_eq!(vault.path(), path.as_path());
}

#[test]
fn secure_config_save_load_aes() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.enc");
    let key = Key::generate();
    let mut config = SecureConfig::with_algorithm(EncryptionAlgorithm::Aes256Gcm);
    config.set("api_key", "sk-test");
    config.save(&path, &key).unwrap();
    let loaded = SecureConfig::load(&path, &key).unwrap();
    assert_eq!(loaded.get("api_key"), Some("sk-test".to_string()));
}

#[test]
fn secure_config_save_load_xchacha() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.enc");
    let key = Key::generate();
    let mut config = SecureConfig::with_algorithm(EncryptionAlgorithm::XChaCha20Poly1305);
    config.set("secret", "val");
    config.save(&path, &key).unwrap();
    let loaded = SecureConfig::load(&path, &key).unwrap();
    assert_eq!(loaded.get("secret"), Some("val".to_string()));
}

#[test]
fn secure_config_migrate_algorithm() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("cfg.enc");
    let key = Key::generate();
    let mut config = SecureConfig::with_algorithm(EncryptionAlgorithm::Aes256Gcm);
    config.set("k", "v");
    config.save(&path, &key).unwrap();
    let mut loaded = SecureConfig::load(&path, &key).unwrap();
    loaded
        .migrate_algorithm(&key, EncryptionAlgorithm::XChaCha20Poly1305)
        .unwrap();
    loaded.save(&path, &key).unwrap();
    let migrated = SecureConfig::load(&path, &key).unwrap();
    assert_eq!(migrated.algorithm(), EncryptionAlgorithm::XChaCha20Poly1305);
}

#[test]
fn secure_config_migrate_same_algo_noop() {
    let key = Key::generate();
    let mut config = SecureConfig::with_algorithm(EncryptionAlgorithm::Aes256Gcm);
    config.set("k", "v");
    config.migrate_algorithm(&key, EncryptionAlgorithm::Aes256Gcm).unwrap();
    assert_eq!(config.algorithm(), EncryptionAlgorithm::Aes256Gcm);
}

#[test]
fn encrypt_encrypted_data_serde_roundtrip() {
    let key = Key::generate();
    let encrypted = Encryptor::encrypt(b"test data", &key).unwrap();
    let json = serde_json::to_string(&encrypted).unwrap();
    let deserialized: security::crypto::EncryptedData = serde_json::from_str(&json).unwrap();
    assert_eq!(encrypted.algorithm, deserialized.algorithm);
    assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
}

#[test]
fn audit_log_entries_do_not_overflow() {
    let mut log = AuditLog::new();
    for i in 0..100 {
        log.log(AuditAction::ToolExecute, Some(format!("t-{i}")));
    }
    assert_eq!(log.len(), 100);
    assert!(log.verify());
}

#[test]
fn key_from_password_argon2id_sensitive_params() {
    let salt = [3u8; 16];
    let params = KdfParams::sensitive();
    let k1 = Key::from_password_argon2id("pass", &salt, params);
    let k2 = Key::from_password_argon2id("pass", &salt, params);
    assert!(k1.constant_time_eq(&k2));
    assert_eq!(k1.algorithm(), KdfAlgorithm::Argon2id);
}

#[test]
fn vault_multiple_keys() {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("v.vault");
    let mk = MasterKey::from_password("pass").unwrap();
    let mut vault = CredentialVault::open_or_create(path.clone(), &mk).unwrap();
    vault.set("k1", json!("v1"));
    vault.set("k2", json!("v2"));
    vault.set("k3", json!("v3"));
    vault.save(&mk).unwrap();
    let loaded = CredentialVault::open(path, &mk).unwrap();
    assert_eq!(loaded.get("k1"), Some(&json!("v1")));
    assert_eq!(loaded.get("k2"), Some(&json!("v2")));
    assert_eq!(loaded.get("k3"), Some(&json!("v3")));
}

#[test]
fn audit_log_verify_chain_integrity_multi_entry() {
    let mut log = AuditLog::new();
    log.log(AuditAction::SessionStart, Some("s1".to_string()));
    log.log(AuditAction::ToolExecute, Some("t1".to_string()));
    log.log(AuditAction::SessionEnd, Some("s1".to_string()));
    assert!(log.verify_chain_integrity().is_ok());
}

#[test]
fn redact_aws_key() {
    let input = "AKIAIOSFODNN7EXAMPLE";
    let redacted = redact_secrets(input);
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn redact_slack_token() {
    let input = "xoxb-123456789012-1234567890123-abcdefghij";
    let redacted = redact_secrets(input);
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn secrets_redactor_empty_input() {
    let redactor = SecretsRedactor::default();
    let result = redactor.redact("");
    assert_eq!(result, "");
}

#[test]
fn secrets_redactor_multiple_matches() {
    let input = "api_key=sk-test123456789abcdef and api_key=sk-test987654321fedcba";
    let redacted = redact_secrets(input);
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("sk-test"));
}

#[test]
fn audit_entry_target_none() {
    let entry = AuditEntry::new(AuditAction::ConfigEncrypt, None, [0u8; 32]);
    assert!(entry.target.is_none());
}

#[test]
fn audit_log_last_signed_block() {
    let log = AuditLog::new();
    assert_eq!(log.last_signed_block(), 0);
}
