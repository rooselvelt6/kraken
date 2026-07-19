#![allow(clippy::needless_pass_by_value)]

use proptest::prelude::*;
use security::crypto::constant_time_eq;
use security::secrets::contains_secrets;
use security::SecretsRedactor;

proptest! {
    #[test]
    fn constant_time_eq_is_reflexive(data in prop::collection::vec(0u8..255u8, 0..200)) {
        prop_assert!(constant_time_eq(&data, &data));
    }

    #[test]
    fn constant_time_eq_symmetric(a in prop::collection::vec(0u8..255u8, 0..200), b in prop::collection::vec(0u8..255u8, 0..200)) {
        prop_assert_eq!(constant_time_eq(&a, &b), constant_time_eq(&b, &a));
    }

    #[test]
    fn constant_time_eq_different_lengths_false(a in prop::collection::vec(0u8..255u8, 0..100), extra in prop::collection::vec(0u8..255u8, 1..20)) {
        let mut b = a.clone();
        b.extend_from_slice(&extra);
        prop_assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn key_roundtrip_base64(_dummy in 0u32..1000u32) {
        let key = security::Key::generate();
        let encoded = key.to_base64();
        let decoded = security::Key::from_base64(&encoded).unwrap();
        prop_assert!(key.constant_time_eq(&decoded));
    }

    #[test]
    fn encrypt_decrypt_roundtrip(data in prop::collection::vec(0u8..255u8, 0..1000)) {
        let key = security::Key::generate();
        let encrypted = security::Encryptor::encrypt(&data, &key).unwrap();
        let decrypted = security::Encryptor::decrypt(&encrypted, &key).unwrap();
        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn redact_secrets_never_leaks_full_secret(
        secret in "[a-zA-Z0-9]{16,64}",
    ) {
        let input = format!("api_key={secret} is here");
        let redacted = security::redact_secrets(&input);
        prop_assert!(!redacted.contains(&secret), "redacted output should not contain the full secret");
    }

    #[test]
    fn redact_sensitive_value_preserves_non_sensitive_keys(
        key in "[a-zA-Z_]{1,30}",
        value in "[a-zA-Z0-9]{1,50}",
    ) {
        let lower = key.to_lowercase();
        let is_sensitive = [
            "api_key", "apikey", "api-key",
            "secret", "secret_key", "secret-key",
            "password", "passwd", "pass",
            "token", "auth_token", "bearer",
            "access_token", "refresh_token",
            "private_key", "private-key", "privkey",
            "ssh_key", "ssh-key",
            "db_password", "db-password",
            "jwt", "session_key",
        ]
        .iter()
        .any(|s| lower.contains(s));
        if !is_sensitive {
            let result = SecretsRedactor::redact_sensitive_value(&key, &value);
            prop_assert_eq!(result, value);
        }
    }

    #[test]
    fn redact_sensitive_value_shortens_long_sensitive(
        value in "[a-zA-Z0-9]{5,100}",
    ) {
        let result = SecretsRedactor::redact_sensitive_value("api_key", &value);
        prop_assert!(result.ends_with("..."), "sensitive value should end with '...'");
        prop_assert!(result.starts_with(&value[..4]), "should preserve first 4 chars");
    }

    #[test]
    fn redact_sensitive_value_stars_short_values(
        value in "[a-zA-Z0-9]{1,4}",
    ) {
        let result = SecretsRedactor::redact_sensitive_value("secret", &value);
        prop_assert_eq!(result, "***");
    }

    #[test]
    fn contains_secrets_matches_known_patterns(
        prefix in "[a-zA-Z_]{1,20}",
        secret_value in "[a-zA-Z0-9]{20,60}",
    ) {
        let input = format!("{prefix}=api_key={secret_value}");
        prop_assert!(contains_secrets(&input));
    }

    #[test]
    fn contains_secrets_rejects_benign(input in "[a-zA-Z0-9 .,!?]{1,200}") {
        let has_secret_pattern = input.contains("api_key=")
            || input.contains("apikey=")
            || input.contains("secret=")
            || input.contains("password=")
            || input.contains("token=");
        if !has_secret_pattern {
            prop_assert!(!contains_secrets(&input));
        }
    }
}
