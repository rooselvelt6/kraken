use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HashInfo {
    pub name: &'static str,
    pub category: HashCategory,
    pub length: usize,
    pub pattern: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HashCategory {
    Md5,
    Sha1,
    Sha2,
    Sha3,
    Bcrypt,
    Argon2,
    Ntlm,
    Lm,
    Unix,
    Blowfish,
    Ripemd,
    Whirlpool,
    Gost,
    Skein,
    Other,
}

static HASH_SIGNATURES: &[HashInfo] = &[
    HashInfo { name: "MD5", category: HashCategory::Md5, length: 32, pattern: "^[a-f0-9]{32}$" },
    HashInfo { name: "MD5 (upper)", category: HashCategory::Md5, length: 32, pattern: "^[A-F0-9]{32}$" },
    HashInfo { name: "MD5 (mixed)", category: HashCategory::Md5, length: 32, pattern: "^[a-fA-F0-9]{32}$" },
    HashInfo { name: "SHA1", category: HashCategory::Sha1, length: 40, pattern: "^[a-f0-9]{40}$" },
    HashInfo { name: "SHA1 (upper)", category: HashCategory::Sha1, length: 40, pattern: "^[A-F0-9]{40}$" },
    HashInfo { name: "SHA2-224", category: HashCategory::Sha2, length: 56, pattern: "^[a-f0-9]{56}$" },
    HashInfo { name: "SHA2-256", category: HashCategory::Sha2, length: 64, pattern: "^[a-f0-9]{64}$" },
    HashInfo { name: "SHA2-384", category: HashCategory::Sha2, length: 96, pattern: "^[a-f0-9]{96}$" },
    HashInfo { name: "SHA2-512", category: HashCategory::Sha2, length: 128, pattern: "^[a-f0-9]{128}$" },
    HashInfo { name: "SHA3-224", category: HashCategory::Sha3, length: 56, pattern: "^[a-f0-9]{56}$" },
    HashInfo { name: "SHA3-256", category: HashCategory::Sha3, length: 64, pattern: "^[a-f0-9]{64}$" },
    HashInfo { name: "SHA3-384", category: HashCategory::Sha3, length: 96, pattern: "^[a-f0-9]{96}$" },
    HashInfo { name: "SHA3-512", category: HashCategory::Sha3, length: 128, pattern: "^[a-f0-9]{128}$" },
    HashInfo { name: "bcrypt ($2b$)", category: HashCategory::Bcrypt, length: 0, pattern: "^\\$2[abxy]\\$\\d{2}\\$[./A-Za-z0-9]{53}$" },
    HashInfo { name: "bcrypt ($2a$)", category: HashCategory::Bcrypt, length: 0, pattern: "^\\$2a\\$\\d{2}\\$[./A-Za-z0-9]{53}$" },
    HashInfo { name: "bcrypt ($2y$)", category: HashCategory::Bcrypt, length: 0, pattern: "^\\$2y\\$\\d{2}\\$[./A-Za-z0-9]{53}$" },
    HashInfo { name: "Argon2id", category: HashCategory::Argon2, length: 0, pattern: "^\\$argon2id\\$v=\\d+\\$m=\\d+,t=\\d+,p=\\d+\\$[./A-Za-z0-9]+\\$[./A-Za-z0-9]+$" },
    HashInfo { name: "Argon2i", category: HashCategory::Argon2, length: 0, pattern: "^\\$argon2i\\$v=\\d+\\$m=\\d+,t=\\d+,p=\\d+\\$[./A-Za-z0-9]+\\$[./A-Za-z0-9]+$" },
    HashInfo { name: "Argon2d", category: HashCategory::Argon2, length: 0, pattern: "^\\$argon2d\\$v=\\d+\\$m=\\d+,t=\\d+,p=\\d+\\$[./A-Za-z0-9]+\\$[./A-Za-z0-9]+$" },
    HashInfo { name: "NTLM", category: HashCategory::Ntlm, length: 32, pattern: "^[a-fA-F0-9]{32}$" },
    HashInfo { name: "LM", category: HashCategory::Lm, length: 32, pattern: "^[a-fA-F0-9]{32}$" },
    HashInfo { name: "Unix DES (crypt)", category: HashCategory::Unix, length: 13, pattern: "^[./a-zA-Z0-9]{13}$" },
    HashInfo { name: "Unix MD5 ($1$)", category: HashCategory::Unix, length: 0, pattern: "^\\$1\\$[./a-zA-Z0-9]{1,8}\\$[./a-zA-Z0-9]{22}$" },
    HashInfo { name: "Unix SHA256 ($5$)", category: HashCategory::Unix, length: 0, pattern: "^\\$5\\$[./a-zA-Z0-9]{1,16}\\$[./a-zA-Z0-9]{43}$" },
    HashInfo { name: "Unix SHA512 ($6$)", category: HashCategory::Unix, length: 0, pattern: "^\\$6\\$[./a-zA-Z0-9]{1,16}\\$[./a-zA-Z0-9]{86}$" },
    HashInfo { name: "Blowfish (Eksblowfish)", category: HashCategory::Blowfish, length: 0, pattern: "^\\$2[abxy]\\$\\d{2}\\$[./A-Za-z0-9]{53}$" },
    HashInfo { name: "RIPEMD-160", category: HashCategory::Ripemd, length: 40, pattern: "^[a-f0-9]{40}$" },
    HashInfo { name: "Whirlpool", category: HashCategory::Whirlpool, length: 128, pattern: "^[a-f0-9]{128}$" },
    HashInfo { name: "GOST R 34.11-2012 (Streebog 256)", category: HashCategory::Gost, length: 64, pattern: "^[a-f0-9]{64}$" },
    HashInfo { name: "GOST R 34.11-2012 (Streebog 512)", category: HashCategory::Gost, length: 128, pattern: "^[a-f0-9]{128}$" },
    HashInfo { name: "Skein-256", category: HashCategory::Skein, length: 64, pattern: "^[a-f0-9]{64}$" },
    HashInfo { name: "Skein-512", category: HashCategory::Skein, length: 128, pattern: "^[a-f0-9]{128}$" },
];

pub fn identify_hash(hash: &str) -> Vec<&'static HashInfo> {
    let trimmed = hash.trim();
    HASH_SIGNATURES.iter().filter(|info| {
        if info.length == 0 || info.length == trimmed.len() {
            if let Ok(re) = regex::Regex::new(info.pattern) {
                return re.is_match(trimmed);
            }
        }
        false
    }).collect()
}

pub fn identify_hash_best(hash: &str) -> Option<&'static HashInfo> {
    identify_hash(hash).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_md5() {
        let hash = "5d41402abc4b2a76b9719d911017c592";
        let results = identify_hash(hash);
        assert!(results.iter().any(|h| h.name == "MD5"));
    }

    #[test]
    fn test_identify_sha1() {
        let hash = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        let results = identify_hash(hash);
        assert!(results.iter().any(|h| h.name == "SHA1"));
    }

    #[test]
    fn test_identify_sha256() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let results = identify_hash(hash);
        assert!(results.iter().any(|h| h.name == "SHA2-256"));
    }

    #[test]
    fn test_identify_sha512() {
        let hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let results = identify_hash(hash);
        assert!(results.iter().any(|h| h.name == "SHA2-512"));
    }

    #[test]
    fn test_identify_bcrypt() {
        let hash = "$2b$12$LJ3m4ys3Lk0T7ebf3Y7OeuR2oGj6xVrM7H9KmG8J5pN5q5d5f5e5q";
        let results = identify_hash(hash);
        assert!(results.iter().any(|h| h.name.starts_with("bcrypt")));
    }

    #[test]
    fn test_identify_argon2id() {
        let hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$R9udFb7TaqI9xPTxyB4h6A";
        let results = identify_hash(hash);
        assert!(results.iter().any(|h| h.name == "Argon2id"));
    }

    #[test]
    fn test_identify_unix_sha512() {
        let hash = format!("$6$abcdefghijklmnop${}", "1".repeat(86));
        let results = identify_hash(&hash);
        assert!(results.iter().any(|h| h.name == "Unix SHA512 ($6$)"));
    }

    #[test]
    fn test_unknown_hash() {
        let hash = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let results = identify_hash(hash);
        assert!(results.is_empty());
    }

    #[test]
    fn test_identify_best() {
        let hash = "5d41402abc4b2a76b9719d911017c592";
        let info = identify_hash_best(hash);
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "MD5");
    }
}
