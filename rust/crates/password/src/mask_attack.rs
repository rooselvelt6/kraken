#[derive(Debug, Clone)]
pub struct MaskAttack {
    pub mask: Vec<char>,
    pub custom_charsets: Vec<(char, String)>,
}

impl MaskAttack {
    pub fn new(mask: &str) -> Self {
        MaskAttack {
            mask: mask.chars().collect(),
            custom_charsets: Vec::new(),
        }
    }

    pub fn with_charset(mut self, placeholder: char, charset: &str) -> Self {
        self.custom_charsets.push((placeholder, charset.to_string()));
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut results = Vec::new();
        let charsets = self.resolve_charsets();
        Self::generate_recursive(&self.mask, &charsets, 0, String::new(), &mut results);
        results
    }

    fn resolve_charsets(&self) -> Vec<Vec<char>> {
        let mut charsets = Vec::new();
        let custom_map: std::collections::HashMap<char, String> =
            self.custom_charsets.iter().cloned().collect();
        let mut i = 0;

        while i < self.mask.len() {
            if self.mask[i] == '?' && i + 1 < self.mask.len() {
                let next = self.mask[i + 1];
                let chars = match next {
                    'l' | 'L' => "abcdefghijklmnopqrstuvwxyz".chars().collect(),
                    'u' | 'U' => "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect(),
                    'd' | 'D' => "0123456789".chars().collect(),
                    's' | 'S' => "!@#$%^&*()_+-=[]{}|;':\",./<>?`~".chars().collect(),
                    'a' | 'A' => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect(),
                    'h' | 'H' => "0123456789abcdef".chars().collect(),
                    'b' | 'B' => "01".chars().collect(),
                    '?' => vec!['?'],
                    other => {
                        if let Some(cs) = custom_map.get(&other) {
                            cs.chars().collect()
                        } else {
                            vec![other]
                        }
                    }
                };
                charsets.push(chars);
                i += 2;
            } else {
                charsets.push(vec![self.mask[i]]);
                i += 1;
            }
        }
        charsets
    }

    fn generate_recursive(
        _mask_chars: &[char],
        charsets: &[Vec<char>],
        depth: usize,
        current: String,
        results: &mut Vec<String>,
    ) {
        if depth == charsets.len() {
            results.push(current);
            return;
        }
        for &c in &charsets[depth] {
            let mut next = current.clone();
            next.push(c);
            Self::generate_recursive(_mask_chars, charsets, depth + 1, next, results);
        }
    }

    pub fn generate_limited(&self, max_count: usize) -> Vec<String> {
        let all = self.generate();
        all.into_iter().take(max_count).collect()
    }
}

pub fn mask_to_regex(mask: &str) -> String {
    let mut regex = String::from("^");
    let mut chars = mask.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '?' => {
                let next = chars.next().unwrap_or('a');
                match next {
                    'l' => regex.push_str("[a-z]"),
                    'u' => regex.push_str("[A-Z]"),
                    'd' => regex.push_str("[0-9]"),
                    's' => regex.push_str("[!@#$%^&*()_+\\-=\\[\\]{}|;':\\\",./<>?`~]"),
                    'a' => regex.push_str("[a-zA-Z0-9]"),
                    'h' => regex.push_str("[0-9a-f]"),
                    'b' => regex.push_str("[01]"),
                    '?' => regex.push_str("\\?"),
                    _ => regex.push(next),
                }
            }
            _ => {
                if c.is_ascii_punctuation() || c == ' ' {
                    regex.push('\\');
                }
                regex.push(c);
            }
        }
    }
    regex.push('$');
    regex
}

pub fn mask_attack_with_hash(
    mask: &str,
    hash: &str,
    hash_type: &str,
    max_attempts: usize,
) -> Option<String> {
    let attack = MaskAttack::new(mask);
    let candidates = attack.generate_limited(max_attempts);

    let verifier: Option<Box<dyn crate::hash_cracker::HashVerifier>> = match hash_type {
        "MD5" => Some(Box::new(crate::hash_cracker::Md5Verifier)),
        "SHA1" => Some(Box::new(crate::hash_cracker::Sha1Verifier)),
        "SHA2-256" | "SHA256" => Some(Box::new(crate::hash_cracker::Sha256Verifier)),
        "SHA2-512" | "SHA512" => Some(Box::new(crate::hash_cracker::Sha512Verifier)),
        _ => None,
    };

    match verifier {
        Some(v) => {
            for pw in &candidates {
                if v.verify(pw, hash) {
                    return Some(pw.clone());
                }
            }
            None
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_generate_simple() {
        let attack = MaskAttack::new("?d?d");
        let results = attack.generate();
        assert_eq!(results.len(), 100);
        assert!(results.contains(&"00".to_string()));
        assert!(results.contains(&"99".to_string()));
    }

    #[test]
    fn test_mask_generate_lower() {
        let attack = MaskAttack::new("?l?l");
        let results = attack.generate_limited(10);
        assert_eq!(results.len(), 10);
        assert!(results.contains(&"aa".to_string()));
    }

    #[test]
    fn test_mask_generate_mixed() {
        let attack = MaskAttack::new("?u?d");
        let results = attack.generate();
        assert_eq!(results.len(), 260);
        assert!(results.contains(&"A0".to_string()));
    }

    #[test]
    fn test_mask_to_regex() {
        let re = mask_to_regex("?l?d");
        assert_eq!(re, "^[a-z][0-9]$");
    }

    #[test]
    fn test_mask_to_regex_literal() {
        let re = mask_to_regex("hello");
        assert_eq!(re, "^hello$");
    }

    #[test]
    fn test_custom_charset() {
        let attack = MaskAttack::new("?1?d")
            .with_charset('1', "abc");
        let results = attack.generate();
        assert_eq!(results.len(), 30);
        assert!(results.contains(&"a0".to_string()));
    }

    #[test]
    fn test_hex_mask() {
        let attack = MaskAttack::new("?h?h");
        let results = attack.generate_limited(50);
        assert_eq!(results.len(), 50);
    }

    #[test]
    fn test_binary_mask() {
        let attack = MaskAttack::new("?b?b?b");
        let results = attack.generate();
        assert_eq!(results.len(), 8);
    }

    #[test]
    fn test_special_mask() {
        let attack = MaskAttack::new("?s");
        let results = attack.generate();
        assert!(!results.is_empty());
        assert!(results.contains(&"!".to_string()));
    }

    #[test]
    fn test_mask_attack_with_hash_found() {
        let result = mask_attack_with_hash(
            "?d?d?d?d",
            "81dc9bdb52d04dc20036dbd8313ed055",
            "MD5",
            10000,
        );
        assert_eq!(result, Some("1234".to_string()));
    }

    #[test]
    fn test_mask_attack_with_hash_not_found() {
        let result = mask_attack_with_hash(
            "?d?d?d",
            "5d41402abc4b2a76b9719d911017c592",
            "MD5",
            10,
        );
        assert!(result.is_none());
    }
}
