use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStats {
    pub total_passwords: usize,
    pub unique_passwords: usize,
    pub length_stats: LengthStats,
    pub char_stats: CharStats,
    pub entropy_estimates: EntropyStats,
    pub top_passwords: Vec<(String, usize)>,
    pub pattern_matches: HashMap<String, usize>,
    pub analyzed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LengthStats {
    pub min: usize,
    pub max: usize,
    pub mean: f64,
    pub median: usize,
    pub mode: usize,
    pub histogram: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharStats {
    pub has_uppercase: usize,
    pub has_lowercase: usize,
    pub has_digit: usize,
    pub has_special: usize,
    pub only_digits: usize,
    pub only_lowercase: usize,
    pub only_uppercase: usize,
    pub common_patterns: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyStats {
    pub min_entropy: f64,
    pub max_entropy: f64,
    pub mean_entropy: f64,
    pub weak_passwords: usize,
    pub moderate_passwords: usize,
    pub strong_passwords: usize,
}

impl PasswordStats {
    pub fn analyze(passwords: &[String]) -> Self {
        let total = passwords.len();
        let mut unique: Vec<String> = passwords.to_vec();
        unique.sort();
        unique.dedup();
        let unique_count = unique.len();

        let lengths: Vec<usize> = passwords.iter().map(|p| p.len()).collect();
        let length_stats = Self::compute_length_stats(&lengths);

        let char_stats = Self::compute_char_stats(passwords);

        let entropies: Vec<f64> = passwords.iter().map(|p| estimate_entropy(p)).collect();
        let entropy_stats = Self::compute_entropy_stats(&entropies);

        let mut freq: HashMap<String, usize> = HashMap::new();
        for p in passwords {
            *freq.entry(p.clone()).or_insert(0) += 1;
        }
        let mut freq_vec: Vec<(String, usize)> = freq.into_iter().collect();
        freq_vec.sort_by_key(|b| std::cmp::Reverse(b.1));

        let top_passwords = freq_vec.into_iter().take(20).collect();

        let mut pattern_matches = HashMap::new();
        pattern_matches.insert(
            "sequences".into(),
            passwords.iter().filter(|p| has_sequence(p)).count(),
        );
        pattern_matches.insert(
            "repeated_chars".into(),
            passwords.iter().filter(|p| has_repeated(p)).count(),
        );
        pattern_matches.insert(
            "common_replacements".into(),
            passwords
                .iter()
                .filter(|p| has_common_replacement(p))
                .count(),
        );
        pattern_matches.insert(
            "dates".into(),
            passwords.iter().filter(|p| has_date_pattern(p)).count(),
        );

        Self {
            total_passwords: total,
            unique_passwords: unique_count,
            length_stats,
            char_stats,
            entropy_estimates: entropy_stats,
            top_passwords,
            pattern_matches,
            analyzed_at: Utc::now(),
        }
    }

    fn compute_length_stats(lengths: &[usize]) -> LengthStats {
        if lengths.is_empty() {
            return LengthStats {
                min: 0,
                max: 0,
                mean: 0.0,
                median: 0,
                mode: 0,
                histogram: Vec::new(),
            };
        }

        let min = *lengths.iter().min().unwrap();
        let max = *lengths.iter().max().unwrap();
        let mean = lengths.iter().sum::<usize>() as f64 / lengths.len() as f64;

        let mut sorted = lengths.to_vec();
        sorted.sort();
        let mid = sorted.len() / 2;
        let median = if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        };

        let mut freq: HashMap<usize, usize> = HashMap::new();
        for &len in lengths {
            *freq.entry(len).or_insert(0) += 1;
        }
        let mode = freq.into_iter().max_by_key(|&(_, count)| count).map(|(len, _)| len).unwrap_or(0);

        let mut histogram: Vec<(usize, usize)> = Vec::new();
        for len in min..=max.min(min + 40) {
            let count = lengths.iter().filter(|&&l| l == len).count();
            if count > 0 {
                histogram.push((len, count));
            }
        }

        LengthStats {
            min,
            max,
            mean,
            median,
            mode,
            histogram,
        }
    }

    fn compute_char_stats(passwords: &[String]) -> CharStats {
        CharStats {
            has_uppercase: passwords.iter().filter(|p| p.chars().any(|c| c.is_uppercase())).count(),
            has_lowercase: passwords.iter().filter(|p| p.chars().any(|c| c.is_lowercase())).count(),
            has_digit: passwords.iter().filter(|p| p.chars().any(|c| c.is_ascii_digit())).count(),
            has_special: passwords
                .iter()
                .filter(|p| p.chars().any(|c| !c.is_alphanumeric()))
                .count(),
            only_digits: passwords.iter().filter(|p| p.chars().all(|c| c.is_ascii_digit())).count(),
            only_lowercase: passwords
                .iter()
                .filter(|p| p.chars().all(|c| c.is_lowercase()))
                .count(),
            only_uppercase: passwords
                .iter()
                .filter(|p| p.chars().all(|c| c.is_uppercase()))
                .count(),
            common_patterns: HashMap::new(),
        }
    }

    fn compute_entropy_stats(entropies: &[f64]) -> EntropyStats {
        if entropies.is_empty() {
            return EntropyStats {
                min_entropy: 0.0,
                max_entropy: 0.0,
                mean_entropy: 0.0,
                weak_passwords: 0,
                moderate_passwords: 0,
                strong_passwords: 0,
            };
        }

        let min_entropy = entropies.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_entropy = entropies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let mean_entropy = entropies.iter().sum::<f64>() / entropies.len() as f64;

        let weak = entropies.iter().filter(|&&e| e < 30.0).count();
        let moderate = entropies.iter().filter(|&&e| (30.0..=60.0).contains(&e)).count();
        let strong = entropies.iter().filter(|&&e| e > 60.0).count();

        EntropyStats {
            min_entropy,
            max_entropy,
            mean_entropy,
            weak_passwords: weak,
            moderate_passwords: moderate,
            strong_passwords: strong,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "Passwords: {} total, {} unique | Length: {}-{} (mean {:.1}) | \
             Entropy: {:.1}-{:.1} (mean {:.1}) | \
             Weak: {}, Moderate: {}, Strong: {} | \
             Upper: {}, Lower: {}, Digits: {}, Special: {}",
            self.total_passwords,
            self.unique_passwords,
            self.length_stats.min,
            self.length_stats.max,
            self.length_stats.mean,
            self.entropy_estimates.min_entropy,
            self.entropy_estimates.max_entropy,
            self.entropy_estimates.mean_entropy,
            self.entropy_estimates.weak_passwords,
            self.entropy_estimates.moderate_passwords,
            self.entropy_estimates.strong_passwords,
            self.char_stats.has_uppercase,
            self.char_stats.has_lowercase,
            self.char_stats.has_digit,
            self.char_stats.has_special,
        )
    }

    pub fn top_n(&self, n: usize) -> &[(String, usize)] {
        let end = n.min(self.top_passwords.len());
        &self.top_passwords[..end]
    }

    pub fn weak_passwords_ratio(&self) -> f64 {
        if self.total_passwords == 0 {
            return 0.0;
        }
        self.entropy_estimates.weak_passwords as f64 / self.total_passwords as f64
    }
}

fn estimate_entropy(password: &str) -> f64 {
    let mut charset_size = 0u32;
    if password.chars().any(|c| c.is_lowercase()) {
        charset_size += 26;
    }
    if password.chars().any(|c| c.is_uppercase()) {
        charset_size += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        charset_size += 10;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        charset_size += 32;
    }
    if charset_size == 0 {
        return 0.0;
    }
    password.len() as f64 * (charset_size as f64).log2()
}

fn has_sequence(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 3 {
        return false;
    }
    for w in chars.windows(3) {
        let a = w[0] as u8;
        let b = w[1] as u8;
        let c = w[2] as u8;
        if (b as i16 - a as i16) == 1 && (c as i16 - b as i16) == 1 {
            return true;
        }
        if (a as i16 - b as i16) == 1 && (b as i16 - c as i16) == 1 {
            return true;
        }
    }
    false
}

fn has_repeated(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 3 {
        return false;
    }
    for w in chars.windows(3) {
        if w[0] == w[1] && w[1] == w[2] {
            return true;
        }
    }
    false
}

fn has_common_replacement(s: &str) -> bool {
    let replacements = ["@", "!", "3", "4", "0", "$", "1", "5"];
    replacements.iter().any(|&r| s.contains(r))
}

fn has_date_pattern(s: &str) -> bool {
    let years = ["19", "20"];
    years.iter().any(|&y| s.contains(y)) && s.chars().any(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty() {
        let stats = PasswordStats::analyze(&[]);
        assert_eq!(stats.total_passwords, 0);
    }

    #[test]
    fn test_analyze_single() {
        let stats = PasswordStats::analyze(&["password123".to_string()]);
        assert_eq!(stats.total_passwords, 1);
        assert_eq!(stats.unique_passwords, 1);
    }

    #[test]
    fn test_analyze_duplicates() {
        let pws = vec!["abc".to_string(), "abc".to_string(), "xyz".to_string()];
        let stats = PasswordStats::analyze(&pws);
        assert_eq!(stats.total_passwords, 3);
        assert_eq!(stats.unique_passwords, 2);
    }

    #[test]
    fn test_length_stats() {
        let stats = PasswordStats::analyze(&["a".to_string(), "bb".to_string(), "ccc".to_string()]);
        assert_eq!(stats.length_stats.min, 1);
        assert_eq!(stats.length_stats.max, 3);
        assert!((stats.length_stats.mean - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_char_stats() {
        let stats = PasswordStats::analyze(&[
            "ABC123!".to_string(),
            "lower".to_string(),
            "12345".to_string(),
        ]);
        assert_eq!(stats.char_stats.has_uppercase, 1);
        assert_eq!(stats.char_stats.has_lowercase, 1);
        assert_eq!(stats.char_stats.has_digit, 2);
        assert_eq!(stats.char_stats.only_digits, 1);
    }

    #[test]
    fn test_entropy_estimate() {
        let low = estimate_entropy("a");
        let high = estimate_entropy("Tr0ub4dor&3!");
        assert!(low < high);
    }

    #[test]
    fn test_top_passwords() {
        let pws = vec![
            "password".to_string(),
            "password".to_string(),
            "123456".to_string(),
        ];
        let stats = PasswordStats::analyze(&pws);
        assert!(!stats.top_passwords.is_empty());
        let top = stats.top_n(1);
        assert_eq!(top.len(), 1);
    }

    #[test]
    fn test_summary() {
        let stats = PasswordStats::analyze(&["Test123!".to_string()]);
        let s = stats.summary();
        assert!(s.contains("Passwords:"));
        assert!(s.contains("Entropy:"));
    }

    #[test]
    fn test_weak_ratio() {
        let stats = PasswordStats::analyze(&["a".to_string(), "Tr0ub4dor&3!".to_string()]);
        let ratio = stats.weak_passwords_ratio();
        assert!(ratio > 0.0);
    }

    #[test]
    fn test_sequence_detection() {
        assert!(has_sequence("abc"));
        assert!(has_sequence("xyz"));
        assert!(has_sequence("cba"));
        assert!(!has_sequence("qwerty"));
    }

    #[test]
    fn test_repeated_detection() {
        assert!(has_repeated("aaa"));
        assert!(has_repeated("111"));
        assert!(!has_repeated("abca"));
    }

    #[test]
    fn test_date_pattern() {
        assert!(has_date_pattern("password2024"));
        assert!(!has_date_pattern("password"));
    }

    #[test]
    fn test_pattern_matches() {
        let stats = PasswordStats::analyze(&[
            "abc123".to_string(),
            "password".to_string(),
            "111111".to_string(),
        ]);
        assert!(stats.pattern_matches.contains_key("sequences"));
        assert!(stats.pattern_matches.contains_key("repeated_chars"));
    }
}
