use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatResult {
    pub package: String,
    pub matches: Vec<TyposquatMatch>,
    pub risk_level: String,
    pub total_suspicious: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatMatch {
    pub suspicious_name: String,
    pub similarity: f64,
    pub technique: String,
    pub known_malicious: bool,
}

pub struct TyposquatDetector;

impl Default for TyposquatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TyposquatDetector {
    pub fn new() -> Self {
        TyposquatDetector
    }

    /// Checks a package name for typosquatting patterns.
    ///
    /// # Examples
    ///
    /// ```
    /// use supplychain::TyposquatDetector;
    ///
    /// let result = TyposquatDetector::check("serde");
    /// assert_eq!(result.package, "serde");
    /// assert!(result.risk_level == "LOW" || result.risk_level == "MEDIUM");
    /// ```
    pub fn check(name: &str) -> TyposquatResult {
        let mut matches = Vec::new();

        matches.extend(Self::check_typosquatting(name));
        matches.extend(Self::check_homograph(name));
        matches.extend(Self::check_combosquatting(name));
        matches.extend(Self::check_prefix_suffix(name));

        matches.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));
        matches.dedup_by(|a, b| a.suspicious_name == b.suspicious_name);

        let high_risk = matches.iter().any(|m| m.similarity > 0.8);
        let risk_level = if high_risk {
            "HIGH".to_string()
        } else if matches.len() >= 3 {
            "MEDIUM".to_string()
        } else if matches.is_empty() {
            "LOW".to_string()
        } else {
            "MEDIUM".to_string()
        };

        let total = matches.len();
        TyposquatResult {
            package: name.to_string(),
            matches,
            risk_level,
            total_suspicious: total,
        }
    }

    fn check_typosquatting(name: &str) -> Vec<TyposquatMatch> {
        let mut results = Vec::new();
        let known = Self::known_packages();

        for kp in &known {
            let dist = levenshtein_distance(name, kp);
            if dist > 0 && dist as f64 / kp.len().max(name.len()) as f64 <= 0.3 {
                let sim = 1.0 - dist as f64 / kp.len().max(name.len()) as f64;
                results.push(TyposquatMatch {
                    suspicious_name: kp.to_string(),
                    similarity: sim,
                    technique: "typosquatting".to_string(),
                    known_malicious: false,
                });
            }
        }
        results
    }

    fn check_homograph(name: &str) -> Vec<TyposquatMatch> {
        let mut results = Vec::new();
        let homoglyphs = [
            ('a', vec!['а', 'à', 'á', 'â', 'ã', 'ä']),
            ('e', vec!['е', 'è', 'é', 'ê', 'ë']),
            ('i', vec!['і', 'ì', 'í', 'î', 'ï']),
            ('o', vec!['о', 'ò', 'ó', 'ô', 'õ', 'ö']),
            ('u', vec!['ù', 'ú', 'û', 'ü']),
            ('c', vec!['с', 'ç']),
            ('p', vec!['р']),
            ('s', vec!['ѕ']),
        ];

        let has_homograph = name.chars().any(|c| {
            homoglyphs.iter().any(|(_, glyphs)| glyphs.contains(&c))
        });

        if has_homograph {
            let normalized: String = name.chars().map(|c| {
                for (ascii, glyphs) in &homoglyphs {
                    if glyphs.contains(&c) {
                        return *ascii;
                    }
                }
                c
            }).collect();

            if normalized != name {
                if let Some(known_name) = Self::known_packages().iter().find(|kp| **kp == normalized) {
                    results.push(TyposquatMatch {
                        suspicious_name: known_name.clone(),
                        similarity: 0.95,
                        technique: "homograph".to_string(),
                        known_malicious: true,
                    });
                }
            }
        }
        results
    }

    fn check_combosquatting(name: &str) -> Vec<TyposquatMatch> {
        let mut results = Vec::new();
        if name.len() > 15 {
            return results;
        }
        let prefixes = ["dev", "test", "prod", "safe", "secure", "new", "old", "lib", "tmp"];
        let suffixes = ["dev", "test", "prod", "safe", "secure", "lib", "api", "core", "helper", "util"];

        for prefix in &prefixes {
            let combined = format!("{}-{}", prefix, name);
            let sim = name.len() as f64 / combined.len().max(1) as f64;
            if sim > 0.5 {
                results.push(TyposquatMatch {
                    suspicious_name: combined,
                    similarity: sim,
                    technique: "combosquatting (prefix)".to_string(),
                    known_malicious: false,
                });
            }
        }

        for suffix in &suffixes {
            let combined = format!("{}-{}", name, suffix);
            let sim = name.len() as f64 / combined.len().max(1) as f64;
            if sim > 0.5 {
                results.push(TyposquatMatch {
                    suspicious_name: combined,
                    similarity: sim,
                    technique: "combosquatting (suffix)".to_string(),
                    known_malicious: false,
                });
            }
        }
        results
    }

    fn check_prefix_suffix(name: &str) -> Vec<TyposquatMatch> {
        let mut results = Vec::new();
        let known = Self::known_packages();

        for kp in &known {
            if name.starts_with(kp) && name.len() > kp.len() {
                let sim = kp.len() as f64 / name.len() as f64;
                results.push(TyposquatMatch {
                    suspicious_name: kp.clone(),
                    similarity: sim,
                    technique: "dependency confusion (prefix)".to_string(),
                    known_malicious: false,
                });
            } else if kp.starts_with(name) && kp.len() > name.len() {
                let sim = name.len() as f64 / kp.len() as f64;
                results.push(TyposquatMatch {
                    suspicious_name: kp.clone(),
                    similarity: sim,
                    technique: "dependency confusion (substring)".to_string(),
                    known_malicious: false,
                });
            }
        }
        results
    }

    fn known_packages() -> Vec<String> {
        vec![
            "openssl".to_string(),
            "serde".to_string(),
            "reqwest".to_string(),
            "tokio".to_string(),
            "axum".to_string(),
            "actix-web".to_string(),
            "log4j".to_string(),
            "lodash".to_string(),
            "express".to_string(),
            "bootstrap".to_string(),
            "jquery".to_string(),
            "moment".to_string(),
            "react".to_string(),
            "angular".to_string(),
            "vue".to_string(),
            "guzzle".to_string(),
            "requests".to_string(),
        ]
    }
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];

    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, val) in dp[0].iter_mut().enumerate() {
        *val = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[m][n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typosquatting() {
        let result = TyposquatDetector::check("reqwuest");
        assert!(result.total_suspicious > 0);
    }

    #[test]
    fn test_no_match() {
        let result = TyposquatDetector::check("completely-unique-package-xyz");
        assert_eq!(result.total_suspicious, 0);
    }

    #[test]
    fn test_combosquatting() {
        let result = TyposquatDetector::check("serde");
        let combos = result.matches.iter().filter(|m| m.technique.contains("combosquatting")).count();
        assert!(combos > 0);
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein_distance("reqwest", "reqwuest"), 1);
        assert_eq!(levenshtein_distance("same", "same"), 0);
        assert_eq!(levenshtein_distance("abc", "xyz"), 3);
    }

    #[test]
    fn test_risk_high() {
        let result = TyposquatDetector::check("reqwuest");
        assert_eq!(result.risk_level, "HIGH");
    }

    #[test]
    fn test_typosquat_serde() {
        let result = TyposquatDetector::check("test");
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("risk_level"));
    }

    #[test]
    fn test_levenshtein_empty_strings() {
        assert_eq!(levenshtein_distance("", ""), 0);
    }

    #[test]
    fn test_levenshtein_one_empty() {
        assert_eq!(levenshtein_distance("abc", ""), 3);
        assert_eq!(levenshtein_distance("", "abc"), 3);
    }

    #[test]
    fn test_levenshtein_single_char_diff() {
        assert_eq!(levenshtein_distance("abc", "axc"), 1);
    }

    #[test]
    fn test_risk_level_low_for_unique() {
        let result = TyposquatDetector::check("zzz-unique-abc-123");
        assert_eq!(result.risk_level, "LOW");
    }

    #[test]
    fn test_typosquat_result_struct() {
        let result = TyposquatDetector::check("test");
        assert_eq!(result.package, "test");
        assert!(result.total_suspicious >= 0);
    }

    #[test]
    fn test_typosquat_match_struct() {
        let m = TyposquatMatch {
            suspicious_name: "serde".to_string(),
            similarity: 0.9,
            technique: "typosquatting".to_string(),
            known_malicious: false,
        };
        assert_eq!(m.similarity, 0.9);
        assert!(!m.known_malicious);
    }

    #[test]
    fn test_typosquat_homograph_detection() {
        let result = TyposquatDetector::check("sеrde");
        let homographs = result.matches.iter().filter(|m| m.technique == "homograph").count();
        assert!(homographs > 0);
    }

    #[test]
    fn test_typosquat_combosquatting_long_name() {
        let result = TyposquatDetector::check("a-very-long-package-name-here");
        let combos = result.matches.iter().filter(|m| m.technique.contains("combosquatting")).count();
        assert_eq!(combos, 0);
    }

    #[test]
    fn test_typosquat_prefix_suffix() {
        let result = TyposquatDetector::check("opensslabc");
        let prefix_suffix = result.matches.iter().filter(|m| m.technique.contains("dependency confusion") || m.technique.contains("typosquatting")).count();
        assert!(prefix_suffix > 0);
    }

    #[test]
    fn test_typosquat_detector_default() {
        let detector = TyposquatDetector::default();
        let result = TyposquatDetector::check("test");
        assert!(result.total_suspicious >= 0);
    }

    #[test]
    fn test_typosquat_risk_medium() {
        let result = TyposquatDetector::check("serde-dev-test");
        assert!(result.risk_level == "MEDIUM" || result.risk_level == "HIGH");
    }
}
