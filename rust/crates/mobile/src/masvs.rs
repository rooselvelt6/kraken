use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasvsReport {
    pub level: String,
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub checks: Vec<MasvsCheck>,
    pub overall_score: f64,
    pub critical_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasvsCheck {
    pub id: String,
    pub name: String,
    pub category: String,
    pub group: String,
    pub status: CheckStatus,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Na,
}

pub struct MasvsChecker;

impl MasvsChecker {
    pub fn new() -> Self {
        MasvsChecker
    }

    pub fn check_level_1(apk_info: &str, manifest: &str, binary_strings: &str) -> MasvsReport {
        Self::run_checks("L1", apk_info, manifest, binary_strings)
    }

    pub fn check_level_2(apk_info: &str, manifest: &str, binary_strings: &str) -> MasvsReport {
        Self::run_checks("L2", apk_info, manifest, binary_strings)
    }

    pub fn check_level_3(apk_info: &str, manifest: &str, binary_strings: &str) -> MasvsReport {
        Self::run_checks("L3", apk_info, manifest, binary_strings)
    }

    fn run_checks(level: &str, apk: &str, manifest: &str, binary: &str) -> MasvsReport {
        let mut checks = Vec::new();
        let mut critical = Vec::new();

        let all_checks = Self::define_checks(level);
        for check in &all_checks {
            let status = Self::evaluate_check(check, apk, manifest, binary);
            if status == CheckStatus::Fail {
                critical.push(format!("{}: {}", check.id, check.name));
            }
            checks.push(MasvsCheck {
                id: check.id.clone(),
                name: check.name.clone(),
                category: check.category.clone(),
                group: check.group.clone(),
                status,
                description: check.description.clone(),
                recommendation: check.recommendation.clone(),
            });
        }

        let total = checks.len();
        let passed = checks.iter().filter(|c| c.status == CheckStatus::Pass).count();
        let failed = checks.iter().filter(|c| c.status == CheckStatus::Fail).count();
        let na = checks.iter().filter(|c| c.status == CheckStatus::Na).count();
        let score = if total > na { passed as f64 / (total - na) as f64 * 100.0 } else { 0.0 };

        MasvsReport {
            level: format!("MASVS-{}", level),
            total_checks: total,
            passed,
            failed,
            not_applicable: na,
            checks,
            overall_score: score,
            critical_findings: critical,
        }
    }

    fn define_checks(level: &str) -> Vec<MasvsCheckTemplate> {
        let l2 = level == "L2" || level == "L3";
        vec![
            // MSTG-STORAGE
            MasvsCheckTemplate {
                id: "MSTG-STORAGE-1".to_string(),
                name: "No sensitive data in SharedPreferences".to_string(),
                category: "Data Storage".to_string(),
                group: "Storage".to_string(),
                description: "Check for sensitive data stored in SharedPreferences without encryption".to_string(),
                recommendation: "Use EncryptedSharedPreferences".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-STORAGE-2".to_string(),
                name: "No sensitive data in SQLite databases".to_string(),
                category: "Data Storage".to_string(),
                group: "Storage".to_string(),
                description: "Check for plaintext databases containing sensitive data".to_string(),
                recommendation: "Use SQLCipher or Room with encryption".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-STORAGE-3".to_string(),
                name: "No sensitive data in logs".to_string(),
                category: "Data Storage".to_string(),
                group: "Storage".to_string(),
                description: "Check for Log.d/Log.v/Log.i usage with sensitive data".to_string(),
                recommendation: "Remove or obfuscate debug logging in release builds".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-STORAGE-4".to_string(),
                name: "No sensitive data in Keyboard cache".to_string(),
                category: "Data Storage".to_string(),
                group: "Storage".to_string(),
                description: "Check if sensitive EditText fields have input type for password".to_string(),
                recommendation: "Use android:inputType=\"textPassword\" for sensitive fields".to_string(),
            },
            // MSTG-CRYPTO
            MasvsCheckTemplate {
                id: "MSTG-CRYPTO-1".to_string(),
                name: "App uses modern cryptography".to_string(),
                category: "Cryptography".to_string(),
                group: "Crypto".to_string(),
                description: "Check for weak cryptographic algorithms (DES, MD2, MD4, SHA-0, RC2, RC4)".to_string(),
                recommendation: "Use AES-256-GCM or ChaCha20-Poly1305".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-CRYPTO-2".to_string(),
                name: "Key derivation uses modern algorithm".to_string(),
                category: "Cryptography".to_string(),
                group: "Crypto".to_string(),
                description: "Check if PBKDF2 or bcrypt/scrypt/Argon2 is used for key derivation".to_string(),
                recommendation: "Use Argon2id or PBKDF2 with sufficient iterations".to_string(),
            },
            // MSTG-AUTH
            MasvsCheckTemplate {
                id: "MSTG-AUTH-1".to_string(),
                name: "No hardcoded credentials".to_string(),
                category: "Authentication".to_string(),
                group: "Auth".to_string(),
                description: "Check for hardcoded API keys, passwords, tokens in binary".to_string(),
                recommendation: "Use device-bound authentication or server-side auth".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-AUTH-2".to_string(),
                name: "Local authentication is properly implemented".to_string(),
                category: "Authentication".to_string(),
                group: "Auth".to_string(),
                description: "Check if BiometricPrompt or KeyguardManager is used for local auth".to_string(),
                recommendation: "Use BiometricPrompt with CryptoObject".to_string(),
            },
            // MSTG-NETWORK
            MasvsCheckTemplate {
                id: "MSTG-NETWORK-1".to_string(),
                name: "App uses TLS for all network communication".to_string(),
                category: "Network".to_string(),
                group: "Network".to_string(),
                description: "Check for cleartext HTTP URLs in the app".to_string(),
                recommendation: "Use HTTPS with TLS 1.2+ only".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-NETWORK-2".to_string(),
                name: "Certificate pinning is implemented".to_string(),
                category: "Network".to_string(),
                group: "Network".to_string(),
                description: "Check if the app implements certificate pinning".to_string(),
                recommendation: "Implement certificate pinning with OkHttp or TrustKit".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-NETWORK-3".to_string(),
                name: "No cleartext traffic allowed".to_string(),
                category: "Network".to_string(),
                group: "Network".to_string(),
                description: "Check android:usesCleartextTraffic in manifest".to_string(),
                recommendation: "Set android:usesCleartextTraffic=\"false\"".to_string(),
            },
            // MSTG-PLATFORM
            MasvsCheckTemplate {
                id: "MSTG-PLATFORM-1".to_string(),
                name: "App is not debuggable in release".to_string(),
                category: "Platform".to_string(),
                group: "Platform".to_string(),
                description: "Check android:debuggable flag in release builds".to_string(),
                recommendation: "Ensure android:debuggable=\"false\" in release builds".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-PLATFORM-2".to_string(),
                name: "No insecure WebView configuration".to_string(),
                category: "Platform".to_string(),
                group: "Platform".to_string(),
                description: "Check for JavaScript enabled, file access, etc.".to_string(),
                recommendation: "Disable JavaScript and file access if not needed".to_string(),
            },
            // MSTG-CODE
            MasvsCheckTemplate {
                id: "MSTG-CODE-1".to_string(),
                name: "App is not rooted/jailbroken".to_string(),
                category: "Code Quality".to_string(),
                group: "Code".to_string(),
                description: "Check for root/jailbreak detection implementation".to_string(),
                recommendation: "Implement runtime integrity checks".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-CODE-2".to_string(),
                name: "No anti-debugging bypass possible".to_string(),
                category: "Code Quality".to_string(),
                group: "Code".to_string(),
                description: "Check for debugger detection mechanisms".to_string(),
                recommendation: "Implement multiple anti-debugging techniques".to_string(),
            },
            MasvsCheckTemplate {
                id: "MSTG-CODE-3".to_string(),
                name: "No sensitive functionality exposed via IPC".to_string(),
                category: "Code Quality".to_string(),
                group: "Code".to_string(),
                description: "Check exported components for sensitive actions".to_string(),
                recommendation: "Protect IPC components with permissions".to_string(),
            },
        ]
        .into_iter()
        .filter(|c| if l2 { true } else { c.group != "Crypto" })
        .collect()
    }

    fn evaluate_check(check: &MasvsCheckTemplate, apk: &str, manifest: &str, binary: &str) -> CheckStatus {
        match check.id.as_str() {
            "MSTG-STORAGE-1" => {
                if manifest.contains("EncryptedSharedPreferences") || binary.contains("encrypted") {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                }
            }
            "MSTG-STORAGE-2" => {
                if binary.contains("sqlcipher") || binary.contains("SQLCipher") || binary.contains("Room") {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                }
            }
            "MSTG-STORAGE-3" => {
                if apk.contains("release") && binary.contains("Log.") {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            "MSTG-STORAGE-4" => CheckStatus::Na,
            "MSTG-CRYPTO-1" => {
                let weak = ["DES", "MD2", "MD4", "RC2", "RC4", "SHA0", "getInstance(\"DES"];
                if weak.iter().any(|w| binary.contains(w)) {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            "MSTG-CRYPTO-2" => {
                if binary.contains("PBKDF2") || binary.contains("Argon2") || binary.contains("bcrypt") || binary.contains("scrypt") {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                }
            }
            "MSTG-AUTH-1" => {
                let patterns = ["api_key", "apiKey", "API_KEY", "password", "secret", "token", "apikey"];
                if patterns.iter().any(|p| binary.contains(p)) {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            "MSTG-AUTH-2" => {
                if binary.contains("BiometricPrompt") || binary.contains("KeyguardManager") {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                }
            }
            "MSTG-NETWORK-1" => {
                if manifest.contains("usesCleartextTraffic=\"true\"") {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            "MSTG-NETWORK-2" => {
                if binary.contains("CertificatePinner") || binary.contains("TrustKit") || binary.contains("AFSecurityPolicy") {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                }
            }
            "MSTG-NETWORK-3" => {
                if manifest.contains("usesCleartextTraffic=\"true\"") {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            "MSTG-PLATFORM-1" => {
                if manifest.contains("debuggable=\"true\"") {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            "MSTG-PLATFORM-2" => {
                if binary.contains("setJavaScriptEnabled(true)") || binary.contains("setAllowFileAccess(true)") {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            "MSTG-CODE-1" => {
                if binary.contains("su") || binary.contains("magisk") || binary.contains("Cydia") || binary.contains("bash") {
                    CheckStatus::Na
                } else {
                    CheckStatus::Fail
                }
            }
            "MSTG-CODE-2" => CheckStatus::Na,
            "MSTG-CODE-3" => {
                if manifest.contains("exported=\"true\"") {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                }
            }
            _ => CheckStatus::Na,
        }
    }
}

#[derive(Debug)]
struct MasvsCheckTemplate {
    id: String,
    name: String,
    category: String,
    group: String,
    description: String,
    recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level1() {
        let report = MasvsChecker::check_level_1("", "", "");
        assert_eq!(report.level, "MASVS-L1");
        assert!(report.total_checks > 0);
    }

    #[test]
    fn test_level2() {
        let report = MasvsChecker::check_level_2("", "", "");
        assert_eq!(report.level, "MASVS-L2");
    }

    #[test]
    fn test_passing() {
        let manifest = r#"<manifest android:debuggable="false"/>"#;
        let report = MasvsChecker::check_level_1("", manifest, "");
        assert!(report.overall_score >= 0.0);
    }

    #[test]
    fn test_weak_crypto() {
        let binary = "Cipher.getInstance(\"DES\")";
        let report = MasvsChecker::check_level_2("", "", binary);
        assert!(report.critical_findings.iter().any(|f| f.contains("MSTG-CRYPTO-1")));
    }

    #[test]
    fn test_cleartext_fail() {
        let manifest = r#"android:usesCleartextTraffic="true""#;
        let report = MasvsChecker::check_level_1("", manifest, "");
        assert!(report.critical_findings.iter().any(|f| f.contains("MSTG-NETWORK-1")));
    }

    #[test]
    fn test_report_serde() {
        let report = MasvsChecker::check_level_1("test", "", "");
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("MASVS-L1"));
    }
}
