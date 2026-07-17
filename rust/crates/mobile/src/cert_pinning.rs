use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningReport {
    pub has_pinning: bool,
    pub implementation_type: String,
    pub pinned_domains: Vec<DomainPinning>,
    pub trust_manager: Option<String>,
    pub bypass_api: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPinning {
    pub domain: String,
    pub pins: Vec<String>,
    pub algorithm: String,
    pub expiration: Option<String>,
}

pub struct CertPinningChecker;

impl Default for CertPinningChecker {
    fn default() -> Self {
        CertPinningChecker
    }
}

impl CertPinningChecker {
    pub fn new() -> Self {
        CertPinningChecker
    }

    pub fn android_check(decompiled_source: &str) -> PinningReport {
        let mut pins = Vec::new();
        let mut has_pinning = false;
        let mut impl_type = "none".to_string();
        let mut trust_manager = None;
        let mut bypass_apis = Vec::new();

        if decompiled_source.contains("CertificatePinner") || decompiled_source.contains("certificatePinner") {
            has_pinning = true;
            impl_type = "OkHttp CertificatePinner".to_string();
            let domains = Self::extract_okhttp_pins(decompiled_source);
            pins.extend(domains);
        }

        if decompiled_source.contains("TrustManagerBuilder") || decompiled_source.contains("trustManager") {
            has_pinning = true;
            impl_type = "Custom TrustManager".to_string();
            trust_manager = Some("Custom TrustManager".to_string());
        }

        if decompiled_source.contains("NetworkSecurityPolicy")
            || decompiled_source.contains("network_security_config")
            || decompiled_source.contains("@xml/network_security_config") {
            has_pinning = true;
            impl_type = "Network Security Config".to_string();
        }

        if decompiled_source.contains("TrustKit") || decompiled_source.contains("trustkit") {
            has_pinning = true;
            impl_type = "TrustKit".to_string();
            trust_manager = Some("TrustKit".to_string());
        }

        let bypass_patterns = [
            "X509TrustManager",
            "checkClientTrusted",
            "checkServerTrusted",
            "onReceivedSslError",
            "proceed",
            "ALLOW_ALL_HOSTNAME_VERIFIER",
            "setHostnameVerifier",
            "NOP",
            "ALLOW_ALL",
        ];

        for pattern in &bypass_patterns {
            if decompiled_source.contains(pattern) {
                bypass_apis.push(pattern.to_string());
            }
        }

        let recommendations = Self::recommend(pins.is_empty() || !has_pinning, &bypass_apis);

        PinningReport {
            has_pinning,
            implementation_type: impl_type,
            pinned_domains: pins,
            trust_manager,
            bypass_api: bypass_apis,
            recommendations,
        }
    }

    pub fn ios_check(binary_strings: &str) -> PinningReport {
        let pins = Vec::new();
        let mut has_pinning = false;
        let mut impl_type = "none".to_string();
        let mut trust_manager = None;
        let mut bypass_apis = Vec::new();

        if binary_strings.contains("NSURLSession") && binary_strings.contains("challengeForProtectionSpace") {
            has_pinning = true;
            impl_type = "NSURLSessionDelegate".to_string();
        }

        if binary_strings.contains("AFSecurityPolicy") {
            has_pinning = true;
            impl_type = "AFNetworking AFSecurityPolicy".to_string();
        }

        if binary_strings.contains("TrustKit") {
            has_pinning = true;
            impl_type = "TrustKit (iOS)".to_string();
            trust_manager = Some("TrustKit".to_string());
        }

        if binary_strings.contains("SecTrustEvaluate") && binary_strings.contains("SecCertificateCreateWithData") {
            has_pinning = true;
            impl_type = "Security Framework (manual)".to_string();
        }

        let ios_bypass = [
            "didReceiveAuthenticationChallenge",
            "canAuthenticateAgainstProtectionSpace",
            "continueWithoutCredential",
            "useCredential",
            "kSecTrustResultUnspecified",
            "kSecTrustResultProceed",
        ];

        for pattern in &ios_bypass {
            if binary_strings.contains(pattern) {
                bypass_apis.push(pattern.to_string());
            }
        }

        let recommendations = Self::recommend(pins.is_empty() || !has_pinning, &bypass_apis);

        PinningReport {
            has_pinning,
            implementation_type: impl_type,
            pinned_domains: pins,
            trust_manager,
            bypass_api: bypass_apis,
            recommendations,
        }
    }

    fn extract_okhttp_pins(source: &str) -> Vec<DomainPinning> {
        let mut domains = Vec::new();
        let re = regex::Regex::new(r#"(?i)(certificatePinner|addCheck|\.add)\(.*?\"([a-z0-9.*-]+\.[a-z]{2,})\".*?\"(sha256|sha1)/([A-Fa-f0-9+/=]+)\""#).unwrap();
        for cap in re.captures_iter(source) {
            let domain = cap.get(2).map(|m| m.as_str()).unwrap_or("unknown").to_string();
            let hash = format!("{}/{}", cap.get(3).map(|m| m.as_str()).unwrap_or("sha256"), cap.get(4).map(|m| m.as_str()).unwrap_or(""));
            if let Some(existing) = domains.iter_mut().find(|d: &&mut DomainPinning| d.domain == domain) {
                existing.pins.push(hash);
            } else {
                domains.push(DomainPinning {
                    domain,
                    pins: vec![hash],
                    algorithm: "SHA-256".to_string(),
                    expiration: None,
                });
            }
        }
        domains
    }

    fn recommend(missing_pinning: bool, bypass_apis: &[String]) -> Vec<String> {
        let mut recs = Vec::new();
        if missing_pinning {
            recs.push("No certificate pinning detected — implement pinning to prevent MITM".to_string());
        }
        for api in bypass_apis {
            if api == "ALLOW_ALL_HOSTNAME_VERIFIER" || api == "ALLOW_ALL" || api == "NOP" {
                recs.push(format!("Dangerous: {} allows all certificates", api));
            } else {
                recs.push(format!("SSL bypass API detected: {}", api));
            }
        }
        recs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_no_pinning() {
        let report = CertPinningChecker::android_check("");
        assert!(!report.has_pinning);
    }

    #[test]
    fn test_android_okhttp_pinning() {
        let src = r#"
            CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();
        "#;
        let report = CertPinningChecker::android_check(src);
        assert!(report.has_pinning);
        assert_eq!(report.implementation_type, "OkHttp CertificatePinner");
    }

    #[test]
    fn test_android_trustkit() {
        let src = "TrustKit.initializeWithConfiguration";
        let report = CertPinningChecker::android_check(src);
        assert!(report.has_pinning);
    }

    #[test]
    fn test_android_bypass() {
        let src = "ALLOW_ALL_HOSTNAME_VERIFIER";
        let report = CertPinningChecker::android_check(src);
        assert!(report.bypass_api.contains(&"ALLOW_ALL_HOSTNAME_VERIFIER".to_string()));
    }

    #[test]
    fn test_ios_no_pinning() {
        let report = CertPinningChecker::ios_check("");
        assert!(!report.has_pinning);
    }

    #[test]
    fn test_ios_nsurlsession() {
        let src = "challengeForProtectionSpace NSURLSession";
        let report = CertPinningChecker::ios_check(src);
        assert!(report.has_pinning);
    }

    #[test]
    fn test_ios_bypass() {
        let src = "continueWithoutCredential";
        let report = CertPinningChecker::ios_check(src);
        assert!(report.bypass_api.contains(&"continueWithoutCredential".to_string()));
    }

    #[test]
    fn test_pinning_report_serde() {
        let report = CertPinningChecker::android_check("");
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("has_pinning"));
    }
}
