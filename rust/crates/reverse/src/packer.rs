use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerSignature {
    pub name: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerDetection {
    pub detected: bool,
    pub packers: Vec<PackerSignature>,
    pub entropy_score: f64,
    pub section_anomalies: Vec<String>,
}

pub struct PackerDetector;

impl PackerDetector {
    pub fn detect(data: &[u8]) -> PackerDetection {
        let mut packers = Vec::new();
        let mut anomalies = Vec::new();

        if let Some(name) = Self::check_upx(data) {
            packers.push(PackerSignature {
                name,
                description: "UPX executable packer".to_string(),
                severity: "low".to_string(),
            });
        }

        if Self::check_vmprotect(data) {
            packers.push(PackerSignature {
                name: "VMProtect".to_string(),
                description: "VMProtect software protection".to_string(),
                severity: "high".to_string(),
            });
        }

        if Self::check_themida(data) {
            packers.push(PackerSignature {
                name: "Themida".to_string(),
                description: "Themida/WinLicense code obfuscation".to_string(),
                severity: "high".to_string(),
            });
        }

        if Self::check_aspack(data) {
            packers.push(PackerSignature {
                name: "ASPack".to_string(),
                description: "ASPack executable compressor".to_string(),
                severity: "low".to_string(),
            });
        }

        if Self::check_mpress(data) {
            packers.push(PackerSignature {
                name: "MPRESS".to_string(),
                description: "MPRESS executable compressor".to_string(),
                severity: "low".to_string(),
            });
        }

        if Self::check_armadillo(data) {
            packers.push(PackerSignature {
                name: "Armadillo".to_string(),
                description: "Armadillo software protection".to_string(),
                severity: "medium".to_string(),
            });
        }

        if Self::check_enigma(data) {
            packers.push(PackerSignature {
                name: "Enigma Protector".to_string(),
                description: "Enigma software protection system".to_string(),
                severity: "medium".to_string(),
            });
        }

        if Self::check_confuser(data) {
            packers.push(PackerSignature {
                name: "ConfuserEx".to_string(),
                description: ".NET obfuscator".to_string(),
                severity: "medium".to_string(),
            });
        }

        if data.len() > 4 {
            let entropy = crate::entropy::compute_entropy(data);
            if entropy > 7.5 {
                anomalies.push(format!("High overall entropy ({:.4})", entropy));
            }

            if let Ok(text) = std::str::from_utf8(&data[..data.len().min(1024)]) {
                if !text.contains("GetProcAddress") && !text.contains("LoadLibrary") {
                    anomalies.push("No import resolution code found in first 1KB".to_string());
                }
            }

            let section_count = Self::count_sections(data);
            if section_count > 10 {
                anomalies.push(format!("Unusual number of sections ({})", section_count));
            }
        }

        let detected = !packers.is_empty();

        PackerDetection {
            detected,
            packers,
            entropy_score: if data.is_empty() { 0.0 } else { crate::entropy::compute_entropy(data) },
            section_anomalies: anomalies,
        }
    }

    fn check_upx(data: &[u8]) -> Option<String> {
        if let Ok(text) = std::str::from_utf8(data) {
            for section in &["UPX!", "UPX0", "UPX1", "UPX2"] {
                if text.contains(section) {
                    return Some("UPX".to_string());
                }
            }
        }
        None
    }

    fn check_vmprotect(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            text.contains("VMPROTECT")
                || text.contains("VMProtect")
                || text.contains(".vmp0")
                || text.contains(".vmp1")
        } else {
            false
        }
    }

    fn check_themida(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            text.contains("Themida")
                || text.contains("WinLicense")
                || text.contains(".themida")
        } else {
            false
        }
    }

    fn check_aspack(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            text.contains("ASPack")
                || text.contains(".aspack")
                || text.contains("aspack!")
        } else {
            false
        }
    }

    fn check_mpress(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            text.contains("MPRESS")
                || text.contains("MPRESS1")
                || text.contains("MPRESS2")
        } else {
            false
        }
    }

    fn check_armadillo(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            text.contains("Armadillo")
                || text.contains("CIPHER")
                || text.contains("ARM protector")
        } else {
            false
        }
    }

    fn check_enigma(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            text.contains("Enigma")
                && (text.contains("protector") || text.contains("Protector"))
        } else {
            false
        }
    }

    fn check_confuser(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            text.contains("Confuser")
                || text.contains("ConfuserEx")
        } else {
            false
        }
    }

    fn count_sections(data: &[u8]) -> usize {
        if data.len() < 64 { return 0; }
        if data[0] == 0x4d && data[1] == 0x5a {
            if let Ok(text) = std::str::from_utf8(data) {
                return text.matches(".text")
                    .chain(text.matches(".data"))
                    .chain(text.matches(".rdata"))
                    .chain(text.matches(".rsrc"))
                    .chain(text.matches(".reloc"))
                    .chain(text.matches(".bss"))
                    .chain(text.matches(".idata"))
                    .chain(text.matches(".edata"))
                    .chain(text.matches(".tls"))
                    .chain(text.matches(".pdata"))
                    .chain(text.matches(".xdata"))
                    .chain(text.matches(".gfids"))
                    .chain(text.matches(".sxdata"))
                    .chain(text.matches(".cormeta"))
                    .count();
            }
        }
        0
    }
}

pub fn format_packer_detection(detection: &PackerDetection) -> String {
    let mut out = "Packer Detection\n".to_string();
    out.push_str(&format!("Packed: {}\n", if detection.detected { "YES" } else { "NO" }));
    out.push_str(&format!("Entropy: {:.4}\n", detection.entropy_score));

    if !detection.packers.is_empty() {
        out.push_str(&format!("\nDetected Packers ({})", detection.packers.len()));
        for p in &detection.packers {
            out.push_str(&format!("\n  - {} ({}): {}", p.name, p.severity, p.description));
        }
        out.push('\n');
    }

    if !detection.section_anomalies.is_empty() {
        out.push_str("\nAnomalies:\n");
        for a in &detection.section_anomalies {
            out.push_str(&format!("  - {}\n", a));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_upx() {
        let data = b"some data with UPX! marker";
        let result = PackerDetector::check_upx(data);
        assert_eq!(result, Some("UPX".to_string()));
    }

    #[test]
    fn test_check_vmprotect() {
        let data = b"binary with VMProtect protection";
        assert!(PackerDetector::check_vmprotect(data));
        assert!(!PackerDetector::check_vmprotect(b"clean binary"));
    }

    #[test]
    fn test_check_themida() {
        let data = b"Themida protected binary";
        assert!(PackerDetector::check_themida(data));
    }

    #[test]
    fn test_detect_no_packer() {
        let data = b"clean normal executable binary code";
        let result = PackerDetector::detect(data);
        assert!(!result.detected);
    }

    #[test]
    fn test_detect_upx() {
        let data = b"UPX! packed binary data here";
        let result = PackerDetector::detect(data);
        assert!(result.detected);
        assert!(result.packers.iter().any(|p| p.name == "UPX"));
    }

    #[test]
    fn test_packer_signature() {
        let sig = PackerSignature {
            name: "UPX".to_string(),
            description: "UPX packer".to_string(),
            severity: "low".to_string(),
        };
        assert_eq!(sig.name, "UPX");
        assert_eq!(sig.severity, "low");
    }

    #[test]
    fn test_packer_detection_format() {
        let detection = PackerDetection {
            detected: true,
            packers: vec![PackerSignature {
                name: "UPX".to_string(),
                description: "UPX packer".to_string(),
                severity: "low".to_string(),
            }],
            entropy_score: 6.5,
            section_anomalies: vec![],
        };
        let formatted = format_packer_detection(&detection);
        assert!(formatted.contains("YES"));
        assert!(formatted.contains("UPX"));
    }

    #[test]
    fn test_anomalies_detection() {
        let detection = PackerDetection {
            detected: false,
            packers: vec![],
            entropy_score: 7.8,
            section_anomalies: vec!["High overall entropy (7.8000)".to_string()],
        };
        assert!(!detection.detected);
        assert_eq!(detection.section_anomalies.len(), 1);
    }

    #[test]
    fn test_empty_data() {
        let result = PackerDetector::detect(b"");
        assert!(!result.detected);
        assert_eq!(result.entropy_score, 0.0);
    }

    #[test]
    fn test_check_aspack() {
        assert!(PackerDetector::check_aspack(b"binary with ASPack protection"));
        assert!(!PackerDetector::check_aspack(b"clean binary"));
    }

    #[test]
    fn test_check_mpress() {
        assert!(PackerDetector::check_mpress(b"binary with MPRESS1 section"));
        assert!(!PackerDetector::check_mpress(b"clean binary"));
    }

    #[test]
    fn test_check_armadillo() {
        assert!(PackerDetector::check_armadillo(b"binary with Armadillo protection"));
        assert!(!PackerDetector::check_armadillo(b"clean binary"));
    }

    #[test]
    fn test_check_enigma() {
        assert!(PackerDetector::check_enigma(b"Enigma Protector software"));
        assert!(PackerDetector::check_enigma(b"Enigma without protector"));
        assert!(!PackerDetector::check_enigma(b"clean binary"));
    }

    #[test]
    fn test_check_confuser() {
        assert!(PackerDetector::check_confuser(b"ConfuserEx obfuscator"));
        assert!(PackerDetector::check_confuser(b"Confuser tool"));
        assert!(!PackerDetector::check_confuser(b"clean binary"));
    }

    #[test]
    fn test_check_upx_variants() {
        assert_eq!(PackerDetector::check_upx(b"UPX0 section"), Some("UPX".to_string()));
        assert_eq!(PackerDetector::check_upx(b"UPX1 section"), Some("UPX".to_string()));
        assert_eq!(PackerDetector::check_upx(b"UPX2 section"), Some("UPX".to_string()));
        assert_eq!(PackerDetector::check_upx(b"clean binary"), None);
    }

    #[test]
    fn test_check_vmprotect_variants() {
        assert!(PackerDetector::check_vmprotect(b".vmp0 section"));
        assert!(PackerDetector::check_vmprotect(b".vmp1 section"));
        assert!(PackerDetector::check_vmprotect(b"VMPROTECT"));
    }

    #[test]
    fn test_check_themida_variants() {
        assert!(PackerDetector::check_themida(b"Themida protection"));
        assert!(PackerDetector::check_themida(b"WinLicense"));
        assert!(PackerDetector::check_themida(b".themida"));
    }

    #[test]
    fn test_detect_aspack() {
        let result = PackerDetector::detect(b"binary with ASPack packed data");
        assert!(result.detected);
        assert!(result.packers.iter().any(|p| p.name == "ASPack"));
    }

    #[test]
    fn test_detect_mpress() {
        let result = PackerDetector::detect(b"binary with MPRESS2 section here");
        assert!(result.detected);
        assert!(result.packers.iter().any(|p| p.name == "MPRESS"));
    }

    #[test]
    fn test_detect_armadillo() {
        let result = PackerDetector::detect(b"binary with Armadillo protection");
        assert!(result.detected);
        assert!(result.packers.iter().any(|p| p.name == "Armadillo"));
    }

    #[test]
    fn test_detect_vmprotect() {
        let result = PackerDetector::detect(b"VMProtect protected binary");
        assert!(result.detected);
        assert!(result.packers.iter().any(|p| p.name == "VMProtect"));
    }

    #[test]
    fn test_detect_themida() {
        let result = PackerDetector::detect(b"Themida protected binary");
        assert!(result.detected);
        assert!(result.packers.iter().any(|p| p.name == "Themida"));
    }

    #[test]
    fn test_detect_confuserex() {
        let result = PackerDetector::detect(b"ConfuserEx obfuscated .net");
        assert!(result.detected);
        assert!(result.packers.iter().any(|p| p.name == "ConfuserEx"));
    }

    #[test]
    fn test_packer_detection_format_no_packer() {
        let detection = PackerDetection {
            detected: false,
            packers: vec![],
            entropy_score: 4.0,
            section_anomalies: vec![],
        };
        let formatted = format_packer_detection(&detection);
        assert!(formatted.contains("NO"));
        assert!(!formatted.contains("Detected Packers"));
    }

    #[test]
    fn test_packer_detection_format_with_anomalies() {
        let detection = PackerDetection {
            detected: false,
            packers: vec![],
            entropy_score: 7.9,
            section_anomalies: vec!["High overall entropy (7.9000)".to_string()],
        };
        let formatted = format_packer_detection(&detection);
        assert!(formatted.contains("Anomalies"));
        assert!(formatted.contains("High overall entropy"));
    }

    #[test]
    fn test_packer_detection_format_multiple_packers() {
        let detection = PackerDetection {
            detected: true,
            packers: vec![
                PackerSignature {
                    name: "UPX".to_string(),
                    description: "UPX packer".to_string(),
                    severity: "low".to_string(),
                },
                PackerSignature {
                    name: "VMProtect".to_string(),
                    description: "VMProtect".to_string(),
                    severity: "high".to_string(),
                },
            ],
            entropy_score: 7.0,
            section_anomalies: vec![],
        };
        let formatted = format_packer_detection(&detection);
        assert!(formatted.contains("2"));
        assert!(formatted.contains("UPX"));
        assert!(formatted.contains("VMProtect"));
    }

    #[test]
    fn test_packer_signature_severity_levels() {
        let low = PackerSignature {
            name: "A".to_string(),
            description: "A".to_string(),
            severity: "low".to_string(),
        };
        let medium = PackerSignature {
            name: "B".to_string(),
            description: "B".to_string(),
            severity: "medium".to_string(),
        };
        let high = PackerSignature {
            name: "C".to_string(),
            description: "C".to_string(),
            severity: "high".to_string(),
        };
        assert_eq!(low.severity, "low");
        assert_eq!(medium.severity, "medium");
        assert_eq!(high.severity, "high");
    }
}
