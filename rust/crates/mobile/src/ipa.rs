use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaInfo {
    pub bundle_id: String,
    pub version: String,
    pub build: String,
    pub name: String,
    pub min_os: String,
    pub executable: String,
    pub entitlements: Vec<String>,
    pub frameworks: Vec<String>,
    pub capabilities: Vec<String>,
    pub has_bitcode: bool,
    pub has_push_notifications: bool,
    pub uses_encryption: bool,
    pub architectures: Vec<String>,
    pub device_family: Vec<String>,
    pub supported_orientations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub key: String,
    pub value: String,
    pub dangerous: bool,
}

pub struct IpaAnalyzer;

impl Default for IpaAnalyzer {
    fn default() -> Self {
        IpaAnalyzer
    }
}

impl IpaAnalyzer {
    pub fn new() -> Self {
        IpaAnalyzer
    }

    pub fn analyze(data: &[u8]) -> Result<IpaInfo, String> {
        if data.len() < 4 {
            return Err("Invalid IPA: too small".to_string());
        }
        if data[0..4] != [0x50, 0x4b, 0x03, 0x04] {
            return Err("Invalid IPA: missing ZIP magic".to_string());
        }

        let content = String::from_utf8_lossy(data);
        let plist = Self::extract_info_plist(data);

        let bundle_id = Self::extract_plist_value(&plist, "CFBundleIdentifier").unwrap_or_else(|| "unknown".to_string());
        let version = Self::extract_plist_value(&plist, "CFBundleShortVersionString").unwrap_or_else(|| "0.0".to_string());
        let build = Self::extract_plist_value(&plist, "CFBundleVersion").unwrap_or_else(|| "0".to_string());
        let name = Self::extract_plist_value(&plist, "CFBundleDisplayName")
            .or_else(|| Self::extract_plist_value(&plist, "CFBundleName"))
            .unwrap_or_else(|| "unknown".to_string());
        let min_os = Self::extract_plist_value(&plist, "MinimumOSVersion").unwrap_or_else(|| "0.0".to_string());
        let executable = Self::extract_plist_value(&plist, "CFBundleExecutable").unwrap_or_else(|| "unknown".to_string());

        let entitlements = Self::extract_entitlements(&plist);
        let capabilities = Self::extract_capabilities(data, &plist);
        let frameworks = Self::find_frameworks(data);

        let has_bitcode = content.contains("__bitcode") || content.contains("LLVM");
        let has_push = entitlements.iter().any(|e| e.contains("push") || e.contains("aps-environment"));
        let uses_encryption = plist.contains("ITSEncryption") || plist.contains("NSAppTransportSecurity");
        let architectures = Self::detect_architectures(data);
        let device_family = Self::extract_device_family(&plist);
        let supported_orientations = Self::extract_orientations(&plist);

        Ok(IpaInfo {
            bundle_id,
            version,
            build,
            name,
            min_os,
            executable,
            entitlements,
            frameworks,
            capabilities,
            has_bitcode,
            has_push_notifications: has_push,
            uses_encryption,
            architectures,
            device_family,
            supported_orientations,
        })
    }

    fn extract_info_plist(data: &[u8]) -> String {
        let content = String::from_utf8_lossy(data);
        if let Some(start) = content.find("<?xml version=\"1.0\"") {
            let search = "<plist";
            if let Some(pstart) = content[start..].find(search) {
                let abs = start + pstart;
                if let Some(pend) = content[abs..].find("</plist>") {
                    return content[abs..abs + pend + 8].to_string();
                }
            }
        }
        if let Some(start) = content.find("<plist") {
            if let Some(end) = content[start..].find("</plist>") {
                return content[start..start + end + 8].to_string();
            }
        }
        String::new()
    }

    fn extract_plist_value(plist: &str, key: &str) -> Option<String> {
        let search = format!("<key>{}</key>", key);
        if let Some(pos) = plist.find(&search) {
            let after = &plist[pos + search.len()..];
            for tag in &["<string>", "<integer>"] {
                if let Some(vstart) = after.find(tag) {
                    let val_start = vstart + tag.len();
                    let close = tag.replace('<', "</");
                    if let Some(vend) = after[val_start..].find(&close) {
                        return Some(after[val_start..val_start + vend].to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_entitlements(plist: &str) -> Vec<String> {
        let mut ents = Vec::new();
        if let Some(start) = plist.find("<key>Entitlements</key>") {
            let after = &plist[start..];
            if let Some(dstart) = after.find("<dict>") {
                let in_dict = &after[dstart + 6..];
                let mut pos = 0;
                while let Some(kstart) = in_dict[pos..].find("<key>") {
                    let abs = pos + kstart + 5;
                    if let Some(kend) = in_dict[abs..].find("</key>") {
                        let key = &in_dict[abs..abs + kend];
                        if key.len() < 100 {
                            ents.push(key.to_string());
                        }
                        pos = abs + kend + 6;
                    } else {
                        break;
                    }
                }
            }
        }

        if plist.contains("aps-environment") {
            ents.push("aps-environment (push notifications)".to_string());
        }
        if plist.contains("com.apple.security.application-groups") {
            ents.push("App Groups".to_string());
        }
        if plist.contains("com.apple.developer.ubiquity-kvstore-identifier") {
            ents.push("iCloud KV Storage".to_string());
        }
        if plist.contains("com.apple.developer.pass-type-identifiers") {
            ents.push("Wallet / PassKit".to_string());
        }
        if plist.contains("com.apple.developer.healthkit") {
            ents.push("HealthKit".to_string());
        }

        ents.sort();
        ents.dedup();
        ents
    }

    fn extract_capabilities(data: &[u8], _plist: &str) -> Vec<String> {
        let content = String::from_utf8_lossy(data);
        let mut caps = Vec::new();
        let keywords = ["GameKit", "StoreKit", "MapKit", "CoreLocation", "AVFoundation",
            "CoreBluetooth", "AssetsLibrary", "CoreImage", "Metal", "ARKit", "Vision",
            "CoreNFC", "LocalAuthentication", "FaceID", "TouchID"];
        for kw in &keywords {
            if content.contains(kw) {
                caps.push(kw.to_string());
            }
        }
        caps
    }

    fn find_frameworks(data: &[u8]) -> Vec<String> {
        let content = String::from_utf8_lossy(data);
        let mut frameworks = Vec::new();
        let re = regex::Regex::new(r#"(?i)([a-zA-Z]+)\.framework"#).unwrap();
        for cap in re.find_iter(&content) {
            frameworks.push(cap.as_str().to_string());
        }
        frameworks.sort();
        frameworks.dedup();
        frameworks
    }

    fn detect_architectures(data: &[u8]) -> Vec<String> {
        let mut archs = Vec::new();
        if data.windows(4).any(|w| w == [0xfe, 0xed, 0xfa, 0xce]) {
            archs.push("arm64".to_string());
        }
        if data.windows(4).any(|w| w == [0xfe, 0xed, 0xfa, 0xcf]) {
            archs.push("armv7".to_string());
        }
        if data.windows(4).any(|w| w == [0xce, 0xfa, 0xed, 0xfe]) {
            archs.push("i386".to_string());
        }
        if data.windows(4).any(|w| w == [0xcf, 0xfa, 0xed, 0xfe]) {
            archs.push("x86_64".to_string());
        }
        if archs.is_empty() {
            archs.push("unknown".to_string());
        }
        archs
    }

    fn extract_device_family(plist: &str) -> Vec<String> {
        let mut families = Vec::new();
        if let Some(val) = Self::extract_plist_value(plist, "UIDeviceFamily") {
            if val.contains("1") { families.push("iPhone".to_string()); }
            if val.contains("2") { families.push("iPad".to_string()); }
            if val.contains("3") { families.push("Apple TV".to_string()); }
        }
        if families.is_empty() {
            families.push("iPhone/iPad".to_string());
        }
        families
    }

    fn extract_orientations(plist: &str) -> Vec<String> {
        let mut orients = Vec::new();
        let orient_keywords = [
            ("UIInterfaceOrientationPortrait", "Portrait"),
            ("UIInterfaceOrientationLandscapeLeft", "Landscape Left"),
            ("UIInterfaceOrientationLandscapeRight", "Landscape Right"),
            ("UIInterfaceOrientationPortraitUpsideDown", "Portrait Upside Down"),
        ];
        for (key, name) in &orient_keywords {
            if plist.contains(key) {
                orients.push(name.to_string());
            }
        }
        orients
    }

    pub fn check_ipa_security(info: &IpaInfo) -> Vec<String> {
        let mut findings = Vec::new();

        if !info.uses_encryption {
            findings.push("No encryption declaration (ITSAppUsesNonExemptEncryption not set)".to_string());
        }

        if info.entitlements.iter().any(|e| e.contains("push") || e.contains("aps-environment")) {
            findings.push("Push notifications enabled — verify APNs certificate security".to_string());
        }

        if info.min_os.as_str() < "13.0" {
            findings.push(format!("Minimum iOS version {} is outdated (13.0+ recommended)", info.min_os));
        }

        info.entitlements.iter().for_each(|e| {
            if e.contains("keychain-access-groups") || e.contains("keychain") {
                findings.push(format!("Keychain access group entitlement: {}", e));
            }
        });

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> Vec<u8> {
        let mut data = vec![0x50, 0x4b, 0x03, 0x04];
        let plist = r#"<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.test.app</string>
    <key>CFBundleShortVersionString</key><string>1.5</string>
    <key>CFBundleVersion</key><string>42</string>
    <key>CFBundleDisplayName</key><string>TestApp</string>
    <key>MinimumOSVersion</key><string>12.0</string>
    <key>CFBundleExecutable</key><string>TestApp</string>
    <key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array>
</dict>
</plist>"#;
        data.extend_from_slice(plist.as_bytes());
        data
    }

    #[test]
    fn test_analyze_ipa() {
        let info = IpaAnalyzer::analyze(&sample_data()).unwrap();
        assert_eq!(info.bundle_id, "com.test.app");
        assert_eq!(info.version, "1.5");
    }

    #[test]
    fn test_invalid_ipa() {
        let result = IpaAnalyzer::analyze(b"bad");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_ipa() {
        let result = IpaAnalyzer::analyze(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_plist_value() {
        let plist = "<key>CFBundleIdentifier</key><string>com.test</string>";
        let val = IpaAnalyzer::extract_plist_value(plist, "CFBundleIdentifier");
        assert_eq!(val, Some("com.test".to_string()));
    }

    #[test]
    fn test_architectures() {
        let data = vec![0xfe, 0xed, 0xfa, 0xce, 0xcf, 0xfa, 0xed, 0xfe];
        let archs = IpaAnalyzer::detect_architectures(&data);
        assert!(archs.contains(&"arm64".to_string()));
        assert!(archs.contains(&"x86_64".to_string()));
    }

    #[test]
    fn test_frameworks() {
        let data = b"UIKit.framework Foundation.framework UIKit.framework";
        let fws = IpaAnalyzer::find_frameworks(data);
        assert!(fws.contains(&"UIKit.framework".to_string()));
        assert_eq!(fws.len(), 2);
    }

    #[test]
    fn test_ipa_security() {
        let info = IpaAnalyzer::analyze(&sample_data()).unwrap();
        let findings = IpaAnalyzer::check_ipa_security(&info);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_ipa_info_serde() {
        let info = IpaAnalyzer::analyze(&sample_data()).unwrap();
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("com.test.app"));
    }
}
