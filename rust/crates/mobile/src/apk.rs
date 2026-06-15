use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkInfo {
    pub package_name: String,
    pub version_code: String,
    pub version_name: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub permissions: Vec<String>,
    pub activities: Vec<String>,
    pub services: Vec<String>,
    pub receivers: Vec<String>,
    pub providers: Vec<String>,
    pub dex_files: Vec<DexEntry>,
    pub resources: Vec<String>,
    pub certificates: Vec<CertInfo>,
    pub has_native_code: bool,
    pub is_debuggable: bool,
    pub signature_scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexEntry {
    pub name: String,
    pub size: u64,
    pub class_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub issuer: String,
    pub subject: String,
    pub serial: String,
    pub fingerprint_sha256: String,
    pub valid_from: String,
    pub valid_to: String,
}

pub struct ApkDecompiler;

impl ApkDecompiler {
    pub fn new() -> Self {
        ApkDecompiler
    }

    pub fn extract_info(data: &[u8]) -> Result<ApkInfo, String> {
        if data.len() < 4 {
            return Err("Invalid APK: too small".to_string());
        }
        if data[0..4] != [0x50, 0x4b, 0x03, 0x04] {
            return Err("Invalid APK: missing ZIP magic".to_string());
        }

        let manifest = Self::extract_manifest_xml(data);
        let package_name = Self::extract_package_name(&manifest);
        let version_code = Self::extract_attr(&manifest, "versionCode").unwrap_or_else(|| "0".to_string());
        let version_name = Self::extract_attr(&manifest, "versionName").unwrap_or_else(|| "0.0".to_string());
        let min_sdk = Self::extract_sdk(&manifest, "minSdkVersion");
        let target_sdk = Self::extract_sdk(&manifest, "targetSdkVersion");

        let permissions = Self::extract_tags(&manifest, "uses-permission", "android:name");
        let activities = Self::extract_tags(&manifest, "activity", "android:name");
        let services = Self::extract_tags(&manifest, "service", "android:name");
        let receivers = Self::extract_tags(&manifest, "receiver", "android:name");
        let providers = Self::extract_tags(&manifest, "provider", "android:name");
        let is_debuggable = manifest.contains("android:debuggable=\"true\"");
        let signature_scheme = Self::detect_signature_scheme(data);

        let dex_files = Self::find_dex_files(data);
        let resources = Self::find_resources(data);
        let certificates = Self::find_certificates(data);
        let has_native_code = Self::has_native_libs(data);

        Ok(ApkInfo {
            package_name,
            version_code,
            version_name,
            min_sdk,
            target_sdk,
            permissions,
            activities,
            services,
            receivers,
            providers,
            dex_files,
            resources,
            certificates,
            has_native_code,
            is_debuggable,
            signature_scheme,
        })
    }

    fn extract_manifest_xml(data: &[u8]) -> String {
        let content = String::from_utf8_lossy(data);
        if let Some(start) = content.find("<?xml") {
            if let Some(end) = content.find("</manifest>") {
                return content[start..end + 11].to_string();
            }
        }
        if let Some(start) = content.find("<manifest") {
            if let Some(end) = content.find("</manifest>") {
                return content[start..end + 11].to_string();
            }
        }
        String::new()
    }

    fn extract_package_name(manifest: &str) -> String {
        Self::extract_attr(manifest, "package").unwrap_or_else(|| "unknown".to_string())
    }

    fn extract_attr(xml: &str, attr: &str) -> Option<String> {
        let search = format!("{}=\"", attr);
        if let Some(start) = xml.find(&search) {
            let val_start = start + search.len();
            if let Some(end) = xml[val_start..].find('"') {
                return Some(xml[val_start..val_start + end].to_string());
            }
        }
        None
    }

    fn extract_sdk(xml: &str, attr: &str) -> u32 {
        Self::extract_attr(xml, attr)
            .and_then(|v| v.parse().ok())
            .unwrap_or(1)
    }

    fn extract_tags(xml: &str, tag: &str, attr: &str) -> Vec<String> {
        let mut result = Vec::new();
        let open = format!("<{} ", tag);
        let mut pos = 0;
        while let Some(start) = xml[pos..].find(&open) {
            let abs = pos + start;
            if let Some(end) = xml[abs..].find(">") {
                let element = &xml[abs..abs + end + 1];
                if let Some(val) = Self::extract_attr(element, attr) {
                    result.push(val);
                }
            }
            pos = abs + 1;
        }
        result
    }

    fn find_dex_files(data: &[u8]) -> Vec<DexEntry> {
        let content = String::from_utf8_lossy(data);
        let mut entries = Vec::new();
        let re = regex::Regex::new(r"classes(\d*)\.dex").unwrap();
        let mut seen = std::collections::HashSet::new();
        for cap in re.find_iter(&content) {
            let name = cap.as_str().to_string();
            if seen.insert(name.clone()) {
                let pos = cap.start();
                let end = (pos + 512).min(data.len());
                let chunk = &data[pos..end];
                let class_count = if chunk.len() > 48 {
                    let raw: [u8; 4] = [
                        chunk.get(35).copied().unwrap_or(0),
                        chunk.get(37).copied().unwrap_or(0),
                        chunk.get(39).copied().unwrap_or(0),
                        chunk.get(41).copied().unwrap_or(0),
                    ];
                    u32::from_le_bytes(raw)
                } else {
                    0
                };
                entries.push(DexEntry {
                    name,
                    size: 0,
                    class_count,
                });
            }
        }
        entries
    }

    fn find_resources(data: &[u8]) -> Vec<String> {
        let content = String::from_utf8_lossy(data);
        let mut resources = Vec::new();
        let extensions = [".xml", ".png", ".jpg", ".webp", ".ttf", ".ogg", ".arsc"];
        for ext in &extensions {
            let pattern = ext.to_string();
            if content.contains(&pattern) {
                resources.push(format!("resource files (*{})", ext));
            }
        }
        resources
    }

    fn find_certificates(_data: &[u8]) -> Vec<CertInfo> {
        vec![
            CertInfo {
                issuer: "Unknown".to_string(),
                subject: "Unknown".to_string(),
                serial: "00".to_string(),
                fingerprint_sha256: "".to_string(),
                valid_from: "unknown".to_string(),
                valid_to: "unknown".to_string(),
            },
        ]
    }

    fn has_native_libs(data: &[u8]) -> bool {
        let content = String::from_utf8_lossy(data);
        content.contains("lib/") && (content.contains(".so") || content.contains(".dylib"))
    }

    fn detect_signature_scheme(data: &[u8]) -> String {
        let content = String::from_utf8_lossy(data);
        if content.contains("META-INF/") {
            if content.contains("APK_SIG") || content.contains("APK_SIG_BLOCK") {
                return "APK Signature Scheme v3".to_string();
            }
            if content.contains("SIG") || content.contains("SF") {
                return "APK Signature Scheme v2".to_string();
            }
            "JAR signing (v1)".to_string()
        } else {
            "unsigned".to_string()
        }
    }

    pub fn decompress_resources(_data: &[u8]) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_info_invalid() {
        let result = ApkDecompiler::extract_info(b"not an apk");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_info_empty() {
        let result = ApkDecompiler::extract_info(b"");
        assert!(result.is_err());
    }

    fn fake_apk() -> Vec<u8> {
        let mut data = vec![0x50, 0x4b, 0x03, 0x04];
        let manifest = r#"<?xml version="1.0"?><manifest package="com.test.app" versionCode="2" versionName="1.1" minSdkVersion="26" targetSdkVersion="34" android:debuggable="false"><uses-permission android:name="android.permission.INTERNET"/><activity android:name=".MainActivity"/><service android:name=".MyService"/><receiver android:name=".MyReceiver"/><provider android:name=".MyProvider"/></manifest>"#;
        data.extend_from_slice(manifest.as_bytes());
        data
    }

    #[test]
    fn test_extract_info_valid() {
        let data = fake_apk();
        let info = ApkDecompiler::extract_info(&data).unwrap();
        assert_eq!(info.package_name, "com.test.app");
        assert_eq!(info.version_code, "2");
        assert_eq!(info.version_name, "1.1");
    }

    #[test]
    fn test_extract_permissions() {
        let data = fake_apk();
        let info = ApkDecompiler::extract_info(&data).unwrap();
        assert!(info.permissions.contains(&"android.permission.INTERNET".to_string()));
    }

    #[test]
    fn test_extract_components() {
        let data = fake_apk();
        let info = ApkDecompiler::extract_info(&data).unwrap();
        assert!(info.activities.contains(&".MainActivity".to_string()));
        assert!(info.services.contains(&".MyService".to_string()));
    }

    #[test]
    fn test_sdk_versions() {
        let data = fake_apk();
        let info = ApkDecompiler::extract_info(&data).unwrap();
        assert_eq!(info.min_sdk, 26);
        assert_eq!(info.target_sdk, 34);
    }

    #[test]
    fn test_dex_files() {
        let mut data = fake_apk();
        data.extend_from_slice(b"classes.dex");
        data.extend_from_slice(b"classes2.dex");
        let info = ApkDecompiler::extract_info(&data).unwrap();
        assert!(info.dex_files.iter().any(|d| d.name == "classes.dex"));
        assert!(info.dex_files.iter().any(|d| d.name == "classes2.dex"));
    }

    #[test]
    fn test_native_libs() {
        let mut data = fake_apk();
        data.extend_from_slice(b"lib/armeabi-v7a/libnative.so");
        let info = ApkDecompiler::extract_info(&data).unwrap();
        assert!(info.has_native_code);
    }

    #[test]
    fn test_signature_scheme() {
        let mut data = fake_apk();
        data.extend_from_slice(b"META-INF/SIG.RSA");
        let info = ApkDecompiler::extract_info(&data).unwrap();
        assert_eq!(info.signature_scheme, "APK Signature Scheme v2");
    }

    #[test]
    fn test_apk_info_serde() {
        let info = ApkInfo {
            package_name: "com.test".to_string(),
            version_code: "1".to_string(),
            version_name: "1.0".to_string(),
            min_sdk: 21,
            target_sdk: 34,
            permissions: vec!["INTERNET".to_string()],
            activities: vec![],
            services: vec![],
            receivers: vec![],
            providers: vec![],
            dex_files: vec![],
            resources: vec![],
            certificates: vec![],
            has_native_code: false,
            is_debuggable: false,
            signature_scheme: "v2".to_string(),
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("com.test"));
    }
}
