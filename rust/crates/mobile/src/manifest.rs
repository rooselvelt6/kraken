use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestReport {
    pub package: String,
    pub version: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub permissions: Vec<PermissionAnalysis>,
    pub components: Vec<Component>,
    pub dangerous_perm_count: usize,
    pub total_perm_count: usize,
    pub exported_components: Vec<String>,
    pub has_backup: bool,
    pub has_debuggable: bool,
    pub has_allow_backup: bool,
    pub uses_cleartext: bool,
    pub custom_permissions: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAnalysis {
    pub name: String,
    pub protection_level: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub component_type: String,
    pub exported: bool,
    pub intent_filters: Vec<String>,
}

const DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BODY_SENSORS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
];

pub struct ManifestAnalyzer;

impl ManifestAnalyzer {
    pub fn new() -> Self {
        ManifestAnalyzer
    }

    pub fn analyze(xml: &str) -> ManifestReport {
        let package = Self::extract_attr(xml, "package").unwrap_or_else(|| "unknown".to_string());
        let version = Self::extract_attr(xml, "versionName").unwrap_or_else(|| "0.0".to_string());
        let min_sdk = Self::extract_sdk(xml, "minSdkVersion");
        let target_sdk = Self::extract_sdk(xml, "targetSdkVersion");

        let raw_permissions = Self::extract_tags(xml, "uses-permission", "android:name");
        let mut permissions = Vec::new();
        for perm in &raw_permissions {
            let level = if DANGEROUS_PERMISSIONS.contains(&perm.as_str()) {
                "dangerous"
            } else {
                "normal"
            };
            permissions.push(PermissionAnalysis {
                name: perm.clone(),
                protection_level: level.to_string(),
                description: String::new(),
            });
        }

        let dangerous_perm_count = permissions.iter().filter(|p| p.protection_level == "dangerous").count();
        let total_perm_count = permissions.len();

        let components = Self::extract_components(xml);
        let exported: Vec<String> = components.iter()
            .filter(|c| c.exported)
            .map(|c| format!("{} ({})", c.name, c.component_type))
            .collect();

        let has_backup = xml.contains("android:allowBackup=\"true\"");
        let has_debuggable = xml.contains("android:debuggable=\"true\"");
        let has_allow_backup = has_backup;
        let uses_cleartext = xml.contains("android:usesCleartextTraffic=\"true\"");

        let custom_permissions = Self::extract_tags(xml, "permission", "android:name");

        let recommendations = Self::generate_recommendations(
            dangerous_perm_count,
            &exported,
            has_backup,
            has_debuggable,
            uses_cleartext,
            target_sdk,
        );

        ManifestReport {
            package,
            version,
            min_sdk,
            target_sdk,
            permissions,
            components,
            dangerous_perm_count,
            total_perm_count,
            exported_components: exported,
            has_backup,
            has_debuggable,
            has_allow_backup,
            uses_cleartext,
            custom_permissions,
            recommendations,
        }
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
        let mut results = Vec::new();
        let open = format!("<{} ", tag);
        let mut pos = 0;
        while let Some(start) = xml[pos..].find(&open) {
            let abs = pos + start;
            if let Some(end) = xml[abs..].find('>') {
                let element = &xml[abs..abs + end + 1];
                if let Some(val) = Self::extract_attr(element, attr) {
                    results.push(val);
                }
            }
            pos = abs + 1;
        }
        results
    }

    fn extract_components(xml: &str) -> Vec<Component> {
        let mut components = Vec::new();
        for comp_type in &["activity", "service", "receiver", "provider"] {
            let open = format!("<{} ", comp_type);
            let mut pos = 0;
            while let Some(start) = xml[pos..].find(&open) {
                let abs = pos + start;
                if let Some(end) = xml[abs..].find('>') {
                    let element = &xml[abs..abs + end + 1];
                    let name = Self::extract_attr(element, "android:name").unwrap_or_else(|| "unknown".to_string());
                    let exported = element.contains("android:exported=\"true\"");
                    let mut filters = Vec::new();
                    let filter_open = "<intent-filter>";
                    if let Some(fstart) = element.find(filter_open) {
                        if let Some(_fend) = element[fstart + 14..].find("</intent-filter>") {
                            filters.push("has intent filter".to_string());
                        }
                    }
                    components.push(Component {
                        name,
                        component_type: comp_type.to_string(),
                        exported,
                        intent_filters: filters,
                    });
                }
                pos = abs + 1;
            }
        }
        components
    }

    fn generate_recommendations(
        dangerous_count: usize,
        exported: &[String],
        has_backup: bool,
        has_debuggable: bool,
        uses_cleartext: bool,
        target_sdk: u32,
    ) -> Vec<String> {
        let mut recs = Vec::new();

        if dangerous_count > 5 {
            recs.push(format!("High risk: {} dangerous permissions requested. Review necessity of each.", dangerous_count));
        }

        for comp in exported {
            recs.push(format!("Exported component without protection: {}", comp));
        }

        if has_backup {
            recs.push("android:allowBackup enabled — sensitive data may be extractable via ADB backup".to_string());
        }

        if has_debuggable {
            recs.push("android:debuggable enabled — remove in release builds".to_string());
        }

        if uses_cleartext {
            recs.push("Cleartext HTTP traffic allowed — use HTTPS only".to_string());
        }

        if target_sdk < 33 {
            recs.push(format!("targetSdkVersion {} is outdated (33+ recommended for modern permissions)", target_sdk));
        }

        recs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> String {
        r#"<?xml version="1.0"?>
<manifest package="com.test.app" versionName="2.0" minSdkVersion="26" targetSdkVersion="34">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <activity android:name=".MainActivity" android:exported="true">
        <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
    </activity>
    <service android:name=".BackgroundService"/>
    <receiver android:name=".BootReceiver" android:exported="true"/>
    <provider android:name=".FileProvider"/>
</manifest>"#.to_string()
    }

    #[test]
    fn test_analyze_basic() {
        let report = ManifestAnalyzer::analyze(&sample_manifest());
        assert_eq!(report.package, "com.test.app");
        assert_eq!(report.version, "2.0");
    }

    #[test]
    fn test_permissions() {
        let report = ManifestAnalyzer::analyze(&sample_manifest());
        assert_eq!(report.total_perm_count, 3);
        assert!(report.permissions.iter().any(|p| p.name == "android.permission.CAMERA"));
    }

    #[test]
    fn test_dangerous_permissions() {
        let report = ManifestAnalyzer::analyze(&sample_manifest());
        assert!(report.dangerous_perm_count > 0);
    }

    #[test]
    fn test_exported_components() {
        let report = ManifestAnalyzer::analyze(&sample_manifest());
        assert!(!report.exported_components.is_empty());
        assert!(report.exported_components.iter().any(|c| c.contains(".MainActivity")));
    }

    #[test]
    fn test_empty_manifest() {
        let report = ManifestAnalyzer::analyze("");
        assert_eq!(report.package, "unknown");
    }

    #[test]
    fn test_recommendations() {
        let report = ManifestAnalyzer::analyze(&sample_manifest());
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_debuggable() {
        let xml = r#"<manifest package="com.test" android:debuggable="true"/>"#;
        let report = ManifestAnalyzer::analyze(xml);
        assert!(report.has_debuggable);
    }

    #[test]
    fn test_manifest_report_serde() {
        let report = ManifestAnalyzer::analyze(&sample_manifest());
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("com.test.app"));
    }
}
