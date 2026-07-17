use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDetectionResult {
    pub is_rooted: RootStatus,
    pub indicators: Vec<RootIndicator>,
    pub confidence: f64,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RootStatus {
    Rooted,
    NotRooted,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootIndicator {
    pub name: String,
    pub detection_type: String,
    pub found: bool,
    pub severity: String,
}

pub struct RootDetector;

impl Default for RootDetector {
    fn default() -> Self {
        RootDetector
    }
}

impl RootDetector {
    pub fn new() -> Self {
        RootDetector
    }

    pub fn android_detect(files: &[String], packages: &[String], props: &[String]) -> RootDetectionResult {
        let mut indicators = Vec::new();
        let mut root_count = 0usize;

        let check_files = [
            ("su binary", "/system/bin/su", "file", "HIGH"),
            ("su binary (xbin)", "/system/xbin/su", "file", "HIGH"),
            ("su binary (sbin)", "/sbin/su", "file", "HIGH"),
            ("Magisk binary", "/sbin/magisk", "file", "HIGH"),
            ("SuperSU apk", "/system/app/SuperSU.apk", "file", "MEDIUM"),
            ("Magisk Manager", "/data/app/com.topjohnwu.magisk", "file", "HIGH"),
            ("Busybox", "/system/xbin/busybox", "file", "MEDIUM"),
            ("Root management", "/system/app/Superuser.apk", "file", "MEDIUM"),
        ];

        for (name, path, dtype, severity) in &check_files {
            let found = files.contains(&path.to_string());
            if found {
                root_count += 1;
            }
            indicators.push(RootIndicator {
                name: name.to_string(),
                detection_type: dtype.to_string(),
                found,
                severity: severity.to_string(),
            });
        }

        let check_packages = [
            ("Magisk", "com.topjohnwu.magisk", "package", "HIGH"),
            ("SuperSU", "eu.chainfire.supersu", "package", "HIGH"),
            ("KingRoot", "com.kingroot.kinguser", "package", "HIGH"),
            ("KingoRoot", "com.kingo.root", "package", "HIGH"),
            ("TowelRoot", "com.koushikdutta.superuser", "package", "MEDIUM"),
            ("Magisk Delta", "io.github.huskydg.magisk", "package", "HIGH"),
            ("KernelSU", "me.weishu.kernelsu", "package", "HIGH"),
        ];

        for (name, pkg, dtype, severity) in &check_packages {
            let found = packages.contains(&pkg.to_string());
            if found {
                root_count += 1;
            }
            indicators.push(RootIndicator {
                name: name.to_string(),
                detection_type: dtype.to_string(),
                found,
                severity: severity.to_string(),
            });
        }

        let check_props = [
            ("test-keys", "ro.build.tags", "property"),
            ("engineering", "ro.build.type", "property"),
            ("debuggable", "ro.debuggable", "property"),
            ("secure = 0", "ro.secure", "property"),
        ];

        for (name, prop, dtype) in &check_props {
            let found = props.iter().any(|p| p.contains(prop));
            if found {
                root_count += 1;
            }
            indicators.push(RootIndicator {
                name: name.to_string(),
                detection_type: dtype.to_string(),
                found,
                severity: "LOW".to_string(),
            });
        }

        let (status, confidence, method) = if root_count >= 3 {
            (RootStatus::Rooted, 0.9, "Multiple indicators detected".to_string())
        } else if root_count >= 1 {
            (RootStatus::Rooted, 0.5, "Partial indicators detected".to_string())
        } else {
            (RootStatus::NotRooted, 0.1, "No root indicators found".to_string())
        };

        RootDetectionResult { is_rooted: status, indicators, confidence, method }
    }

    pub fn ios_detect(files: &[String], apps: &[String]) -> RootDetectionResult {
        let mut indicators = Vec::new();
        let mut jailbreak_count = 0usize;

        let jailbreak_files = [
            ("Cydia", "/Applications/Cydia.app", "file"),
            ("Sileo", "/Applications/Sileo.app", "file"),
            ("Zebra", "/Applications/Zebra.app", "file"),
            ("unc0ver", "/Applications/unc0ver.app", "file"),
            ("Chimera", "/Applications/Chimera.app", "file"),
            ("Taurine", "/Applications/Taurine.app", "file"),
            ("checkra1n", "/Applications/checkra1n.app", "file"),
            ("SSH", "/usr/bin/sshd", "file"),
            ("Bash", "/bin/bash", "file"),
            ("Mobile Substrate", "/Library/MobileSubstrate", "file"),
        ];

        for (name, path, dtype) in &jailbreak_files {
            let found = files.contains(&path.to_string());
            if found {
                jailbreak_count += 1;
            }
            indicators.push(RootIndicator {
                name: name.to_string(),
                detection_type: dtype.to_string(),
                found,
                severity: "HIGH".to_string(),
            });
        }

        let jailbreak_apps = [
            ("Cydia", "com.saurik.Cydia"),
            ("Sileo", "org.coolstar.SileoStore"),
            ("Zebra", "xyz.willy.Zebra"),
            ("Filza", "com.tigisoftware.Filza"),
        ];

        for (name, bundle) in &jailbreak_apps {
            let found = apps.contains(&bundle.to_string());
            if found {
                jailbreak_count += 1;
            }
            indicators.push(RootIndicator {
                name: name.to_string(),
                detection_type: "bundle".to_string(),
                found,
                severity: "HIGH".to_string(),
            });
        }

        let (status, confidence, method) = if jailbreak_count >= 3 {
            (RootStatus::Rooted, 0.95, "Multiple jailbreak indicators".to_string())
        } else if jailbreak_count >= 1 {
            (RootStatus::Rooted, 0.6, "Partial jailbreak indicators".to_string())
        } else {
            (RootStatus::NotRooted, 0.1, "No jailbreak indicators".to_string())
        };

        RootDetectionResult { is_rooted: status, indicators, confidence, method }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_rooted() {
        let files = vec![
            "/system/bin/su".to_string(),
            "/sbin/magisk".to_string(),
        ];
        let packages = vec!["com.topjohnwu.magisk".to_string()];
        let props = vec![];
        let result = RootDetector::android_detect(&files, &packages, &props);
        assert_eq!(result.is_rooted, RootStatus::Rooted);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_android_not_rooted() {
        let result = RootDetector::android_detect(&[], &[], &[]);
        assert_eq!(result.is_rooted, RootStatus::NotRooted);
    }

    #[test]
    fn test_ios_jailbroken() {
        let files = vec![
            "/Applications/Cydia.app".to_string(),
            "/bin/bash".to_string(),
        ];
        let apps = vec!["com.saurik.Cydia".to_string()];
        let result = RootDetector::ios_detect(&files, &apps);
        assert_eq!(result.is_rooted, RootStatus::Rooted);
    }

    #[test]
    fn test_ios_not_jailbroken() {
        let result = RootDetector::ios_detect(&[], &[]);
        assert_eq!(result.is_rooted, RootStatus::NotRooted);
    }

    #[test]
    fn test_android_partial() {
        let files = vec!["/system/xbin/busybox".to_string()];
        let result = RootDetector::android_detect(&files, &[], &[]);
        assert_eq!(result.is_rooted, RootStatus::Rooted);
        assert!(result.confidence < 0.7);
    }

    #[test]
    fn test_root_detection_serde() {
        let result = RootDetector::android_detect(&[], &[], &[]);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("NotRooted"));
    }
}
