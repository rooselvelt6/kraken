use regex::Regex;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub extra: Option<String>,
    pub full: String,
}

impl KernelVersion {
    pub fn from_content(content: &str, file_path: &Path) -> Option<Self> {
        let file_name = file_path.file_name()?.to_str()?;

        if file_name == "Makefile" || file_name == "version.h" || file_name == "utsrelease.h"
        {
            return Self::from_makefile_or_header(content);
        }

        None
    }

    fn from_makefile_or_header(content: &str) -> Option<Self> {
        let patterns = [
            r#"VERSION\s*=\s*(\d+)\s*\n.*PATCHLEVEL\s*=\s*(\d+)\s*\n.*SUBLEVEL\s*=\s*(\d+)"#,
            r#"VERSION\s*=\s*(\d+)"#,
            r#"PATCHLEVEL\s*=\s*(\d+)"#,
            r#"SUBLEVEL\s*=\s*(\d+)"#,
            r#"EXTRAVERSION\s*=\s*(.+)"#,
            r#"#define LINUX_VERSION_CODE\s+\d+"#,
            r#"#define UTS_RELEASE\s+"([^"]+)"#,
        ];

        if let Some(caps) = Regex::new(patterns[0])
            .ok()?
            .captures(content)
        {
            let major: u16 = caps.get(1)?.as_str().parse().ok()?;
            let minor: u16 = caps.get(2)?.as_str().parse().ok()?;
            let patch: u16 = caps.get(3)?.as_str().parse().ok()?;

            let extra = Regex::new(patterns[4])
                .ok()?
                .captures(content)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().trim().to_string());

            let full = format!("{}.{}.{}{}", major, minor, patch,
                extra.clone().unwrap_or_default());

            return Some(KernelVersion { major, minor, patch, extra, full });
        }

        if let Some(caps) = Regex::new(patterns[6])
            .ok()?
            .captures(content)
        {
            let full = caps.get(1)?.as_str().to_string();
            let parts: Vec<&str> = full.splitn(3, '.').collect();
            if parts.len() >= 2 {
                let major = parts[0].parse().ok()?;
                let minor = parts[1].parse().ok()?;

                let (patch, extra) = if parts.len() >= 3 {
                    let rest = parts[2].trim();
                    let patch_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                    let p: u16 = rest[..patch_end].parse().ok()?;
                    let e = if patch_end < rest.len() { Some(rest[patch_end..].to_string()) } else { None };
                    (p, e)
                } else {
                    (0, None)
                };

                return Some(KernelVersion { major, minor, patch, extra, full });
            }
        }

        None
    }

    /// Parses a version string like `6.8.12`, `linux-6.8.12-arch1`, or `v5.15.0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use vulnscan::kernel::version::KernelVersion;
    /// let v = KernelVersion::parse_full("6.8.12").unwrap();
    /// assert_eq!(v.major, 6);
    /// assert_eq!(v.minor, 8);
    /// assert_eq!(v.patch, 12);
    /// assert!(v.extra.is_none());
    ///
    /// let v = KernelVersion::parse_full("linux-5.15.0-91-generic").unwrap();
    /// assert_eq!(v.major, 5);
    /// assert_eq!(v.minor, 15);
    /// assert_eq!(v.patch, 0);
    /// assert_eq!(v.extra.as_deref(), Some("-91-generic"));
    /// ```
    pub fn parse_full(version_str: &str) -> Option<Self> {
        let v = version_str.trim();
        let v = v.strip_prefix("linux-").or(v.strip_prefix("v")).unwrap_or(v);

        let parts: Vec<&str> = v.splitn(3, '.').collect();
        if parts.len() < 2 {
            return None;
        }

        let major: u16 = parts[0].parse().ok()?;
        let minor: u16 = parts[1].parse().ok()?;

        let (patch, extra) = if parts.len() >= 3 {
            let rest = parts[2].trim();
            let patch_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            let p: u16 = rest[..patch_end].parse().unwrap_or(0);
            let e = if patch_end < rest.len() { Some(rest[patch_end..].to_string()) } else { None };
            (p, e)
        } else {
            (0, None)
        };

        Some(KernelVersion {
            major,
            minor,
            patch,
            extra,
            full: version_str.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_kernel_makefile() {
        let content = "VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 12\nEXTRAVERSION = -arch1\n";
        let v = KernelVersion::from_makefile_or_header(content).unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 8);
        assert_eq!(v.patch, 12);
        assert_eq!(v.extra, Some("-arch1".to_string()));
    }

    #[test]
    fn test_parse_utsrelease() {
        let content = "#define UTS_RELEASE \"5.15.0-91-generic\"\n";
        let v = KernelVersion::from_makefile_or_header(content).unwrap();
        assert_eq!(v.major, 5);
        assert_eq!(v.minor, 15);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_full_version() {
        let v = KernelVersion::parse_full("linux-6.8.12-arch1").unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 8);
        assert_eq!(v.patch, 12);
    }

    #[test]
    fn test_none_on_non_kernel() {
        let p = PathBuf::from("main.c");
        let v = KernelVersion::from_content("int main() {}", &p);
        assert!(v.is_none());
    }

    #[test]
    fn test_parse_full_version_v_prefix() {
        let v = KernelVersion::parse_full("v6.8.12").unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 8);
        assert_eq!(v.patch, 12);
        assert!(v.extra.is_none());
    }

    #[test]
    fn test_parse_full_version_with_extra() {
        let v = KernelVersion::parse_full("5.15.0-91-generic").unwrap();
        assert_eq!(v.major, 5);
        assert_eq!(v.minor, 15);
        assert_eq!(v.patch, 0);
        assert_eq!(v.extra.as_deref(), Some("-91-generic"));
    }

    #[test]
    fn test_parse_full_version_linux_prefix() {
        let v = KernelVersion::parse_full("linux-6.1.0-rc1").unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 0);
        assert_eq!(v.extra.as_deref(), Some("-rc1"));
    }

    #[test]
    fn test_parse_full_version_two_parts() {
        let v = KernelVersion::parse_full("6.8").unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 8);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_full_version_invalid() {
        assert!(KernelVersion::parse_full("not-a-version").is_none());
    }

    #[test]
    fn test_parse_full_version_single_part() {
        assert!(KernelVersion::parse_full("6").is_none());
    }

    #[test]
    fn test_makefile_extraversion() {
        let content = "VERSION = 5\nPATCHLEVEL = 10\nSUBLEVEL = 0\nEXTRAVERSION = -rc1\n";
        let v = KernelVersion::from_makefile_or_header(content).unwrap();
        assert_eq!(v.major, 5);
        assert_eq!(v.minor, 10);
        assert_eq!(v.patch, 0);
        assert_eq!(v.extra, Some("-rc1".to_string()));
        assert!(v.full.contains("5.10.0"));
    }

    #[test]
    fn test_makefile_no_extraversion() {
        let content = "VERSION = 6\nPATCHLEVEL = 1\nSUBLEVEL = 55\n";
        let v = KernelVersion::from_makefile_or_header(content).unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 55);
        assert!(v.extra.is_none());
    }

    #[test]
    fn test_utsrelease_with_patch() {
        let content = "#define UTS_RELEASE \"6.8.12-arch1-1\"\n";
        let v = KernelVersion::from_makefile_or_header(content).unwrap();
        assert_eq!(v.major, 6);
        assert_eq!(v.minor, 8);
        assert_eq!(v.patch, 12);
        assert_eq!(v.extra.as_deref(), Some("-arch1-1"));
    }

    #[test]
    fn test_from_content_non_makefile() {
        let p = PathBuf::from("version.h");
        let content = "#define UTS_RELEASE \"5.15.99\"\n";
        let v = KernelVersion::from_content(content, &p).unwrap();
        assert_eq!(v.major, 5);
        assert_eq!(v.minor, 15);
        assert_eq!(v.patch, 99);
    }

    #[test]
    fn test_from_content_unknown_file() {
        let p = PathBuf::from("README.md");
        let v = KernelVersion::from_content("version 6.1.0", &p);
        assert!(v.is_none(), "Unknown file type should return None");
    }

    #[test]
    fn test_parse_full_preserves_input_string() {
        let v = KernelVersion::parse_full("v5.4.210").unwrap();
        assert_eq!(v.full, "v5.4.210");
    }

    #[test]
    fn test_makefile_version_zero() {
        let content = "VERSION = 0\nPATCHLEVEL = 0\nSUBLEVEL = 0\n";
        let v = KernelVersion::from_makefile_or_header(content).unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_full_large_version() {
        let v = KernelVersion::parse_full("99.999.9999").unwrap();
        assert_eq!(v.major, 99);
        assert_eq!(v.minor, 999);
        assert_eq!(v.patch, 9999);
    }
}
