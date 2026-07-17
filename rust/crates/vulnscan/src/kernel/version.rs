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
}
