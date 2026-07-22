use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraversalKind {
    DirectoryDotDot,
    SymlinkEscape,
    DoubleEncoding,
    UnicodeNormalization,
    ProcSelfFd,
    NullByte,
    DeviceFile,
    FifoPipe,
    WindowsAlternateDataStream,
}

impl TraversalKind {
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::DirectoryDotDot => "directory traversal via ../",
            Self::SymlinkEscape => "symlink escape outside workspace",
            Self::DoubleEncoding => "double-encoded path traversal",
            Self::UnicodeNormalization => "unicode normalization attack",
            Self::ProcSelfFd => "/proc/self/fd/ access",
            Self::NullByte => "null byte injection",
            Self::DeviceFile => "device file access",
            Self::FifoPipe => "FIFO pipe access",
            Self::WindowsAlternateDataStream => "Windows alternate data stream",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraversalDetection {
    pub kind: TraversalKind,
    pub path: String,
    pub detail: String,
}

#[must_use]
pub fn detect_traversal(path: &str) -> Vec<TraversalDetection> {
    let mut detections = Vec::new();

    // 1. Directory traversal via `..`
    if detect_dotdot(path) {
        detections.push(TraversalDetection {
            kind: TraversalKind::DirectoryDotDot,
            path: path.to_string(),
            detail: "path contains '..' components".to_string(),
        });
    }

    // 2. Double encoding
    if detect_double_encoding(path) {
        detections.push(TraversalDetection {
            kind: TraversalKind::DoubleEncoding,
            path: path.to_string(),
            detail: "path contains double-encoded traversal sequences".to_string(),
        });
    }

    // 3. Unicode normalization attacks
    if detect_unicode_normalization(path) {
        detections.push(TraversalDetection {
            kind: TraversalKind::UnicodeNormalization,
            path: path.to_string(),
            detail: "path contains characters with ambiguous unicode normalization".to_string(),
        });
    }

    // 4. /proc/self/fd/ access
    if detect_proc_self_fd(path) {
        detections.push(TraversalDetection {
            kind: TraversalKind::ProcSelfFd,
            path: path.to_string(),
            detail: "path accesses /proc/self/fd/".to_string(),
        });
    }

    // 5. Null bytes
    if detect_null_byte(path) {
        detections.push(TraversalDetection {
            kind: TraversalKind::NullByte,
            path: path.to_string(),
            detail: "path contains null byte".to_string(),
        });
    }

    // 6. Device files
    if detect_device_file(path) {
        detections.push(TraversalDetection {
            kind: TraversalKind::DeviceFile,
            path: path.to_string(),
            detail: "path accesses a device file".to_string(),
        });
    }

    // 7. Windows alternate data stream
    if detect_windows_ads(path) {
        detections.push(TraversalDetection {
            kind: TraversalKind::WindowsAlternateDataStream,
            path: path.to_string(),
            detail: "path contains Windows alternate data stream syntax".to_string(),
        });
    }

    detections
}

pub fn validate_path_safety(path: &Path, workspace_root: &Path) -> Result<(), String> {
    let path_str = path.to_string_lossy();

    // Check for null bytes
    if path_str.contains('\0') {
        return Err("path contains null byte".into());
    }

    // Check for device files
    let path_str_lower = path_str.to_lowercase();
    if path_str_lower.starts_with("/dev/") {
        return Err("device file access blocked".into());
    }

    // Resolve symlinks if path exists
    if path.exists() {
        let metadata = path
            .symlink_metadata()
            .map_err(|e| format!("metadata: {e}"))?;

        if metadata.is_symlink() {
            let resolved = path.canonicalize().map_err(|e| format!("canonicalize: {e}"))?;
            let canonical_root = workspace_root
                .canonicalize()
                .map_err(|e| format!("workspace canonicalize: {e}"))?;
            if !resolved.starts_with(&canonical_root) {
                return Err("symlink escapes workspace".into());
            }
        }

        // Check for FIFO/pipe via platform-specific metadata
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if metadata.file_type().is_fifo() {
                return Err("FIFO pipe access blocked".into());
            }
        }
    }

    Ok(())
}

fn detect_dotdot(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let segments: Vec<&str> = normalized.split('/').collect();
    let mut depth: isize = 0;
    for seg in &segments {
        match *seg {
            "." | "" => {}
            ".." => depth -= 1,
            _ => depth += 1,
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

fn detect_double_encoding(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("%252e")
        || lower.contains("%252f")
        || lower.contains("%255c")
        || lower.contains("%%32%65")
        || lower.contains("%c0%ae")
        || lower.contains("%c0%af")
        || lower.contains("%c1%9c")
        || lower.contains("%e0%80%ae")
        || lower.contains("%e0%80%af")
}

fn detect_unicode_normalization(path: &str) -> bool {
    path.contains('\u{FE64}')
        || path.contains('\u{FE65}')
        || path.contains('\u{FF0E}')
        || path.contains('\u{FF0F}')
        || path.contains('\u{FF3C}')
        || path.contains('\u{2024}')
        || path.contains('\u{2025}')
        || path.contains('\u{2026}')
        || path.contains('\u{2E2E}')
        || path.contains('\u{A789}')
        || path.contains('\u{FF01}')
        || path.contains('\u{FE56}')
        || path.contains('\u{FE57}')
}

fn detect_proc_self_fd(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("/proc/self/fd/")
        || lower.contains("/proc/self/cwd")
        || lower.contains("/proc/self/root")
        || lower.contains("/proc/1/")
}

fn detect_null_byte(path: &str) -> bool {
    path.contains('\0')
}

fn detect_device_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.starts_with("/dev/")
        || lower.starts_with("/proc/")
        || lower.starts_with("/sys/")
}

fn detect_windows_ads(path: &str) -> bool {
    path.contains("::$")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_dotdot() {
        assert!(detect_dotdot("../../../etc/passwd"));
        assert!(detect_dotdot("foo/../../bar"));
        assert!(!detect_dotdot("foo/bar/baz"));
        assert!(!detect_dotdot("foo/bar"));
    }

    #[test]
    fn detects_double_encoding() {
        assert!(detect_double_encoding("%252e%252f"));
        assert!(detect_double_encoding("%c0%ae%c0%af"));
        assert!(!detect_double_encoding("normal/path"));
    }

    #[test]
    fn detects_proc_self_fd() {
        assert!(detect_proc_self_fd("/proc/self/fd/0"));
        assert!(detect_proc_self_fd("/proc/self/cwd"));
        assert!(!detect_proc_self_fd("/proc/version"));
    }

    #[test]
    fn detects_null_byte() {
        assert!(detect_null_byte("file.php\0.txt"));
        assert!(!detect_null_byte("normal.txt"));
    }

    #[test]
    fn detects_device_file() {
        assert!(detect_device_file("/dev/sda1"));
        assert!(detect_device_file("/proc/1/mem"));
        assert!(!detect_device_file("/home/user/file.txt"));
    }

    #[test]
    fn detects_windows_ads() {
        assert!(detect_windows_ads("file.txt::$DATA"));
        assert!(!detect_windows_ads("file.txt"));
    }

    #[test]
    fn detect_traversal_returns_multiple() {
        let results = detect_traversal("/proc/self/fd/0\0../../../etc");
        assert!(!results.is_empty());
        assert!(results.iter().any(|d| d.kind == TraversalKind::ProcSelfFd));
        assert!(results.iter().any(|d| d.kind == TraversalKind::NullByte));
    }

    #[test]
    fn safe_path_returns_empty() {
        let results = detect_traversal("/home/user/workspace/file.txt");
        assert!(results.is_empty());
    }
}
