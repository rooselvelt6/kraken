use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FILE_OPS_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerStage {
    Normalization,
    Canonicalization,
    SymlinkResolution,
    ScopeCheck,
    EncodingDetection,
    SizeCheck,
    Allowlist,
}

impl SanitizerStage {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normalization => "normalization",
            Self::Canonicalization => "canonicalization",
            Self::SymlinkResolution => "symlink_resolution",
            Self::ScopeCheck => "scope_check",
            Self::EncodingDetection => "encoding_detection",
            Self::SizeCheck => "size_check",
            Self::Allowlist => "allowlist",
        }
    }
}

#[derive(Debug, Clone)]
pub enum SanitizerIssue {
    PathTraversal(String),
    SymlinkEscape(String),
    OutOfScope(String),
    EncodingAttack(String),
    SizeLimitExceeded { limit: u64, actual: u64 },
    BinaryFile(String),
    NullByte(String),
    DeviceFile(String),
}

impl SanitizerIssue {
    pub fn description(&self) -> String {
        match self {
            Self::PathTraversal(p) => format!("path traversal detected: {p}"),
            Self::SymlinkEscape(p) => format!("symlink escapes workspace: {p}"),
            Self::OutOfScope(p) => format!("path outside workspace: {p}"),
            Self::EncodingAttack(p) => format!("encoding attack detected: {p}"),
            Self::SizeLimitExceeded { limit, actual } => {
                format!("size limit {limit} exceeded: {actual}")
            }
            Self::BinaryFile(p) => format!("binary file blocked: {p}"),
            Self::NullByte(p) => format!("null byte in path: {p}"),
            Self::DeviceFile(p) => format!("device file blocked: {p}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SanitizerResult {
    pub path: PathBuf,
    pub stages_passed: Vec<SanitizerStage>,
    pub issues: Vec<SanitizerIssue>,
}

impl SanitizerResult {
    pub fn is_allowed(&self) -> bool {
        self.issues.is_empty()
    }
}

pub struct SanitizerConfig {
    pub max_read_size: u64,
    pub max_write_size: u64,
    pub max_glob_entries: usize,
    pub max_grep_output_bytes: u64,
    pub allow_binary: bool,
    pub block_device_files: bool,
    pub block_symlink_escape: bool,
    pub block_path_traversal: bool,
    pub block_encoding_attacks: bool,
}

impl Default for SanitizerConfig {
    fn default() -> Self {
        Self {
            max_read_size: 10 * 1024 * 1024,
            max_write_size: 10 * 1024 * 1024,
            max_glob_entries: 1000,
            max_grep_output_bytes: 1024 * 1024,
            allow_binary: false,
            block_device_files: true,
            block_symlink_escape: true,
            block_path_traversal: true,
            block_encoding_attacks: true,
        }
    }
}

pub struct Sanitizer {
    config: SanitizerConfig,
}

impl Sanitizer {
    pub fn new(config: SanitizerConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(SanitizerConfig::default())
    }

    pub fn sanitize_for_read(
        &self,
        path: &str,
        workspace_root: Option<&Path>,
    ) -> SanitizerResult {
        let mut stages_passed = Vec::new();
        let mut issues = Vec::new();

        let path = self.stage_normalization(path, &mut stages_passed, &mut issues);
        let path = self.stage_canonicalization(&path, &mut stages_passed, &mut issues);
        let path = self.stage_symlink_resolution(&path, workspace_root, &mut stages_passed, &mut issues);
        let path = self.stage_scope_check(&path, workspace_root, &mut stages_passed, &mut issues);
        self.stage_encoding_detection(&path, &mut stages_passed, &mut issues);
        self.stage_size_check(&path, self.config.max_read_size, &mut stages_passed, &mut issues);
        self.stage_allowlist(&path, &mut stages_passed, &mut issues);

        SanitizerResult { path, stages_passed, issues }
    }

    pub fn sanitize_for_write(
        &self,
        path: &str,
        workspace_root: Option<&Path>,
    ) -> SanitizerResult {
        let mut stages_passed = Vec::new();
        let mut issues = Vec::new();

        let path = self.stage_normalization(path, &mut stages_passed, &mut issues);
        let path = self.stage_canonicalization(&path, &mut stages_passed, &mut issues);
        let path = self.stage_symlink_resolution(&path, workspace_root, &mut stages_passed, &mut issues);
        let path = self.stage_scope_check(&path, workspace_root, &mut stages_passed, &mut issues);
        self.stage_encoding_detection(&path, &mut stages_passed, &mut issues);
        self.stage_size_check(&path, self.config.max_write_size, &mut stages_passed, &mut issues);
        self.stage_allowlist(&path, &mut stages_passed, &mut issues);

        SanitizerResult { path, stages_passed, issues }
    }

    pub fn sanitize_path(
        &self,
        path: &str,
        workspace_root: Option<&Path>,
    ) -> SanitizerResult {
        let mut stages_passed = Vec::new();
        let mut issues = Vec::new();

        let path = self.stage_normalization(path, &mut stages_passed, &mut issues);
        let path = self.stage_canonicalization(&path, &mut stages_passed, &mut issues);
        let path = self.stage_symlink_resolution(&path, workspace_root, &mut stages_passed, &mut issues);
        let path = self.stage_scope_check(&path, workspace_root, &mut stages_passed, &mut issues);
        self.stage_encoding_detection(&path, &mut stages_passed, &mut issues);
        self.stage_allowlist(&path, &mut stages_passed, &mut issues);

        SanitizerResult { path, stages_passed, issues }
    }

    fn stage_normalization(
        &self,
        path: &str,
        stages: &mut Vec<SanitizerStage>,
        issues: &mut Vec<SanitizerIssue>,
    ) -> PathBuf {
        stages.push(SanitizerStage::Normalization);

        // Convert backslashes to forward slashes
        let normalized = path.replace('\\', "/");

        // Check for null bytes before processing
        if normalized.contains('\0') {
            issues.push(SanitizerIssue::NullByte(path.to_string()));
        }

        // Resolve `.` and `..` components in path string
        let path_buf = if normalized.contains("..") {
            let resolved = resolve_dotdot(&normalized);
            PathBuf::from(resolved)
        } else {
            PathBuf::from(&normalized)
        };

        path_buf
    }

    fn stage_canonicalization(
        &self,
        path: &Path,
        stages: &mut Vec<SanitizerStage>,
        issues: &mut Vec<SanitizerIssue>,
    ) -> PathBuf {
        stages.push(SanitizerStage::Canonicalization);

        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            match std::env::current_dir() {
                Ok(cwd) => cwd.join(path),
                Err(e) => {
                    issues.push(SanitizerIssue::PathTraversal(format!(
                        "cannot resolve cwd: {e}"
                    )));
                    return path.to_path_buf();
                }
            }
        };

        // Try canonicalize, fall back to absolute if path doesn't exist
        absolute.canonicalize().unwrap_or(absolute)
    }

    fn stage_symlink_resolution(
        &self,
        path: &Path,
        workspace_root: Option<&Path>,
        stages: &mut Vec<SanitizerStage>,
        issues: &mut Vec<SanitizerIssue>,
    ) -> PathBuf {
        stages.push(SanitizerStage::SymlinkResolution);

        if !self.config.block_symlink_escape || !path.exists() {
            return path.to_path_buf();
        }

        match path.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                match path.canonicalize() {
                    Ok(resolved) => {
                        if let Some(root) = workspace_root {
                            let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
                            if !resolved.starts_with(&canonical_root) {
                                issues.push(SanitizerIssue::SymlinkEscape(path.display().to_string()));
                            }
                        }
                        resolved
                    }
                    Err(e) => {
                        // Broken symlink
                        issues.push(SanitizerIssue::SymlinkEscape(format!(
                            "broken symlink: {}",
                            e
                        )));
                        path.to_path_buf()
                    }
                }
            }
            Ok(metadata) if cfg!(unix) && {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    metadata.file_type().is_fifo()
                }
                #[cfg(not(unix))]
                false
            } => {
                issues.push(SanitizerIssue::PathTraversal(format!(
                    "fifo pipe: {}",
                    path.display()
                )));
                path.to_path_buf()
            }
            _ => path.to_path_buf(),
        }
    }

    fn stage_scope_check(
        &self,
        path: &Path,
        workspace_root: Option<&Path>,
        stages: &mut Vec<SanitizerStage>,
        issues: &mut Vec<SanitizerIssue>,
    ) -> PathBuf {
        stages.push(SanitizerStage::ScopeCheck);

        if let Some(root) = workspace_root {
            let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            if !canonical_path.starts_with(&canonical_root) {
                issues.push(SanitizerIssue::OutOfScope(path.display().to_string()));
            }
        }

        path.to_path_buf()
    }

    fn stage_encoding_detection(
        &self,
        path: &Path,
        stages: &mut Vec<SanitizerStage>,
        issues: &mut Vec<SanitizerIssue>,
    ) {
        stages.push(SanitizerStage::EncodingDetection);

        if !self.config.block_encoding_attacks {
            return;
        }

        let path_str = path.to_string_lossy();
        let detections = crate::path_traversal::detect_traversal(&path_str);

        for detection in &detections {
            match detection.kind {
                crate::path_traversal::TraversalKind::DirectoryDotDot => {
                    issues.push(SanitizerIssue::PathTraversal(path_str.to_string()));
                }
                crate::path_traversal::TraversalKind::DoubleEncoding => {
                    issues.push(SanitizerIssue::EncodingAttack(path_str.to_string()));
                }
                crate::path_traversal::TraversalKind::UnicodeNormalization => {
                    issues.push(SanitizerIssue::EncodingAttack(path_str.to_string()));
                }
                crate::path_traversal::TraversalKind::NullByte => {
                    issues.push(SanitizerIssue::NullByte(path_str.to_string()));
                }
                crate::path_traversal::TraversalKind::DeviceFile => {
                    issues.push(SanitizerIssue::DeviceFile(path_str.to_string()));
                }
                crate::path_traversal::TraversalKind::ProcSelfFd => {
                    issues.push(SanitizerIssue::PathTraversal(path_str.to_string()));
                }
                crate::path_traversal::TraversalKind::WindowsAlternateDataStream => {
                    issues.push(SanitizerIssue::PathTraversal(path_str.to_string()));
                }
                _ => {}
            }
        }
    }

    fn stage_size_check(
        &self,
        path: &Path,
        limit: u64,
        stages: &mut Vec<SanitizerStage>,
        issues: &mut Vec<SanitizerIssue>,
    ) {
        stages.push(SanitizerStage::SizeCheck);

        if let Ok(metadata) = path.metadata() {
            let len = metadata.len();
            if len > limit {
                issues.push(SanitizerIssue::SizeLimitExceeded {
                    limit,
                    actual: len,
                });
            }
        }
    }

    fn stage_allowlist(
        &self,
        _path: &Path,
        stages: &mut Vec<SanitizerStage>,
        issues: &mut Vec<SanitizerIssue>,
    ) {
        stages.push(SanitizerStage::Allowlist);

        if _path.to_string_lossy().contains('\0') {
            issues.push(SanitizerIssue::NullByte(_path.display().to_string()));
        }

        if self.config.block_device_files {
            let lower = _path.to_string_lossy().to_lowercase();
            if lower.starts_with("/dev/") || lower.starts_with("/proc/") || lower.starts_with("/sys/")
            {
                issues.push(SanitizerIssue::DeviceFile(_path.display().to_string()));
            }
        }
    }
}

fn resolve_dotdot(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let segments: Vec<&str> = path.split('/').collect();
    let mut result: Vec<&str> = Vec::with_capacity(segments.len());

    for seg in segments {
        match seg {
            "" | "." => {}
            ".." => {
                if result.is_empty() && !is_absolute {
                    // Relative path going above root: keep the ../
                    result.push("..");
                } else if !result.is_empty() && result.last() != Some(&"..") {
                    result.pop();
                } else if !is_absolute {
                    result.push("..");
                }
            }
            _ => result.push(seg),
        }
    }

    let output = result.join("/");
    if is_absolute {
        format!("/{output}")
    } else {
        output
    }
}

pub fn track_file_operation() -> u64 {
    FILE_OPS_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn file_op_count() -> u64 {
    FILE_OPS_COUNTER.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizer_rejects_null_byte() {
        let s = Sanitizer::with_defaults();
        let result = s.sanitize_for_read("hello\0.txt", None);
        assert!(result.issues.iter().any(|i| matches!(i, SanitizerIssue::NullByte(_))));
    }

    #[test]
    fn sanitizer_rejects_device_file() {
        let s = Sanitizer::with_defaults();
        let result = s.sanitize_for_read("/dev/sda", None);
        assert!(result.issues.iter().any(|i| matches!(i, SanitizerIssue::DeviceFile(_))));
    }

    #[test]
    fn sanitizer_allows_normal_file() {
        let dir = std::env::temp_dir().join(format!("sanitizer-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let s = Sanitizer::with_defaults();
        let result = s.sanitize_for_read(file_path.to_str().unwrap(), None);
        assert!(result.is_allowed());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitizer_rejects_out_of_scope() {
        let dir = std::env::temp_dir().join(format!("sanitizer-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ws = dir.join("workspace");
        std::fs::create_dir(&ws).unwrap();
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, "data").unwrap();

        let s = Sanitizer::with_defaults();
        let result = s.sanitize_for_read(outside.to_str().unwrap(), Some(&ws));
        assert!(result.issues.iter().any(|i| matches!(i, SanitizerIssue::OutOfScope(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitizer_stages_tracked() {
        let s = Sanitizer::with_defaults();
        let result = s.sanitize_for_read("src/lib.rs", None);
        assert!(!result.stages_passed.is_empty());
        assert_eq!(result.stages_passed.len(), 7);
    }

    #[test]
    fn sanitizer_rejects_oversized_file() {
        let dir = std::env::temp_dir().join(format!("sanitizer-size-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.bin");
        let data = vec![0u8; 100];
        std::fs::write(&big, &data).unwrap();

        let mut config = SanitizerConfig::default();
        config.max_read_size = 50;
        let s = Sanitizer::new(config);
        let result = s.sanitize_for_read(big.to_str().unwrap(), None);
        assert!(result.issues.iter().any(|i| matches!(i, SanitizerIssue::SizeLimitExceeded { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_dotdot_basic() {
        assert_eq!(resolve_dotdot("foo/../bar"), "bar");
        assert_eq!(resolve_dotdot("foo/bar/../../baz"), "baz");
        assert_eq!(resolve_dotdot("a/b/c/../../d"), "a/d");
    }

    #[test]
    fn resolve_dotdot_absolute() {
        assert_eq!(resolve_dotdot("/foo/../bar"), "/bar");
        assert_eq!(resolve_dotdot("/foo/bar/../../baz"), "/baz");
    }

    #[test]
    fn resolve_dotdot_above_root_relative() {
        // Relative paths can go above cwd
        let r = resolve_dotdot("../../etc");
        assert_eq!(r, "../../etc");
    }

    #[test]
    fn file_op_counter_works() {
        let a = track_file_operation();
        let b = track_file_operation();
        assert!(b > a);
    }
}
