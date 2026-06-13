//! Ephemeral tmpfs — Temporary filesystem for sandboxed execution.
//!
//! Provides tmpfs-backed temporary directories with lifecycle management:
//! - Creation of tmpfs mounts (requires mount namespace or privileged access)
//! - Ephemeral working directories that are cleaned up after execution
//! - Memory-backed storage for fast read/write operations

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TmpfsConfig {
    pub size_mb: u64,
    pub mount_point: Option<PathBuf>,
    pub working_directory: PathBuf,
    pub cleanup_on_drop: bool,
}

impl Default for TmpfsConfig {
    fn default() -> Self {
        Self {
            size_mb: 64,
            mount_point: None,
            working_directory: std::env::temp_dir().join(format!(
                "opencode_tmpfs_{}",
                std::process::id()
            )),
            cleanup_on_drop: true,
        }
    }
}

/// An ephemeral tmpfs-backed working directory.
pub struct EphemeralTmpfs {
    pub path: PathBuf,
    cleanup_on_drop: bool,
}

impl EphemeralTmpfs {
    /// Create a new ephemeral tmpfs directory.
    /// Creates the directory on the filesystem (not a real tmpfs mount unless
    /// you have mount permissions). The tmpfs mount requires either:
    /// - A mount namespace with CAP_SYS_ADMIN
    /// - Running as root
    /// - User namespace with mount capabilities
    pub fn new(config: &TmpfsConfig) -> Result<Self, String> {
        let path = config.working_directory.clone();

        // Create the directory
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("cannot create tmpfs dir '{}': {e}", path.display()))?;

        // Try to mount tmpfs if a mount point is configured
        if let Some(ref mount_point) = config.mount_point {
            if let Err(e) = Self::try_mount_tmpfs(mount_point, config.size_mb) {
                log::warn!("tmpfs mount failed (non-fatal, using directory): {e}");
            }
        }

        Ok(Self {
            path,
            cleanup_on_drop: config.cleanup_on_drop,
        })
    }

    /// Create an ephemeral working directory in a parent workspace.
    pub fn in_workspace(workspace: &Path) -> Result<Self, String> {
        let path = workspace.join(format!(".sandbox-tmp-{}", std::process::id()));
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("cannot create workspace tmp '{}': {e}", path.display()))?;
        Ok(Self {
            path,
            cleanup_on_drop: true,
        })
    }

    /// Try to mount a tmpfs at the given path.
    /// Requires CAP_SYS_ADMIN or a user namespace with mount capabilities.
    fn try_mount_tmpfs(mount_point: &Path, size_mb: u64) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            std::fs::create_dir_all(mount_point)
                .map_err(|e| format!("cannot create mount point '{}': {e}", mount_point.display()))?;

            let source = std::ffi::CString::new("tmpfs")
                .map_err(|_| "invalid source".to_string())?;
            let target = std::ffi::CString::new(
                mount_point
                    .to_str()
                    .ok_or_else(|| "invalid mount point path".to_string())?,
            )
            .map_err(|_| "invalid target".to_string())?;
            let fstype = std::ffi::CString::new("tmpfs")
                .map_err(|_| "invalid fstype".to_string())?;
            let options = std::ffi::CString::new(format!("size={}m", size_mb))
                .map_err(|_| "invalid options".to_string())?;

            let ret = unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    fstype.as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    options.as_ptr() as *const std::ffi::c_void,
                )
            };

            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!("mount tmpfs: {err}"));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (mount_point, size_mb);
            Err("tmpfs mounts are only supported on Linux".to_string())
        }
    }

    /// Get the path to the tmpfs directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a file inside the tmpfs.
    pub fn write_file(&self, rel_path: &str, contents: &[u8]) -> Result<PathBuf, String> {
        let full = self.path.join(rel_path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create parent '{}': {e}", parent.display()))?;
        }
        std::fs::write(&full, contents)
            .map_err(|e| format!("cannot write '{}': {e}", full.display()))?;
        Ok(full)
    }

    /// Read a file from inside the tmpfs.
    pub fn read_file(&self, rel_path: &str) -> Result<Vec<u8>, String> {
        let full = self.path.join(rel_path);
        std::fs::read(&full).map_err(|e| format!("cannot read '{}': {e}", full.display()))
    }

    /// Clean up the tmpfs directory.
    pub fn cleanup(&self) -> Result<(), String> {
        if self.path.exists() {
            std::fs::remove_dir_all(&self.path)
                .map_err(|e| format!("cannot cleanup tmpfs '{}': {e}", self.path.display()))?;
        }
        Ok(())
    }
}

impl Drop for EphemeralTmpfs {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tmpfs_config_default() {
        let config = TmpfsConfig::default();
        assert_eq!(config.size_mb, 64);
        assert!(config.cleanup_on_drop);
    }

    #[test]
    fn test_ephemeral_tmpfs_create() {
        let config = TmpfsConfig {
            working_directory: std::env::temp_dir().join(format!(
                "test_ephemeral_{}",
                std::process::id()
            )),
            ..Default::default()
        };
        let tmpfs = EphemeralTmpfs::new(&config).unwrap();
        assert!(tmpfs.path().exists());
        // Cleanup happens on drop
    }

    #[test]
    fn test_ephemeral_tmpfs_write_read() {
        let config = TmpfsConfig {
            working_directory: std::env::temp_dir().join(format!(
                "test_rw_{}",
                std::process::id()
            )),
            ..Default::default()
        };
        let tmpfs = EphemeralTmpfs::new(&config).unwrap();
        let written = tmpfs.write_file("test.txt", b"hello world").unwrap();
        assert!(written.exists());
        let content = tmpfs.read_file("test.txt").unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn test_ephemeral_tmpfs_in_workspace() {
        let workspace = std::env::temp_dir().join(format!(
            "test_workspace_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workspace).unwrap();

        let tmpfs = EphemeralTmpfs::in_workspace(&workspace).unwrap();
        assert!(tmpfs.path().exists());
        assert!(tmpfs.path().parent().unwrap() == workspace);

        // Cleanup
        let _ = tmpfs.cleanup();
        let _ = std::fs::remove_dir(&workspace);
    }

    #[test]
    fn test_ephemeral_tmpfs_cleanup() {
        let config = TmpfsConfig {
            working_directory: std::env::temp_dir().join(format!(
                "test_cleanup_{}",
                std::process::id()
            )),
            cleanup_on_drop: true,
            ..Default::default()
        };
        let path = config.working_directory.clone();
        {
            let tmpfs = EphemeralTmpfs::new(&config).unwrap();
            assert!(path.exists());
            drop(tmpfs); // triggers cleanup
        }
        // Directory should be removed
        assert!(!path.exists());
    }

    #[test]
    fn test_ephemeral_tmpfs_nested_dirs() {
        let config = TmpfsConfig {
            working_directory: std::env::temp_dir().join(format!(
                "test_nested_{}",
                std::process::id()
            )),
            ..Default::default()
        };
        let tmpfs = EphemeralTmpfs::new(&config).unwrap();
        let written = tmpfs
            .write_file("a/b/c/deep.txt", b"deep")
            .unwrap();
        assert!(written.exists());
        assert_eq!(tmpfs.read_file("a/b/c/deep.txt").unwrap(), b"deep");
    }

    #[test]
    fn test_tmpfs_config_custom_size() {
        let config = TmpfsConfig {
            size_mb: 128,
            ..Default::default()
        };
        assert_eq!(config.size_mb, 128);
    }
}
