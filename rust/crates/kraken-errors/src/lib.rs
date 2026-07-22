//! Centralized error types for the Kraken workspace.
//!
//! Each domain crate defines its own error enum. This crate provides the
//! cross-cutting `KrakenError` wrapper that can hold any domain error and
//! implements `From` for the most common upstream error types.

use std::path::PathBuf;

// ─── Tool errors ────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("validation: {}", .0)]
    Validation(String),

    #[error("tool not found: {}", .0)]
    NotFound(String),

    #[error("permission denied: {}", .0)]
    PermissionDenied(String),

    #[error("invalid input: {}", .0)]
    InvalidInput(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("network: {}", .0)]
    Network(String),

    #[error("plugin: {}", .0)]
    Plugin(String),

    #[error("task: {}", .0)]
    Task(String),

    #[error("worker: {}", .0)]
    Worker(String),

    #[error("agent: {}", .0)]
    Agent(String),

    #[error("{}", .0)]
    Other(String),
}

impl From<String> for ToolError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

// ─── Sandbox errors ─────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("seccomp: {}", .0)]
    Seccomp(String),

    #[error("landlock: {}", .0)]
    Landlock(String),

    #[error("namespace: {}", .0)]
    Namespace(String),

    #[error("rlimit: {}", .0)]
    Rlimit(String),

    #[error("tmpfs: {}", .0)]
    Tmpfs(String),

    #[error("nsjail: {}", .0)]
    NsJail(String),

    #[error("mount: {}", .0)]
    Mount(String),

    #[error("platform unsupported: {}", .0)]
    PlatformUnsupported(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("path: {path}: {detail}")]
    Path { path: PathBuf, detail: String },

    #[error("{}", .0)]
    Other(String),
}

impl From<String> for SandboxError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

// ─── Security errors ────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("crypto cipher: {}", .0)]
    CipherInit(String),

    #[error("encrypt: {}", .0)]
    Encrypt(String),

    #[error("decrypt: {}", .0)]
    Decrypt(String),

    #[error("decode: {}", .0)]
    Decode(String),

    #[error("vault: {}", .0)]
    Vault(String),

    #[error("config: {}", .0)]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("validation: {}", .0)]
    Validation(String),

    #[error("{}", .0)]
    Other(String),
}

impl From<String> for SecurityError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

// ─── Wireless errors ────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum WirelessError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("command failed: {}", .0)]
    Command(String),

    #[error("parse: {}", .0)]
    Parse(String),

    #[error("device: {}", .0)]
    Device(String),

    #[error("{}", .0)]
    Other(String),
}

impl From<String> for WirelessError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

// ─── Forensics errors ───────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ForensicsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse: {}", .0)]
    Parse(String),

    #[error("not found: {}", .0)]
    NotFound(String),

    #[error("{}", .0)]
    Other(String),
}

impl From<String> for ForensicsError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

// ─── Network errors ─────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("dns: {}", .0)]
    Dns(String),

    #[error("protocol: {}", .0)]
    Protocol(String),

    #[error("{}", .0)]
    Other(String),
}

impl From<String> for NetworkError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

// ─── Unified KrakenError ────────────────────────────────────────────

/// The top-level error type that can represent any domain error in Kraken.
#[derive(Debug, thiserror::Error)]
pub enum KrakenError {
    #[error("tool: {0}")]
    Tool(#[from] ToolError),

    #[error("sandbox: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("security: {0}")]
    Security(#[from] SecurityError),

    #[error("wireless: {0}")]
    Wireless(#[from] WirelessError),

    #[error("forensics: {0}")]
    Forensics(#[from] ForensicsError),

    #[error("network: {0}")]
    Network(#[from] NetworkError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{}", .0)]
    Other(String),
}

impl From<String> for KrakenError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_roundtrip() {
        let err = ToolError::NotFound("bash".into());
        let display = format!("{err}");
        assert_eq!(display, "tool not found: bash");
    }

    #[test]
    fn sandbox_error_from_string() {
        let err: SandboxError = String::from("seccomp failed").into();
        assert!(format!("{err}").contains("seccomp failed"));
    }

    #[test]
    fn security_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err = SecurityError::Io(io_err);
        assert!(format!("{err}").contains("io:"));
    }

    #[test]
    fn kraken_error_from_tool_error() {
        let err: KrakenError = ToolError::PermissionDenied("denied".into()).into();
        assert!(format!("{err}").contains("tool:"));
    }

    #[test]
    fn kraken_error_from_string() {
        let err: KrakenError = String::from("something went wrong").into();
        assert_eq!(format!("{err}"), "something went wrong");
    }

    #[test]
    fn network_error_from_string() {
        let err: NetworkError = String::from("dns failed").into();
        assert!(format!("{err}").contains("dns failed"));
    }

    #[test]
    fn forensics_error_from_string() {
        let err: ForensicsError = String::from("parse error").into();
        assert!(format!("{err}").contains("parse error"));
    }
}
