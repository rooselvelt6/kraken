//! macOS Sandbox — Seatbelt profiles via `sandbox_init(3)`.
//!
//! Uses Apple's Sandbox framework (Sandbox.h) to restrict process capabilities.
//! The sandbox, once applied, is irreversible for the process lifetime.
//!
//! Seatbelt profiles are defined in `.sb` format (similar to App Sandbox).
//! Available profiles:
//!   - "no-network" — Deny all network access
//!   - "no-write" — Deny file write access except to temporary directory
//!   - "read-only" — Deny all file write access

#![allow(non_upper_case_globals)]

#[cfg(target_os = "macos")]
use std::ffi::CString;

#[cfg(target_os = "macos")]
extern "C" {
    fn sandbox_init(profile: *const std::ffi::c_char, flags: u64, errorbuf: *mut *mut std::ffi::c_char) -> std::ffi::c_int;
    fn sandbox_free_error(errorbuf: *mut std::ffi::c_char);
}

/// Sandbox profile types for macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsSandboxProfile {
    /// No network access
    NoNetwork,
    /// No file writes except temp
    NoWrite,
    /// Read-only filesystem
    ReadOnly,
    /// Custom profile SBPL string
    Custom(&'static str),
}

impl MacOsSandboxProfile {
    #[cfg(target_os = "macos")]
    fn profile_string(&self) -> &str {
        match self {
            Self::NoNetwork => "(
                (version 1),
                (deny default),
                (allow file-read*),
                (allow process*),
                (allow sysctl*),
                (allow mach*),
                (deny network*),
            )",
            Self::NoWrite => "(
                (version 1),
                (deny default),
                (allow file-read*),
                (allow file-write* (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath (env \"TMPDIR\"))),
                (allow process*),
                (allow sysctl*),
                (allow mach*),
                (allow network*),
            )",
            Self::ReadOnly => "(
                (version 1),
                (deny default),
                (allow file-read*),
                (allow process*),
                (allow sysctl*),
                (allow mach*),
                (deny file-write*),
                (allow network*),
            )",
            Self::Custom(s) => s,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacOsSandbox {
    pub profile: MacOsSandboxProfile,
    pub enabled: bool,
}

impl Default for MacOsSandbox {
    fn default() -> Self {
        Self {
            profile: MacOsSandboxProfile::NoNetwork,
            enabled: true,
        }
    }
}

impl MacOsSandbox {
    pub fn new(profile: MacOsSandboxProfile) -> Self {
        Self {
            profile,
            enabled: true,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Apply the macOS sandbox profile.
    /// This is irreversible — once applied, restrictions persist until process exit.
    pub fn apply(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            let profile_str = self.profile.profile_string();
            let c_profile =
                CString::new(profile_str).map_err(|e| format!("CString: {e}"))?;

            let mut errorbuf: *mut std::ffi::c_char = std::ptr::null_mut();
            let ret = unsafe {
                sandbox_init(
                    c_profile.as_ptr(),
                    0, // no flags (not kSandboxNoSandbox)
                    &mut errorbuf,
                )
            };

            if ret != 0 {
                let err_msg = if !errorbuf.is_null() {
                    let msg = unsafe { std::ffi::CStr::from_ptr(errorbuf) }
                        .to_string_lossy()
                        .into_owned();
                    unsafe { sandbox_free_error(errorbuf) };
                    msg
                } else {
                    "unknown sandbox_init error".to_string()
                };
                return Err(format!("sandbox_init: {err_msg}"));
            }

            Ok(())
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = self.profile;
            Err("macOS sandbox is only available on macOS".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_sandbox_default() {
        let sb = MacOsSandbox::default();
        assert!(sb.enabled);
        assert_eq!(sb.profile, MacOsSandboxProfile::NoNetwork);
    }

    #[test]
    fn test_macos_sandbox_disabled() {
        let sb = MacOsSandbox::disabled();
        assert!(!sb.enabled);
        assert!(sb.apply().is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_sandbox_profiles() {
        let profiles = [
            MacOsSandboxProfile::NoNetwork,
            MacOsSandboxProfile::NoWrite,
            MacOsSandboxProfile::ReadOnly,
        ];
        for profile in &profiles {
            let s = profile.profile_string();
            assert!(!s.is_empty());
            assert!(s.contains("(version 1)"));
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_sandbox_custom_profile() {
        let custom = MacOsSandboxProfile::Custom("(version 1)(deny default)");
        let s = custom.profile_string();
        assert!(s.contains("deny default"));
    }

    #[test]
    fn test_macos_sandbox_apply_not_macos() {
        let sb = MacOsSandbox::new(MacOsSandboxProfile::NoNetwork);
        if cfg!(target_os = "macos") {
            // On macOS, this may fail due to sandbox already being active
            // or succeed. Either is fine.
            let _ = sb.apply();
        } else {
            // On non-macOS, it should fail
            assert!(sb.apply().is_err());
        }
    }
}
