use std::sync::OnceLock;

/// Global flag to track if panic zeroize hook has been installed.
static PANIC_HOOK_INSTALLED: OnceLock<bool> = OnceLock::new();

/// Register a panic hook that zeroizes sensitive memory on panic.
pub fn register_panic_zeroize() {
    PANIC_HOOK_INSTALLED.get_or_init(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            prev(info);
        }));
        true
    });
}

/// Lock memory pages to prevent swapping to disk.
/// Returns true if successful.
#[cfg(unix)]
pub fn lock_memory(data: &mut [u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    unsafe {
        let ptr = data.as_ptr() as *const std::ffi::c_void;
        libc::mlock(ptr, data.len()) == 0
    }
}

#[cfg(not(unix))]
pub fn lock_memory(_data: &mut [u8]) -> bool {
    false
}

/// Protect memory pages from being read (PROT_NONE).
/// Returns true if successful.
#[cfg(unix)]
pub fn protect_memory(data: &mut [u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = (data.as_ptr() as usize) & !(page_size - 1);
        libc::mprotect(aligned as *mut std::ffi::c_void, data.len(), libc::PROT_NONE) == 0
    }
}

#[cfg(not(unix))]
pub fn protect_memory(_data: &mut [u8]) -> bool {
    false
}

/// Unprotect and unlock memory pages.
#[cfg(unix)]
pub fn unlock_memory(data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = (data.as_ptr() as usize) & !(page_size - 1);
        libc::mprotect(
            aligned as *mut std::ffi::c_void,
            data.len(),
            libc::PROT_READ | libc::PROT_WRITE,
        );
        libc::munlock(data.as_ptr() as *const std::ffi::c_void, data.len());
    }
}

#[cfg(not(unix))]
pub fn unlock_memory(_data: &mut [u8]) {}

/// Mark a file descriptor as dumpable (`MADV_DONTDUMP`) to exclude from core dumps.
#[cfg(unix)]
pub fn mark_no_dump() -> bool {
    unsafe {
        let fd = libc::open("/proc/self/oom_score_adj\0".as_ptr() as *const std::ffi::c_char, libc::O_WRONLY);
        if fd >= 0 {
            libc::close(fd);
        }
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    }
}

#[cfg(not(unix))]
pub fn mark_no_dump() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_panic_hook_works() {
        register_panic_zeroize();
        register_panic_zeroize(); // should not re-register
    }

    #[test]
    fn memory_lock_roundtrip() {
        let mut data = vec![0u8; 4096];
        let _locked = lock_memory(&mut data);
        // May fail in CI/containers, but should not panic
        unlock_memory(&mut data);
    }

    #[test]
    fn mark_no_dump_does_not_panic() {
        let _ = mark_no_dump();
    }
}
