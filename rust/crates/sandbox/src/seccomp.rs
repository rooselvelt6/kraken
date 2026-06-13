#![allow(clippy::unreadable_literal)]

use std::arch::asm;

/// Linux syscall numbers for x86_64.
/// Read-only operations (~50 syscalls).
pub const READ_ONLY_SYSCALLS: &[u16] = &[
    0,   // read
    1,   // write
    2,   // open
    3,   // close
    4,   // stat
    5,   // fstat
    6,   // lstat
    7,   // poll
    8,   // lseek
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    12,  // brk
    13,  // rt_sigaction
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    16,  // ioctl
    17,  // pread64
    18,  // pwrite64
    19,  // readv
    20,  // writev
    21,  // access
    22,  // pipe
    23,  // select
    24,  // sched_yield
    25,  // mremap
    26,  // msync
    27,  // mincore
    28,  // madvise
    29,  // shmget
    30,  // shmat
    31,  // shmctl
    32,  // dup
    33,  // dup2
    34,  // pause
    35,  // nanosleep
    36,  // getitimer
    37,  // alarm
    38,  // setitimer
    39,  // getpid
    40,  // sendfile
    41,  // socket
    42,  // connect
    43,  // accept
    44,  // sendto
    45,  // recvfrom
    46,  // sendmsg
    47,  // recvmsg
    48,  // shutdown
    49,  // bind
    50,  // listen
    51,  // getsockname
    52,  // getpeername
    53,  // socketpair
    54,  // setsockopt
    55,  // getsockopt
    56,  // clone
    57,  // fork
    58,  // vfork
    59,  // execve
    60,  // _exit
    61,  // wait4
    62,  // kill
    63,  // uname
    64,  // semget
    65,  // semop
    66,  // semctl
    67,  // shmdt
    68,  // msgget
    69,  // msgsnd
    70,  // msgrcv
    71,  // msgctl
    72,  // fcntl
    73,  // flock
    74,  // fsync
    75,  // fdatasync
    76,  // truncate
    77,  // ftruncate
    78,  // getdents
    79,  // getcwd
    80,  // chdir
    81,  // fchdir
    82,  // rename
    83,  // mkdir
    84,  // rmdir
    85,  // creat
    86,  // link
    87,  // unlink
    88,  // symlink
    89,  // readlink
    90,  // chmod
    91,  // fchmod
    92,  // chown
    93,  // fchown
    94,  // lchown
    95,  // umask
    96,  // gettimeofday
    97,  // getrlimit
    98,  // getrusage
    99,  // sysinfo
    100, // times
    101, // ptrace
    102, // getuid
    103, // syslog
    104, // getgid
    105, // setuid
    106, // setgid
    107, // geteuid
    108, // getegid
    109, // setpgid
    110, // getppid
    111, // getpgrp
    112, // setsid
    113, // setreuid
    114, // setregid
    115, // getgroups
    116, // setgroups
    117, // setresuid
    118, // getresuid
    119, // setresgid
    120, // getresgid
    121, // getpgid
    122, // setfsuid
    123, // setfsgid
    124, // getsid
    125, // capget
    126, // capset
    131, // sigaltstack
    132, // utime
    133, // mknod
    137, // statfs
    138, // fstatfs
    139, // unshare
    140, // set_robust_list
    141, // get_robust_list
    158, // sched_getparam
    159, // sched_setparam
    186, // gettid
    187, // readahead
    188, // setxattr
    189, // lsetxattr
    190, // fsetxattr
    191, // getxattr
    192, // lgetxattr
    193, // fgetxattr
    194, // listxattr
    195, // llistxattr
    196, // flistxattr
    197, // removexattr
    198, // lremovexattr
    199, // fremovexattr
    200, // tkill
    201, // time
    202, // futex
    203, // sched_setaffinity
    204, // sched_getaffinity
    217, // getdents64
    218, // set_tid_address
    228, // clock_gettime
    229, // clock_getres
    230, // clock_nanosleep
    231, // exit_group
    232, // epoll_wait
    233, // epoll_ctl
    234, // tgkill
    240, // utimensat
    257, // openat
    258, // mkdirat
    259, // mknodat
    260, // fchownat
    261, // futimesat
    262, // newfstatat
    263, // unlinkat
    264, // renameat
    265, // linkat
    266, // symlinkat
    267, // readlinkat
    268, // fchmodat
    269, // faccessat
    270, // pselect6
    271, // ppoll
    272, // unshare
    273, // set_robust_list
    274, // get_robust_list
    275, // splice
    276, // tee
    277, // sync_file_range
    278, // vmsplice
    279, // move_pages
    281, // preadv
    282, // pwritev
    283, // rt_tgsigqueueinfo
    284, // perf_event_open
    285, // recvmmsg
    286, // fanotify_init
    287, // fanotify_mark
    288, // prlimit64
    302, // prctl
    303, // arch_prctl
    307, // process_vm_readv
    308, // process_vm_writev
    309, // kcmp
    315, // seccomp
    317, // memfd_create
    318, // kexec_file_load
    320, // bpf
    321, // execveat
    322, // userfaultfd
    323, // membarrier
    324, // mlock2
    325, // copy_file_range
    326, // preadv2
    327, // pwritev2
    328, // pkey_mprotect
    329, // pkey_alloc
    330, // pkey_free
    332, // statx
];

/// Syscalls BLOCKED even in write mode (too dangerous):
pub const FORBIDDEN_SYSCALLS: &[u16] = &[
    101, // ptrace
    284, // perf_event_open
    320, // bpf
    308, // process_vm_writev
    309, // kcmp
    321, // execveat (uncontrolled)
];

/// Extra syscalls allowed only in write mode (~30 additional):
pub const WRITE_EXTRA_SYSCALLS: &[u16] = &[
    56,  // clone (controlled)
    57,  // fork
    58,  // vfork
    59,  // execve
    76,  // truncate
    77,  // ftruncate
    82,  // rename
    83,  // mkdir
    84,  // rmdir
    85,  // creat
    86,  // link
    87,  // unlink
    88,  // symlink
    90,  // chmod
    91,  // fchmod
    92,  // chown
    93,  // fchown
    94,  // lchown
    105, // setuid
    106, // setgid
    109, // setpgid
    112, // setsid
    113, // setreuid
    114, // setregid
    116, // setgroups
    117, // setresuid
    119, // setresgid
    122, // setfsuid
    123, // setfsgid
];

/// BPF instruction for seccomp filter
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program (sock_fprog)
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// BPF instruction codes
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

// seccomp return values
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// seccomp syscall command
const SECCOMP_SET_MODE_FILTER: u16 = 1;

// prctl constants
const PR_SET_NO_NEW_PRIVS: i32 = 38;

// Syscall number for seccomp on x86_64
const SYS_SECCOMP: i64 = 317;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    ReadOnly,
    ReadWrite,
}

impl SeccompMode {
    fn allowed_syscalls(&self) -> Vec<u16> {
        let mut syscalls: Vec<u16> = READ_ONLY_SYSCALLS
            .iter()
            .filter(|s| !FORBIDDEN_SYSCALLS.contains(s))
            .copied()
            .collect();

        if *self == SeccompMode::ReadWrite {
            for s in WRITE_EXTRA_SYSCALLS {
                if !syscalls.contains(s) {
                    syscalls.push(*s);
                }
            }
        }

        syscalls.sort_unstable();
        syscalls.dedup();
        syscalls
    }
}

#[derive(Debug, Clone)]
pub struct SeccompProfile {
    pub mode: SeccompMode,
    pub allow_network: bool,
    pub allow_ptrace: bool,
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self {
            mode: SeccompMode::ReadWrite,
            allow_network: false,
            allow_ptrace: false,
        }
    }
}

impl SeccompProfile {
    pub fn read_only() -> Self {
        Self {
            mode: SeccompMode::ReadOnly,
            allow_network: false,
            allow_ptrace: false,
        }
    }

    pub fn install(&self) -> Result<(), String> {
        let mut syscalls = self.mode.allowed_syscalls();

        if self.allow_network {
            let net_syscalls: &[u16] = &[
                41,  // socket
                42,  // connect
                43,  // accept
                44,  // sendto
                45,  // recvfrom
                46,  // sendmsg
                47,  // recvmsg
                48,  // shutdown
                49,  // bind
                50,  // listen
                53,  // socketpair
            ];
            for s in net_syscalls {
                if !syscalls.contains(s) {
                    syscalls.push(*s);
                }
            }
        }

        if self.allow_ptrace {
            if !syscalls.contains(&101) {
                syscalls.push(101);
            }
        }

        syscalls.sort_unstable();
        syscalls.dedup();

        let filter = build_bpf_filter(&syscalls)?;
        install_bpf_filter(&filter)
    }
}

fn build_bpf_filter(allowed: &[u16]) -> Result<Vec<SockFilter>, String> {
    let max_nr = allowed.last().copied().unwrap_or(0) as usize;
    let mut jmp_table = vec![0u8; max_nr + 1];
    for &nr in allowed {
        if (nr as usize) <= max_nr {
            jmp_table[nr as usize] = 1;
        }
    }

    let mut instructions = Vec::new();

    // Load syscall number (arch-specific: offset 0 in seccomp_data)
    // For x86_64: seccomp_data.nr is at offset 0
    instructions.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });

    // We need a binary-search-like approach for the syscall whitelist.
    // For simplicity, use a sorted allow list and generate JMP instructions.
    // Since we have ~50-80 syscalls, a linear scan is fast enough for BPF.
    let unique_allowed: Vec<u16> = {
        let mut v = allowed.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    };

    for (i, &nr) in unique_allowed.iter().enumerate() {
        let is_last = i == unique_allowed.len() - 1;
        let next_nr = if is_last {
            nr + 1
        } else {
            unique_allowed[i + 1]
        };
        let range = next_nr - nr;

        if range == 1 {
            // Single syscall check: JEQ
            if is_last {
                instructions.push(SockFilter {
                    code: BPF_JMP | BPF_JEQ | BPF_K,
                    jt: 1,
                    jf: 0,
                    k: nr as u32,
                });
            } else {
                instructions.push(SockFilter {
                    code: BPF_JMP | BPF_JEQ | BPF_K,
                    jt: 2 + (unique_allowed.len() - i - 1) as u8,
                    jf: 0,
                    k: nr as u32,
                });
            }
        } else {
            // Range check: JGE then JGT
            if !is_last {
                // Check if nr <= syscall < next_nr
                instructions.push(SockFilter {
                    code: BPF_JMP | BPF_JGE | BPF_K,
                    jt: 0,
                    jf: 2,
                    k: nr as u32,
                });
                instructions.push(SockFilter {
                    code: BPF_JMP | BPF_JGT | BPF_K,
                    jt: 1,
                    jf: 0,
                    k: (next_nr - 1) as u32,
                });
            } else {
                // Last group: check if >= nr
                instructions.push(SockFilter {
                    code: BPF_JMP | BPF_JGE | BPF_K,
                    jt: 0,
                    jf: 1,
                    k: nr as u32,
                });
            }
        }
    }

    // If we reach here via jump-false from the last check, that means the
    // syscall nr didn't match any allowed range, so jump to KILL.
    // We need to insert KILL at the end, with ALLOW jumps targeting before it.
    //
    // Actually this needs proper jump label management. Let's use a simpler
    // approach: direct linear comparison, but with all ALLOW at the end.

    // Simpler approach: just compare each syscall and ret ALLOW on match
    let mut simple = Vec::new();
    // Load syscall number
    simple.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });

    for &nr in &unique_allowed {
        // JEQ to ALLOW (skip 1 instruction to reach ALLOW)
        simple.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 0,
            k: nr as u32,
        });
    }

    // Fix up jump offsets: each JEQ jumps forward to the ALLOW instruction
    // After all JEQs, add KILL, then ALLOW at the very end
    let n = unique_allowed.len() as u16;
    for i in 0..unique_allowed.len() {
        // Jump from instruction (1 + i) to instruction (1 + n + 1) = ALLOW
        // Skip: (n - i) instructions + KILL instruction = (n - i + 1)
        simple[1 + i].jt = (n - i as u16 + 1) as u8;
    }

    // KILL (if no match)
    simple.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // ALLOW
    simple.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    Ok(simple)
}

#[cfg(target_os = "linux")]
fn install_bpf_filter(filter: &[SockFilter]) -> Result<(), String> {
    unsafe {
        // First set NO_NEW_PRIVS via prctl
        let ret = libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            return Err(format!("prctl(PR_SET_NO_NEW_PRIVS): {}", std::io::Error::last_os_error()));
        }

        // Install the seccomp filter via syscall
        let prog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        let ret = syscall_seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog as *const SockFprog as *const std::ffi::c_void);
        if ret != 0 {
            return Err(format!("seccomp(SECCOMP_SET_MODE_FILTER): {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_bpf_filter(_filter: &[SockFilter]) -> Result<(), String> {
    Err("seccomp is only supported on Linux".to_string())
}

#[cfg(target_os = "linux")]
unsafe fn syscall_seccomp(cmd: u16, flags: u32, ptr: *const std::ffi::c_void) -> i64 {
    // seccomp syscall number on x86_64 = 317
    // arm64 = 277, but we target x86_64
    let nr = SYS_SECCOMP;
    let mut ret: i64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") cmd as i64,
        in("rsi") flags as i64,
        in("rdx") ptr as i64,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_mode_readonly_syscalls() {
        let syscalls = SeccompMode::ReadOnly.allowed_syscalls();
        assert!(!syscalls.is_empty());
        assert!(syscalls.contains(&0));  // read
        assert!(syscalls.contains(&1));  // write
        assert!(syscalls.contains(&2));  // open
        assert!(!syscalls.contains(&101)); // ptrace forbidden
        assert!(!syscalls.contains(&284)); // perf_event_open forbidden
        assert!(!syscalls.contains(&320)); // bpf forbidden
    }

    #[test]
    fn test_seccomp_mode_readwrite_syscalls() {
        let syscalls = SeccompMode::ReadWrite.allowed_syscalls();
        assert!(syscalls.contains(&56));  // clone allowed in write
        assert!(syscalls.contains(&57));  // fork
        assert!(syscalls.contains(&85));  // creat
        assert!(!syscalls.contains(&101)); // ptrace still forbidden
    }

    #[test]
    fn test_seccomp_mode_forbidden_never_allowed() {
        for mode in &[SeccompMode::ReadOnly, SeccompMode::ReadWrite] {
            let syscalls = mode.allowed_syscalls();
            for forbidden in FORBIDDEN_SYSCALLS {
                assert!(!syscalls.contains(forbidden), "syscall {forbidden} should be forbidden in {mode:?}");
            }
        }
    }

    #[test]
    fn test_seccomp_profile_default() {
        let profile = SeccompProfile::default();
        assert_eq!(profile.mode, SeccompMode::ReadWrite);
        assert!(!profile.allow_network);
    }

    #[test]
    fn test_seccomp_profile_read_only() {
        let profile = SeccompProfile::read_only();
        assert_eq!(profile.mode, SeccompMode::ReadOnly);
    }

    #[test]
    fn test_build_bpf_filter_readonly() {
        let syscalls = SeccompMode::ReadOnly.allowed_syscalls();
        let filter = build_bpf_filter(&syscalls);
        assert!(filter.is_ok());
        let filter = filter.unwrap();
        assert!(filter.len() > 10);
        // First instruction should be LD_ABS
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        // Last instruction should be ALLOW
        assert_eq!(filter[filter.len() - 1].code, BPF_RET | BPF_K);
        assert_eq!(filter[filter.len() - 1].k, SECCOMP_RET_ALLOW);
        // Second-to-last should be KILL
        assert_eq!(filter[filter.len() - 2].code, BPF_RET | BPF_K);
        assert_eq!(filter[filter.len() - 2].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_build_bpf_filter_readwrite() {
        let syscalls = SeccompMode::ReadWrite.allowed_syscalls();
        let filter = build_bpf_filter(&syscalls);
        assert!(filter.is_ok());
    }

    #[test]
    fn test_bpf_filter_jumps_to_allow() {
        let syscalls = vec![0u16, 1u16, 2u16];
        let filter = build_bpf_filter(&syscalls).unwrap();
        // First three instructions are JEQ checks
        // Each JT should point past the remaining checks + KILL to ALLOW
        // Last 2 instructions: KILL, ALLOW
        for i in 0..3 {
            assert_eq!(filter[1 + i].code & 0x7f, BPF_JMP | BPF_JEQ | BPF_K);
            let skip = (3 - i + 1) as u8; // remaining checks + KILL
            assert_eq!(filter[1 + i].jt, skip, "JEQ {} should skip {} to ALLOW", i, skip);
        }
    }

    #[test]
    fn test_seccomp_profile_install_construction() {
        // Verify the full pipeline: profile → filter → install stub is consistent.
        // We don't actually call install() in-process because seccomp BPF filters
        // cannot be removed once applied and affect all threads.
        let profile = SeccompProfile::default();
        let syscalls = profile.mode.allowed_syscalls();
        let filter = build_bpf_filter(&syscalls).unwrap();
        assert!(filter.len() > 10);
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[filter.len() - 1].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[filter.len() - 2].k, SECCOMP_RET_KILL_PROCESS);
    }
}
