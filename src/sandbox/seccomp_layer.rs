//! seccomp-bpf syscall allowlist.
//!
//! We use an allowlist rather than a blocklist: anything not explicitly
//! permitted returns ENOSYS (KillProcess would be stricter, but ENOSYS
//! lets Rust / glibc / rustyline degrade gracefully when they probe for
//! optional features at startup, so the shell actually boots).
//!
//! Crucially, `execve`/`execveat` are NOT on the allowlist: v1 runs
//! every builtin in-process, so there is no legitimate reason to ever
//! spawn a child. Denying execve collapses a huge class of escapes
//! (pager !cmd, find -exec, even if someone found a way to smuggle
//! one in at a layer above seccomp).
//!
//! Only x86_64 and aarch64 are wired up; other arches refuse to seal.

use anyhow::{Result, bail};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("skorupka only supports x86_64 and aarch64");

/// Apply the seccomp-bpf filter to the current thread (and, because we
/// set NO_NEW_PRIVS first, to every thread it later spawns).
pub fn apply() -> Result<()> {
    let allowed: Vec<libc::c_long> = allowed_syscalls();

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in allowed {
        rules.insert(nr, vec![]); // empty rule set = unconditional allow
    }

    // clone() is allowed, but ONLY when no new-namespace flags are set.
    // clone's first argument is `unsigned long flags`, held in a register,
    // which seccomp-bpf CAN filter. We reject any of CLONE_NEWNS, NEWUTS,
    // NEWIPC, NEWUSER, NEWPID, NEWNET, NEWCGROUP in a single MaskedEq rule:
    //     (flags & NS_MASK) == 0 → allow
    //     otherwise             → default action (ENOSYS)
    //
    // Defense-in-depth: mount/setns/pivot_root/unshare are already denied
    // elsewhere in this filter, so even if a namespace flag slipped past,
    // an attacker could not do anything useful inside a fresh namespace.
    // But defense-in-depth means closing what we can close, so we close
    // this too.
    //
    // clone3() below is NOT filtered because its flags live in a struct
    // pointed to by arg 0, and seccomp-bpf cannot dereference user memory.
    const CLONE_NS_MASK: u64 = (libc::CLONE_NEWNS
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWCGROUP) as u64;
    let clone_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_NS_MASK),
            0,
        )
        .expect("build clone seccomp condition"),
    ])
    .expect("build clone seccomp rule");
    rules.insert(libc::SYS_clone, vec![clone_rule]);

    // ioctl is allowed, but ONLY for a narrow set of READ-ONLY terminal
    // and fd-flag cmds. TIOCSTI ("push char into tty input") is the most
    // infamous escape vector and is excluded. The TCSETS* family (set
    // termios attrs) is also excluded — a compromised builtin could use
    // it to put the user's tty into raw/noecho mode and then pump ANSI
    // escapes that the operator's terminal emulator would interpret.
    // Rust stdio / glibc only need TCGETS to probe line-buffering.
    //
    // cmd is the 2nd syscall arg (index 1), a 32-bit int widened to a
    // 64-bit register. SeccompCmpArgLen::Dword compares the low 32 bits.
    const IOCTL_CMD_ARG: u8 = 1;
    let ioctl_allowed_cmds: &[u64] = &[
        0x5401, // TCGETS     — isatty / line-buffering probe (read-only)
        0x540F, // TIOCGPGRP  — foreground pgrp read (read-only)
        0x5413, // TIOCGWINSZ — window size read (read-only)
        0x541B, // FIONREAD   — bytes available to read (read-only)
        0x5421, // FIONBIO    — set O_NONBLOCK on fd (fd flag, not tty mode)
        0x5450, // FIOCLEX    — set FD_CLOEXEC (fd flag)
        0x5451, // FIONCLEX   — clear FD_CLOEXEC (fd flag)
    ];
    let ioctl_rules: Vec<SeccompRule> = ioctl_allowed_cmds
        .iter()
        .map(|&cmd| {
            SeccompRule::new(vec![
                SeccompCondition::new(
                    IOCTL_CMD_ARG,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    cmd,
                )
                .expect("build ioctl seccomp condition"),
            ])
            .expect("build ioctl seccomp rule")
        })
        .collect();
    rules.insert(libc::SYS_ioctl, ioctl_rules);

    let filter = SeccompFilter::new(
        rules,
        // Default action for anything NOT in the allowlist.
        SeccompAction::Errno(libc::ENOSYS as u32),
        // Action for rules that match (unconditional allow).
        SeccompAction::Allow,
        TARGET_ARCH,
    )
    .map_err(|e| anyhow::anyhow!("build seccomp filter: {:?}", e))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow::anyhow!("compile seccomp filter: {:?}", e))?;

    seccompiler::apply_filter(&prog)
        .map_err(|e| anyhow::anyhow!("apply seccomp filter: {:?}", e))?;

    // Sanity check: try something we *know* is denied. execve of a
    // nonexistent path should return ENOSYS, not ENOENT.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_execve,
            c"/nonexistent".as_ptr(),
            std::ptr::null::<*const libc::c_char>(),
            std::ptr::null::<*const libc::c_char>(),
        )
    };
    if rc != -1 {
        bail!("seccomp self-check: execve returned {} (expected -1)", rc);
    }
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if err != libc::ENOSYS {
        bail!(
            "seccomp self-check: execve errno={} (expected ENOSYS={})",
            err,
            libc::ENOSYS
        );
    }

    Ok(())
}

/// Return the list of syscalls we permit. Kept in one place so it can
/// be audited as a single unit.
fn allowed_syscalls() -> Vec<libc::c_long> {
    let mut v = vec![
        // --- process lifecycle ---
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        // --- thread creation (we need it for pipeline stages) ---
        // SYS_clone is installed separately above with a MaskedEq rule on
        // the flags argument that rejects every CLONE_NEW* namespace flag.
        // It is NOT listed here because BTreeMap::insert would overwrite
        // the filtered rule set with an unconditional allow.
        //
        // clone3 is required on modern glibc (2.34+, default on Ubuntu
        // 24.04 / kernel 6.8+). glibc's pthread_create uses clone3 first
        // and caches success after any successful call, so once we've
        // spawned the first pipeline thread it will never fall back to
        // SYS_clone — denying clone3 would break every pipeline.
        //
        // clone3 passes its flags inside a `struct clone_args` pointed
        // to by arg 0, and seccomp-bpf cannot dereference user memory,
        // so we cannot apply a MaskedEq rule here. This is a known
        // kernel-interface limitation, not a skorupka design choice.
        //
        // Defense-in-depth mitigations for the unfiltered path:
        //   - mount, umount2, pivot_root, chroot, setns, unshare, and
        //     SYS_clone-with-NS-flags are all denied. A fresh user or
        //     mount namespace gives the attacker no new filesystem reach.
        //   - execve/execveat are denied, so they cannot hand control to
        //     a setuid binary that would normally gain privileges across
        //     the namespace boundary.
        //   - Landlock is inherited across namespace creation.
        //   - PR_SET_NO_NEW_PRIVS is inherited and cannot be disabled.
        // The residual attack surface is therefore limited to whatever a
        // new-namespace-but-still-sandboxed process can do, which in
        // practice is nothing the parent couldn't already do.
        libc::SYS_clone3,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_membarrier,
        libc::SYS_rseq,
        // --- memory ---
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        // --- I/O ---
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_lseek,
        libc::SYS_close,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_fcntl,
        // ioctl is NOT added here — it's installed separately below with
        // an explicit cmd allowlist (TIOCSTI excluded).
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        // --- filesystem (landlock enforces paths) ---
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_getdents64,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        // --- process info ---
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getppid,
        libc::SYS_getpgid,
        libc::SYS_getpgrp,
        libc::SYS_uname,
        libc::SYS_prlimit64,
        libc::SYS_getrlimit,
        libc::SYS_getrandom,
        libc::SYS_sysinfo,
        // --- time ---
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        // --- misc runtime plumbing ---
        // prctl: glibc/rust probe PR_GET_DUMPABLE etc. We already set
        //   PR_SET_NO_NEW_PRIVS before seccomp seals, so allowing prctl
        //   post-seal cannot be used to disable that bit.
        libc::SYS_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_tgkill,
        libc::SYS_tkill,
        libc::SYS_kill,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigsuspend,
        libc::SYS_signalfd4,
        libc::SYS_fstatfs,
        libc::SYS_statfs,
        libc::SYS_getrusage,
        libc::SYS_times,
    ];

    // arch-specific extras
    #[cfg(target_arch = "x86_64")]
    {
        v.push(libc::SYS_arch_prctl);
        v.push(libc::SYS_stat);
        v.push(libc::SYS_lstat);
        v.push(libc::SYS_open);
        v.push(libc::SYS_access);
        v.push(libc::SYS_pipe);
        v.push(libc::SYS_select);
        v.push(libc::SYS_dup2);
        v.push(libc::SYS_epoll_create);
        v.push(libc::SYS_epoll_wait);
        v.push(libc::SYS_readlink);
        v.push(libc::SYS_poll);
    }

    v.sort();
    v.dedup();
    v
}
