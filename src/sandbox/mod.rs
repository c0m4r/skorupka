//! Sandbox orchestration.
//!
//! Call `seal()` exactly once, before reading any untrusted input. It
//! applies the security layers in strict order; if any layer fails, the
//! process exits rather than continuing unprotected.
//!
//!   1. PR_SET_NO_NEW_PRIVS
//!   2. Drop capabilities
//!   3. rlimits
//!   4. FD hygiene (open /dev/null, dup2 stdio, close stray fds)
//!   5. Landlock ruleset (RO view of allowed paths)
//!   6. seccomp-bpf filter (denies execve, ptrace, mount, …)

use anyhow::{Context, Result};
use std::path::Path;

pub mod caps;
pub mod fds;
pub mod landlock_layer;
pub mod noprivs;
pub mod rlimits;
pub mod seccomp_layer;

use crate::config::{Limits, UserPolicy};

/// Apply every sandbox layer in the correct order.
/// After this returns Ok(()), the current process is confined and cannot
/// `execve`, `ptrace`, mount, unshare, reach outside `allowed_paths_ro`,
/// or elevate privileges.
pub fn seal(policy: &UserPolicy, limits: &Limits) -> Result<()> {
    noprivs::set_no_new_privs().context("PR_SET_NO_NEW_PRIVS")?;
    caps::drop_all().context("dropping capabilities")?;
    rlimits::apply(limits).context("applying rlimits")?;
    fds::hygiene().context("fd hygiene")?;

    // Open O_PATH|O_NOFOLLOW fds to every allowed directory NOW — before
    // Landlock and seccomp are active.  Once we hold a file descriptor the
    // kernel pins the inode; any later rename or symlink swap of the
    // directory entry cannot redirect the Landlock rule to a different path.
    // Doing this here (rather than at config-parse time) keeps OwnedFd
    // lifetime management out of the config layer, and doing it before
    // seccomp means the open(2) syscall is still permitted.
    let path_fds =
        landlock_layer::open_path_fds(&policy.allowed_paths_ro).context("opening path fds")?;
    landlock_layer::apply(path_fds).context("landlock")?;
    seccomp_layer::apply().context("seccomp")?;
    Ok(())
}

/// `skorupka check` — print a readiness report.
///
/// Exits with code 0 when all required features are present. Exits with
/// code 1 if any required feature is missing so that CI and install
/// scripts can detect a broken host without parsing text.
pub fn check() -> Result<()> {
    let color = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
    let (green, yellow, red, bold, reset) = if color {
        ("\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[1m", "\x1b[0m")
    } else {
        ("", "", "", "", "")
    };

    let ok_tag   = format!("{green}[ok]  {reset}");
    let warn_tag = format!("{yellow}[warn]{reset}");
    let fail_tag = format!("{red}[FAIL]{reset}");

    println!("{bold}skorupka check{reset}");
    println!("==============");

    let mut failures: u32 = 0;
    let mut warnings: u32 = 0;

    // --- Kernel version ---------------------------------------------------
    let uts = nix::sys::utsname::uname().ok();
    let kver = uts
        .as_ref()
        .map(|u| u.release().to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("  {ok_tag} kernel:        {kver}");

    // --- Landlock LSM presence + ABI version ------------------------------
    // /sys/kernel/security/lsm is the authoritative active-LSM list; some
    // distros enable landlock without creating the /sys/kernel/security/landlock
    // subdirectory (e.g. Ubuntu 24.04), so we check the list only.
    let lsm_list = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let landlock_listed = lsm_list.split(',').any(|s| s.trim() == "landlock");
    if landlock_listed {
        let abi = probe_landlock_abi();
        let (abi_tag, abi_desc) = match abi {
            Some(v) if v >= 3 => (
                &ok_tag,
                format!("ABI v{v} — full fs-access + refer + truncate (≥Linux 6.2)"),
            ),
            Some(v) if v == 2 => (
                &warn_tag,
                format!("ABI v{v} — fs-access + refer, no truncate (Linux 5.19–6.1)"),
            ),
            Some(1) => (
                &warn_tag,
                "ABI v1 — basic fs-access only (Linux 5.13–5.18)".to_string(),
            ),
            Some(v) => (&ok_tag, format!("ABI v{v}")),
            None => (&warn_tag, "ABI probe failed (syscall returned error)".to_string()),
        };
        println!("  {abi_tag} landlock:      enabled, {abi_desc}");
        if matches!(abi, Some(v) if v < 3) || abi.is_none() {
            println!("         note:  ABI <v3 means LANDLOCK_ACCESS_FS_TRUNCATE is absent;");
            println!("                sandbox runs in PartiallyEnforced mode (see README).");
            warnings += 1;
        }
    } else {
        println!("  {fail_tag} landlock:      NOT listed in /sys/kernel/security/lsm");
        println!("         fix:   enable CONFIG_SECURITY_LANDLOCK and add 'landlock' to");
        println!("                lsm= in kernel command-line or /etc/default/grub.");
        failures += 1;
    }

    // --- PR_SET_NO_NEW_PRIVS ----------------------------------------------
    // Actually attempt the set (harmless — it is already the process's own
    // attribute and sticky only downward for children we never create).
    let nnp_ok = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0;
    if nnp_ok {
        println!("  {ok_tag} no_new_privs:  supported");
    } else {
        println!("  {fail_tag} no_new_privs:  prctl(PR_SET_NO_NEW_PRIVS) failed");
        println!("         fix:   kernel must have CONFIG_SECCOMP or CONFIG_SECURITY_YAMA.");
        failures += 1;
    }

    // --- seccomp-bpf ------------------------------------------------------
    // /proc/sys/kernel/seccomp/actions_avail is only created when the
    // kernel is compiled with CONFIG_SECCOMP_FILTER; its presence is
    // therefore a reliable indicator that seccomp BPF is available.
    // The file's contents list BPF *return-code* actions (errno, kill_thread,
    // …), not the word "filter" — checking for "filter" in the text would
    // be wrong.
    let seccomp_path = Path::new("/proc/sys/kernel/seccomp/actions_avail");
    match std::fs::read_to_string(seccomp_path) {
        Ok(actions) => {
            println!("  {ok_tag} seccomp-bpf:   enabled (actions: {})", actions.trim());
        }
        Err(_) => {
            println!("  {fail_tag} seccomp-bpf:   /proc/sys/kernel/seccomp/actions_avail missing");
            println!("         fix:   rebuild kernel with CONFIG_SECCOMP_FILTER=y.");
            failures += 1;
        }
    }

    // --- /dev/null accessibility (required for FD hygiene) ----------------
    match std::fs::OpenOptions::new().read(true).open("/dev/null") {
        Ok(_) => println!("  {ok_tag} /dev/null:     accessible"),
        Err(e) => {
            println!("  {fail_tag} /dev/null:     not accessible: {e}");
            println!("         fix:   /dev/null must exist; re-create with: mknod /dev/null c 1 3");
            failures += 1;
        }
    }

    // --- Unprivileged user namespaces (clone3 mitigation) -----------------
    // clone3 passes its flags in a userspace struct that seccomp-bpf cannot
    // dereference, so we cannot filter namespace-creation flags on clone3.
    // The best deployment mitigation is to disable unprivileged user
    // namespaces at the kernel level.
    let userns_path = Path::new("/proc/sys/kernel/unprivileged_userns_clone");
    match std::fs::read_to_string(userns_path) {
        Ok(val) => {
            if val.trim() == "0" {
                println!("  {ok_tag} userns:        unprivileged user namespaces disabled");
            } else {
                println!("  {warn_tag} userns:        unprivileged user namespaces enabled");
                println!("         fix:   sysctl kernel.unprivileged_userns_clone=0");
                println!("         note:  clone3 flags cannot be filtered by seccomp-bpf;");
                println!("                disabling unprivileged userns closes this gap.");
                warnings += 1;
            }
        }
        Err(_) => {
            // Sysctl may not exist on all kernels (some use AppArmor userns
            // restrictions instead, e.g. Ubuntu 24.04+).
            println!("  {warn_tag} userns:        /proc/sys/kernel/unprivileged_userns_clone not found");
            println!("         note:  if your kernel allows unprivileged user namespaces,");
            println!("                consider restricting them via sysctl or AppArmor.");
            warnings += 1;
        }
    }

    // --- Config file ------------------------------------------------------
    let config_path = Path::new("/etc/skorupka/config.toml");
    if config_path.exists() {
        match std::fs::read_to_string(config_path) {
            Ok(_) => println!("  {ok_tag} config:        /etc/skorupka/config.toml readable"),
            Err(e) => {
                println!("  {fail_tag} config:        /etc/skorupka/config.toml unreadable: {e}");
                println!("         fix:   ensure the file is readable by the skorupka user.");
                failures += 1;
            }
        }
    } else {
        println!("  {warn_tag} config:        /etc/skorupka/config.toml not found");
        println!("         fix:   run `skorupka install` to create a default config.");
        warnings += 1;
    }

    // --- Binary permissions -----------------------------------------------
    match std::env::current_exe().and_then(|p| std::fs::metadata(&p).map(|m| (p, m))) {
        Ok((exe, meta)) => {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                println!("  {fail_tag} binary:        {exe} is world-writable (mode {mode:04o})",
                    exe = exe.display());
                println!("         fix:   chmod o-w {}", exe.display());
                failures += 1;
            } else if mode & 0o111 == 0 {
                println!("  {fail_tag} binary:        {exe} is not executable (mode {mode:04o})",
                    exe = exe.display());
                println!("         fix:   chmod +x {}", exe.display());
                failures += 1;
            } else {
                println!("  {ok_tag} binary:        {} (mode {:04o})", exe.display(), mode & 0o7777);
            }
        }
        Err(e) => {
            println!("  {warn_tag} binary:        could not stat current executable: {e}");
            warnings += 1;
        }
    }

    // --- Summary ----------------------------------------------------------
    println!();
    if failures == 0 && warnings == 0 {
        println!("{green}Result: all checks passed.{reset}");
        println!("Ready to run `skorupka install` and configure sshd.");
    } else if failures == 0 {
        println!("{yellow}Result: {warnings} warning(s), 0 failures — sandbox runs in degraded mode.{reset}");
        println!("Review the warnings above before deploying to production.");
    } else {
        println!(
            "{red}Result: {failures} failure(s), {warnings} warning(s) — sandbox will NOT start correctly.{reset}"
        );
        println!("Resolve the failures above before running `skorupka run`.");
        std::process::exit(1);
    }

    Ok(())
}

/// Probe the highest Landlock ABI version supported by the running kernel.
///
/// Calls `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
/// (flag value 1 << 0 = 1). The kernel returns the max ABI version (≥1) on
/// success, or −1 on failure (EOPNOTSUPP if landlock is absent, ENOSYS if
/// the syscall doesn't exist). This is the canonical detection approach from
/// the kernel documentation.
fn probe_landlock_abi() -> Option<u32> {
    // LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32,
        )
    };
    if ret >= 1 { Some(ret as u32) } else { None }
}
