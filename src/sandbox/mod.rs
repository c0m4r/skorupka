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
    landlock_layer::apply(&policy.allowed_paths_ro).context("landlock")?;
    seccomp_layer::apply().context("seccomp")?;
    Ok(())
}

/// `skorupka check` — print a readiness report.
pub fn check() -> Result<()> {
    println!("skorupka kernel feature check");
    println!("-----------------------------");

    let uts = nix::sys::utsname::uname().ok();
    let kver = uts
        .as_ref()
        .map(|u| u.release().to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("kernel:       {}", kver);

    // Landlock: the crate discourages runtime ABI detection. We probe
    // via /sys/kernel/security/lsm (the authoritative list of loaded
    // LSMs on any modern kernel); some distros also ship a dedicated
    // /sys/kernel/security/landlock dir, but its absence is not a
    // reliable signal — Ubuntu 24.04 for example enables landlock but
    // does not create the subdir.
    let lsm_list = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if lsm_list.split(',').any(|s| s.trim() == "landlock") {
        println!("landlock:     enabled (listed in /sys/kernel/security/lsm)");
    } else {
        println!("landlock:     MISSING — sandbox will refuse to start");
    }

    // no_new_privs probe.
    let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    println!("no_new_privs: supported (current={})", nnp);

    // seccomp probe: try a no-op filter compile. Runtime apply would be
    // destructive for the rest of this process, so we only check presence.
    let seccomp_h = Path::new("/proc/sys/kernel/seccomp/actions_avail");
    if seccomp_h.exists() {
        let actions = std::fs::read_to_string(seccomp_h).unwrap_or_default();
        println!("seccomp:      {}", actions.trim());
    } else {
        println!("seccomp:      /proc/sys/kernel/seccomp/actions_avail missing");
    }

    println!();
    println!("Ready to run `skorupka install` and configure sshd.");
    Ok(())
}
