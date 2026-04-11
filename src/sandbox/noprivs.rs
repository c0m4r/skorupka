//! PR_SET_NO_NEW_PRIVS — kills setuid escalation across any later execve.
//!
//! Must be applied before seccomp (seccomp requires NNP unless you have
//! CAP_SYS_ADMIN, which we drop immediately after).

use anyhow::{bail, Result};

pub fn set_no_new_privs() -> Result<()> {
    // SAFETY: pure prctl call, no memory touched.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        bail!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}
