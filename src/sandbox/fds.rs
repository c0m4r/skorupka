//! FD hygiene.
//!
//! Runs BEFORE landlock seals, so we can still open /dev/null. We:
//!   1. Open /dev/null once and stash it as a process-wide "blackhole" fd.
//!   2. Make sure stdin/stdout/stderr are open (dup2 /dev/null over any
//!      missing slot).
//!   3. Close every other inherited fd (> 2), to defeat fd-smuggling from
//!      a misconfigured parent.
//!
//! After landlock+seccomp seal, the sandbox cannot open /dev/null again,
//! so having this fd stashed means builtins can always route noisy
//! output to it without re-opening anything.

use anyhow::{Context, Result, bail};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::sync::OnceLock;

static BLACKHOLE: OnceLock<RawFd> = OnceLock::new();

/// Returns a raw fd to /dev/null that was opened before the sandbox was
/// sealed. Callers MUST NOT close it. Reserved for v2 (external
/// commands) when we need to wire /dev/null into child stdio.
#[allow(dead_code)]
pub fn blackhole() -> RawFd {
    *BLACKHOLE
        .get()
        .expect("fds::hygiene() was never called before fds::blackhole()")
}

pub fn hygiene() -> Result<()> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    // 1. Open /dev/null (RW so it can sink writes and provide EOF reads).
    // nix 0.29 returns an OwnedFd directly.
    let devnull = open("/dev/null", OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty())
        .context("opening /dev/null")?;

    // 2. Make sure stdio is present. If sshd already wired ptys to 0/1/2
    // (normal interactive case), fstat will succeed and we leave them
    // alone. Otherwise, dup2 /dev/null over the missing slot.
    for target in [0, 1, 2] {
        // SAFETY: fstat on a fixed fd, output goes to a stack struct.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(target, &mut st) };
        if rc != 0 {
            // Missing or invalid — replace with /dev/null.
            // SAFETY: dup2 with valid source fd and a small integer target.
            let rc2 = unsafe { libc::dup2(devnull.as_raw_fd(), target) };
            if rc2 < 0 {
                bail!(
                    "dup2(/dev/null, {}) failed: {}",
                    target,
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    // 3. Close every other inherited fd. We iterate /proc/self/fd rather
    // than blindly looping to RLIMIT_NOFILE, which is cheaper and does
    // not trip over fds the rlimit layer just lowered.
    close_other_fds(&[0, 1, 2, devnull.as_raw_fd()])?;

    // 4. Stash the blackhole fd for the rest of the process's life.
    // We leak the OwnedFd (into_raw_fd) because we want it to survive
    // for the entire program.
    let raw = devnull.into_raw_fd();
    BLACKHOLE.set(raw).ok();

    Ok(())
}

fn close_other_fds(keep: &[RawFd]) -> Result<()> {
    let dir = match std::fs::read_dir("/proc/self/fd") {
        Ok(d) => d,
        Err(_) => {
            // Fallback: loop to a sane ceiling.
            for fd in 3..1024 {
                if !keep.contains(&fd) {
                    // SAFETY: close on a small fd; errors ignored.
                    unsafe { libc::close(fd) };
                }
            }
            return Ok(());
        }
    };
    let mut victims = Vec::new();
    for ent in dir.flatten() {
        if let Some(name) = ent.file_name().to_str() {
            if let Ok(fd) = name.parse::<RawFd>() {
                if !keep.contains(&fd) {
                    victims.push(fd);
                }
            }
        }
    }
    for fd in victims {
        // SAFETY: fd came from /proc/self/fd; close is safe either way.
        unsafe { libc::close(fd) };
    }
    Ok(())
}
