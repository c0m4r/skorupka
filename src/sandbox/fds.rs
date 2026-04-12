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
    // Use raw opendir/readdir so we can identify and skip the directory
    // fd itself. std::fs::ReadDir would close its internal fd when
    // dropped, and then our close loop would close the same number
    // again — a double-close that is UB even though it's currently
    // benign (single-threaded at this point).
    //
    // SAFETY: opendir returns a valid DIR* or null. We check for null.
    let dir = unsafe { libc::opendir(c"/proc/self/fd".as_ptr()) };
    if dir.is_null() {
        // Fallback: brute-force close to a sane ceiling.
        for fd in 3..1024 {
            if !keep.contains(&fd) {
                // SAFETY: close on a small fd; errors ignored.
                unsafe { libc::close(fd) };
            }
        }
        return Ok(());
    }
    // dirfd() returns the fd backing the DIR stream — we must not close
    // it manually; closedir() will do that.
    // SAFETY: dir is a valid, non-null DIR* from opendir above.
    let dir_fd = unsafe { libc::dirfd(dir) };

    let mut victims = Vec::new();
    loop {
        // SAFETY: readdir returns a pointer to an internal dirent or null.
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            break;
        }
        // SAFETY: d_name is a null-terminated C string.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        if let Ok(s) = name.to_str() {
            if let Ok(fd) = s.parse::<RawFd>() {
                if fd != dir_fd && !keep.contains(&fd) {
                    victims.push(fd);
                }
            }
        }
    }
    // SAFETY: closedir frees the DIR and closes dir_fd exactly once.
    unsafe { libc::closedir(dir) };

    for fd in victims {
        // SAFETY: fd came from /proc/self/fd and is not the now-closed
        // dir_fd; close is safe.
        unsafe { libc::close(fd) };
    }
    Ok(())
}
