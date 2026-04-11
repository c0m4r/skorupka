//! Resource limits.
//!
//! Defence against fork bombs, runaway CPU, memory exhaustion, core-dump
//! info leaks, and (with RLIMIT_FSIZE=0) unintended writes.

use crate::config::Limits;
use anyhow::{bail, Result};

fn setrl(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> Result<()> {
    let rl = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: setrlimit with a valid pointer to a stack-allocated rlimit.
    let rc = unsafe { libc::setrlimit(resource, &rl) };
    if rc != 0 {
        bail!(
            "setrlimit(resource={}) failed: {}",
            resource,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

pub fn apply(l: &Limits) -> Result<()> {
    // RLIMIT_NPROC counts the *calling user's* total processes, not
    // just this sandbox. For a dedicated sandbox user it's safe to cap
    // absolutely, but when skorupka runs as a regular user (e.g. during
    // selftest or interactive testing) that user likely already has
    // hundreds of processes, and a low absolute cap makes every thread
    // spawn in the REPL fail with EAGAIN. Instead we compute
    // `current_user_nproc + configured_slack` — this still prevents
    // fork bombs (an attacker cannot spawn more than `slack` additional
    // processes) while keeping the REPL functional.
    let current_nproc = current_user_nproc_estimate();
    let nproc_cap = current_nproc.saturating_add(l.rlimit_nproc);
    setrl(libc::RLIMIT_NPROC, nproc_cap, nproc_cap)?;
    setrl(libc::RLIMIT_CPU, l.rlimit_cpu_sec, l.rlimit_cpu_sec)?;
    setrl(
        libc::RLIMIT_AS,
        l.rlimit_as_mb * 1024 * 1024,
        l.rlimit_as_mb * 1024 * 1024,
    )?;
    setrl(
        libc::RLIMIT_FSIZE,
        l.rlimit_fsize_mb * 1024 * 1024,
        l.rlimit_fsize_mb * 1024 * 1024,
    )?;
    setrl(libc::RLIMIT_NOFILE, l.rlimit_nofile, l.rlimit_nofile)?;
    // No core dumps at all — they can leak file contents.
    setrl(libc::RLIMIT_CORE, 0, 0)?;
    Ok(())
}

/// Estimate of how many threads/processes the calling uid already has.
/// RLIMIT_NPROC counts every thread across the user's entire process
/// set, so we must sum the `Threads:` field of /proc/<pid>/status, not
/// just count pids. A few misses either way are fine — this is a
/// fork-bomb cap, not a quota.
fn current_user_nproc_estimate() -> u64 {
    let uid = unsafe { libc::getuid() };
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return 4096;
    };
    let mut count: u64 = 0;
    for ent in dir.flatten() {
        let name = ent.file_name();
        let Some(s) = name.to_str() else { continue };
        if !s.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(ent.path().join("status")) else {
            continue;
        };
        let mut this_uid: Option<libc::uid_t> = None;
        let mut threads: u64 = 1;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                this_uid = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok());
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                threads = rest.trim().parse().unwrap_or(1);
            }
        }
        if this_uid == Some(uid) {
            count += threads;
        }
    }
    count.max(1)
}
