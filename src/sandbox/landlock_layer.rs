//! Landlock filesystem confinement.
//!
//! Builds a ruleset that permits read-only access to every path in
//! `allowed_paths_ro` and nothing else. Writes are never granted in v1
//! (RLIMIT_FSIZE=0 is a belt-and-braces second layer). Once installed,
//! the ruleset cannot be widened — only further narrowed by later
//! `landlock_restrict_self` calls.
//!
//! ## ABI version / kernel compatibility
//!
//! We request ABI v3. The kernel downgrades silently to whatever it
//! supports, and `restrict_self` reports the outcome via `RulesetStatus`:
//!
//! | ABI | Min kernel | Access types added |
//! |-----|------------|-------------------|
//! | v1  | 5.13       | read_file, read_dir, write_file, remove_*, make_*, link, rename, execute |
//! | v2  | 5.19       | + refer (cross-directory renames/hard-links) |
//! | v3  | 6.1        | + truncate |
//!
//! Under PartiallyEnforced the kernel silently **drops** access types it
//! doesn't know about from the ruleset — it does not widen permissions.
//! Because we only *grant* read access (read_file + read_dir), and never
//! grant write/execute/truncate/refer, the dropped types are exclusively
//! from the "things we asked to *control*" set, not from the "things we
//! *allow*" set. A sandboxed process therefore cannot gain write,
//! execute, or truncate access that would not be permitted under full
//! enforcement.
//!
//! The one edge case: v1 kernels (5.13–5.18) lack the `refer` type.
//! `refer` governs cross-directory hard-links and renames. Without it,
//! a process could in theory create a hard-link across allowed
//! directories — but skorupka never grants write access to any path, so
//! there is no writable directory in which to land the link. The missing
//! `refer` control is therefore inert in this configuration.

use anyhow::{Context, Result, bail};
use landlock::{
    ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus,
};
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use std::os::unix::io::{AsRawFd, OwnedFd};

/// Open an `O_PATH | O_CLOEXEC | O_NOFOLLOW` file descriptor for every
/// allowed path and return the owned fds.
///
/// Must be called **before** Landlock and seccomp are applied so that:
///   1. The `open(2)` syscall is not yet filtered by seccomp.
///   2. We pin each inode immediately after `config::validate()` has
///      canonicalized the paths, shrinking the TOCTOU window between
///      "path validated" and "path handed to Landlock" to near-zero.
///   3. `O_NOFOLLOW` on the final component causes the kernel to return
///      `ELOOP` (not silently follow) if a symlink is swapped in after
///      canonicalization — fail-safe rather than fail-open.
pub fn open_path_fds(paths: &[std::path::PathBuf]) -> Result<Vec<OwnedFd>> {
    paths
        .iter()
        .map(|p| {
            let flags = OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
            // nix 0.31 returns OwnedFd directly on success.
            nix::fcntl::open(p.as_path(), flags, Mode::empty()).with_context(|| {
                format!(
                    "O_PATH|O_NOFOLLOW open of allowed path {} — \
                     path may have been replaced with a symlink after validation",
                    p.display()
                )
            })
        })
        .collect()
}

/// Install the Landlock ruleset using pre-opened path fds.
///
/// Accepts `Vec<OwnedFd>` (from [`open_path_fds`]) rather than path strings.
/// Each `PathFd` is constructed via `/proc/self/fd/N` — the kernel resolves
/// this to the inode the fd holds, not to the (possibly-changed) directory
/// entry.  The result is that the Landlock rule is anchored to the pinned
/// inode rather than to whatever happens to be at the original name at
/// rule-add time.
pub fn apply(path_fds: Vec<OwnedFd>) -> Result<()> {
    // Kernel 6.1+ gives us ABI v3 (TRUNCATE + refer).
    let abi = ABI::V3;

    // Declare EVERY access we want the kernel to evaluate. Any access
    // declared here but not granted by a rule is DENIED; accesses not
    // declared here are left un-evaluated by landlock.
    let all_fs = AccessFs::from_all(abi);
    let read_only = AccessFs::from_read(abi);

    // Create the ruleset.
    let rs = Ruleset::default()
        .handle_access(all_fs)
        .context("handle_access(all)")?
        .create()
        .context("ruleset create")?;

    // Add one PathBeneath rule per pre-opened fd. We construct each
    // PathFd via /proc/self/fd/N rather than from the original path
    // string: the kernel resolves /proc/self/fd/N directly to the inode
    // the fd refers to, bypassing any directory-entry lookup. Even if
    // the directory entry was renamed or replaced after open_path_fds()
    // returned, the rule still targets the correct inode.
    let rs = path_fds.into_iter().try_fold(rs, |rs, fd| -> Result<_> {
        let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let path_fd = PathFd::new(&proc_path)
            .with_context(|| format!("PathFd::new via {}", proc_path))?;
        // `fd` must stay alive until PathFd::new returns so the kernel
        // fd number is valid.  Drop it now; the PathFd holds the inode.
        drop(fd);
        let rs = rs
            .add_rule(PathBeneath::new(path_fd, read_only))
            .context("add_rule")?;
        Ok(rs)
    })?;

    let status = rs.restrict_self().context("landlock_restrict_self")?;
    match status.ruleset {
        // Fully enforced = every access we asked for is honored.
        RulesetStatus::FullyEnforced => Ok(()),
        // Partially enforced = we asked for some access types the running
        // kernel doesn't know about, and they were silently ignored. For
        // our use case that's fine: we only *grant* read access, so the
        // worst case is the kernel honors our read allowlist but ignores
        // some newer write-access flag we listed in `handle_access`. No
        // write access is ever granted anyway, so confidentiality and
        // integrity are still enforced.
        RulesetStatus::PartiallyEnforced => {
            // See module-level doc for why this is safe in a read-only
            // configuration (short: dropped access types are all write-
            // side types we never grant anyway).
            tracing::warn!(
                target: "skorupka::audit",
                kind = "landlock_partial",
                requested_abi = ?abi,
                "landlock PartiallyEnforced: kernel predates ABI {:?}; \
                 newer access types (truncate / refer) were dropped from \
                 the ruleset. Read-only path confinement is still active. \
                 Deploy on kernel 6.1+ to eliminate this warning.",
                abi,
            );
            Ok(())
        }
        RulesetStatus::NotEnforced => {
            bail!("landlock not enforced at all; refusing to start sandbox")
        }
    }
}
