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

pub fn apply(allowed_ro: &[std::path::PathBuf]) -> Result<()> {
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

    // Add one PathBeneath rule per allowed path. `add_rule` consumes and
    // returns the ruleset, so we fold.
    let rs = allowed_ro.iter().try_fold(rs, |rs, p| -> Result<_> {
        let fd = PathFd::new(p).with_context(|| format!("opening allowed path {}", p.display()))?;
        let rs = rs
            .add_rule(PathBeneath::new(fd, read_only))
            .with_context(|| format!("add_rule for {}", p.display()))?;
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
