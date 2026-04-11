//! Landlock filesystem confinement.
//!
//! Builds a ruleset that permits read-only access to every path in
//! `allowed_paths_ro` and nothing else. Writes are never granted in v1
//! (RLIMIT_FSIZE=0 is a belt-and-braces second layer). Once installed,
//! the ruleset cannot be widened — only further narrowed by later
//! `landlock_restrict_self` calls.

use anyhow::{bail, Context, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
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
        let fd = PathFd::new(p)
            .with_context(|| format!("opening allowed path {}", p.display()))?;
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
            tracing::warn!(
                "landlock partially enforced: kernel is older than the ABI we built for, \
                 but the read-only allowlist is still active"
            );
            Ok(())
        }
        RulesetStatus::NotEnforced => {
            bail!("landlock not enforced at all; refusing to start sandbox")
        }
    }
}
