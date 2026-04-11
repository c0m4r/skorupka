use super::Ctx;
use anyhow::{bail, Result};
use std::io::{Read, Write};
use std::path::PathBuf;

pub fn run(
    argv: &[String],
    _stdin: &mut dyn Read,
    _stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    if argv.len() != 2 {
        bail!("usage: cd <dir>");
    }
    let target = resolve(&ctx.cwd, &argv[1]);
    // Canonicalize through the real filesystem; landlock will deny if
    // we're stepping outside the allowed view.
    let canon = std::fs::canonicalize(&target)
        .map_err(|e| anyhow::anyhow!("cd: {}: {}", target.display(), e))?;
    let md = std::fs::metadata(&canon)
        .map_err(|e| anyhow::anyhow!("cd: {}: {}", canon.display(), e))?;
    if !md.is_dir() {
        bail!("cd: not a directory: {}", canon.display());
    }
    // Mirror cwd into the real process so relative openat() from ls/cat
    // resolves the same way.
    std::env::set_current_dir(&canon)
        .map_err(|e| anyhow::anyhow!("cd: set_current_dir: {}", e))?;
    ctx.cwd = canon;
    Ok(())
}

fn resolve(cwd: &std::path::Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() {
        p
    } else {
        cwd.join(p)
    }
}
