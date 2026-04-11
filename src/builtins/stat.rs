use super::Ctx;
use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub fn run(
    argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    if argv.len() < 2 {
        bail!("usage: stat <path> [path...]");
    }
    for f in argv.iter().skip(1) {
        let p = resolve(&ctx.cwd, f);
        let md = std::fs::symlink_metadata(&p)
            .with_context(|| format!("stat: {}", p.display()))?;
        writeln!(
            stdout,
            "{}: size={} mode={:o} uid={} gid={} mtime={}",
            p.display(),
            md.len(),
            md.mode() & 0o7777,
            md.uid(),
            md.gid(),
            md.mtime()
        )?;
    }
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
