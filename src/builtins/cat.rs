use super::Ctx;
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::path::PathBuf;

pub fn run(
    argv: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    let files: Vec<&String> = argv.iter().skip(1).collect();
    if files.is_empty() {
        // No args: pass stdin through, so `cat | grep foo` works.
        copy(stdin, stdout)?;
        return Ok(());
    }
    for f in files {
        let p = resolve(&ctx.cwd, f);
        let mut fh = std::fs::File::open(&p).with_context(|| format!("cat: {}", p.display()))?;
        copy(&mut fh, stdout)?;
    }
    Ok(())
}

fn resolve(cwd: &std::path::Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() { p } else { cwd.join(p) }
}

/// Copy `src` to `dst` in 16 KiB chunks. Budget enforcement and ANSI
/// stripping are handled transparently by the `SafeWriter` wrapped around
/// `dst` at the REPL layer; this function just moves bytes.
fn copy(src: &mut dyn Read, dst: &mut dyn Write) -> Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..n])?;
    }
}
