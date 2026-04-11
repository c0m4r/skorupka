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
        // No args: pass stdin through, so `cat | grep foo` works even if
        // a user is curious.
        copy(stdin, stdout, &mut ctx.output_budget)?;
        return Ok(());
    }
    for f in files {
        let p = resolve(&ctx.cwd, f);
        let mut fh = std::fs::File::open(&p)
            .with_context(|| format!("cat: {}", p.display()))?;
        copy(&mut fh, stdout, &mut ctx.output_budget)?;
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

fn copy(src: &mut dyn Read, dst: &mut dyn Write, budget: &mut u64) -> Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        if *budget == 0 {
            anyhow::bail!("output budget exhausted");
        }
        // Cap the read at remaining budget so a partial buffer doesn't
        // silently drop bytes between read and write.
        let want = std::cmp::min(buf.len() as u64, *budget) as usize;
        let n = src.read(&mut buf[..want])?;
        if n == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..n])?;
        *budget -= n as u64;
    }
}
