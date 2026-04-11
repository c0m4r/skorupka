use super::{budget_spend, Ctx};
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

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
        copy(stdin, stdout, &ctx.output_budget)?;
        return Ok(());
    }
    for f in files {
        let p = resolve(&ctx.cwd, f);
        let mut fh = std::fs::File::open(&p)
            .with_context(|| format!("cat: {}", p.display()))?;
        copy(&mut fh, stdout, &ctx.output_budget)?;
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

fn copy(src: &mut dyn Read, dst: &mut dyn Write, budget: &AtomicU64) -> Result<()> {
    use std::sync::atomic::Ordering;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let remaining = budget.load(Ordering::Relaxed);
        if remaining == 0 {
            anyhow::bail!("output budget exhausted");
        }
        // Cap the read request to the remaining budget so we never try to
        // write more than we are allowed to spend. The actual spend is
        // committed atomically after the read so we know the exact count.
        let want = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = src.read(&mut buf[..want])?;
        if n == 0 {
            return Ok(());
        }
        if !budget_spend(budget, n as u64) {
            anyhow::bail!("output budget exhausted");
        }
        dst.write_all(&buf[..n])?;
    }
}
