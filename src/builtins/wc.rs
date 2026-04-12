use super::{Ctx, read_line_capped};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

pub fn run(
    argv: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    let files: Vec<&String> = argv
        .iter()
        .skip(1)
        .filter(|s| !s.starts_with('-'))
        .collect();
    if files.is_empty() {
        let (l, w, b) = count(BufReader::new(stdin))?;
        writeln!(stdout, " {} {} {}", l, w, b)?;
    } else {
        let (mut tl, mut tw, mut tb) = (0u64, 0u64, 0u64);
        for f in &files {
            let p = resolve(&ctx.cwd, f);
            let fh = std::fs::File::open(&p).with_context(|| format!("wc: {}", p.display()))?;
            let (l, w, b) = count(BufReader::new(fh))?;
            writeln!(stdout, " {} {} {} {}", l, w, b, p.display())?;
            tl += l;
            tw += w;
            tb += b;
        }
        if files.len() > 1 {
            writeln!(stdout, " {} {} {} total", tl, tw, tb)?;
        }
    }
    Ok(())
}

fn count<R: BufRead>(mut r: R) -> Result<(u64, u64, u64)> {
    let mut lines = 0u64;
    let mut words = 0u64;
    let mut bytes = 0u64;
    let mut buf = Vec::new();
    loop {
        // SEC-002: capped read prevents unbounded allocation on long lines.
        let got = read_line_capped(&mut r, &mut buf)?;
        if got == 0 {
            break;
        }
        bytes += buf.len() as u64;
        if buf.ends_with(b"\n") {
            lines += 1;
        }
        words += buf
            .split(|&b| b == b' ' || b == b'\t' || b == b'\n')
            .filter(|s| !s.is_empty())
            .count() as u64;
    }
    Ok((lines, words, bytes))
}

fn resolve(cwd: &std::path::Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() { p } else { cwd.join(p) }
}
