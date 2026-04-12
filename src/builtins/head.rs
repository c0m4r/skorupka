use super::{Ctx, read_line_capped};
use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

pub fn run(
    argv: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    let (n, files) = parse_args(argv)?;
    if files.is_empty() {
        head_reader(BufReader::new(stdin), stdout, n)?;
    } else {
        for f in files {
            let p = resolve(&ctx.cwd, &f);
            let fh = std::fs::File::open(&p).with_context(|| format!("head: {}", p.display()))?;
            head_reader(BufReader::new(fh), stdout, n)?;
        }
    }
    Ok(())
}

fn parse_args(argv: &[String]) -> Result<(usize, Vec<String>)> {
    let mut n = 10;
    let mut files = Vec::new();
    let mut it = argv.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-n" => {
                let v = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("head: -n needs value"))?;
                n = v.parse().context("head: -n value")?;
            }
            s if s.starts_with("-") => {
                let num = &s[1..];
                if num.chars().all(|c| c.is_ascii_digit()) {
                    n = num.parse().context("head: -N value")?;
                } else {
                    bail!("head: unknown flag {}", s);
                }
            }
            s => files.push(s.to_string()),
        }
    }
    Ok((n, files))
}

fn head_reader<R: BufRead>(mut r: R, w: &mut dyn Write, n: usize) -> Result<()> {
    let mut line = Vec::new();
    for _ in 0..n {
        // SEC-002: capped read prevents unbounded allocation on long lines.
        let got = read_line_capped(&mut r, &mut line)?;
        if got == 0 {
            break;
        }
        write_bytes(w, &line)?;
    }
    Ok(())
}

/// Write `b` to `w`. Budget enforcement is handled transparently by the
/// `SafeWriter` wrapper in the REPL layer; builtins just write normally.
pub(crate) fn write_bytes(w: &mut dyn Write, b: &[u8]) -> Result<()> {
    w.write_all(b)?;
    Ok(())
}

fn resolve(cwd: &std::path::Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() { p } else { cwd.join(p) }
}
