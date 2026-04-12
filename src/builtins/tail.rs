use super::head::write_bytes;
use super::{Ctx, read_line_capped};
use anyhow::{Context, Result, bail};
use std::collections::VecDeque;
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
        tail_reader(BufReader::new(stdin), stdout, n)?;
    } else {
        for f in files {
            let p = resolve(&ctx.cwd, &f);
            let fh = std::fs::File::open(&p).with_context(|| format!("tail: {}", p.display()))?;
            tail_reader(BufReader::new(fh), stdout, n)?;
        }
    }
    Ok(())
}

/// Maximum number of lines tail will buffer. Prevents pathological
/// values from causing unbounded ring-buffer growth that could exhaust
/// RLIMIT_AS (each buffered line can be up to 1 MiB from
/// `read_line_capped`).
const MAX_N: usize = 100_000;

fn parse_args(argv: &[String]) -> Result<(usize, Vec<String>)> {
    let mut n = 10usize;
    let mut files = Vec::new();
    let mut it = argv.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-n" => {
                let v = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("tail: -n needs value"))?;
                n = v.parse().context("tail: -n value")?;
            }
            s if s.starts_with("-") => {
                let num = &s[1..];
                if num.chars().all(|c| c.is_ascii_digit()) {
                    n = num.parse().context("tail: -N value")?;
                } else {
                    bail!("tail: unknown flag {} (note: -f disabled in v1)", s);
                }
            }
            s => files.push(s.to_string()),
        }
    }
    if n > MAX_N {
        bail!("tail: -n value {} exceeds maximum ({})", n, MAX_N);
    }
    Ok((n, files))
}

fn tail_reader<R: BufRead>(mut r: R, w: &mut dyn Write, n: usize) -> Result<()> {
    let mut ring: VecDeque<Vec<u8>> = VecDeque::with_capacity(n.min(4096));
    let mut line = Vec::new();
    loop {
        // SEC-002: capped read prevents unbounded allocation on long lines.
        let got = read_line_capped(&mut r, &mut line)?;
        if got == 0 {
            break;
        }
        if ring.len() == n {
            ring.pop_front();
        }
        ring.push_back(line.clone());
    }
    for line in &ring {
        write_bytes(w, line)?;
    }
    Ok(())
}

fn resolve(cwd: &std::path::Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() { p } else { cwd.join(p) }
}
