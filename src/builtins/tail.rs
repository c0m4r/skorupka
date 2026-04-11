use super::head::write_bytes;
use super::Ctx;
use anyhow::{bail, Context, Result};
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
        tail_reader(BufReader::new(stdin), stdout, n, &mut ctx.output_budget)?;
    } else {
        for f in files {
            let p = resolve(&ctx.cwd, &f);
            let fh = std::fs::File::open(&p)
                .with_context(|| format!("tail: {}", p.display()))?;
            tail_reader(BufReader::new(fh), stdout, n, &mut ctx.output_budget)?;
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
                let v = it.next().ok_or_else(|| anyhow::anyhow!("tail: -n needs value"))?;
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
    Ok((n, files))
}

fn tail_reader<R: BufRead>(
    mut r: R,
    w: &mut dyn Write,
    n: usize,
    budget: &mut u64,
) -> Result<()> {
    let mut ring: VecDeque<Vec<u8>> = VecDeque::with_capacity(n.min(4096));
    loop {
        let mut line = Vec::new();
        let got = r.read_until(b'\n', &mut line)?;
        if got == 0 {
            break;
        }
        if ring.len() == n {
            ring.pop_front();
        }
        ring.push_back(line);
    }
    for line in &ring {
        write_bytes(w, line, budget)?;
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
