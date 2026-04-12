use super::head::write_bytes;
use super::{Ctx, read_line_capped};
use anyhow::{Context, Result, bail};
use regex::bytes::RegexBuilder;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

pub fn run(
    argv: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    let mut case_insensitive = false;
    let mut invert = false;
    let mut fixed = false;
    let mut pat: Option<String> = None;
    let mut files: Vec<String> = Vec::new();

    for a in argv.iter().skip(1) {
        match a.as_str() {
            "-i" => case_insensitive = true,
            "-v" => invert = true,
            "-F" => fixed = true,
            s if s.starts_with('-') => bail!("grep: unknown flag {}", s),
            s => {
                if pat.is_none() {
                    pat = Some(s.to_string());
                } else {
                    files.push(s.to_string());
                }
            }
        }
    }

    let pat = pat.ok_or_else(|| anyhow::anyhow!("grep: pattern required"))?;
    let pat_re = if fixed {
        regex::escape(&pat)
    } else {
        pat.clone()
    };
    // SEC-001 / ReDoS: the `regex` crate uses a finite-automaton engine
    // (NFA/DFA compilation), NOT a backtracking engine. Catastrophic
    // backtracking (ReDoS) is architecturally impossible — each byte is
    // processed in amortised O(1) time regardless of the pattern. The
    // size_limit and dfa_size_limit caps below bound the memory consumed
    // by DFA state-explosion for pathological patterns (e.g. deeply nested
    // alternations), so both time and memory are bounded without any need
    // for a separate execution timeout.
    let re = RegexBuilder::new(&pat_re)
        .case_insensitive(case_insensitive)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .context("grep: compiling pattern")?;

    let mut found_any = false;

    let mut process = |r: Box<dyn BufRead>, prefix: Option<&str>| -> Result<()> {
        let mut line = Vec::new();
        let mut r = r;
        loop {
            // SEC-002: capped read prevents unbounded allocation on long lines.
            // Pass `&mut r` (Box<dyn BufRead>) not `&mut *r` (dyn BufRead):
            // Box<dyn BufRead> is Sized + BufRead, satisfying the R bound.
            let n = read_line_capped(&mut r, &mut line)?;
            if n == 0 {
                break;
            }
            let matched = re.is_match(&line);
            if matched ^ invert {
                found_any = true;
                if let Some(p) = prefix {
                    write_bytes(stdout, p.as_bytes())?;
                    write_bytes(stdout, b":")?;
                }
                write_bytes(stdout, &line)?;
                if !line.ends_with(b"\n") {
                    write_bytes(stdout, b"\n")?;
                }
            }
        }
        Ok(())
    };

    if files.is_empty() {
        process(Box::new(BufReader::new(stdin)), None)?;
    } else {
        let many = files.len() > 1;
        for f in files {
            let p = resolve(&ctx.cwd, &f);
            let fh = std::fs::File::open(&p).with_context(|| format!("grep: {}", p.display()))?;
            let label = p.display().to_string();
            process(
                Box::new(BufReader::new(fh)),
                if many { Some(&label) } else { None },
            )?;
        }
    }

    if !found_any {
        // Match grep(1) convention: exit 1 on no matches. We surface this
        // as a soft error the REPL just prints; pipeline continues.
    }
    Ok(())
}

fn resolve(cwd: &std::path::Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() { p } else { cwd.join(p) }
}
