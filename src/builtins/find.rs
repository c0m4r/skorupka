//! Restricted find: walks a directory tree, optionally filters by
//! name substring. No `-exec`, no `-delete`, no `-print0` shenanigans.

use super::Ctx;
use anyhow::{Result, bail};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub fn run(
    argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut name_substr: Option<String> = None;
    let mut type_filter: Option<char> = None;
    let mut max_depth: Option<usize> = None;

    let mut it = argv.iter().skip(1).peekable();
    // Roots come first, stop at first flag starting with '-'.
    while let Some(a) = it.peek() {
        if a.starts_with('-') {
            break;
        }
        roots.push(resolve(&ctx.cwd, a));
        it.next();
    }
    if roots.is_empty() {
        roots.push(ctx.cwd.clone());
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "-name" => {
                let v = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("find: -name needs value"))?;
                name_substr = Some(v.clone());
            }
            "-type" => {
                let v = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("find: -type needs value"))?;
                let c = v.chars().next().unwrap_or('?');
                if !matches!(c, 'f' | 'd' | 'l') {
                    bail!("find: -type must be f, d, or l");
                }
                type_filter = Some(c);
            }
            "-maxdepth" => {
                let v = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("find: -maxdepth needs value"))?;
                max_depth = Some(v.parse()?);
            }
            "-exec" | "-execdir" | "-delete" | "-ok" => {
                bail!("find: {} is disabled in the sandbox", a);
            }
            other => bail!("find: unknown option {}", other),
        }
    }

    for r in roots {
        walk(&r, 0, max_depth, &name_substr, type_filter, stdout, ctx)?;
    }
    Ok(())
}

fn walk(
    path: &Path,
    depth: usize,
    max_depth: Option<usize>,
    name_substr: &Option<String>,
    type_filter: Option<char>,
    out: &mut dyn Write,
    _ctx: &mut Ctx,
) -> Result<()> {
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((path.to_path_buf(), depth));
    while let Some((p, d)) = queue.pop_front() {
        let md = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let matches_name = match name_substr {
            None => true,
            Some(sub) => p
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.contains(sub))
                .unwrap_or(false),
        };
        let ft = md.file_type();
        let matches_type = match type_filter {
            None => true,
            Some('f') => ft.is_file(),
            Some('d') => ft.is_dir(),
            Some('l') => ft.is_symlink(),
            _ => true,
        };
        if matches_name && matches_type {
            let line = format!("{}\n", p.display());
            super::head::write_bytes(out, line.as_bytes())?;
        }
        if ft.is_dir() {
            if let Some(md2) = max_depth {
                if d >= md2 {
                    continue;
                }
            }
            if let Ok(rd) = std::fs::read_dir(&p) {
                for e in rd.flatten() {
                    queue.push_back((e.path(), d + 1));
                }
            }
        }
    }
    Ok(())
}

fn resolve(cwd: &Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() { p } else { cwd.join(p) }
}
