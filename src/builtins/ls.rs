use super::Ctx;
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub fn run(
    argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    let mut long = false;
    let mut all = false;
    let mut targets: Vec<String> = Vec::new();
    for a in argv.iter().skip(1) {
        match a.as_str() {
            "-l" => long = true,
            "-a" => all = true,
            "-la" | "-al" => {
                long = true;
                all = true;
            }
            s if s.starts_with('-') => anyhow::bail!("ls: unknown flag {}", s),
            s => targets.push(s.to_string()),
        }
    }
    if targets.is_empty() {
        targets.push(ctx.cwd.display().to_string());
    }

    for t in &targets {
        let p = resolve(&ctx.cwd, t);
        let md = std::fs::metadata(&p)
            .with_context(|| format!("ls: {}", p.display()))?;
        if md.is_dir() {
            list_dir(&p, long, all, stdout)?;
        } else {
            list_one(&p, long, stdout)?;
        }
    }
    Ok(())
}

fn list_dir(dir: &Path, long: bool, all: bool, w: &mut dyn Write) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("ls: read_dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name();
        let n = name.to_string_lossy();
        if !all && n.starts_with('.') {
            continue;
        }
        if long {
            // symlink_metadata does NOT follow symlinks, so entries that
            // point outside the allowed view are displayed as 'l' rather
            // than triggering a landlock-denied metadata call that
            // aborts the rest of the listing.
            let md = match std::fs::symlink_metadata(e.path()) {
                Ok(m) => m,
                Err(_) => {
                    writeln!(w, "? {:>10} {}", 0, n)?;
                    continue;
                }
            };
            let kind = if md.file_type().is_symlink() {
                'l'
            } else if md.is_dir() {
                'd'
            } else {
                '-'
            };
            writeln!(w, "{} {:>10} {}", kind, md.len(), n)?;
        } else {
            writeln!(w, "{}", n)?;
        }
    }
    Ok(())
}

fn list_one(p: &Path, long: bool, w: &mut dyn Write) -> Result<()> {
    let md = std::fs::metadata(p)?;
    if long {
        writeln!(w, "- {:>10} {}", md.len(), p.display())?;
    } else {
        writeln!(w, "{}", p.display())?;
    }
    Ok(())
}

fn resolve(cwd: &Path, arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.is_absolute() {
        p
    } else {
        cwd.join(p)
    }
}
