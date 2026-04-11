use super::Ctx;
use anyhow::Result;
use std::io::{Read, Write};

pub fn run(
    _argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    writeln!(stdout, "skorupka — restricted sandbox shell")?;
    writeln!(stdout, "Available commands:")?;
    let mut names: Vec<_> = ctx.enabled.iter().collect();
    names.sort();
    for n in names {
        writeln!(stdout, "  {}", n)?;
    }
    writeln!(stdout)?;
    writeln!(
        stdout,
        "Pipelines use '|'. No ';', '&', '>', '<', '$', '`', globs, or quotes except \"…\"."
    )?;
    writeln!(stdout, "File access is limited to whitelisted paths.")?;
    Ok(())
}
