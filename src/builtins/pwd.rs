use super::Ctx;
use anyhow::Result;
use std::io::{Read, Write};

pub fn run(
    _argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    ctx: &mut Ctx,
) -> Result<()> {
    writeln!(stdout, "{}", ctx.cwd.display())?;
    Ok(())
}
