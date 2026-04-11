use super::Ctx;
use anyhow::Result;
use std::io::{Read, Write};

pub fn run(
    argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    _ctx: &mut Ctx,
) -> Result<()> {
    let mut first = true;
    for a in argv.iter().skip(1) {
        if !first {
            stdout.write_all(b" ")?;
        }
        stdout.write_all(a.as_bytes())?;
        first = false;
    }
    stdout.write_all(b"\n")?;
    Ok(())
}
