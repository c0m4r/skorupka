use super::Ctx;
use anyhow::Result;
use std::io::{Read, Write};

pub fn run(
    argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    _ctx: &mut Ctx,
) -> Result<()> {
    let uid = nix::unistd::Uid::current();
    let gid = nix::unistd::Gid::current();
    // User::from_uid reads /etc/passwd, which landlock likely forbids.
    // On failure, omit the name rather than printing `uid(uid)` which
    // looks like a bug.
    let user = nix::unistd::User::from_uid(uid).ok().flatten().map(|u| u.name);
    if argv.first().map(|s| s.as_str()) == Some("whoami") {
        match user {
            Some(n) => writeln!(stdout, "{}", n)?,
            None => writeln!(stdout, "{}", uid.as_raw())?,
        }
    } else {
        match user {
            Some(n) => writeln!(stdout, "uid={}({}) gid={}", uid.as_raw(), n, gid.as_raw())?,
            None => writeln!(stdout, "uid={} gid={}", uid.as_raw(), gid.as_raw())?,
        }
    }
    Ok(())
}
