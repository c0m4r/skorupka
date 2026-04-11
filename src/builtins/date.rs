use super::Ctx;
use anyhow::Result;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(
    _argv: &[String],
    _stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    _ctx: &mut Ctx,
) -> Result<()> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Minimal UTC formatter — no timezone db access needed.
    let (y, mo, d, h, mi, s) = epoch_to_utc(secs as i64);
    writeln!(
        stdout,
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, mo, d, h, mi, s
    )?;
    Ok(())
}

fn epoch_to_utc(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    // Algorithm from Howard Hinnant's date library (public domain).
    let z = secs.div_euclid(86400) + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    let tod = secs.rem_euclid(86400) as u32;
    (y, m, d, tod / 3600, (tod / 60) % 60, tod % 60)
}
