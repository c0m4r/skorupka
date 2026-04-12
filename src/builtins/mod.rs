//! Built-in commands.
//!
//! Every command users can invoke is implemented right here in Rust,
//! as a pure function over `(argv, stdin, stdout, ctx)`. Nothing ever
//! shells out. This is the whole point: the argv is already a
//! `Vec<String>` by the time a builtin sees it, so there are no
//! metacharacters to interpret, no PATH lookups, no quoting subtleties,
//! and no child processes to escape into.

use anyhow::Result;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

/// Hard per-line size cap used by all `read_until`-based builtins.
///
/// A single line longer than 1 MiB is almost certainly a binary file
/// being fed through a text builtin, or adversarial input attempting to
/// force unbounded heap allocation. We truncate the line rather than
/// allocating without limit.
pub(crate) const MAX_LINE_BYTES: usize = 1 << 20; // 1 MiB

/// Read one newline-terminated line from `r`, capped at [`MAX_LINE_BYTES`].
///
/// Semantics mirror `BufRead::read_until(b'\n', buf)`:
/// - `buf` is cleared on entry.
/// - Returns `Ok(0)` only at EOF.
/// - Otherwise returns `Ok(n)` where `n > 0` and `buf` contains the line
///   (possibly without a trailing `\n` if EOF was hit mid-line).
///
/// If the underlying line is longer than `MAX_LINE_BYTES`, the excess bytes
/// up to and including the next `\n` are consumed and discarded so the
/// next call starts at a fresh line boundary.
pub(crate) fn read_line_capped<R: BufRead>(r: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    buf.clear();
    // `Take` makes the reader look like it ends after MAX_LINE_BYTES bytes,
    // so `read_until` cannot grow `buf` beyond that regardless of line length.
    let n = r
        .by_ref()
        .take(MAX_LINE_BYTES as u64)
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(0);
    }
    // If we stopped at the cap without finding a newline, drain the rest of
    // this line from the underlying reader so the next call starts cleanly.
    if !buf.ends_with(b"\n") {
        let mut discard = [0u8; 4096];
        loop {
            let got = r.read(&mut discard)?;
            if got == 0 {
                break; // EOF
            }
            if discard[..got].contains(&b'\n') {
                break; // consumed through the newline
            }
        }
    }
    Ok(n)
}

pub mod cat;
pub mod cd;
pub mod date;
pub mod echo;
pub mod find;
pub mod grep;
pub mod head;
pub mod help;
pub mod id;
pub mod ls;
pub mod pwd;
pub mod stat;
pub mod tail;
pub mod wc;

/// Per-REPL mutable state passed to every builtin.
pub struct Ctx {
    /// Logical working directory (we track it ourselves rather than relying
    /// on the process cwd, to give consistent errors under landlock).
    pub cwd: std::path::PathBuf,
    /// Enabled builtin names for the current user.
    pub enabled: std::collections::HashSet<String>,
    /// Output byte budget for the current pipeline. Builtins do NOT draw
    /// from this directly — all budget enforcement happens inside
    /// `SafeWriter` in the REPL layer, so every write from any builtin
    /// (writeln!, write_all, or a helper) is automatically budget-checked.
    /// The field is held here so the REPL can hand it to SafeWriter and
    /// reset it between pipeline invocations.
    pub output_budget: Arc<AtomicU64>,
}

/// Builtin signature. stdin/stdout are trait objects so pipeline stages
/// can wire them to pipes or the terminal uniformly.
pub type BuiltinFn = fn(&[String], &mut dyn Read, &mut dyn Write, &mut Ctx) -> Result<()>;

/// Look up a builtin by name.
pub fn lookup(name: &str) -> Option<BuiltinFn> {
    Some(match name {
        "help" => help::run,
        "exit" | "quit" => exit_stub,
        "pwd" => pwd::run,
        "cd" => cd::run,
        "ls" => ls::run,
        "cat" => cat::run,
        "echo" => echo::run,
        "head" => head::run,
        "tail" => tail::run,
        "wc" => wc::run,
        "grep" => grep::run,
        "find" => find::run,
        "date" => date::run,
        "id" | "whoami" => id::run,
        "stat" => stat::run,
        _ => return None,
    })
}

/// `exit` is handled specially by the REPL (it needs to break the loop),
/// so this stub exists only so `lookup("exit")` returns `Some`.
fn exit_stub(
    _argv: &[String],
    _stdin: &mut dyn Read,
    _stdout: &mut dyn Write,
    _ctx: &mut Ctx,
) -> Result<()> {
    Ok(())
}

/// All known builtin names (for help output and tab completion lists).
#[allow(dead_code)]
pub const ALL: &[&str] = &[
    "help", "exit", "pwd", "cd", "ls", "cat", "echo", "head", "tail", "wc", "grep", "find", "date",
    "id", "whoami", "stat",
];
