//! Built-in commands.
//!
//! Every command users can invoke is implemented right here in Rust,
//! as a pure function over `(argv, stdin, stdout, ctx)`. Nothing ever
//! shells out. This is the whole point: the argv is already a
//! `Vec<String>` by the time a builtin sees it, so there are no
//! metacharacters to interpret, no PATH lookups, no quoting subtleties,
//! and no child processes to escape into.

use anyhow::Result;
use std::io::{Read, Write};

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
    /// Output byte budget for one pipeline, decremented as bytes are written.
    pub output_budget: u64,
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
    "help", "exit", "pwd", "cd", "ls", "cat", "echo", "head", "tail", "wc", "grep", "find",
    "date", "id", "whoami", "stat",
];
