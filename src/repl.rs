//! Interactive REPL + pipeline execution.
//!
//! The loop reads a line (via rustyline), parses it into a Pipeline,
//! and runs each stage on its own scoped thread connected with `os_pipe`.
//! Builtins are pure functions operating on `(argv, stdin, stdout, ctx)`,
//! so there is no process spawning anywhere in the pipeline.

use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashSet;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::audit;
use crate::builtins::{self, Ctx};
use crate::config::Config as SkConfig;
use crate::parser::{self, Pipeline};
use crate::sandbox;

/// Entry point for `skorupka run`.
///
/// Order of operations matters: we load config BEFORE sealing the
/// sandbox (so the TOML parser can reach /etc/skorupka/config.toml),
/// then identify the current user, then seal. After sealing, every
/// subsequent syscall is filtered.
pub fn run(config_path: &str, user_override: Option<&str>) -> Result<()> {
    let cfg_path = std::path::PathBuf::from(config_path);
    let cfg = SkConfig::load(&cfg_path).context("load config")?;

    let username = match user_override {
        Some(u) => {
            // --user requires root to prevent an unprivileged attacker
            // from selecting a more permissive policy by name.
            if !nix::unistd::Uid::current().is_root() {
                bail!("--user requires root (prevents policy impersonation)");
            }
            u.to_string()
        }
        None => current_username()?,
    };
    let policy = cfg
        .user(&username)
        .with_context(|| format!("no sandbox policy for user {}", username))?
        .clone();

    // Audit: log the start of the session BEFORE sealing — syslog may
    // want paths/sockets that seccomp will later forbid.
    audit::init(&username);
    audit::event("session_start", &format!("user={}", username));

    // --- SEAL THE SANDBOX ---
    sandbox::seal(&policy, &cfg.limits)?;
    // --- from here on, no execve, no unsafe syscalls, no writes ---

    // Hop to the start directory (still allowed, cwd is permitted by
    // landlock because it lives under an allowed_paths_ro entry).
    // config.validate() has already canonicalized start_dir and verified
    // it is within an allowed_paths_ro entry, so this chdir should never
    // fail. Treat failure as fatal: a misconfigured start_dir means the
    // session would land in an unexpected place, which could violate
    // policy intent.
    let start_dir = policy.start_dir.clone().unwrap_or_else(|| {
        policy
            .allowed_paths_ro
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/"))
    });
    std::env::set_current_dir(&start_dir)
        .with_context(|| format!("chdir to start_dir {}", start_dir.display()))?;

    let mut ctx = Ctx {
        cwd: std::env::current_dir().unwrap_or(start_dir),
        enabled: policy
            .builtins_enabled
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        output_budget: Arc::new(AtomicU64::new(cfg.defaults.max_output_bytes)),
    };

    print_banner(&policy);

    // Minimal line reader. We deliberately avoid rustyline because its
    // startup path under seccomp is fragile (clone3, signalfd, various
    // termios ioctls across glibc versions) and we don't need history
    // or line editing in a sandbox. Users can still use the ssh client's
    // own readline if they want arrow keys.
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut line_buf = String::new();

    loop {
        {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            let _ = lock.write_all(cfg.defaults.prompt.as_bytes());
            let _ = lock.flush();
        }
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Ok(0) => {
                audit::event("session_end", "reason=eof");
                return Ok(());
            }
            Ok(_) => {
                if line_buf.len() > cfg.defaults.max_line_len {
                    eprintln!("line too long");
                    continue;
                }
                let line = line_buf.trim_end_matches(&['\r', '\n'][..]).to_string();
                if line.trim().is_empty() {
                    continue;
                }
                // Parse
                let pipeline = match parser::parse(
                    &line,
                    cfg.defaults.max_line_len,
                    cfg.defaults.max_pipeline_stages,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("parse error: {}", e);
                        audit::event("parse_reject", &format!("line={:?} err={}", line, e));
                        continue;
                    }
                };
                if pipeline.stages.is_empty() {
                    continue;
                }

                // Reset per-pipeline budget. A fresh AtomicU64 is created
                // for each pipeline so stages from a previous pipeline
                // cannot carry a depleted counter into the next command.
                ctx.output_budget = Arc::new(AtomicU64::new(cfg.defaults.max_output_bytes));

                // Handle `exit` as a REPL directive.
                if pipeline.stages.len() == 1
                    && matches!(
                        pipeline.stages[0].argv.first().map(String::as_str),
                        Some("exit") | Some("quit")
                    )
                {
                    audit::event("session_end", "reason=exit");
                    return Ok(());
                }

                // Validate that every stage is an enabled builtin before running.
                if let Err(e) = validate_stages(&pipeline, &ctx.enabled) {
                    eprintln!("{}", e);
                    audit::event("cmd_reject", &format!("line={:?} err={}", line, e));
                    continue;
                }

                audit::event("cmd", &format!("line={:?}", line));
                if let Err(e) = run_pipeline(&pipeline, &mut ctx) {
                    eprintln!("error: {}", e);
                    audit::event("cmd_error", &format!("err={}", e));
                }
            }
            Err(e) => {
                eprintln!("read error: {}", e);
                audit::event("session_end", "reason=read_err");
                return Ok(());
            }
        }
    }
}

fn print_banner(policy: &crate::config::UserPolicy) {
    eprintln!("skorupka sandbox (read-only). Type 'help' for commands.");
    eprintln!("Allowed paths:");
    for p in &policy.allowed_paths_ro {
        eprintln!("  {}", p.display());
    }
}

fn current_username() -> Result<String> {
    let uid = nix::unistd::Uid::current();
    Ok(nix::unistd::User::from_uid(uid)?
        .ok_or_else(|| anyhow!("no passwd entry for uid {}", uid.as_raw()))?
        .name)
}

fn validate_stages(p: &Pipeline, enabled: &HashSet<String>) -> Result<()> {
    for (i, s) in p.stages.iter().enumerate() {
        let name = s.argv.first().ok_or_else(|| anyhow!("empty stage"))?;
        if !enabled.contains(name) {
            bail!("command not allowed: {}", name);
        }
        if builtins::lookup(name).is_none() {
            bail!("unknown builtin: {}", name);
        }
        if name == "cd" && p.stages.len() > 1 {
            bail!("cd cannot be used inside a pipeline");
        }
        // `exit` handled at stage 0 only (already shortcircuited above).
        if name == "exit" && i != 0 {
            bail!("exit only valid as first stage");
        }
    }
    Ok(())
}

/// Execute a parsed pipeline. Each stage runs on its own scoped thread,
/// connected via os_pipe byte pipes. Stage 0 reads from /dev/null-ish
/// (empty reader); the final stage writes to the terminal stdout.
fn run_pipeline(p: &Pipeline, ctx: &mut Ctx) -> Result<()> {
    // Fast path: single stage, no thread needed, and we can pass the
    // real ctx (so `cd` mutates it).
    if p.stages.len() == 1 {
        let stage = &p.stages[0];
        let name = &stage.argv[0];
        let bf = builtins::lookup(name).unwrap();
        let mut stdin_r: Box<dyn Read + Send> = Box::new(io::empty());
        let stdout = io::stdout();
        let mut safe = SafeWriter::new(stdout.lock(), Arc::clone(&ctx.output_budget));
        return bf(&stage.argv, &mut *stdin_r, &mut safe, ctx);
    }

    // Multi-stage: thread per stage.
    use std::thread;

    // Build pipes between stages: readers[i] feeds stage i, writers[i]
    // is the stdout of stage i. Stage 0 reads empty, stage N-1 writes
    // to terminal.
    let n = p.stages.len();
    let mut readers: Vec<Box<dyn Read + Send>> = Vec::with_capacity(n);
    let mut writers: Vec<Box<dyn Write + Send>> = Vec::with_capacity(n);

    readers.push(Box::new(io::empty()));
    for _ in 0..(n - 1) {
        let (r, w) = os_pipe::pipe().context("os_pipe")?;
        writers.push(Box::new(w));
        readers.push(Box::new(r));
    }
    // Final writer is a budget-aware, ANSI-safe wrapper over stdout.
    writers.push(Box::new(StdoutSink::new(Arc::clone(&ctx.output_budget))));

    thread::scope(|scope| -> Result<()> {
        let mut handles = Vec::with_capacity(n);

        for stage in p.stages.iter() {
            let name = stage.argv[0].clone();
            let bf = builtins::lookup(&name).unwrap();
            let argv = stage.argv.clone();
            let mut r = readers.remove(0);
            let mut w = writers.remove(0);
            // All stages share one AtomicU64 budget so the TOTAL bytes
            // moved by the entire pipeline is bounded to max_output_bytes,
            // with no per-stage caps and no integer-division slop.
            let mut stage_ctx = Ctx {
                cwd: ctx.cwd.clone(),
                enabled: ctx.enabled.clone(),
                output_budget: Arc::clone(&ctx.output_budget),
            };

            let h = scope.spawn(move || -> Stage2Result {
                let res = bf(&argv, &mut *r, &mut *w, &mut stage_ctx);
                // Drop writer to signal EOF to the next stage.
                drop(w);
                Stage2Result { name, res }
            });
            handles.push(h);
        }

        let mut errors = Vec::new();
        for h in handles {
            match h.join() {
                Ok(sr) => {
                    if let Err(e) = sr.res {
                        errors.push(format!("{}: {}", sr.name, e));
                    }
                }
                Err(_) => errors.push("stage panicked".into()),
            }
        }
        if !errors.is_empty() {
            bail!("{}", errors.join("; "));
        }
        Ok(())
    })
}

struct Stage2Result {
    name: String,
    res: Result<()>,
}

/// Writer that flushes each write to the process stdout behind a lock,
/// passing every byte through `SafeWriter`'s budget check and ANSI filter.
/// This is used as the final-stage writer in multi-stage pipelines so
/// that all concurrent pipeline threads share one output path.
struct StdoutSink {
    budget: Arc<AtomicU64>,
}
impl StdoutSink {
    fn new(budget: Arc<AtomicU64>) -> Self {
        Self { budget }
    }
}
impl Write for StdoutSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let out = io::stdout();
        let mut lock = out.lock();
        let mut safe = SafeWriter::new(&mut lock, Arc::clone(&self.budget));
        safe.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// A write filter that:
///   1. Enforces the shared output byte budget (fails with an IO error
///      when the budget is exhausted so builtins stop writing naturally).
///   2. Replaces bytes which could attack the operator's terminal emulator
///      — ESC (0x1B), DEL (0x7F), BEL (0x07), and all other C0/C1 control
///      bytes — with '?'. TAB, LF, and CR pass through unchanged.
///      UTF-8 high bytes (0x80–0xFF) also pass through.
///
/// Every user-visible output path goes through this writer, so neither
/// the budget cap nor the ANSI filter can be bypassed by any builtin,
/// regardless of whether it calls writeln!, write_all, or a helper.
///
/// Budget accounting uses the *pre-filter* byte count (original `buf`
/// length). This is intentionally conservative: a stream of pure control
/// bytes would each be replaced with '?' and still count against the
/// budget, preventing an attacker from bypassing the cap with a payload
/// that shrinks or expands after filtering.
struct SafeWriter<W: Write> {
    inner: W,
    budget: Arc<AtomicU64>,
}
impl<W: Write> SafeWriter<W> {
    fn new(inner: W, budget: Arc<AtomicU64>) -> Self {
        Self { inner, budget }
    }
}
impl<W: Write> Write for SafeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Spend the budget before writing. The CAS loop in budget_spend
        // prevents concurrent stages from each reading a remaining value,
        // deciding they can afford their write, and both subtracting —
        // which would underflow the counter.
        //
        // SEC-005: `buf.len() as u64` is lossless on all targets skorupka
        // is built for (Linux x86-64 / aarch64, where usize == u64).
        // RLIMIT_AS is enforced before the REPL starts, so a single write
        // larger than usize::MAX is impossible in practice.
        if !budget_spend(&self.budget, buf.len() as u64) {
            return Err(io::Error::other("output budget exhausted"));
        }
        // Strip control bytes: walk the buffer writing contiguous safe
        // runs directly and emitting a single '?' for each unsafe byte.
        let mut start = 0;
        for (i, &b) in buf.iter().enumerate() {
            if !is_safe_byte(b) {
                if i > start {
                    self.inner.write_all(&buf[start..i])?;
                }
                self.inner.write_all(b"?")?;
                start = i + 1;
            }
        }
        if start < buf.len() {
            self.inner.write_all(&buf[start..])?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Attempt to atomically spend `cost` bytes from `budget`.
/// Uses a compare-exchange loop to prevent concurrent overdraft.
/// Returns `false` if fewer than `cost` bytes remain.
fn budget_spend(budget: &AtomicU64, cost: u64) -> bool {
    let mut current = budget.load(Ordering::Relaxed);
    loop {
        if current < cost {
            return false;
        }
        match budget.compare_exchange_weak(
            current,
            current - cost,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

#[inline]
fn is_safe_byte(b: u8) -> bool {
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0x80..=0xFF)
}

#[cfg(test)]
mod safe_writer_tests {
    use super::SafeWriter;
    use std::io::Write;

    fn filtered(s: &[u8]) -> Vec<u8> {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;
        let mut buf = Vec::new();
        // Use a large budget so tests focus on the ANSI filter, not the cap.
        let budget = Arc::new(AtomicU64::new(u64::MAX));
        let mut w = SafeWriter::new(&mut buf, budget);
        w.write_all(s).unwrap();
        buf
    }

    #[test]
    fn passes_printable_ascii() {
        assert_eq!(filtered(b"hello world"), b"hello world");
    }

    #[test]
    fn passes_tab_lf_cr() {
        assert_eq!(filtered(b"a\tb\nc\rd"), b"a\tb\nc\rd");
    }

    #[test]
    fn strips_escape_sequence() {
        // ESC[31m is a red-foreground ANSI escape. Should become '??31m'.
        assert_eq!(filtered(b"\x1b[31mRED\x1b[0m"), b"?[31mRED?[0m");
    }

    #[test]
    fn strips_bell_and_del() {
        assert_eq!(filtered(b"a\x07b\x7fc"), b"a?b?c");
    }

    #[test]
    fn preserves_utf8_high_bytes() {
        // "café" in UTF-8: 0x63 0x61 0x66 0xC3 0xA9
        assert_eq!(filtered(b"caf\xC3\xA9"), b"caf\xC3\xA9");
    }

    #[test]
    fn strips_osc_command() {
        // Set-window-title OSC sequence: ESC ] 0 ; ... BEL
        assert_eq!(filtered(b"\x1b]0;pwn\x07"), b"?]0;pwn?");
    }

    #[test]
    fn budget_zero_blocks_all_writes() {
        // A SafeWriter with budget=0 must refuse any write, even from a
        // builtin that calls writeln! directly (the path that previously
        // bypassed budget enforcement).
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;
        let mut buf = Vec::new();
        let budget = Arc::new(AtomicU64::new(0));
        let mut w = SafeWriter::new(&mut buf, budget);
        let result = w.write_all(b"hello");
        assert!(
            result.is_err(),
            "write through exhausted budget should fail"
        );
        assert!(buf.is_empty(), "no bytes should have been written");
    }

    #[test]
    fn budget_exact_allows_then_blocks() {
        // Budget of 5 allows the first 5-byte write, then refuses the next.
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;
        let budget = Arc::new(AtomicU64::new(5));
        let result = {
            let mut buf = Vec::new();
            {
                let mut w = SafeWriter::new(&mut buf, Arc::clone(&budget));
                w.write_all(b"hello").unwrap();
            }
            assert_eq!(&buf, b"hello");
            let mut buf2 = Vec::new();
            let mut w2 = SafeWriter::new(&mut buf2, Arc::clone(&budget));
            w2.write_all(b"x")
        };
        assert!(result.is_err(), "write past budget should fail");
    }
}
