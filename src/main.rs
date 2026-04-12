//! skorupka — hardened SSH sandbox shell.
//!
//! Entry point for the `skorupka` binary. Dispatches to subcommands:
//!   - `run`       — enter the sandboxed REPL (what sshd invokes)
//!   - `check`     — verify kernel feature support
//!   - `install`   — write default config and print sshd snippet
//!   - `adduser`   — create a sandbox user
//!   - `selftest`  — run in-process escape-attempt suite

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

mod audit;
mod builtins;
mod config;
mod install;
mod parser;
mod repl;
mod sandbox;
mod selftest;

/// The only `-c` argument value sshd is allowed to pass us. sshd wraps
/// ForceCommand as `shell -c '<ForceCommand>'`, so if we set ForceCommand
/// to exactly this sentinel, any other `-c` invocation (sftp-server,
/// scp backend, user-supplied remote command) is detectable as non-sshd
/// and rejected with an audit event.
const FORCECOMMAND_SENTINEL: &str = "/usr/local/bin/skorupka run";

#[derive(Parser)]
#[command(name = "skorupka", version, about = "Hardened SSH sandbox shell")]
struct Cli {
    /// Non-interactive command passthrough. sshd passes ForceCommand via
    /// this flag when skorupka is a login shell. Any value OTHER than the
    /// ForceCommand sentinel is rejected, which blocks sftp-server, scp,
    /// rsync, and `ssh host 'arbitrary command'` exfil paths.
    #[arg(short = 'c', long = "command", hide = true)]
    command: Option<String>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enter the sandboxed REPL (default action when invoked as a login shell).
    Run {
        /// Override config path.
        #[arg(long, default_value = "/etc/skorupka/config.toml")]
        config: String,
        /// Override the sandbox user (for testing; normally derived from getuid).
        #[arg(long)]
        user: Option<String>,
    },
    /// Verify kernel landlock / seccomp / no-new-privs support.
    Check,
    /// Write default config and print the sshd_config snippet.
    Install,
    /// Create a sandbox user.
    Adduser {
        name: String,
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,
    },
    /// Run the in-process escape-attempt suite under the real sandbox.
    Selftest,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "skorupka=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // `-c` and a subcommand together would let someone piggyback (e.g.
    // `skorupka -c '<sentinel>' selftest` would run selftest as the
    // sandbox user). Reject this BEFORE sentinel matching so neither
    // path can be abused.
    if cli.command.is_some() && cli.cmd.is_some() {
        bail!("skorupka: -c and subcommand are mutually exclusive");
    }

    // `-c` handler. Only the ForceCommand sentinel is honored; everything
    // else gets an audit event and exits non-zero. We accept the sentinel
    // whether or not it has the leading slash or the trailing `run`, to
    // tolerate operators who install skorupka in /usr/bin vs /usr/local/bin.
    if let Some(c) = cli.command.as_deref() {
        let trimmed = c.trim();
        let ok = trimmed == FORCECOMMAND_SENTINEL
            || trimmed == "skorupka run"
            || trimmed.ends_with("/skorupka run");
        if !ok {
            // No audit::init yet (pre-REPL), so we log via tracing directly.
            // Stderr goes to sshd's session log.
            tracing::warn!(
                target: "skorupka::audit",
                kind = "reject_noninteractive",
                forbidden_command = %trimmed,
                "non-interactive access denied"
            );
            eprintln!("skorupka: non-interactive access denied");
            std::process::exit(1);
        }
        // Sentinel matched → fall through to default Run.
    }

    // Default action (no subcommand) = `run`, so setting skorupka as a login
    // shell Just Works: sshd invokes `skorupka` with no args.
    match cli.cmd.unwrap_or(Cmd::Run {
        config: "/etc/skorupka/config.toml".into(),
        user: None,
    }) {
        Cmd::Run { config, user } => repl::run(&config, user.as_deref()),
        Cmd::Check => sandbox::check(),
        Cmd::Install => install::install(),
        Cmd::Adduser { name, paths } => install::adduser(&name, &paths),
        Cmd::Selftest => selftest::run(),
    }
}
