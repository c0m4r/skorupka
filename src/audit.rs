//! Audit logging.
//!
//! Writes structured events to stderr via the `tracing` crate so the
//! operator can pipe the sshd session output (or an attached syslog
//! collector) to a log aggregator. We intentionally do NOT open a file
//! or a unix socket here — once the sandbox is sealed, the process has
//! no file-write access, and seccomp would block a syslog(2) call
//! anyway. Stderr is owned by sshd and persists.

use std::sync::OnceLock;

static USER: OnceLock<String> = OnceLock::new();

pub fn init(user: &str) {
    let _ = USER.set(user.to_string());
}

pub fn event(kind: &str, detail: &str) {
    let user = USER.get().map(String::as_str).unwrap_or("?");
    tracing::info!(target: "skorupka::audit", user, kind, detail, "audit");
}
