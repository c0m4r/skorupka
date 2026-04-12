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
    let sanitized = sanitize_log(detail);
    tracing::info!(target: "skorupka::audit", user, kind, detail = %sanitized, "audit");
}

/// Sanitize a string for safe log output.
///
/// Truncates to 512 characters and replaces anything that is not a
/// printable ASCII graphic character or a space with '?'. This prevents
/// log injection attacks where crafted input could confuse downstream
/// log aggregators that parse structured formats (syslog, JSON lines).
fn sanitize_log(s: &str) -> String {
    s.chars()
        .take(512)
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .collect()
}
