//! TOML configuration schema and loader.
//!
//! The config file is parsed *before* landlock + seccomp are sealed,
//! so the parser can still reach `/etc/skorupka/config.toml`. After
//! parsing, the per-user allowed-path set is used to build the landlock
//! ruleset, which then cannot be widened.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default, rename = "user")]
    pub users: Vec<UserPolicy>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Defaults {
    #[serde(default = "default_prompt")]
    pub prompt: String,
    #[serde(default)]
    pub history_file: String,
    #[serde(default = "default_max_line_len")]
    pub max_line_len: usize,
    #[serde(default = "default_max_pipeline_stages")]
    pub max_pipeline_stages: usize,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: u64,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            prompt: default_prompt(),
            history_file: String::new(),
            max_line_len: default_max_line_len(),
            max_pipeline_stages: default_max_pipeline_stages(),
            max_output_bytes: default_max_output_bytes(),
        }
    }
}

fn default_prompt() -> String {
    "skorupka> ".into()
}
fn default_max_line_len() -> usize {
    4096
}
fn default_max_pipeline_stages() -> usize {
    8
}
fn default_max_output_bytes() -> u64 {
    100 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
pub struct Limits {
    #[serde(default = "default_nproc")]
    pub rlimit_nproc: u64,
    #[serde(default = "default_cpu")]
    pub rlimit_cpu_sec: u64,
    #[serde(default = "default_as_mb")]
    pub rlimit_as_mb: u64,
    #[serde(default)]
    pub rlimit_fsize_mb: u64, // 0 = no writes
    #[serde(default = "default_nofile")]
    pub rlimit_nofile: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rlimit_nproc: default_nproc(),
            rlimit_cpu_sec: default_cpu(),
            rlimit_as_mb: default_as_mb(),
            // NOTE: fsize must be non-zero. Landlock is the authoritative
            // write-denial layer (it rejects O_WRONLY/O_CREAT on any file
            // not under an rw-granted path, and we grant none in v1).
            // RLIMIT_FSIZE cannot be set to 0 because stdio is often
            // redirected to a session log by sshd/operators, and a
            // zero limit kills the process with SIGXFSZ on the first
            // subsequent eprintln. 64 MiB is enough headroom for a
            // long interactive session without leaving a useful amount
            // of disk space for an attacker who somehow slipped past
            // landlock.
            rlimit_fsize_mb: 64,
            rlimit_nofile: default_nofile(),
        }
    }
}

fn default_nproc() -> u64 {
    16
}
fn default_cpu() -> u64 {
    600
}
fn default_as_mb() -> u64 {
    512
}
fn default_nofile() -> u64 {
    64
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct UserPolicy {
    pub name: String,
    #[serde(default)]
    pub allowed_paths_ro: Vec<PathBuf>,
    #[serde(default = "default_builtins")]
    pub builtins_enabled: Vec<String>,
    #[serde(default)]
    pub start_dir: Option<PathBuf>,

    // Reserved for v2 (external commands). Unused in v1.
    #[serde(default)]
    pub allow_devnull: bool,
    #[serde(default)]
    pub allow_devzero: bool,
}

/// Root paths that nullify or massively weaken the sandbox. `/proc`,
/// `/sys` and `/dev` each expose primitives that can be used to read
/// process memory (`/proc/self/mem`), attack kernel state (`/sys/kernel/*`),
/// or reach arbitrary devices. `/` defeats landlock entirely.
fn reject_dangerous_root(user: &str, p: &std::path::Path) -> Result<()> {
    let s = p.to_string_lossy();
    if s == "/" {
        bail!("user {}: allowed_paths_ro entry '/' is forbidden (would nullify landlock)", user);
    }
    for dr in &["/proc", "/sys", "/dev"] {
        if s == *dr || s.starts_with(&format!("{}/", dr)) {
            bail!(
                "user {}: allowed_paths_ro entry {:?} is inside {} — exposes kernel/device internals",
                user, p, dr
            );
        }
    }
    Ok(())
}

fn default_builtins() -> Vec<String> {
    [
        "help", "exit", "pwd", "cd", "ls", "cat", "echo", "head", "tail", "wc", "grep", "find",
        "date", "id", "whoami", "stat", "pager",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.users.is_empty() {
            bail!("config has no [[user]] entries");
        }
        for u in &self.users {
            if u.name.is_empty() {
                bail!("user entry with empty name");
            }
            for p in &u.allowed_paths_ro {
                if !p.is_absolute() {
                    bail!("user {}: allowed_paths_ro entry {:?} is not absolute", u.name, p);
                }
                reject_dangerous_root(&u.name, p)?;
                // Require the path to exist AND be resolvable at config-
                // load time. This catches typos, permissions problems,
                // and "symlink is still to-be-created" setups where a
                // literal check passes but the real target is dangerous.
                let canon = p.canonicalize().map_err(|e| {
                    anyhow!(
                        "user {}: allowed_paths_ro entry {:?} does not resolve: {}",
                        u.name, p, e
                    )
                })?;
                if canon != *p {
                    reject_dangerous_root(&u.name, &canon)?;
                }
            }
        }
        Ok(())
    }

    pub fn user(&self, name: &str) -> Result<&UserPolicy> {
        self.users
            .iter()
            .find(|u| u.name == name)
            .ok_or_else(|| anyhow!("no policy for user {}", name))
    }
}
