//! TOML configuration schema and loader.
//!
//! The config file is parsed *before* landlock + seccomp are sealed,
//! so the parser can still reach `/etc/skorupka/config.toml`. After
//! parsing, the per-user allowed-path set is used to build the landlock
//! ruleset, which then cannot be widened.

use anyhow::{Context, Result, anyhow, bail};
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
        bail!(
            "user {}: allowed_paths_ro entry '/' is forbidden (would nullify landlock)",
            user
        );
    }
    for dr in &["/proc", "/sys", "/dev"] {
        if s == *dr || s.starts_with(&format!("{}/", dr)) {
            bail!(
                "user {}: allowed_paths_ro entry {:?} is inside {} — exposes kernel/device internals",
                user,
                p,
                dr
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
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate the config and **replace every stored path with its canonical
    /// form**.
    ///
    /// Security note (Report-3 High / TOCTOU): we used to call
    /// `canonicalize()` only for validation but then passed the *original*
    /// symlink path to Landlock's `PathFd::new()`. An attacker who can
    /// swap the symlink target between the validation check and the
    /// `PathFd::new()` open could have the kernel open a different inode
    /// than the one we validated.  Storing the canonical path eliminates
    /// the race: both the safety check and the Landlock call use the same
    /// resolved, absolute path with no symlink components.
    pub fn validate(&mut self) -> Result<()> {
        if self.users.is_empty() {
            bail!("config has no [[user]] entries");
        }
        for u in &mut self.users {
            // Clone name to avoid borrowing `u` while we also mutate its fields.
            let name = u.name.clone();
            if name.is_empty() {
                bail!("user entry with empty name");
            }
            for p in &mut u.allowed_paths_ro {
                if !p.is_absolute() {
                    bail!(
                        "user {}: allowed_paths_ro entry {:?} is not absolute",
                        name,
                        p
                    );
                }
                reject_dangerous_root(&name, p)?;
                // Require the path to exist AND be resolvable at config-
                // load time. This catches typos, permissions problems,
                // and "symlink is still to-be-created" setups where a
                // literal check passes but the real target is dangerous.
                let canon = p.canonicalize().map_err(|e| {
                    anyhow!(
                        "user {}: allowed_paths_ro entry {:?} does not resolve: {}",
                        name,
                        p,
                        e
                    )
                })?;
                if canon != *p {
                    reject_dangerous_root(&name, &canon)?;
                }
                // Replace with the canonical form. Landlock's PathFd::new()
                // will open this path; using the canonical path means no
                // symlink component can be swapped between now and then.
                *p = canon;
            }

            // Validate and canonicalize start_dir if configured.
            // (Report-3 Low-Med): start_dir was previously unvalidated —
            // it could point outside the allowed paths.
            if let Some(sd) = u.start_dir.take() {
                if !sd.is_absolute() {
                    bail!("user {}: start_dir {:?} must be an absolute path", name, sd);
                }
                let canon_sd = sd.canonicalize().map_err(|e| {
                    anyhow!("user {}: start_dir {:?} does not resolve: {}", name, sd, e)
                })?;
                // start_dir must be reachable under at least one allowed path.
                let within = u
                    .allowed_paths_ro
                    .iter()
                    .any(|allowed| canon_sd.starts_with(allowed));
                if !within {
                    bail!(
                        "user {}: start_dir {:?} is not within any allowed_paths_ro entry",
                        name,
                        canon_sd
                    );
                }
                u.start_dir = Some(canon_sd);
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
