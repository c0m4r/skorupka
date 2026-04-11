//! `skorupka install` and `skorupka adduser`.
//!
//! Both are safe, idempotent scaffolding helpers that operate OUTSIDE
//! the sealed sandbox (they're invoked by an admin, not the restricted
//! user).

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

const DEFAULT_CONFIG: &str = r#"# /etc/skorupka/config.toml
[defaults]
prompt = "skorupka> "
history_file = ""
max_line_len = 4096
max_pipeline_stages = 8
max_output_bytes = 104857600

[limits]
rlimit_nproc    = 16
rlimit_cpu_sec  = 600
rlimit_as_mb    = 512
rlimit_fsize_mb = 64    # landlock is the real write-denial; this is just a session-log cap
rlimit_nofile   = 64

# Example user. Add one [[user]] block per sandbox user.
# [[user]]
# name = "loguser"
# allowed_paths_ro = ["/var/log", "/etc/hostname"]
# builtins_enabled = ["ls","cat","head","tail","grep","wc","pwd","cd","find","date","id","help","exit","stat","echo"]
# start_dir = "/var/log"
# allow_devnull = false   # reserved for v2 (external commands)
# allow_devzero = false   # reserved for v2 (external commands)
"#;

const SSHD_SNIPPET: &str = r#"# --- BEGIN skorupka sandbox ---
# ForceCommand below blocks sftp-server, scp, rsync, and
# `ssh host '<arbitrary command>'` — sshd always replaces the user's
# requested command with this sentinel, and skorupka accepts only this
# exact string via its -c handler. Any other -c invocation is audit-
# logged and rejected.
Match Group skorupka
    ForceCommand /usr/local/bin/skorupka run
    PermitTTY yes
    X11Forwarding no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    PermitTunnel no
    PermitUserRC no
    GatewayPorts no
# --- END skorupka sandbox ---
"#;

pub fn install() -> Result<()> {
    let cfg_dir = Path::new("/etc/skorupka");
    let cfg_file = cfg_dir.join("config.toml");

    if !cfg_dir.exists() {
        fs::create_dir_all(cfg_dir)
            .with_context(|| format!("mkdir {}", cfg_dir.display()))?;
    }
    if cfg_file.exists() {
        println!("note: {} already exists, leaving it alone", cfg_file.display());
    } else {
        fs::write(&cfg_file, DEFAULT_CONFIG)
            .with_context(|| format!("write {}", cfg_file.display()))?;
        // Config is world-readable but not writable.
        set_mode(&cfg_file, 0o644)?;
        println!("wrote {}", cfg_file.display());
    }

    // sshd drop-in. We write it directly into sshd_config.d/ rather than
    // making the operator copy-paste from the terminal. `sshd_config.d/`
    // has been the recommended include path on every current distro for
    // years; if it's absent the operator is running an unusually old
    // sshd and we fall back to printing instructions.
    let sshd_dir = Path::new("/etc/ssh/sshd_config.d");
    let sshd_file = sshd_dir.join("90-skorupka.conf");
    if sshd_dir.is_dir() {
        if sshd_file.exists() {
            println!("note: {} already exists, leaving it alone", sshd_file.display());
        } else {
            fs::write(&sshd_file, SSHD_SNIPPET)
                .with_context(|| format!("write {}", sshd_file.display()))?;
            set_mode(&sshd_file, 0o644)?;
            println!("wrote {}", sshd_file.display());
        }
    } else {
        println!();
        println!("note: {} does not exist on this system.", sshd_dir.display());
        println!("Add the following block to /etc/ssh/sshd_config manually:");
        println!();
        println!("{}", SSHD_SNIPPET);
    }

    println!();
    println!("Next steps:");
    println!("  1. groupadd -f skorupka");
    println!("  2. sshd -t && systemctl reload ssh   # or sshd on non-Debian");
    println!("  3. skorupka adduser <name> --paths /var/log");
    println!();
    println!("Audit events go to stderr of each sshd session. If you want");
    println!("them collected centrally, point sshd's logging (or a systemd");
    println!("journal rule tagged with `skorupka::audit`) at your SIEM.");
    Ok(())
}

pub fn adduser(name: &str, paths: &[String]) -> Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        bail!("invalid username: {:?}", name);
    }
    if paths.is_empty() {
        bail!("--paths is required (comma-separated list of absolute directories)");
    }
    for p in paths {
        let pp = Path::new(p);
        if !pp.is_absolute() {
            bail!("path {:?} is not absolute", p);
        }
        if !pp.exists() {
            bail!("path {:?} does not exist", p);
        }
    }

    println!("Manual steps (run as root):");
    println!("  groupadd -f skorupka");
    println!("  useradd -m -s /usr/local/bin/skorupka -g skorupka {}", name);
    println!();
    println!("Then append this block to /etc/skorupka/config.toml:");
    println!();
    let paths_list = paths
        .iter()
        .map(|p| format!("{:?}", p))
        .collect::<Vec<_>>()
        .join(", ");
    println!("[[user]]");
    println!("name = \"{}\"", name);
    println!("allowed_paths_ro = [{}]", paths_list);
    println!("builtins_enabled = [\"ls\",\"cat\",\"head\",\"tail\",\"grep\",\"wc\",\"pwd\",\"cd\",\"find\",\"date\",\"id\",\"help\",\"exit\",\"stat\",\"echo\"]");
    println!("start_dir = {:?}", paths[0]);
    Ok(())
}

fn set_mode(p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(p)?;
    let mut perms = meta.permissions();
    perms.set_mode(mode);
    fs::set_permissions(p, perms)?;
    Ok(())
}
