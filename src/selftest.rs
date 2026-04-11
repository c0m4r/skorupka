//! `skorupka selftest` — runs a suite of escape attempts against the
//! sealed sandbox and asserts they all fail.
//!
//! The selftest uses a tmp directory as its sole allowed_paths_ro entry,
//! seals the sandbox, then tries each attack vector in turn.

use crate::config::{Limits, UserPolicy};
use crate::sandbox;
use anyhow::{bail, Result};
use std::path::PathBuf;

pub fn run() -> Result<()> {
    println!("skorupka selftest");
    println!("-----------------");

    // Build a policy that permits only /tmp (always exists).
    let policy = UserPolicy {
        name: "selftest".into(),
        allowed_paths_ro: vec![PathBuf::from("/tmp")],
        builtins_enabled: vec!["ls".into()],
        start_dir: Some(PathBuf::from("/tmp")),
        allow_devnull: false,
        allow_devzero: false,
    };
    let limits = Limits::default();

    // Plant symlink escape attempts BEFORE sealing, so the post-seal
    // tests can try to dereference them. We use a pid-suffixed name to
    // avoid collisions; we deliberately do not clean up because seccomp
    // denies `unlink` / `unlinkat` post-seal anyway.
    let pid = std::process::id();
    let symlink_file = std::path::PathBuf::from(format!(
        "/tmp/skorupka_selftest_symlink_file_{}", pid
    ));
    let symlink_dir = std::path::PathBuf::from(format!(
        "/tmp/skorupka_selftest_symlink_dir_{}", pid
    ));
    let _ = std::fs::remove_file(&symlink_file);
    let _ = std::fs::remove_file(&symlink_dir);
    // File symlink: /tmp/...sym → /etc/shadow
    std::os::unix::fs::symlink("/etc/shadow", &symlink_file).ok();
    // Directory symlink: /tmp/...sym → /etc (an out-of-jail dir)
    std::os::unix::fs::symlink("/etc", &symlink_dir).ok();

    println!("sealing sandbox...");
    sandbox::seal(&policy, &limits)?;
    println!("sealed.");

    let mut pass = 0;
    let mut fail = 0;
    let mut run = |name: &str, f: &dyn Fn() -> Result<()>| {
        match f() {
            Ok(()) => {
                println!("  [ok]   {}", name);
                pass += 1;
            }
            Err(e) => {
                println!("  [FAIL] {}: {}", name, e);
                fail += 1;
            }
        }
    };

    run("execve of /bin/sh is blocked", &|| {
        // SAFETY: we *want* this to fail.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_execve,
                b"/bin/sh\0".as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
            )
        };
        if rc == -1 {
            Ok(())
        } else {
            bail!("execve returned {}", rc)
        }
    });

    run("open /etc/shadow is denied by landlock", &|| {
        match std::fs::File::open("/etc/shadow") {
            Ok(_) => bail!("unexpectedly opened /etc/shadow"),
            Err(_) => Ok(()),
        }
    });

    run("open /etc/passwd is denied by landlock", &|| {
        match std::fs::File::open("/etc/passwd") {
            Ok(_) => bail!("unexpectedly opened /etc/passwd"),
            Err(_) => Ok(()),
        }
    });

    run("mount is blocked by seccomp", &|| {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_mount,
                b"none\0".as_ptr(),
                b"/mnt\0".as_ptr(),
                b"tmpfs\0".as_ptr(),
                0u64,
                std::ptr::null::<u8>(),
            )
        };
        if rc == -1 { Ok(()) } else { bail!("mount returned {}", rc) }
    });

    run("unshare(NEWUSER) blocked by seccomp", &|| {
        let rc = unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER) };
        if rc == -1 { Ok(()) } else { bail!("unshare returned {}", rc) }
    });

    run("clone(CLONE_NEWUSER) blocked by seccomp arg filter", &|| {
        // Directly invoke clone with the namespace flag — this is the
        // path an attacker would take to bypass the unshare block. The
        // MaskedEq rule on SYS_clone must reject it before kernel entry.
        // We pass a null stack; the clone will never actually run far
        // enough to need one because seccomp denies it first.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWUSER as libc::c_ulong,
                std::ptr::null::<u8>(),
                std::ptr::null::<u8>(),
                std::ptr::null::<u8>(),
                0u64,
            )
        };
        if rc == -1 { Ok(()) } else { bail!("clone(NEWUSER) returned {}", rc) }
    });

    run("clone(CLONE_NEWNS) blocked by seccomp arg filter", &|| {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWNS as libc::c_ulong,
                std::ptr::null::<u8>(),
                std::ptr::null::<u8>(),
                std::ptr::null::<u8>(),
                0u64,
            )
        };
        if rc == -1 { Ok(()) } else { bail!("clone(NEWNS) returned {}", rc) }
    });

    run("ptrace blocked by seccomp", &|| {
        let rc = unsafe { libc::syscall(libc::SYS_ptrace, 0u64, 0u64, 0u64, 0u64) };
        if rc == -1 { Ok(()) } else { bail!("ptrace returned {}", rc) }
    });

    run("bpf blocked by seccomp", &|| {
        let rc = unsafe {
            libc::syscall(libc::SYS_bpf, 0u64, std::ptr::null::<u8>(), 0u64)
        };
        if rc == -1 { Ok(()) } else { bail!("bpf returned {}", rc) }
    });

    run("write to /tmp is denied (RO landlock + fsize=0)", &|| {
        match std::fs::write("/tmp/skorupka_selftest_should_fail", b"x") {
            Ok(_) => bail!("unexpectedly wrote to /tmp"),
            Err(_) => Ok(()),
        }
    });

    run("reading /tmp itself is allowed", &|| {
        std::fs::read_dir("/tmp")?;
        Ok(())
    });

    run("open /proc/self/mem is denied by landlock", &|| {
        match std::fs::File::open("/proc/self/mem") {
            Ok(_) => bail!("unexpectedly opened /proc/self/mem"),
            Err(_) => Ok(()),
        }
    });

    run("open /dev/tty is denied by landlock", &|| {
        match std::fs::File::open("/dev/tty") {
            Ok(_) => bail!("unexpectedly opened /dev/tty"),
            Err(_) => Ok(()),
        }
    });

    run("open /sys/kernel is denied by landlock", &|| {
        match std::fs::read_dir("/sys/kernel") {
            Ok(_) => bail!("unexpectedly opened /sys/kernel"),
            Err(_) => Ok(()),
        }
    });

    run("file symlink escape /tmp → /etc/shadow denied at open", &|| {
        match std::fs::File::open(&symlink_file) {
            Ok(_) => bail!("unexpectedly opened /etc/shadow via symlink"),
            Err(_) => Ok(()),
        }
    });

    run("dir symlink escape /tmp → /etc denied at read_dir", &|| {
        match std::fs::read_dir(&symlink_dir) {
            Ok(mut it) => {
                // read_dir can succeed lazily; force it to actually walk
                // at least one entry so the denial happens during the
                // test, not after.
                if it.next().is_some() {
                    bail!("unexpectedly listed /etc via symlink");
                }
                Ok(())
            }
            Err(_) => Ok(()),
        }
    });

    run("reading file INSIDE dir symlink target denied", &|| {
        // Even if read_dir somehow succeeded, opening a known file
        // beneath the symlinked directory must fail.
        let leaked = symlink_dir.join("shadow");
        match std::fs::File::open(&leaked) {
            Ok(_) => bail!("unexpectedly opened /etc/shadow via dir symlink"),
            Err(_) => Ok(()),
        }
    });

    run("TIOCSTI ioctl is blocked by seccomp", &|| {
        // TIOCSTI pushes a byte into the controlling tty's input queue.
        // Our seccomp ioctl cmd allowlist excludes it; the call must
        // return -1 with ENOSYS (seccomp default action).
        const TIOCSTI: libc::c_ulong = 0x5412;
        let ch: u8 = b'x';
        let rc = unsafe {
            libc::ioctl(0, TIOCSTI, &ch as *const u8)
        };
        if rc == -1 {
            Ok(())
        } else {
            bail!("TIOCSTI returned {}", rc)
        }
    });

    run("write to /dev/null is blocked (pre-opened fd is not writable from user code)", &|| {
        // The blackhole fd is held internally by skorupka; user code in
        // a builtin has no way to reach it. Any fresh open("/dev/null")
        // must fail because /dev is not in allowed_paths_ro.
        match std::fs::OpenOptions::new().write(true).open("/dev/null") {
            Ok(_) => bail!("unexpectedly opened /dev/null fresh"),
            Err(_) => Ok(()),
        }
    });

    println!();
    println!("result: {} passed, {} failed", pass, fail);
    if fail > 0 {
        bail!("selftest FAILED");
    }
    Ok(())
}
