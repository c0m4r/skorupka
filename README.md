# skorupka

Hardened SSH sandbox shell: a restricted, landlock+seccomp-sealed
interactive REPL for log analysts and support users, with no containers,
no chroot, and no external command execution.

Skorupka replaces the user's login shell. Once sshd hands control to it,
every file the user can touch is named in a TOML policy, every syscall
they can issue is on a static allowlist, and every command they can run
is a Rust builtin in the same process — there is no `execve` after
startup, so there is nothing to escape *to*.

## Design

A single statically-linked Rust binary that, in order:

1. `PR_SET_NO_NEW_PRIVS` (kills setuid paths across any later `execve`)
2. drops all capabilities (ambient + bounding)
3. sets `RLIMIT_NPROC / CPU / AS / FSIZE / NOFILE / CORE=0`
4. opens `/dev/null` once and scrubs every stray fd above stderr
5. installs a Landlock ruleset granting read-only access to exactly the
   paths in `[[user]].allowed_paths_ro`
6. installs a seccomp-bpf allowlist that **denies `execve` entirely**,
   and argument-filters `ioctl` to 7 read-only cmds (TIOCSTI and the
   TCSETS family are excluded)
7. enters an in-process REPL whose builtins (`ls`, `cat`, `grep`, `head`,
   `tail`, `wc`, `find`, `stat`, …) are all pure Rust functions

The parser forbids every shell metacharacter except `|` for pipelines,
so no builtin can ever receive a dangerous argv. Pipelines are composed
via `os_pipe` across scoped threads — no `fork`, no `execve`, no child
processes anywhere in the hot path. All stdout from builtins is routed
through a `SafeWriter` that strips ANSI escapes, DEL, and C0/C1 control
bytes before they reach the operator's terminal emulator.

## Build

```
cargo build --release
```

Kernel 6.1+, x86_64 / aarch64.

## Install

```
./target/release/skorupka check                          # report kernel feature support
sudo ./target/release/skorupka install                   # writes /etc/skorupka/config.toml
                                                         # and /etc/ssh/sshd_config.d/90-skorupka.conf
sudo groupadd -f skorupka
sudo ./target/release/skorupka adduser loguser --paths /var/log
sudo sshd -t && sudo systemctl reload ssh
./target/release/skorupka selftest                       # 17 in-process escape-attempt tests
```

## Security model

### Threat model

**In-scope attacker.** A user who can authenticate to the sandbox account
over SSH (password, key, whatever sshd is configured to accept) and wants
to read files outside their allowlist, escalate to another user, write to
disk, execute arbitrary code, or pivot off the host.

**Out of scope.**
- A local root on the host (skorupka does not protect against kernel
  compromise or against anyone who already has write access to
  `/etc/skorupka/config.toml`, `/etc/ssh/sshd_config.d/`, or the binary
  itself).
- Kernel 0-days in Landlock, seccomp, or the syscalls we allow. Skorupka
  reduces attack surface; it does not claim to survive a kernel LPE.
- Side channels that depend on shared hardware (timing, cache, Spectre
  family). Mitigate at the hypervisor/host level if that is your threat.
- Denial of service against the *host* via resource exhaustion that
  escapes `RLIMIT_*`. The limits are tuned to keep one user from wedging
  the box, not to give perfect fair-sharing guarantees.
- Physical access, console access, and anything above the ssh layer.

### Defense-in-depth layers

| # | Layer | What it stops | Failure mode if bypassed |
|---|---|---|---|
| 1 | sshd `ForceCommand` + `-c` sentinel | sftp-server, scp, rsync, `ssh host 'cmd'` exfil paths | Attacker can still only speak to skorupka's stdin; layers 4–8 still hold |
| 2 | `PR_SET_NO_NEW_PRIVS` | setuid / file-cap escalation across any later `execve` | Defanged anyway because layer 7 denies `execve` |
| 3 | Capability drop (all ambient + bounding) | `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`, etc. reappearing mid-session | Landlock + seccomp still enforce |
| 4 | `RLIMIT_NPROC / CPU / AS / FSIZE / NOFILE / CORE=0` | fork bombs, cpu-burn, memory exhaustion, core-dump info leaks, write-anything-ever | Seccomp-denied `fork`-family syscalls make nproc moot, but the belt-and-braces stays |
| 5 | FD scrub + pre-opened `/dev/null` blackhole fd | inherited-fd smuggling from sshd; gives skorupka a working write sink even after landlock seals the filesystem | N/A (prerequisite for later layers, not itself a defense) |
| 6 | Landlock read-only ruleset (see §Kernel compatibility) | Reading / writing any path not in `allowed_paths_ro`, including symlink traversal out of the allowlist | Parser+builtin allowlist still prevents `cat /etc/shadow`-style requests from ever being issued |
| 7 | seccomp-bpf allowlist | `execve`, `mount`, `pivot_root`, `chroot`, `unshare`, `setns`, `bpf`, `ptrace`, `process_vm_*`, `keyctl`, `kexec*`, `init_module`, `reboot`, `setuid*`, `capset`, `io_uring_*`, `open_by_handle_at`, `perf_event_open`, TIOCSTI + TCSETS ioctls | Landlock still enforces path confinement |
| 8 | Parser (metacharacter-free) | `;`, `&`, `&&`, `\|\|`, `>`, `<`, globs, `$()`, backticks, tilde expansion, history expansion — none survive tokenization | A bug here is contained by layers 6+7: even with a crafted argv, builtins have no way to escape |
| 9 | Builtin allowlist | Running anything not in `builtins_enabled` for this user | Parser already rejects unknown names |
| 10 | `SafeWriter` ANSI strip | Log-file ANSI escapes reaching the operator's terminal emulator (cursor repositioning, scrollback rewrite, OSC title-injection, a few terminal `!cmd` quirks) | Not a confinement layer; protects the analyst's host |

Layers 6–9 are each independent: removing any one of them still leaves
an attacker with no path to code execution, write access, or
out-of-allowlist file reads. That redundancy is deliberate — each layer
was designed assuming the next layer above it is buggy.

### Attack vectors considered

The list below is what was actively tested (unit tests, [src/selftest.rs](src/selftest.rs),
and round-by-round manual exercise), grouped by the layer that stops
them.

**Command injection & shell metacharacters**
- `ls /etc; cat /etc/shadow` → parse reject (semicolon banned)
- `ls && cat /etc/shadow` → parse reject
- `ls > /tmp/out` → parse reject (redirection banned)
- `cat $(whoami)` → parse reject (`$(…)` banned; `$` is not a legal char)
- `cat \`whoami\`` → parse reject (backticks banned)
- `ls ~root` → tilde expansion is not implemented at all
- Glob `cat /etc/*` → `*` is a literal char; landlock denies `/etc/*`
- Newline / NUL smuggling in quoted strings → parser rejects control
  bytes inside argv

**External-command escapes (classic jailbreak routes)**
- `find /var/log -exec sh {} \;` → `find` builtin has no `-exec`
- `less` `!cmd` → no `less`; skorupka has no pager
- `man foo` → no `man`
- `awk 'BEGIN{system("sh")}'` → no `awk`
- `vim` / `vi` `:!sh` → no editor
- `grep --perl-regexp` back-reference exec → `grep` uses the `regex`
  crate, no perl engine, no system() hook
- Any `execve(…)` / `execveat(…)` call → seccomp `ENOSYS`

**File-path escapes**
- `cat /etc/shadow` → landlock denies `openat`
- `cat /etc/passwd` → landlock denies `openat`
- `cat /proc/self/mem` → landlock denies `openat`
- `cat /dev/tty` → landlock denies `openat`
- `ls /sys/kernel` → landlock denies `read_dir`
- File symlink: `/tmp/X → /etc/shadow`, then `cat /tmp/X` → landlock
  denies the open against the symlink target
- Directory symlink: `/tmp/Y → /etc`, then `ls /tmp/Y` → landlock denies
  the `openat(O_DIRECTORY)` during the first `getdents64`
- Open a file *inside* a symlinked directory: `cat /tmp/Y/shadow` →
  landlock denies the `openat` against the resolved target
- `/dev/null` reopened with `O_WRONLY` from inside a builtin → landlock
  denies: `/dev` isn't in any allowlist; the pre-opened blackhole fd
  is held privately by skorupka and never handed to user code

**Privilege & namespace escapes**
- `unshare(CLONE_NEWUSER)` → seccomp `ENOSYS`
- `mount("none","/mnt","tmpfs",…)` → seccomp `ENOSYS`
- `pivot_root` / `chroot` / `setns` → seccomp `ENOSYS`
- `ptrace(PTRACE_TRACEME, …)` → seccomp `ENOSYS`
- `bpf(BPF_PROG_LOAD, …)` → seccomp `ENOSYS`
- `keyctl` / `add_key` / `request_key` → seccomp `ENOSYS`
- `perf_event_open`, `io_uring_setup`, `userfaultfd` → seccomp `ENOSYS`
- `setuid` / `setgid` / `capset` → seccomp `ENOSYS`; NO_NEW_PRIVS makes
  any future setuid binary silently stripped anyway

**TTY and terminal-emulator attacks**
- `ioctl(tty, TIOCSTI, 'x')` → seccomp-bpf filters the ioctl cmd arg;
  denied with `ENOSYS`
- `ioctl(tty, TCSETS, raw-mode)` → denied; attacker cannot flip the
  analyst's tty into raw / noecho mode
- `cat evil.log` where `evil.log` contains ESC/OSC sequences that
  reposition the analyst's cursor, rewrite scrollback, set the window
  title to a shell command, or clear the screen → `SafeWriter` replaces
  every control byte with `?` before it reaches stdout. UTF-8 high
  bytes are preserved, so legitimate non-ASCII log content still
  renders. Covered by [src/repl.rs:342-386](src/repl.rs#L342-L386)
  unit tests

**Non-interactive exfil over the ssh channel**
- `sftp loguser@host` → sshd `ForceCommand` replaces the subsystem with
  `skorupka run`; the client sees an unparseable banner and bails
- `scp loguser@host:/etc/hostname /tmp/x` → same
- `ssh loguser@host 'cat /etc/shadow'` → `SSH_ORIGINAL_COMMAND` is
  discarded, `skorupka run` starts, stdin closes immediately, session
  ends on EOF. The user's command never executes
- `skorupka -c '/bin/sh'` → audit-logged as `reject_noninteractive`,
  exit 1. The only `-c` value that is honored is the ForceCommand
  sentinel (`/usr/local/bin/skorupka run`)
- `skorupka -c '<sentinel>' selftest` → rejected before the sentinel
  match (subcommand + `-c` are mutually exclusive)

**Output-budget & denial-of-service attempts**
- `cat /var/log/huge.log` → per-pipeline `max_output_bytes` budget cuts
  the read at the byte boundary, returns cleanly
- `find /` through a pipeline → `RLIMIT_CPU` + output budget terminate
- fork bomb → no `fork`/`clone` available to user code; even if it were,
  `RLIMIT_NPROC=16` caps it
- Memory balloon → `RLIMIT_AS` caps address space at 512 MB
- Disk fill via session log → `RLIMIT_FSIZE` caps any single written
  file at 64 MB; no user-controlled write path exists anyway

**Config-layer attacks**
- A `[[user]]` block that names a dangerous root (`/`, `/proc`, `/sys`,
  `/dev`, `/boot`, `/root`, `/run`) → config validator refuses to load
- A path that does not exist → `canonicalize` fails with a named error
- A path that is not absolute → rejected at parse time
- `allow_devnull` / `allow_devzero` are documented in the schema but
  ignored in v1 (no externals to give them to), so turning them on is a
  no-op rather than a widening

### Kernel compatibility

Skorupka requests Landlock ABI v3 and gracefully degrades to whatever
the running kernel supports:

| Landlock ABI | Minimum kernel | Access types added vs. previous |
|---|---|---|
| v1 | 5.13 | read_file, read_dir, write_file, remove_\*, make_\*, link, rename, execute |
| v2 | 5.19 | + refer (cross-directory renames / hard-links) |
| **v3** | **6.1** | **+ truncate** ← what we request |

When the kernel is older than ABI v3, `landlock_restrict_self` returns
`PartiallyEnforced` and skorupka emits a `WARN` log line (tagged
`skorupka::audit kind=landlock_partial`). The security impact of partial
enforcement depends on *which* access types were dropped:

**Why partial enforcement is still safe in a read-only configuration:**
The kernel drops access types it doesn't know about from the ruleset
silently — it does not *widen* permissions. Because skorupka only *grants*
read access (`read_file` + `read_dir`) and never grants write, execute,
truncate, or refer, the dropped types are exclusively ones we listed to
*control* (so the kernel can deny them), not ones we *allow*. A sandboxed
process therefore cannot gain write, execute, or truncate access that
would not be present under full enforcement.

**Residual cases to be aware of:**

| Kernel range | Missing type | What an attacker could theoretically do | Why it's still safe here |
|---|---|---|---|
| 5.13 – 5.18 (ABI v1) | `refer` | Create a hard-link across allowed directories | skorupka never grants write access to any allowed path, so there is no writable destination for the link |
| 5.13 – 6.0 (ABI v1/v2) | `truncate` | Truncate a file on an inherited writable fd | skorupka scrubs every writable fd above stderr before landlock seals; no writable fd survives into user code |

**Recommendation:** deploy on kernel 6.1+ (`ABI::V3`) for fully
enforced confinement with no residual cases. Run `skorupka check` to
confirm the ABI the running kernel supports.

### Known limitations
- **No audit-log aggregation.** Audit events go to each sshd session's
  stderr (and hence to sshd's session log or journald under
  `skorupka::audit`). Piping that to a SIEM is the operator's job; v1
  does not ship a forwarder.
- **No rate limiting.** A user who guesses valid commands can issue
  them as fast as their `RLIMIT_CPU` allows. If you need per-command
  quotas, wire them in externally.
- **No encryption-at-rest for session history.** There is none —
  `history_file = ""` by default and should stay that way.
- **eBPF-LSM is not wired up.** Considered for v2 as a second-line audit
  layer; landlock + seccomp are the enforcement today.

### Reporting

If you find a way to read an out-of-allowlist file, execute anything
outside skorupka's builtin set, or get `execve` to succeed inside a
sealed session, that is a security bug. Please report it privately
before disclosing.

## Status

v1 — read-only, no externals, kernel 6.1+, x86_64 / aarch64.
