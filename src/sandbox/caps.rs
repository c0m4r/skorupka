//! Drop every capability we hold.
//!
//! The sandbox is designed to run as an unprivileged user, so normally
//! there are no caps to drop — but if it is ever launched with any
//! inherited/ambient caps (e.g. via file caps or misconfigured sudo), we
//! want to shed them before reading any untrusted input.
//!
//! We use raw capget/capset rather than pulling in the `caps` crate, to
//! keep the dependency tree small.

use anyhow::{bail, Result};

const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
// Highest capability index in current kernels. We iterate generously; the
// kernel returns EINVAL for unknown caps, which we treat as "done".
const CAP_LAST_CAP_CEILING: i32 = 64;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn drop_all() -> Result<()> {
    // 1. Clear ambient set.
    // SAFETY: prctl, no memory touched.
    unsafe {
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    }

    // 2. Lower bounding set — fail open if we lack CAP_SETPCAP (we
    // probably do, as an unprivileged user).
    for cap in 0..CAP_LAST_CAP_CEILING {
        // SAFETY: PR_CAPBSET_DROP takes an integer cap number.
        unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
        }
    }

    // 3. Zero the thread's effective/permitted/inheritable sets via capset(2).
    let hdr = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapUserData::default(); 2];
    // SAFETY: capset is a normal syscall; we pass correctly-sized structs.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr()) };
    if rc != 0 {
        // Not fatal — an unprivileged user may already have empty sets
        // and the syscall may still EPERM on some kernels.
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            bail!("capset failed: {}", err);
        }
    }
    Ok(())
}
