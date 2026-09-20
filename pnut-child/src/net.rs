//! Network setup helpers.

use crate::error::{Errno, Result};
use crate::fd::OwnedFd;

// `libc::Ioctl` is `c_ulong` on GNU targets but `c_int` on musl. Keeping the
// request in that target-defined type makes this a compile-time regression
// check as well as supplying the exact type `ioctl` expects.
const SIOCSIFFLAGS_REQUEST: libc::Ioctl = libc::SIOCSIFFLAGS as libc::Ioctl;

/// Bring up the loopback interface in the current network namespace.
pub fn bring_up_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Errno::last());
    }

    let sock = OwnedFd::new(sock);
    bring_up_loopback_with_socket(sock.as_raw())
}

fn bring_up_loopback_with_socket(sock: libc::c_int) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
    let name = b"lo\0";

    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.iter().copied()) {
        *dst = src as libc::c_char;
    }

    ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;

    let ret = unsafe { libc::ioctl(sock, SIOCSIFFLAGS_REQUEST, &ifr) };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}
