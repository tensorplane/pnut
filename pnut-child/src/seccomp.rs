//! Raw seccomp filter installation.

use crate::spec::SeccompSpec;

/// Failure returned when the kernel rejects a seccomp filter installation.
///
/// The errno is captured by value immediately after the syscall. It does not
/// borrow the filter program or expose kernel-owned state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompInstallError {
    errno: i32,
}

impl SeccompInstallError {
    /// The Linux errno reported by the failed installation syscall.
    #[must_use]
    pub const fn errno(self) -> i32 {
        self.errno
    }
}

/// Install `spec` as a classic-BPF seccomp filter for the calling thread.
///
/// Installing a filter is irreversible for the calling thread (and may affect
/// other threads when flags request synchronization). Callers are responsible
/// for establishing `no_new_privs` or the needed privileges before calling
/// this function. The kernel copies and validates the classic-BPF program
/// during this call, so the program storage need only remain valid until it
/// returns.
pub fn install_seccomp(spec: &SeccompSpec) -> core::result::Result<(), SeccompInstallError> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            spec.flags,
            &spec.program as *const libc::sock_fprog,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(SeccompInstallError {
            errno: crate::error::Errno::last().0,
        })
    }
}
