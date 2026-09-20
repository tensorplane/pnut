use std::process::Command;

use nix::sys::prctl;
use pnut_child::{SeccompSpec, install_seccomp};

const CHILD_ENV: &str = "PNUT_CHILD_SECCOMP_INSTALL_TEST";
const INVALID_CHILD_ENV: &str = "PNUT_CHILD_SECCOMP_INSTALL_INVALID_TEST";
const DENIED_ERRNO: u32 = libc::EPERM as u32;

#[test]
fn installs_a_filter_in_an_isolated_subprocess() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_filtered_child();
    }

    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("installs_a_filter_in_an_isolated_subprocess")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .status()
        .expect("run filtered child");
    assert!(status.success(), "filtered child exited with {status}");
}

fn run_filtered_child() {
    prctl::set_no_new_privs().expect("set no_new_privs");

    let filter = [
        instruction(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
        instruction(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            1,
            libc::SYS_getpid as u32,
        ),
        instruction(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        instruction(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            1,
            libc::SYS_exit_group as u32,
        ),
        instruction(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        instruction(
            libc::BPF_RET | libc::BPF_K,
            0,
            0,
            libc::SECCOMP_RET_ERRNO | DENIED_ERRNO,
        ),
    ];
    let spec = SeccompSpec {
        program: libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        },
        flags: 0,
    };

    install_seccomp(&spec).expect("install exact filter");
    assert!(nix::unistd::getpid().as_raw() > 0, "allowed syscall failed");
    let denied = nix::unistd::getpgid(None).expect_err("adjacent syscall must be denied");
    assert_eq!(denied, nix::errno::Errno::EPERM);

    std::process::exit(0);
}

const fn instruction(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

#[test]
fn runtime_delegates_to_the_public_installer() {
    let runtime = include_str!("../src/runtime.rs");
    assert!(runtime.contains("install_seccomp(seccomp_spec)"));
}

#[test]
fn rejects_an_invalid_program_in_an_isolated_subprocess() {
    if std::env::var_os(INVALID_CHILD_ENV).is_some() {
        prctl::set_no_new_privs().expect("set no_new_privs");
        let spec = SeccompSpec {
            program: libc::sock_fprog {
                len: 0,
                filter: core::ptr::null_mut(),
            },
            flags: 0,
        };
        let error = install_seccomp(&spec).expect_err("kernel must reject an empty filter");
        assert_eq!(error.errno(), libc::EINVAL);
        return;
    }

    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("rejects_an_invalid_program_in_an_isolated_subprocess")
        .arg("--nocapture")
        .env(INVALID_CHILD_ENV, "1")
        .status()
        .expect("run invalid-filter child");
    assert!(
        status.success(),
        "invalid-filter child exited with {status}"
    );
}
