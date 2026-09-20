//! Ordered child-runtime execution.

use crate::caps;
use crate::completion::{
    self, COMPLETE_CAPABILITIES, COMPLETE_FD_CLOSURE, COMPLETE_MOUNT_PIVOT, COMPLETE_NO_NEW_PRIVS,
    COMPLETE_RLIMITS, COMPLETE_SECCOMP, COMPLETE_STAGE_MASK,
};
use crate::env;
use crate::error::Errno;
use crate::fd;
use crate::install_seccomp;
use crate::io::read_byte;
use crate::landlock;
use crate::mount;
use crate::net;
use crate::process::{self, Prctl};
use crate::report::{Reporter, Stage};
use crate::rlimit;
use crate::spec::ChildSpec;

const EXIT_SETUP_FAILED: libc::c_int = 126;
const EXIT_COMMAND_NOT_FOUND: libc::c_int = 127;

pub fn run(spec: &mut ChildSpec<'_>) -> ! {
    let reporter = Reporter::new(spec.status_fd);
    let completion_is_valid = spec.completion.is_none_or(|sink| {
        let status_fd = spec.status_fd;
        sink.fd() >= 0
            && status_fd.is_some_and(|fd| fd >= 0 && Some(fd) != spec.sync_fd)
            && Some(sink.fd()) != status_fd
            && Some(sink.fd()) != spec.sync_fd
            && spec.mounts.is_some()
            && spec.rlimits.is_some()
            && spec.caps.is_some()
            && spec.fds.close_fds
            && spec.process.no_new_privs
            && spec.seccomp.is_some()
            && spec.fds.actions.iter().all(|action| match *action {
                fd::FdAction::Close(fd) => fd != sink.fd() && Some(fd) != status_fd,
                fd::FdAction::Dup2 { src, dst } => {
                    src != sink.fd()
                        && dst != sink.fd()
                        && Some(src) != status_fd
                        && Some(dst) != status_fd
                }
            })
    });
    if !completion_is_valid {
        let _ = reporter.report_logic(Stage::Completion, 1, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    let mut completed_stages = 0_u32;

    if let Some(sig) = spec.process.pdeathsig
        && let Err(err) =
            process::prctl_set(Prctl::ParentDeathSignal, sig as libc::c_ulong, 0, 0, 0)
    {
        let _ = reporter.report_errno(Stage::ParentDeathSignal, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if spec.process.verify_parent_alive && process::getppid() == 1 {
        let _ = reporter.report_logic(Stage::ParentCheck, 1, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(sync_fd) = spec.sync_fd {
        let sync_result = read_byte(sync_fd).and_then(|_| fd::close(sync_fd));
        if let Err(err) = sync_result {
            let _ = reporter.report_errno(Stage::SyncWait, err, 0, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
    }

    if let Err(err) = process::prctl_set(
        Prctl::Dumpable,
        spec.process.dumpable as libc::c_ulong,
        0,
        0,
        0,
    ) {
        let _ = reporter.report_errno(Stage::Dumpable, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    // Filesystem setup has to happen before any later path-based operations
    // such as hostname-specific proc views, cwd changes, or exec.
    if let Some(mounts) = spec.mounts.as_ref()
        && let Err(err) = mount::setup(mounts)
    {
        let _ = reporter.report_errno(Stage::Mount, err.errno, err.detail, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    if spec.mounts.is_some() {
        completed_stages |= COMPLETE_MOUNT_PIVOT;
    }

    if let Some(hostname) = spec.hostname
        && let Err(err) = process::sethostname(hostname)
    {
        let _ = reporter.report_errno(Stage::Hostname, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if spec.bring_up_loopback
        && let Err(err) = net::bring_up_loopback()
    {
        let _ = reporter.report_errno(Stage::Network, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(rlimits) = spec.rlimits.as_ref()
        && let Err(err) = rlimit::apply(rlimits)
    {
        let _ = reporter.report_errno(Stage::Rlimit, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    if spec.rlimits.is_some() {
        completed_stages |= COMPLETE_RLIMITS;
    }

    if let Some(landlock_spec) = spec.landlock.as_ref()
        && let Err(err) = landlock::apply(landlock_spec)
    {
        let _ = reporter.report_errno(Stage::Landlock, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    let envp = if let Some(env_spec) = spec.env.as_mut() {
        match env::prepare(env_spec) {
            Ok(envp) => envp,
            Err(err) => {
                let _ = reporter.report_errno(Stage::Env, err, 0, EXIT_SETUP_FAILED);
                process::exit_immediately(EXIT_SETUP_FAILED);
            }
        }
    } else {
        process::current_environ()
    };

    if let Some(caps_spec) = spec.caps.as_ref()
        && let Err(err) = caps::apply(caps_spec)
    {
        let _ = reporter.report_errno(Stage::Capabilities, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    if spec.caps.is_some() {
        completed_stages |= COMPLETE_CAPABILITIES;
    }

    if spec.process.new_session
        && let Err(err) = process::setsid()
    {
        let _ = reporter.report_errno(Stage::Setsid, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Err(err) = fd::apply_actions(spec.fds.actions) {
        let _ = reporter.report_errno(Stage::Fd, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    if spec.fds.close_fds {
        let extra_keep = [
            spec.status_fd.unwrap_or(-1),
            spec.completion.map_or(-1, |sink| sink.fd()),
        ];
        if let Err(err) = fd::close_other_fds(spec.fds.keep, &extra_keep) {
            let _ = reporter.report_errno(Stage::Fd, err, 1, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
        completed_stages |= COMPLETE_FD_CLOSURE;
    }

    if spec.process.disable_tsc {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let tsc_result =
            process::prctl_set(Prctl::Tsc, libc::PR_TSC_SIGSEGV as libc::c_ulong, 0, 0, 0);
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let tsc_result = Err(crate::error::Errno::new(libc::EOPNOTSUPP));

        if let Err(err) = tsc_result {
            let _ = reporter.report_errno(Stage::Tsc, err, 0, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
    }

    if spec.process.no_new_privs
        && let Err(err) = process::prctl_set(Prctl::NoNewPrivs, 1, 0, 0, 0)
    {
        let _ = reporter.report_errno(Stage::NoNewPrivs, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    if spec.process.no_new_privs {
        completed_stages |= COMPLETE_NO_NEW_PRIVS;
    }

    if let Some(mdwe_flags) = spec.process.mdwe_flags
        && let Err(err) = process::prctl_set(Prctl::Mdwe, mdwe_flags, 0, 0, 0)
    {
        let _ = reporter.report_errno(Stage::Mdwe, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(seccomp_spec) = spec.seccomp.as_ref()
        && let Err(err) = install_seccomp(seccomp_spec)
    {
        let _ = reporter.report_errno(
            Stage::Seccomp,
            Errno::new(err.errno()),
            0,
            EXIT_SETUP_FAILED,
        );
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    if spec.seccomp.is_some() {
        completed_stages |= COMPLETE_SECCOMP;
    }

    if let Some(cwd) = spec.cwd
        && let Err(err) = process::chdir(cwd)
    {
        let _ = reporter.report_errno(Stage::Cwd, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    // Completion means all setup stages reached the exec boundary. It does
    // not mean exec succeeded: an exec failure below still reports fatal
    // status, and consumers must require that status pipe's clean CLOEXEC EOF.
    if let Some(sink) = spec.completion {
        if completed_stages != COMPLETE_STAGE_MASK {
            let _ = reporter.report_logic(Stage::Completion, 2, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
        if let Err(err) = completion::emit(sink, completed_stages) {
            let _ = reporter.report_errno(Stage::Completion, err, 0, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
    }

    let err = process::execve(&spec.exec, envp);
    if err.0 == libc::ENOENT {
        let _ = reporter.report_exec_errno(err, EXIT_COMMAND_NOT_FOUND, spec.exec.path);
        process::exit_immediately(EXIT_COMMAND_NOT_FOUND);
    } else {
        let _ = reporter.report_exec_errno(err, EXIT_SETUP_FAILED, spec.exec.path);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
}
