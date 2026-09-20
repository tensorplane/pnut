use core::ffi::CStr;
use core::ptr;
use pnut_child::{
    BindMount, BindMountSource, COMPLETE_STAGE_MASK, COMPLETION_BINDING_LEN, COMPLETION_RECORD_LEN,
    CapsSpec, ChildSpec, CompletionRecord, CompletionSink, ExecSpec, FdSpec, MountEntry, MountPlan,
    PreparedBindMount, ProcessSpec, RlimitSpec, SeccompSpec,
};
use std::{
    ffi::CString,
    fs::{self, File},
    os::fd::AsRawFd,
    time::{SystemTime, UNIX_EPOCH},
};

fn pipe_cloexec() -> (libc::c_int, libc::c_int) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    (fds[0], fds[1])
}

fn read_all(fd: libc::c_int) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 128];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n >= 0, "read failed: {}", std::io::Error::last_os_error());
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
}

fn wait_for(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    status
}

fn spec<'a>(
    status_fd: libc::c_int,
    completion: CompletionSink<'a>,
    cwd: Option<&'a CStr>,
    exec: ExecSpec<'a>,
) -> ChildSpec<'a> {
    ChildSpec {
        sync_fd: None,
        status_fd: Some(status_fd),
        completion: Some(completion),
        process: ProcessSpec::default(),
        mounts: None,
        hostname: None,
        bring_up_loopback: false,
        env: None,
        rlimits: None,
        landlock: None,
        caps: None,
        fds: FdSpec {
            actions: &[],
            keep: &[],
            close_fds: false,
        },
        seccomp: None,
        cwd,
        exec,
    }
}

#[allow(clippy::too_many_arguments)]
fn required_spec<'a>(
    status_fd: libc::c_int,
    completion: CompletionSink<'a>,
    mounts: Option<MountPlan<'a>>,
    rlimits: Option<RlimitSpec<'a>>,
    caps: Option<CapsSpec<'a>>,
    close_fds: bool,
    no_new_privs: bool,
    seccomp: Option<SeccompSpec>,
    actions: &'a [pnut_child::FdAction],
) -> ChildSpec<'a> {
    let path = c"/bin/true";
    let argv = [path.as_ptr(), ptr::null()];
    // This helper is used only for preflight-rejection tests. `run` never
    // reaches these borrowed exec values when a required primitive is absent.
    // Leak the two-word argv into the test process to keep the helper simple.
    let argv = Box::leak(Box::new(argv));
    ChildSpec {
        sync_fd: None,
        status_fd: Some(status_fd),
        completion: Some(completion),
        process: ProcessSpec {
            no_new_privs,
            ..ProcessSpec::default()
        },
        mounts,
        hostname: None,
        bring_up_loopback: false,
        env: None,
        rlimits,
        landlock: None,
        caps,
        fds: FdSpec {
            actions,
            keep: &[],
            close_fds,
        },
        seccomp,
        cwd: None,
        exec: ExecSpec { path, argv },
    }
}

fn assert_preflight_rejected(
    mut child_spec: ChildSpec<'_>,
    completion_read: libc::c_int,
    completion_write: libc::c_int,
    status_read: libc::c_int,
    status_write: libc::c_int,
) {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::close(status_read) };
        unsafe { libc::close(completion_read) };
        pnut_child::run(&mut child_spec);
    }
    unsafe { libc::close(status_write) };
    unsafe { libc::close(completion_write) };
    let status = wait_for(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 126);
    assert!(read_all(completion_read).is_empty());
    let bytes = read_all(status_read);
    assert_eq!(
        bytes.len(),
        core::mem::size_of::<pnut_child::ChildFailure>()
    );
    let failure =
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<pnut_child::ChildFailure>()) };
    assert_eq!(
        pnut_child::Stage::from_u16(failure.stage),
        Some(pnut_child::Stage::Completion)
    );
}

#[test]
fn every_required_completion_primitive_is_mandatory() {
    let mounts = [];
    let limits = [];
    let caps = CapsSpec {
        effective: [0; 2],
        permitted: [0; 2],
        inheritable: [0; 2],
        bounding_drop: &[],
        clear_ambient: false,
    };
    let filter = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let seccomp = SeccompSpec {
        program: libc::sock_fprog {
            len: 1,
            filter: filter.as_ptr() as *mut _,
        },
        flags: 0,
    };

    for missing in 0..6 {
        let (status_read, status_write) = pipe_cloexec();
        let (completion_read, completion_write) = pipe_cloexec();
        let binding = [missing as u8; COMPLETION_BINDING_LEN];
        let child_spec = required_spec(
            status_write,
            CompletionSink::new(&binding, completion_write),
            (missing != 0).then_some(MountPlan { entries: &mounts }),
            (missing != 1).then_some(RlimitSpec { limits: &limits }),
            (missing != 2).then_some(caps),
            missing != 3,
            missing != 4,
            (missing != 5).then_some(seccomp),
            &[],
        );
        assert_preflight_rejected(
            child_spec,
            completion_read,
            completion_write,
            status_read,
            status_write,
        );
    }
}

#[test]
fn completion_fd_aliases_and_actions_are_rejected_before_setup() {
    let mounts = [];
    let limits = [];
    let caps = CapsSpec {
        effective: [0; 2],
        permitted: [0; 2],
        inheritable: [0; 2],
        bounding_drop: &[],
        clear_ambient: false,
    };
    let filter = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let seccomp = SeccompSpec {
        program: libc::sock_fprog {
            len: 1,
            filter: filter.as_ptr() as *mut _,
        },
        flags: 0,
    };
    for kind in 0..6 {
        let (status_read, status_write) = pipe_cloexec();
        let (completion_read, completion_write) = pipe_cloexec();
        let binding = [0xD0 + kind; COMPLETION_BINDING_LEN];
        let actions = [
            pnut_child::FdAction::Close(completion_write),
            pnut_child::FdAction::Dup2 {
                src: completion_write,
                dst: 9,
            },
            pnut_child::FdAction::Dup2 {
                src: 9,
                dst: completion_write,
            },
        ];
        let completion_fd = if kind == 0 {
            status_write
        } else if kind == 2 {
            -1
        } else {
            completion_write
        };
        let action_slice = if kind < 3 {
            &[][..]
        } else {
            &actions[(kind - 3) as usize..(kind - 2) as usize]
        };
        let mut child_spec = required_spec(
            status_write,
            CompletionSink::new(&binding, completion_fd),
            Some(MountPlan { entries: &mounts }),
            Some(RlimitSpec { limits: &limits }),
            Some(caps),
            true,
            true,
            Some(seccomp),
            action_slice,
        );
        if kind == 1 {
            child_spec.sync_fd = Some(completion_write);
        }
        assert_preflight_rejected(
            child_spec,
            completion_read,
            completion_write,
            status_read,
            status_write,
        );
    }
}

#[test]
fn status_fd_aliases_and_actions_are_rejected_before_setup() {
    let mounts = [];
    let limits = [];
    let caps = CapsSpec {
        effective: [0; 2],
        permitted: [0; 2],
        inheritable: [0; 2],
        bounding_drop: &[],
        clear_ambient: false,
    };
    let filter = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let seccomp = SeccompSpec {
        program: libc::sock_fprog {
            len: 1,
            filter: filter.as_ptr() as *mut _,
        },
        flags: 0,
    };

    for kind in 0..4 {
        let (status_read, status_write) = pipe_cloexec();
        let (completion_read, completion_write) = pipe_cloexec();
        let actions = [
            pnut_child::FdAction::Close(status_write),
            pnut_child::FdAction::Dup2 {
                src: status_write,
                dst: 9,
            },
            pnut_child::FdAction::Dup2 {
                src: 9,
                dst: status_write,
            },
        ];
        let action_slice = if kind < 3 {
            &actions[kind as usize..kind as usize + 1]
        } else {
            &[]
        };
        let binding = [0xE0 + kind; COMPLETION_BINDING_LEN];
        let mut child_spec = required_spec(
            status_write,
            CompletionSink::new(&binding, completion_write),
            Some(MountPlan { entries: &mounts }),
            Some(RlimitSpec { limits: &limits }),
            Some(caps),
            true,
            true,
            Some(seccomp),
            action_slice,
        );
        if kind == 3 {
            child_spec.sync_fd = Some(status_write);
        }
        assert_preflight_rejected(
            child_spec,
            completion_read,
            completion_write,
            status_read,
            status_write,
        );
    }
}

#[test]
fn completion_requires_a_nonnegative_status_fd() {
    for status_fd in [None, Some(-1)] {
        let (status_read, status_write) = pipe_cloexec();
        let (completion_read, completion_write) = pipe_cloexec();
        let binding = [0xEF; COMPLETION_BINDING_LEN];
        let path = c"/bin/true";
        let argv = [path.as_ptr(), ptr::null()];
        let mut child_spec = spec(
            status_write,
            CompletionSink::new(&binding, completion_write),
            None,
            ExecSpec { path, argv: &argv },
        );
        child_spec.status_fd = status_fd;

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::close(status_read) };
            unsafe { libc::close(completion_read) };
            pnut_child::run(&mut child_spec);
        }
        unsafe { libc::close(status_write) };
        unsafe { libc::close(completion_write) };
        let status = wait_for(pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 126);
        assert!(read_all(completion_read).is_empty());
        assert!(read_all(status_read).is_empty());
    }
}

fn enter_user_mount_namespace() {
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        return;
    }
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWUSER) }, 0);
    std::fs::write("/proc/self/setgroups", "deny\n").unwrap();
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).unwrap();
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
}

fn accepts_completion(
    completion: &[u8],
    status: &[u8],
    binding: &[u8; COMPLETION_BINDING_LEN],
) -> bool {
    // A strict pre-exec record is necessary but deliberately not sufficient:
    // successful exec is proven only by the status FD's clean CLOEXEC EOF.
    CompletionRecord::decode(completion, binding).is_ok() && status.is_empty()
}

fn decode_failure(bytes: &[u8]) -> pnut_child::ChildFailure {
    assert_eq!(
        bytes.len(),
        core::mem::size_of::<pnut_child::ChildFailure>()
    );
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<pnut_child::ChildFailure>()) }
}

struct ProductionResult {
    exit_status: i32,
    completion: Vec<u8>,
    status: Vec<u8>,
}

fn production_case(
    completion_fd_is_read_end: bool,
    deny_completion_close: bool,
    exec_path: &CStr,
) -> ProductionResult {
    let (status_read, status_write) = pipe_cloexec();
    let (completion_read, completion_write) = pipe_cloexec();
    let binding = [0xA5; COMPLETION_BINDING_LEN];
    let completion_fd = if completion_fd_is_read_end {
        completion_read
    } else {
        completion_write
    };
    let completion = CompletionSink::new(&binding, completion_fd);
    // A bind of just `/` at `/host` is insufficient: ELF interpreters are
    // resolved from their absolute path after pivot. Mount the runtime paths
    // at their real locations so this proves `execve`, not merely a write.
    let argv = [exec_path.as_ptr(), ptr::null()];
    let mut mounts = vec![
        MountEntry::Bind(BindMount {
            source: BindMountSource::Path(c"/usr"),
            dst_rel: c"usr",
            src_is_dir: true,
            read_only: true,
        }),
        MountEntry::Bind(BindMount {
            source: BindMountSource::Path(c"/lib"),
            dst_rel: c"lib",
            src_is_dir: true,
            read_only: true,
        }),
    ];
    // Ubuntu images normally have /lib64, but do not make this fixture rely
    // on that layout when the dynamic loader instead lives under /lib.
    if std::path::Path::new("/lib64").is_dir() {
        mounts.push(MountEntry::Bind(BindMount {
            source: BindMountSource::Path(c"/lib64"),
            dst_rel: c"lib64",
            src_is_dir: true,
            read_only: true,
        }));
    }
    let limits = [];
    let caps = CapsSpec {
        effective: [0; 2],
        permitted: [0; 2],
        inheritable: [0; 2],
        bounding_drop: &[],
        clear_ambient: false,
    };
    let filter = if deny_completion_close {
        vec![
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: libc::SYS_close as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ]
    } else {
        vec![libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        }]
    };
    let mut child_spec = ChildSpec {
        sync_fd: None,
        status_fd: Some(status_write),
        completion: Some(completion),
        process: ProcessSpec {
            no_new_privs: true,
            ..ProcessSpec::default()
        },
        mounts: Some(MountPlan { entries: &mounts }),
        hostname: None,
        bring_up_loopback: false,
        env: None,
        rlimits: Some(RlimitSpec { limits: &limits }),
        landlock: None,
        caps: Some(caps),
        fds: FdSpec {
            actions: &[],
            keep: &[],
            close_fds: true,
        },
        seccomp: Some(SeccompSpec {
            program: libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut _,
            },
            flags: 0,
        }),
        cwd: Some(c"/"),
        exec: ExecSpec {
            path: exec_path,
            argv: &argv,
        },
    };

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::close(status_read) };
        if !completion_fd_is_read_end {
            unsafe { libc::close(completion_read) };
        }
        enter_user_mount_namespace();
        pnut_child::run(&mut child_spec);
    }
    unsafe { libc::close(status_write) };
    unsafe { libc::close(completion_write) };
    ProductionResult {
        exit_status: wait_for(pid),
        completion: read_all(completion_read),
        status: read_all(status_read),
    }
}

fn prepared_bind_case(command: &'static CStr) -> ProductionResult {
    let fixture = std::env::temp_dir().join(format!(
        "pnut-prepared-bind-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let source = fixture.join("source");
    let nested = source.join("nested");
    fs::create_dir_all(&nested).expect("prepared bind fixture");
    let nested_path = CString::new(nested.as_os_str().as_encoded_bytes()).expect("nested path");
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                nested_path.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                ptr::null::<libc::c_void>(),
            )
        },
        0,
        "nested fixture mount: {}",
        std::io::Error::last_os_error()
    );
    fs::write(nested.join("inside"), b"proof").expect("nested source content");
    let source_fd = File::open(&source).expect("source directory fd");
    let source_mount = PreparedBindMount::clone_from_fd(source_fd.as_raw_fd(), true)
        .expect("prepare inherited bind source before namespace clone");

    let (status_read, status_write) = pipe_cloexec();
    let (completion_read, completion_write) = pipe_cloexec();
    let binding = [0xB7; COMPLETION_BINDING_LEN];
    let completion = CompletionSink::new(&binding, completion_write);
    let path = c"/usr/bin/dash";
    let argv = [path.as_ptr(), c"-c".as_ptr(), command.as_ptr(), ptr::null()];
    let mut mounts = vec![
        MountEntry::Bind(BindMount {
            source: BindMountSource::Path(c"/usr"),
            dst_rel: c"usr",
            src_is_dir: true,
            read_only: true,
        }),
        MountEntry::Bind(BindMount {
            source: BindMountSource::Path(c"/lib"),
            dst_rel: c"lib",
            src_is_dir: true,
            read_only: true,
        }),
    ];
    if std::path::Path::new("/lib64").is_dir() {
        mounts.push(MountEntry::Bind(BindMount {
            source: BindMountSource::Path(c"/lib64"),
            dst_rel: c"lib64",
            src_is_dir: true,
            read_only: true,
        }));
    }
    mounts.push(MountEntry::Bind(BindMount {
        source: BindMountSource::Path(c"/proc"),
        dst_rel: c"proc",
        src_is_dir: true,
        read_only: true,
    }));
    mounts.push(MountEntry::Bind(BindMount {
        source: BindMountSource::Prepared(&source_mount),
        dst_rel: c"source",
        src_is_dir: true,
        read_only: true,
    }));
    let limits = [];
    let caps = CapsSpec {
        effective: [0; 2],
        permitted: [0; 2],
        inheritable: [0; 2],
        bounding_drop: &[],
        clear_ambient: false,
    };
    let filter = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let mut child_spec = ChildSpec {
        sync_fd: None,
        status_fd: Some(status_write),
        completion: Some(completion),
        process: ProcessSpec {
            no_new_privs: true,
            ..ProcessSpec::default()
        },
        mounts: Some(MountPlan { entries: &mounts }),
        hostname: None,
        bring_up_loopback: false,
        env: None,
        rlimits: Some(RlimitSpec { limits: &limits }),
        landlock: None,
        caps: Some(caps),
        fds: FdSpec {
            actions: &[],
            keep: &[],
            close_fds: true,
        },
        seccomp: Some(SeccompSpec {
            program: libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut _,
            },
            flags: 0,
        }),
        cwd: Some(c"/"),
        exec: ExecSpec { path, argv: &argv },
    };

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::close(status_read) };
        unsafe { libc::close(completion_read) };
        enter_user_mount_namespace();
        pnut_child::run(&mut child_spec);
    }
    unsafe { libc::close(status_write) };
    unsafe { libc::close(completion_write) };
    let result = ProductionResult {
        exit_status: wait_for(pid),
        completion: read_all(completion_read),
        status: read_all(status_read),
    };
    drop(source_fd);
    let unmount = unsafe { libc::umount2(nested_path.as_ptr(), libc::MNT_DETACH) };
    assert_eq!(
        unmount,
        0,
        "nested source cleanup: {}",
        std::io::Error::last_os_error()
    );
    fs::remove_dir_all(fixture).expect("remove procfd fixture");
    result
}

#[test]
#[ignore = "requires user and mount namespaces; CI runs production paths explicitly"]
fn prepared_inherited_fd_bind_preserves_nested_mounts() {
    let result = prepared_bind_case(c"test -f /source/nested/inside");
    assert_eq!(
        result.exit_status,
        0,
        "pnut child failure: {:?}",
        (!result.status.is_empty()).then(|| decode_failure(&result.status))
    );
    assert!(result.status.is_empty());
    assert_eq!(result.completion.len(), COMPLETION_RECORD_LEN);
}

#[test]
#[ignore = "requires user and mount namespaces; CI runs production paths explicitly"]
fn prepared_inherited_fd_bind_is_recursively_read_only() {
    let result = prepared_bind_case(c"! printf blocked > /source/nested/new");
    assert_eq!(
        result.exit_status,
        0,
        "pnut child failure: {:?}",
        (!result.status.is_empty()).then(|| decode_failure(&result.status))
    );
    assert!(result.status.is_empty());
    assert_eq!(result.completion.len(), COMPLETION_RECORD_LEN);
}

#[test]
#[ignore = "requires user and mount namespaces; CI runs production paths explicitly"]
fn prepared_inherited_fd_bind_gets_child_local_mount_order() {
    let result = prepared_bind_case(c"root=0; source=0; n=0; while IFS=' ' read -r _ _ _ _ mountpoint _; do n=$((n + 1)); test \"$mountpoint\" = / && root=$n; test \"$mountpoint\" = /source && source=$n; done < /proc/self/mountinfo; test \"$root\" -gt 0 && test \"$source\" -gt \"$root\"");
    assert_eq!(
        result.exit_status,
        0,
        "pnut child failure: {:?}",
        (!result.status.is_empty()).then(|| decode_failure(&result.status))
    );
    assert!(result.status.is_empty());
    assert_eq!(result.completion.len(), COMPLETION_RECORD_LEN);
}

#[test]
#[ignore = "requires a private mount namespace; CI runs every production path explicitly under sudo"]
fn privileged_completion_evidence_paths() {
    let binding = [0xA5; COMPLETION_BINDING_LEN];
    let success = production_case(false, false, c"/usr/bin/true");
    assert_eq!(success.exit_status, 0);
    assert_eq!(success.completion.len(), COMPLETION_RECORD_LEN);
    let success_record = CompletionRecord::decode(&success.completion, &binding).unwrap();
    assert_eq!(success_record.complete_stage_mask(), COMPLETE_STAGE_MASK);
    assert!(accepts_completion(
        &success.completion,
        &success.status,
        &binding
    ));

    // A pipe read end returns EBADF on write, without the SIGPIPE ambiguity
    // of a write end with no readers.
    let write_failure = production_case(true, false, c"/usr/bin/true");
    assert!(libc::WIFEXITED(write_failure.exit_status));
    assert_eq!(libc::WEXITSTATUS(write_failure.exit_status), 126);
    assert!(write_failure.completion.is_empty());
    assert_eq!(
        pnut_child::Stage::from_u16(decode_failure(&write_failure.status).stage),
        Some(pnut_child::Stage::Completion)
    );
    assert!(!accepts_completion(
        &write_failure.completion,
        &write_failure.status,
        &binding
    ));

    // This valid BPF program permits setup and the evidence write, but makes
    // its required close fail. A raw record must therefore fail closed.
    let close_failure = production_case(false, true, c"/usr/bin/true");
    assert!(libc::WIFEXITED(close_failure.exit_status));
    assert_eq!(libc::WEXITSTATUS(close_failure.exit_status), 126);
    assert_eq!(close_failure.completion.len(), COMPLETION_RECORD_LEN);
    assert!(CompletionRecord::decode(&close_failure.completion, &binding).is_ok());
    assert_eq!(
        pnut_child::Stage::from_u16(decode_failure(&close_failure.status).stage),
        Some(pnut_child::Stage::Completion)
    );
    assert!(!accepts_completion(
        &close_failure.completion,
        &close_failure.status,
        &binding
    ));

    let exec_failure = production_case(false, false, c"/definitely/not/a/pnut-executable");
    assert!(libc::WIFEXITED(exec_failure.exit_status));
    assert_eq!(libc::WEXITSTATUS(exec_failure.exit_status), 127);
    assert_eq!(exec_failure.completion.len(), COMPLETION_RECORD_LEN);
    assert!(CompletionRecord::decode(&exec_failure.completion, &binding).is_ok());
    assert_eq!(
        pnut_child::Stage::from_u16(decode_failure(&exec_failure.status).stage),
        Some(pnut_child::Stage::Exec)
    );
    assert!(!accepts_completion(
        &exec_failure.completion,
        &exec_failure.status,
        &binding
    ));
}

#[test]
fn completion_framing_is_exact_and_strict() {
    let binding = [0xA5; COMPLETION_BINDING_LEN];
    let mut bytes = [0_u8; COMPLETION_RECORD_LEN];
    bytes[..2].copy_from_slice(&CompletionRecord::VERSION.to_le_bytes());
    bytes[2..6].copy_from_slice(&CompletionRecord::TAG);
    bytes[6..6 + COMPLETION_BINDING_LEN].copy_from_slice(&binding);
    bytes[6 + COMPLETION_BINDING_LEN..].copy_from_slice(&COMPLETE_STAGE_MASK.to_le_bytes());

    let record = CompletionRecord::decode(&bytes, &binding).expect("fixed record must decode");
    assert_eq!(record.binding(), &binding);
    assert_eq!(record.complete_stage_mask(), COMPLETE_STAGE_MASK);
    assert_eq!(
        CompletionRecord::decode(&bytes[..bytes.len() - 1], &binding),
        Err(pnut_child::CompletionDecodeError::Length)
    );
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert_eq!(
        CompletionRecord::decode(&extra, &binding),
        Err(pnut_child::CompletionDecodeError::Length)
    );
    let mut reordered = bytes;
    reordered.swap(0, 2);
    assert!(CompletionRecord::decode(&reordered, &binding).is_err());
    let mut wrong_version = bytes;
    wrong_version[0] ^= 1;
    assert_eq!(
        CompletionRecord::decode(&wrong_version, &binding),
        Err(pnut_child::CompletionDecodeError::Version)
    );
    let mut wrong_tag = bytes;
    wrong_tag[2] ^= 1;
    assert_eq!(
        CompletionRecord::decode(&wrong_tag, &binding),
        Err(pnut_child::CompletionDecodeError::Tag)
    );
    let mut wrong_mask = bytes;
    wrong_mask[COMPLETION_RECORD_LEN - 1] ^= 1;
    assert_eq!(
        CompletionRecord::decode(&wrong_mask, &binding),
        Err(pnut_child::CompletionDecodeError::StageMask)
    );
    let wrong_binding = [0x5A; COMPLETION_BINDING_LEN];
    assert_eq!(
        CompletionRecord::decode(&bytes, &wrong_binding),
        Err(pnut_child::CompletionDecodeError::Binding)
    );
}

#[test]
fn setup_failure_emits_failure_and_never_completion() {
    let (status_read, status_write) = pipe_cloexec();
    let (completion_read, completion_write) = pipe_cloexec();
    let binding = [0x5A; COMPLETION_BINDING_LEN];
    let completion = CompletionSink::new(&binding, completion_write);
    let path = c"/bin/true";
    let argv = [path.as_ptr(), ptr::null()];
    let mut child_spec = spec(
        status_write,
        completion,
        Some(c"/definitely/not/a/pnut-directory"),
        ExecSpec { path, argv: &argv },
    );

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::close(status_read) };
        unsafe { libc::close(completion_read) };
        pnut_child::run(&mut child_spec);
    }
    unsafe { libc::close(status_write) };
    unsafe { libc::close(completion_write) };

    let status = wait_for(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 126);
    assert_eq!(read_all(completion_read), []);
    assert_eq!(
        read_all(status_read).len(),
        core::mem::size_of::<pnut_child::ChildFailure>()
    );
}

#[test]
fn completion_fd_cannot_alias_status_fd() {
    let (status_read, status_write) = pipe_cloexec();
    let binding = [0x3C; COMPLETION_BINDING_LEN];
    let completion = CompletionSink::new(&binding, status_write);
    let path = c"/bin/true";
    let argv = [path.as_ptr(), ptr::null()];
    let mut child_spec = spec(
        status_write,
        completion,
        None,
        ExecSpec { path, argv: &argv },
    );

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::close(status_read) };
        pnut_child::run(&mut child_spec);
    }
    unsafe { libc::close(status_write) };

    let status = wait_for(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 126);
    let bytes = read_all(status_read);
    assert_eq!(
        bytes.len(),
        core::mem::size_of::<pnut_child::ChildFailure>()
    );
    let failure =
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<pnut_child::ChildFailure>()) };
    assert_eq!(
        pnut_child::Stage::from_u16(failure.stage),
        Some(pnut_child::Stage::Completion)
    );
}
