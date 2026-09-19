//! Fixed completion evidence emitted immediately before `execve`.
//!
//! This is evidence that child setup reached the exec boundary, not evidence
//! that `execve` succeeded. Consumers must additionally require the clean
//! CLOEXEC close of the separate status descriptor and no `ChildFailure`.

use crate::error::{Errno, Result};
use crate::fd;
use crate::io::write_all;

/// Size of the caller-prevalidated binding carried by completion evidence.
pub const COMPLETION_BINDING_LEN: usize = 32;
/// Exact byte length of one completion record.
pub const COMPLETION_RECORD_LEN: usize = 42;

/// Protocol-owned bits for the setup primitives completion evidence requires.
///
/// These intentionally do not follow `Stage` discriminants: `Stage` is the
/// failure-reporting protocol and can gain unrelated stages without changing
/// completion evidence. The runtime sets each bit only after its primitive
/// has returned success.
pub(crate) const COMPLETE_MOUNT_PIVOT: u32 = 1 << 0;
pub(crate) const COMPLETE_RLIMITS: u32 = 1 << 1;
pub(crate) const COMPLETE_CAPABILITIES: u32 = 1 << 2;
pub(crate) const COMPLETE_FD_CLOSURE: u32 = 1 << 3;
pub(crate) const COMPLETE_NO_NEW_PRIVS: u32 = 1 << 4;
pub(crate) const COMPLETE_SECCOMP: u32 = 1 << 5;
pub const COMPLETE_STAGE_MASK: u32 = COMPLETE_MOUNT_PIVOT
    | COMPLETE_RLIMITS
    | COMPLETE_CAPABILITIES
    | COMPLETE_FD_CLOSURE
    | COMPLETE_NO_NEW_PRIVS
    | COMPLETE_SECCOMP;

/// A dedicated, parent-prevalidated destination for completion evidence.
///
/// The fixed-size binding is supplied by the parent before `clone3`; stage
/// bits, statuses, and payload bytes are intentionally not caller inputs.
#[derive(Clone, Copy, Debug)]
pub struct CompletionSink<'a> {
    binding: &'a [u8; COMPLETION_BINDING_LEN],
    fd: libc::c_int,
}

impl<'a> CompletionSink<'a> {
    /// Associate a prevalidated fixed binding with its child-write FD.
    pub const fn new(binding: &'a [u8; COMPLETION_BINDING_LEN], fd: libc::c_int) -> Self {
        Self { binding, fd }
    }

    pub(crate) const fn fd(self) -> libc::c_int {
        self.fd
    }
}

/// A decoded completion record. It has no public constructor because the
/// version, tag, and stage mask are runtime protocol constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionRecord {
    binding: [u8; COMPLETION_BINDING_LEN],
    complete_stage_mask: u32,
}

impl CompletionRecord {
    /// Wire-format version for a completion record.
    pub const VERSION: u16 = 1;
    /// Fixed wire-format tag for a completion record.
    pub const TAG: [u8; 4] = *b"PCMP";

    /// Decode exactly one completion record. Partial, concatenated, altered,
    /// or reordered records are rejected.
    pub fn decode(
        bytes: &[u8],
        expected_binding: &[u8; COMPLETION_BINDING_LEN],
    ) -> core::result::Result<Self, CompletionDecodeError> {
        if bytes.len() != COMPLETION_RECORD_LEN {
            return Err(CompletionDecodeError::Length);
        }
        if u16::from_le_bytes([bytes[0], bytes[1]]) != Self::VERSION {
            return Err(CompletionDecodeError::Version);
        }
        if bytes[2..6] != Self::TAG {
            return Err(CompletionDecodeError::Tag);
        }
        let mut binding = [0; COMPLETION_BINDING_LEN];
        binding.copy_from_slice(&bytes[6..6 + COMPLETION_BINDING_LEN]);
        if &binding != expected_binding {
            return Err(CompletionDecodeError::Binding);
        }
        let mask_start = 6 + COMPLETION_BINDING_LEN;
        let complete_stage_mask = u32::from_le_bytes([
            bytes[mask_start],
            bytes[mask_start + 1],
            bytes[mask_start + 2],
            bytes[mask_start + 3],
        ]);
        if complete_stage_mask != COMPLETE_STAGE_MASK {
            return Err(CompletionDecodeError::StageMask);
        }
        Ok(Self {
            binding,
            complete_stage_mask,
        })
    }

    pub const fn binding(&self) -> &[u8; COMPLETION_BINDING_LEN] {
        &self.binding
    }

    pub const fn complete_stage_mask(&self) -> u32 {
        self.complete_stage_mask
    }
}

/// Why a completion byte sequence was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDecodeError {
    Length,
    Version,
    Tag,
    Binding,
    StageMask,
}

/// Write and close completion evidence. Both operations are mandatory: a
/// failure is returned to the runtime so it can fail closed through status.
pub(crate) fn emit(sink: CompletionSink<'_>, complete_stage_mask: u32) -> Result<()> {
    let mut bytes = [0_u8; COMPLETION_RECORD_LEN];
    bytes[0..2].copy_from_slice(&CompletionRecord::VERSION.to_le_bytes());
    bytes[2..6].copy_from_slice(&CompletionRecord::TAG);
    bytes[6..6 + COMPLETION_BINDING_LEN].copy_from_slice(sink.binding);
    bytes[6 + COMPLETION_BINDING_LEN..].copy_from_slice(&complete_stage_mask.to_le_bytes());
    write_all(sink.fd, &bytes)?;
    fd::close(sink.fd).map_err(|err| Errno(err.0))
}
