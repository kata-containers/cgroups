// Copyright (c) 2026 And Group
// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use std::io;
use std::path::PathBuf;

/// Convenience alias for `Result<T, CoreError>`.
pub type CoreResult<T> = std::result::Result<T, CoreError>;

/// Core errors shared across all cgroup backends.
///
/// These errors originate in the pure-core layer (path validation, parsing)
/// and will be preserved as context by backend-specific error enums.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A cgroup path failed validation.
    #[error("invalid cgroup path {input:?} in {operation}: {reason}")]
    InvalidPath {
        /// The original input that was rejected.
        input: PathBuf,
        /// Why the path was rejected.
        reason: PathReason,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },

    /// A kernel text format failed to parse.
    #[error("Parse {kind:?} in {line}: {reason}")]
    ParseError {
        /// Which input format was being parsed.
        kind: ParseSource,
        /// 1-based line number in the input text.
        line: usize,
        /// Human-readable description of the malformation.
        reason: String,
    },

    /// A host discovery step failed while reading the host.
    #[error("discovery failed at {step} ({path}): {cause}")]
    Discovery {
        /// The discovery step that failed.
        step: &'static str,
        /// The host path the step was operating on.
        path: PathBuf,
        /// The underlying I/O error, preserved as the error-chain source.
        #[source]
        cause: io::Error,
    },

    /// A process identifier failed validation.
    #[error("invalid process ID {raw}: {reason}")]
    InvalidProcessId {
        /// The raw integer provided.
        raw: u64,
        /// Why the process ID was rejected.
        reason: &'static str,
    },
}

/// Errors that can occur during cgroup process or thread attachment.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    /// The destination violates the validated attachment path contract.
    #[error("invalid attachment destination: {source}")]
    InvalidDestination {
        /// Context-preserving path validation error.
        #[source]
        source: CoreError,
    },

    /// A selected hierarchy has no visible mount to execute against.
    #[error("no visible mount for hierarchy '{hierarchy}' below {}", root.display())]
    MissingHierarchyMount {
        /// Controller or unified hierarchy requiring a mount.
        hierarchy: String,
        /// Configured cgroupfs root.
        root: PathBuf,
    },

    /// Inspecting or creating an attachment directory failed.
    #[error("{backend} attachment for process {pid}: {operation} at {} failed: {source}", target.display())]
    TargetIo {
        /// Backend performing the filesystem operation.
        backend: &'static str,
        /// Process being attached.
        pid: crate::model::pid::ProcessId,
        /// Filesystem operation that failed.
        operation: &'static str,
        /// Complete target path.
        target: PathBuf,
        /// Controller names sharing this target, or `0::` on v2.
        controllers: Vec<String>,
        /// Unmodified operating system error.
        #[source]
        source: io::Error,
    },

    /// A v1 membership write failed, possibly after other hierarchies migrated.
    #[error("{backend} {operation} for process {pid} failed in {controllers:?} at {}: {source}; partially migrated hierarchies: {completed:?}", target.display())]
    WriteMembership {
        /// Backend performing the migration.
        backend: &'static str,
        /// Process or thread being migrated.
        pid: crate::model::pid::ProcessId,
        /// Process or thread attachment operation.
        operation: &'static str,
        /// Controller names on the failed hierarchy.
        controllers: Vec<String>,
        /// Complete membership file path that failed.
        target: PathBuf,
        /// Controller names of every successfully migrated hierarchy.
        completed: Vec<Vec<String>>,
        /// Unmodified operating system error.
        #[source]
        source: io::Error,
    },

    /// A process identifier failed validation.
    #[error("invalid process ID {value}")]
    InvalidProcessId {
        /// The raw value that failed validation.
        value: u64,
    },

    /// Failed to read the process membership file from procfs.
    #[error("failed to read membership for process {pid} from {}: {source}", path.display())]
    ReadMembership {
        /// Process ID whose membership was requested.
        pid: crate::model::pid::ProcessId,
        /// File path that could not be read.
        path: std::path::PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse the process membership content.
    #[error("failed to parse membership for process {pid}: {source}")]
    ParseMembership {
        /// Process ID whose membership failed to parse.
        pid: crate::model::pid::ProcessId,
        /// Underlying core parse error.
        #[source]
        source: CoreError,
    },

    /// A required hierarchy or controller membership record is missing.
    #[error("no membership record found for process {pid} in hierarchy '{hierarchy}'")]
    MissingHierarchyMembership {
        /// Process ID missing the record.
        pid: crate::model::pid::ProcessId,
        /// Hierarchy or controller name.
        hierarchy: String,
    },

    /// The observed membership path is outside the managed cgroup subtree.
    #[error("process {pid} in cgroup '{}' is outside managed cgroup '{}'", observed.display(), managed.as_path().display())]
    OutsideManagedCgroup {
        /// Process ID observed outside the subtree.
        pid: crate::model::pid::ProcessId,
        /// Observed membership path from procfs.
        observed: std::path::PathBuf,
        /// Base path of the manager.
        managed: crate::model::path::CgroupPath,
    },

    /// Membership is ambiguous or contradictory.
    #[error("ambiguous membership for process {pid}: {detail}")]
    AmbiguousMembership {
        /// Process ID with ambiguous membership.
        pid: crate::model::pid::ProcessId,
        /// Explanation of ambiguity.
        detail: String,
    },

    /// The resolved target cgroup does not exist and cannot be created.
    #[error("resolved target cgroup '{}' for process {pid} does not exist: {source}", target.display())]
    MissingResolvedTarget {
        /// Process ID targeted.
        pid: crate::model::pid::ProcessId,
        /// Target directory path that does not exist.
        target: std::path::PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The resolved subgroup path contains non-UTF-8 bytes and cannot be passed to systemd D-Bus.
    #[error("systemd D-Bus interface does not support non-UTF-8 subgroup path '{}'", path.as_path().display())]
    NonUtf8SystemdSubgroup {
        /// Subgroup path with invalid UTF-8.
        path: crate::model::path::CgroupPath,
    },

    /// The requested operation is unsupported by the backend.
    #[error("operation '{operation}' is unsupported on {backend} backend")]
    Unsupported {
        /// Backend name (e.g. "cgroupfs" or "systemd").
        backend: &'static str,
        /// Name or description of the unsupported operation.
        operation: &'static str,
    },
}

/// Reason a cgroup path was rejected by [`CoreError::InvalidPath`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathReason {
    /// The path is absolute (starts with `/`).
    #[error("path is absolute")]
    Absolute,
    /// The path is relative where the input must begin with `/` (e.g. the
    /// path field of a `/proc/<pid>/cgroup` membership line).
    #[error("path is relative but a leading `/` is required")]
    Relative,
    /// The path contains a `..` component that could escape the cgroup root.
    #[error("path contains a parent component (..)")]
    ParentComponent,
    /// The path contains a `.` component.
    #[error("path contains a current component (.)")]
    CurrentComponent,
    /// The path contains an empty component (e.g. `a//b`).
    #[error("path contains an empty component")]
    EmptyComponent,
    /// The path contains a NUL byte (`\0`), which no filesystem path can
    /// carry (kernel path syscalls reject it).
    #[error("path contains a NUL byte")]
    NulByte,
    /// The path is the filesystem root.
    #[error("path is the filesystem root")]
    Root,
    /// The input contains a `/` separator where a single component is
    /// required.
    #[error("input contains a `/` separator but a single component is required")]
    Separator,
    /// The path fails a containment check: it is not a descendant of the
    /// expected base path.
    #[error("path is not contained within the expected base")]
    ContainmentViolation,
}

/// Identifies which input format a [`CoreError::ParseError`] came from.
///
/// Pure parsers are handed text and know only its format; the concrete
/// file the text was read from is supplied by the discovery layer when
/// it performs the I/O.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseSource {
    /// Mount-table records in `/proc/self/mountinfo` format.
    #[error("mountinfo mount table")]
    Mountinfo,
    /// Membership records in `/proc/<pid>/cgroup` format.
    #[error("cgroup membership records")]
    Membership,
}
