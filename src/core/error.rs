// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use std::ffi::OsString;
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
    #[error(transparent)]
    PathError(#[from] PathError),

    /// A `/proc/<pid>/cgroup` membership record failed to parse.
    #[error(transparent)]
    ParseMembershipError(#[from] ParseMembershipError),

    /// A mountinfo record failed to parse.
    #[error(transparent)]
    ParseMountError(#[from] ParseMountError),
}

/// A malformed `/proc/<pid>/cgroup` membership record.
///
/// Each variant identifies a failed rule and carries the 1-based input line.
/// The pure parser knows the input format, but not the concrete file path.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseMembershipError {
    /// The record has fewer than three colon-separated fields.
    #[error("invalid cgroup membership at line {line}: expected three fields, found {found}")]
    MissingFields { line: usize, found: usize },
    /// The hierarchy ID contains bytes that cannot be parsed as text.
    #[error(
        "invalid cgroup membership at line {line}: hierarchy ID {input:?} is not valid ASCII text"
    )]
    InvalidHierarchyEncoding { line: usize, input: OsString },
    /// The hierarchy ID is not a `u32`.
    #[error("invalid cgroup membership at line {line}: hierarchy ID {input:?} is not an integer")]
    InvalidHierarchyId { line: usize, input: OsString },
    /// A comma-separated controller name is empty.
    #[error("invalid cgroup membership at line {line}: empty controller name in {list:?}")]
    EmptyController { line: usize, list: OsString },
    /// A controller name is not valid UTF-8.
    #[error(
        "invalid cgroup membership at line {line}: controller name {input:?} is not valid UTF-8"
    )]
    InvalidControllerEncoding { line: usize, input: OsString },
    /// Unified hierarchy ID 0 has a non-empty controller list.
    #[error("invalid cgroup membership at line {line}: unified hierarchy has controllers {controllers:?}")]
    UnexpectedUnifiedControllers { line: usize, controllers: OsString },
    /// A v1 hierarchy has no controller names.
    #[error(
        "invalid cgroup membership at line {line}: v1 hierarchy {hierarchy_id} has no controllers"
    )]
    MissingV1Controllers { line: usize, hierarchy_id: u32 },
    /// The cgroup path field is empty.
    #[error("invalid cgroup membership at line {line}: cgroup path is empty")]
    EmptyPath { line: usize },
    /// The observed cgroup path does not begin with `/`.
    #[error("invalid cgroup membership at line {line}: cgroup path {input:?} is relative")]
    RelativePath { line: usize, input: PathBuf },
    /// The observed cgroup path contains an empty component.
    #[error("invalid cgroup membership at line {line}: cgroup path {input:?} contains an empty component")]
    EmptyPathComponent { line: usize, input: PathBuf },
    /// The observed cgroup path contains a `.` component.
    #[error("invalid cgroup membership at line {line}: cgroup path {input:?} contains a current-directory component")]
    CurrentPathComponent { line: usize, input: PathBuf },
    /// The observed cgroup path contains a NUL byte.
    #[error("invalid cgroup membership at line {line}: cgroup path {input:?} contains a NUL byte")]
    NulPathComponent { line: usize, input: PathBuf },
    /// A hierarchy ID appears on more than one line.
    #[error("invalid cgroup membership at line {line}: hierarchy ID {hierarchy_id} repeats line {first_line}")]
    DuplicateHierarchyId {
        line: usize,
        hierarchy_id: u32,
        first_line: usize,
    },
    /// A controller is bound by more than one record.
    #[error("invalid cgroup membership at line {line}: controller {controller:?} repeats line {first_line}")]
    DuplicateController {
        line: usize,
        controller: String,
        first_line: usize,
    },
    /// The legacy OCI string API cannot represent the parsed path.
    #[error("invalid cgroup membership at line {line}: path {input:?} is not valid UTF-8 for the legacy OCI Manager API")]
    LegacyPathNotUtf8 { line: usize, input: PathBuf },
}

impl ParseMembershipError {
    /// 1-based line number of the offending record.
    pub fn line(&self) -> usize {
        match self {
            Self::MissingFields { line, .. }
            | Self::InvalidHierarchyEncoding { line, .. }
            | Self::InvalidHierarchyId { line, .. }
            | Self::EmptyController { line, .. }
            | Self::InvalidControllerEncoding { line, .. }
            | Self::UnexpectedUnifiedControllers { line, .. }
            | Self::MissingV1Controllers { line, .. }
            | Self::EmptyPath { line }
            | Self::RelativePath { line, .. }
            | Self::EmptyPathComponent { line, .. }
            | Self::CurrentPathComponent { line, .. }
            | Self::NulPathComponent { line, .. }
            | Self::DuplicateHierarchyId { line, .. }
            | Self::DuplicateController { line, .. }
            | Self::LegacyPathNotUtf8 { line, .. } => *line,
        }
    }
}

/// A malformed mountinfo record.
///
/// Each variant identifies a failed rule and carries the 1-based input line.
/// The pure parser knows the input format, but not the concrete file path.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseMountError {
    /// The ` - ` separator is absent.
    #[error("invalid mountinfo at line {line}: missing ` - ` separator")]
    MissingSeparator { line: usize },
    /// Too few fields precede the separator.
    #[error("invalid mountinfo at line {line}: expected at least six mount fields, found {found}")]
    MissingMountFields { line: usize, found: usize },
    /// The mount ID is not a `u32`.
    #[error("invalid mountinfo at line {line}: mount ID {input:?} is not an integer")]
    InvalidMountId { line: usize, input: OsString },
    /// The parent ID is not a `u32`.
    #[error("invalid mountinfo at line {line}: parent ID {input:?} is not an integer")]
    InvalidParentId { line: usize, input: OsString },
    /// The device field is not `major:minor` with `u32` components.
    #[error("invalid mountinfo at line {line}: device {input:?} is not `<major>:<minor>`")]
    InvalidDevice { line: usize, input: OsString },
    /// The mount root field is empty.
    #[error("invalid mountinfo at line {line}: mount root is empty")]
    EmptyMountRoot { line: usize },
    /// The mount options field is empty.
    #[error("invalid mountinfo at line {line}: mount options are empty")]
    EmptyMountOptions { line: usize },
    /// The mount point is not an absolute path.
    #[error("invalid mountinfo at line {line}: mount point {input:?} is not absolute")]
    NonAbsoluteMountPoint { line: usize, input: PathBuf },
    /// Fewer than three filesystem fields follow the separator.
    #[error("invalid mountinfo at line {line}: expected filesystem type, source, and super options; found {found} fields")]
    MissingFilesystemFields { line: usize, found: usize },
    /// The filesystem type field is empty.
    #[error("invalid mountinfo at line {line}: filesystem type is empty")]
    EmptyFilesystemType { line: usize },
    /// The superblock options field is empty.
    #[error("invalid mountinfo at line {line}: super options are empty")]
    EmptySuperOptions { line: usize },
    /// The filesystem type cannot be represented as UTF-8.
    #[error("invalid mountinfo at line {line}: filesystem type {input:?} is not valid UTF-8")]
    InvalidFilesystemTypeEncoding { line: usize, input: OsString },
    /// The main filesystem type before `.` is empty.
    #[error("invalid mountinfo at line {line}: filesystem type before `.` is empty")]
    EmptyFilesystemTypeBeforeSubtype { line: usize },
    /// The filesystem subtype after `.` is empty.
    #[error("invalid mountinfo at line {line}: filesystem subtype after `.` is empty")]
    EmptyFilesystemSubtype { line: usize },
    /// A filesystem field contains an unknown or truncated escape.
    #[error("invalid mountinfo at line {line}: unknown or truncated escape {input:?} in {field}")]
    InvalidEscape {
        line: usize,
        field: &'static str,
        input: OsString,
    },
    /// The legacy OCI string API cannot represent the parsed mount point.
    #[error("invalid mountinfo at line {line}: mount point {input:?} is not valid UTF-8 for the legacy OCI Manager API")]
    LegacyMountPointNotUtf8 { line: usize, input: PathBuf },
}

impl ParseMountError {
    /// 1-based line number of the offending record.
    pub fn line(&self) -> usize {
        match self {
            Self::MissingSeparator { line }
            | Self::MissingMountFields { line, .. }
            | Self::InvalidMountId { line, .. }
            | Self::InvalidParentId { line, .. }
            | Self::InvalidDevice { line, .. }
            | Self::EmptyMountRoot { line }
            | Self::EmptyMountOptions { line }
            | Self::NonAbsoluteMountPoint { line, .. }
            | Self::MissingFilesystemFields { line, .. }
            | Self::EmptyFilesystemType { line }
            | Self::EmptySuperOptions { line }
            | Self::InvalidFilesystemTypeEncoding { line, .. }
            | Self::EmptyFilesystemTypeBeforeSubtype { line }
            | Self::EmptyFilesystemSubtype { line }
            | Self::InvalidEscape { line, .. }
            | Self::LegacyMountPointNotUtf8 { line, .. } => *line,
        }
    }
}

/// An error returned when a path cannot represent a safe cgroup path.
///
/// Each variant names the failed validation rule directly and retains the
/// original input and operation so callers can both match the failure and
/// report useful context.
///
/// # Examples
///
/// ```
/// use cgroups_rs::core::{CgroupPath, PathError};
///
/// match CgroupPath::new("/absolute").unwrap_err() {
///     PathError::AbsolutePath { input, operation } => {
///         assert_eq!(input, std::path::Path::new("/absolute"));
///         assert_eq!(operation, "CgroupPath::new");
///     }
///     error => panic!("unexpected error: {error}"),
/// }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The path is absolute (starts with `/`).
    #[error("invalid cgroup path {input:?} in {operation}: path is absolute")]
    AbsolutePath {
        /// The original input that was rejected.
        input: PathBuf,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },

    /// The path is relative where the input must begin with `/` (e.g. the
    /// path field of a `/proc/<pid>/cgroup` membership line).
    #[error(
        "invalid cgroup path {input:?} in {operation}: path is relative but a leading `/` is required"
    )]
    RelativePath {
        /// The original input that was rejected.
        input: PathBuf,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },

    /// The path contains a `..` component that could escape the cgroup root.
    #[error("invalid cgroup path {input:?} in {operation}: path contains a parent component (..)")]
    ParentComponent {
        /// The original input that was rejected.
        input: PathBuf,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },

    /// The path contains a `.` component.
    #[error("invalid cgroup path {input:?} in {operation}: path contains a current component (.)")]
    CurrentComponent {
        /// The original input that was rejected.
        input: PathBuf,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },

    /// The path contains an empty component (e.g. `a//b`).
    #[error("invalid cgroup path {input:?} in {operation}: path contains an empty component")]
    EmptyComponent {
        /// The original input that was rejected.
        input: PathBuf,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },

    /// The path contains a NUL byte (`\0`), which no filesystem path can
    /// carry (kernel path syscalls reject it).
    #[error("invalid cgroup path {input:?} in {operation}: path contains a NUL byte")]
    NulByte {
        /// The original input that was rejected.
        input: PathBuf,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },

    /// The path is the filesystem root.
    #[error("invalid cgroup path {input:?} in {operation}: path is the filesystem root")]
    RootPath {
        /// The original input that was rejected.
        input: PathBuf,
        /// The operation that attempted to use the path.
        operation: &'static str,
    },
}
