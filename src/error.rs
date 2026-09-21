// Copyright (c) 2026 And Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT

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
}
