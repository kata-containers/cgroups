// Copyright (c) 2026 And Group
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
    /// The entire input is empty, distinct from an empty component between
    /// separators (e.g. `a//b`); the root must be constructed explicitly.
    #[error("path is empty")]
    EmptyPath,
    /// The path is the filesystem root.
    #[error("path is the filesystem root")]
    Root,
    /// The input contains a `/` separator where a single component is
    /// required.
    #[error("input contains a `/` separator but a single component is required")]
    Separator,
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
