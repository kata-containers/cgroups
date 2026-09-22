// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use std::path::PathBuf;

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
