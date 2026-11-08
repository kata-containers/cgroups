// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::error::Error as StdError;
use std::fmt;
use std::path::{Path, PathBuf};

/// An invalid PID record in a cgroup membership pseudo-file.
#[derive(Debug, thiserror::Error)]
#[error("expected an unsigned PID at line {line}, got {input:?}: {cause}")]
pub struct ParsePidError {
    /// The 1-based line containing the invalid record.
    pub line: usize,
    /// The complete record, before trimming whitespace.
    pub input: String,
    /// The integer format rule that failed.
    #[source]
    pub cause: std::num::ParseIntError,
}

/// Adds the concrete file path to a PID record parsing error.
#[derive(Debug, thiserror::Error)]
#[error("failed to parse membership file {path:?}: {cause}")]
pub struct ParsePidFileError {
    /// The membership pseudo-file being read.
    pub path: PathBuf,
    /// The parser's input, line number, and original error.
    #[source]
    pub cause: ParsePidError,
}

/// The failed stage and byte-preserving path of a controller resource read.
///
/// This is the source of [`ErrorKind::ReadFailed`] and [`ErrorKind::ParseError`]
/// errors from contextual readers. The original I/O or parser error remains
/// available through [`std::error::Error::source`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ReadFileError {
    /// Opening the target for reading failed.
    #[error("failed to open controller file {path:?} for reading: {cause}")]
    Open {
        /// The complete target path, including the cgroup directory.
        path: PathBuf,
        /// The original open error.
        #[source]
        cause: std::io::Error,
    },
    /// Reading the opened target failed.
    #[error("failed to read controller file {path:?}: {cause}")]
    Read {
        /// The complete target path, including the cgroup directory.
        path: PathBuf,
        /// The original read error.
        #[source]
        cause: std::io::Error,
    },
    /// Parsing the file contents failed.
    #[error("failed to parse controller file {path:?}, input {input:?}: {cause}")]
    Parse {
        /// The complete target path, including the cgroup directory.
        path: PathBuf,
        /// The complete file contents before trimming whitespace.
        input: String,
        /// The original parser error.
        #[source]
        cause: Box<dyn StdError + Send + Sync>,
    },
}

impl ReadFileError {
    /// Return the complete target path associated with this error.
    pub fn path(&self) -> &Path {
        match self {
            Self::Open { path, .. } | Self::Read { path, .. } | Self::Parse { path, .. } => path,
        }
    }

    /// Return the underlying I/O error if the failure occurred during open or read.
    pub fn io_error(&self) -> Option<&std::io::Error> {
        match self {
            Self::Open { cause, .. } | Self::Read { cause, .. } => Some(cause),
            Self::Parse { .. } => None,
        }
    }
}

/// The failed stage and byte-preserving path of a controller resource write.
///
/// This is the source of resource setters' [`ErrorKind::WriteFailed`] errors.
/// Its source is the original [`std::io::Error`], retaining the OS error code.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum WriteFileError {
    /// Opening the target for writing failed; no bytes were written to it.
    #[error("failed to open controller file {path:?} for writing: {cause}")]
    Open {
        /// The complete target path, including the cgroup directory.
        path: PathBuf,
        /// The original open error.
        #[source]
        cause: std::io::Error,
    },
    /// Writing to the opened target failed; the write may have been partial.
    #[error("failed to write controller file {path:?}: {cause}")]
    Write {
        /// The complete target path, including the cgroup directory.
        path: PathBuf,
        /// The original write error.
        #[source]
        cause: std::io::Error,
    },
}

impl WriteFileError {
    /// Return the complete target path associated with this error.
    pub fn path(&self) -> &Path {
        match self {
            Self::Open { path, .. } | Self::Write { path, .. } => path,
        }
    }

    /// Return the underlying I/O error.
    pub fn io_error(&self) -> &std::io::Error {
        match self {
            Self::Open { cause, .. } | Self::Write { cause, .. } => cause,
        }
    }
}

/// A controller attribute name rejected before opening a filesystem target.
///
/// Attribute names identify one file within the controller directory, rather
/// than a cgroup path. [`ErrorKind::InvalidPath`] retains this structured source.
#[non_exhaustive]
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum AttributeNameError {
    /// An attribute name cannot be empty.
    #[error("invalid controller attribute {input:?} in {operation}: name is empty")]
    EmptyName {
        /// The original attribute name.
        input: String,
        /// The operation that attempted to use the name.
        operation: &'static str,
    },
    /// An absolute path would replace the controller directory.
    #[error("invalid controller attribute {input:?} in {operation}: path is absolute")]
    AbsolutePath {
        /// The original attribute name.
        input: String,
        /// The operation that attempted to use the name.
        operation: &'static str,
    },
    /// The current-directory component does not name an attribute file.
    #[error(
        "invalid controller attribute {input:?} in {operation}: name is the current directory"
    )]
    CurrentComponent {
        /// The original attribute name.
        input: String,
        /// The operation that attempted to use the name.
        operation: &'static str,
    },
    /// The parent-directory component could escape the controller directory.
    #[error("invalid controller attribute {input:?} in {operation}: name is the parent directory")]
    ParentComponent {
        /// The original attribute name.
        input: String,
        /// The operation that attempted to use the name.
        operation: &'static str,
    },
    /// Attribute names must not contain the Linux path separator `/`.
    #[error(
        "invalid controller attribute {input:?} in {operation}: name contains a path separator"
    )]
    PathSeparator {
        /// The original attribute name.
        input: String,
        /// The operation that attempted to use the name.
        operation: &'static str,
    },
    /// Filesystem names cannot contain a NUL byte.
    #[error("invalid controller attribute {input:?} in {operation}: name contains a NUL byte")]
    NulByte {
        /// The original attribute name.
        input: String,
        /// The operation that attempted to use the name.
        operation: &'static str,
    },
}

/// The different types of errors that can occur while manipulating control groups.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    #[error("fs error")]
    FsError,

    #[error("common error: {0}")]
    Common(String),

    /// An error occured while writing to a control group file.
    /// Resource setters use the controller file name and intended serialized
    /// contents, with [`WriteFileError`] as the source for the full path and
    /// original OS error. Other legacy write entrypoints may use a full path
    /// or an open-operation placeholder instead.
    #[error("unable to write to a control group file {0}, value {1}")]
    WriteFailed(String, String),

    /// An error occured while trying to read from a control group file.
    /// Contextual resource readers attach [`ReadFileError`] as the source to
    /// preserve the byte-exact path and original I/O error.
    #[error("unable to read a control group file {0}")]
    ReadFailed(String),

    /// An error occured while trying to remove a control group.
    #[error("unable to remove a control group")]
    RemoveFailed,

    /// An error occured while trying to parse a value from a control group file.
    ///
    /// Contextual resource readers attach [`ReadFileError::Parse`] as the source
    /// to preserve the path, input, and original parser error. Other parsers may
    /// attach domain-specific diagnostics instead.
    #[error("unable to parse control group file")]
    ParseError,

    /// You tried to do something invalid.
    ///
    /// This could be because you tried to set a value in a control group that is not a root
    /// control group. Or, when using unified hierarchy, you tried to add a task in a leaf node.
    #[error("the requested operation is invalid")]
    InvalidOperation,

    /// The path of the control group was invalid.
    ///
    /// Cgroup path constructors and controller attribute writers reject path
    /// traversal. Attribute-name failures retain [`AttributeNameError`] as
    /// their source, including the original name and operation.
    #[error("the given path is invalid")]
    InvalidPath,

    #[error("invalid bytes size")]
    InvalidBytesSize,

    /// A requested controller is unavailable to the handle or hierarchy.
    #[error("controller {controller:?} is unavailable{}", .path.as_ref().map(|path| format!(" at {}", path.display())).unwrap_or_default())]
    UnsupportedController {
        /// The requested name, using the hierarchy's kernel spelling.
        controller: String,
        /// The controller-list file associated with availability on v2.
        /// V1 name validation has no single source path and reports `None`.
        /// Snapshot-based validation does not read this path.
        path: Option<PathBuf>,
    },

    /// Creation was requested with an explicitly empty controller selection.
    #[error("cannot create cgroup {path:?} with an empty controller selection")]
    EmptyControllerSelection {
        /// The requested path relative to the hierarchy.
        path: PathBuf,
    },

    /// Using method in wrong cgroup version.
    #[error("using method in wrong cgroup version")]
    CgroupVersion,

    /// Using method in wrong cgroup mode.
    #[error("using method in wrong cgroup mode.")]
    CgroupMode,

    /// Subsystems is empty.
    #[error("subsystems is empty")]
    SubsystemsEmpty,

    /// An unknown error has occured.
    #[error("an unknown error")]
    Other,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    cause: Option<Box<dyn StdError + Send + Sync>>,
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(cause) = &self.cause {
            write!(f, "{} caused by: {:?}", self.kind, cause)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        #[allow(clippy::manual_map)]
        match self.cause {
            Some(ref x) => Some(&**x),
            None => None,
        }
    }
}

impl Error {
    pub(crate) fn from_string(s: String) -> Self {
        Self {
            kind: ErrorKind::Common(s),
            cause: None,
        }
    }
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self { kind, cause: None }
    }

    pub(crate) fn with_cause<E>(kind: ErrorKind, cause: E) -> Self
    where
        E: 'static + Send + Sync + StdError,
    {
        Self {
            kind,
            cause: Some(Box::new(cause)),
        }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Return the underlying I/O error if this error carries one, unwrapping
    /// contextual [`ReadFileError`] and [`WriteFileError`] wrappers.
    pub(crate) fn io_error(&self) -> Option<&std::io::Error> {
        let cause = self.cause.as_deref()?;
        if let Some(err) = cause.downcast_ref::<ReadFileError>() {
            return err.io_error();
        }
        if let Some(err) = cause.downcast_ref::<WriteFileError>() {
            return Some(err.io_error());
        }
        cause.downcast_ref::<std::io::Error>()
    }

    /// Return whether the underlying filesystem operation failed because the
    /// requested cgroup file does not exist.
    ///
    /// This is intentionally narrower than matching [`ErrorKind::ReadFailed`]:
    /// callers may use it for kernel-version-dependent optional files without
    /// hiding permission, I/O, or parse failures.
    pub(crate) fn is_not_found(&self) -> bool {
        self.io_error()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_read_distinguishes_contextual_io_from_parser_errors() {
        let missing = ReadFileError::Open {
            path: PathBuf::from("optional.stat"),
            cause: std::io::Error::from_raw_os_error(libc::ENOENT),
        };
        let error = Error::with_cause(ErrorKind::ReadFailed("optional.stat".into()), missing);
        assert_eq!(crate::fs::optional_read::<u64>(Err(error)).unwrap(), 0);

        for errno in [libc::EACCES, libc::EIO] {
            let failed_read = ReadFileError::Read {
                path: PathBuf::from("optional.stat"),
                cause: std::io::Error::from_raw_os_error(errno),
            };
            let error =
                Error::with_cause(ErrorKind::ReadFailed("optional.stat".into()), failed_read);
            assert!(!error.is_not_found());
            assert!(crate::fs::optional_read::<u64>(Err(error)).is_err());
        }

        let failed_parse = ReadFileError::Parse {
            path: PathBuf::from("optional.stat"),
            input: "invalid".into(),
            cause: Box::new(std::io::Error::from_raw_os_error(libc::ENOENT)),
        };
        let error = Error::with_cause(ErrorKind::ParseError, failed_parse);
        assert!(!error.is_not_found());
        assert_eq!(
            crate::fs::optional_read::<u64>(Err(error))
                .unwrap_err()
                .kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_optional_read_only_defaults_not_found() {
        let missing = Error::with_cause(
            ErrorKind::ReadFailed("optional.stat".into()),
            std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        );
        assert_eq!(crate::fs::optional_read::<u64>(Err(missing)).unwrap(), 0);

        let denied = Error::with_cause(
            ErrorKind::ReadFailed("optional.stat".into()),
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        let error = crate::fs::optional_read::<u64>(Err(denied)).unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::ReadFailed("optional.stat".into()));
        assert!(!error.is_not_found());
    }

    #[test]
    fn test_contextual_error_helpers() {
        let p = Path::new("/sys/fs/cgroup/test/file");
        let io_err = std::io::Error::from_raw_os_error(libc::EOPNOTSUPP);
        let open_read = ReadFileError::Open {
            path: p.to_path_buf(),
            cause: io_err,
        };
        assert_eq!(open_read.path(), p);
        assert_eq!(
            open_read.io_error().unwrap().raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );

        let error = Error::with_cause(ErrorKind::ReadFailed(p.display().to_string()), open_read);
        assert_eq!(
            error.io_error().unwrap().raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );

        let write_err = WriteFileError::Write {
            path: p.to_path_buf(),
            cause: std::io::Error::from_raw_os_error(libc::ENOSPC),
        };
        assert_eq!(write_err.path(), p);
        assert_eq!(write_err.io_error().raw_os_error(), Some(libc::ENOSPC));

        let error = Error::with_cause(ErrorKind::WriteFailed("file".into(), "1".into()), write_err);
        assert_eq!(error.io_error().unwrap().raw_os_error(), Some(libc::ENOSPC));
    }
}
