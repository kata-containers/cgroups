// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::error::Error as StdError;
use std::fmt;

/// The different types of errors that can occur while manipulating control groups.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    #[error("fs error")]
    FsError,

    #[error("common error: {0}")]
    Common(String),

    /// An error occured while writing to a control group file.
    #[error("unable to write to a control group file {0}, value {1}")]
    WriteFailed(String, String),

    /// A multi-file update partially succeeded before failing on a subsequent file.
    #[error("multi-file update partially succeeded ({succeeded:?}) before failing on {file}, value {value}")]
    PartialWriteFailed {
        succeeded: Vec<String>,
        file: String,
        value: String,
    },

    /// An error occured while trying to read from a control group file.
    #[error("unable to read a control group file {0}")]
    ReadFailed(String),

    /// An error occured while trying to remove a control group.
    #[error("unable to remove a control group")]
    RemoveFailed,

    /// An error occured while trying to parse a value from a control group file.
    ///
    /// In the future, there will be some information attached to this field.
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
    /// This could be caused by trying to escape the control group filesystem via a string of "..".
    /// This crate checks against this and operations will fail with this error.
    #[error("the given path is invalid")]
    InvalidPath,

    #[error("invalid bytes size")]
    InvalidBytesSize,

    /// The specified controller is not in the list of supported controllers.
    #[error("specified controller is not in the list of supported controllers")]
    SpecifiedControllers,

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
    succeeded: Vec<String>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let succeeded = self.succeeded();
        if !succeeded.is_empty() && !matches!(self.kind, ErrorKind::PartialWriteFailed { .. }) {
            write!(f, "partially succeeded: {:?}; ", succeeded)?;
        }
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
            succeeded: Vec::new(),
        }
    }
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            cause: None,
            succeeded: Vec::new(),
        }
    }

    pub(crate) fn with_cause<E>(kind: ErrorKind, cause: E) -> Self
    where
        E: 'static + Send + Sync + StdError,
    {
        Self {
            kind,
            cause: Some(Box::new(cause)),
            succeeded: Vec::new(),
        }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Return whether the underlying filesystem operation failed because the
    /// requested cgroup file does not exist.
    ///
    /// This is intentionally narrower than matching [`ErrorKind::ReadFailed`]:
    /// callers may use it for kernel-version-dependent optional files without
    /// hiding permission, I/O, or parse failures.
    pub(crate) fn is_not_found(&self) -> bool {
        self.cause
            .as_deref()
            .and_then(|cause| cause.downcast_ref::<std::io::Error>())
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
    }

    /// Return the list of file updates that succeeded before this error occurred.
    pub fn succeeded(&self) -> &[String] {
        match &self.kind {
            ErrorKind::PartialWriteFailed { succeeded, .. } => succeeded.as_slice(),
            _ => &self.succeeded,
        }
    }

    /// Attach a list of succeeded file updates to this error.
    ///
    /// If `succeeded` is non-empty and `self.kind` is [`ErrorKind::WriteFailed`],
    /// `self.kind` is upgraded to [`ErrorKind::PartialWriteFailed`].
    pub fn with_succeeded(mut self, succeeded: Vec<String>) -> Self {
        if !succeeded.is_empty() {
            if let ErrorKind::WriteFailed(file, value) = self.kind {
                self.kind = ErrorKind::PartialWriteFailed {
                    succeeded: succeeded.clone(),
                    file,
                    value,
                };
            }
        }
        self.succeeded = succeeded;
        self
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_without_succeeded() {
        let err = Error::new(ErrorKind::WriteFailed("cpu.shares".into(), "1024".into()));
        assert!(err.succeeded().is_empty());
        assert_eq!(
            err.kind(),
            &ErrorKind::WriteFailed("cpu.shares".into(), "1024".into())
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
    fn test_error_with_succeeded_upgrades_write_failed() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = Error::with_cause(
            ErrorKind::WriteFailed("cpu.cfs_quota_us".into(), "50000".into()),
            io_err,
        )
        .with_succeeded(vec!["cpu.shares".into(), "cpu.cfs_period_us".into()]);

        assert_eq!(
            err.succeeded(),
            &["cpu.shares".to_string(), "cpu.cfs_period_us".to_string()]
        );
        assert_eq!(
            err.kind(),
            &ErrorKind::PartialWriteFailed {
                succeeded: vec!["cpu.shares".into(), "cpu.cfs_period_us".into()],
                file: "cpu.cfs_quota_us".into(),
                value: "50000".into(),
            }
        );
        assert!(err.source().is_some());
        let disp = format!("{}", err);
        assert!(disp.contains("multi-file update partially succeeded"));
        assert!(disp.contains("cpu.shares"));
        assert!(disp.contains("permission denied"));
    }

    use std::fs::{self, File, Permissions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use crate::fs::blkio::BlkIoController;
    use crate::fs::cpuacct::CpuAcctController;
    use crate::fs::cpuset::CpuSetController;
    use crate::fs::{Controller, CpuResources, Resources};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let rand_id: u64 = rand::random();
            let path = std::env::temp_dir().join(format!("cgroup_test_{}_{}", prefix, rand_id));
            fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn path(&self) -> &PathBuf {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            // Reset permissions so removal doesn't fail
            for entry in fs::read_dir(&self.path).into_iter().flatten().flatten() {
                let _ = fs::set_permissions(entry.path(), Permissions::from_mode(0o644));
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_partial_write_failure_reports_succeeded_changes() {
        crate::skip_if_root!();

        let fixture = TestDir::new("partial_write");
        let dir = fixture.path();

        // Create cpuset.cpus as writable
        let cpus_path = dir.join("cpuset.cpus");
        File::create(&cpus_path).unwrap();
        fs::set_permissions(&cpus_path, Permissions::from_mode(0o644)).unwrap();

        // Create cpuset.mems as read-only (0444) to trigger a permission denied error
        let mems_path = dir.join("cpuset.mems");
        File::create(&mems_path).unwrap();
        fs::set_permissions(&mems_path, Permissions::from_mode(0o444)).unwrap();

        let controller = CpuSetController::new(dir.clone(), dir.clone(), false);

        let resources = Resources {
            cpu: CpuResources {
                cpus: Some("0-1".to_string()),
                mems: Some("0".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let result = controller.apply(&resources);
        assert!(
            result.is_err(),
            "apply should fail due to read-only cpuset.mems"
        );

        let err = result.unwrap_err();

        // Verify succeeded list contains the first operation
        assert_eq!(err.succeeded(), &["cpuset.cpus".to_string()]);

        // Verify error kind was upgraded to PartialWriteFailed
        match err.kind() {
            ErrorKind::PartialWriteFailed {
                succeeded,
                file,
                value,
            } => {
                assert_eq!(succeeded, &["cpuset.cpus".to_string()]);
                assert!(
                    file.contains("cpuset.mems"),
                    "failing file should be cpuset.mems, got {}",
                    file
                );
                assert_eq!(value, "[CREATE FILE]");
            }
            other => panic!("expected PartialWriteFailed, got {:?}", other),
        }

        // Verify underlying cause is PermissionDenied
        let source = err
            .source()
            .expect("should preserve underlying io::Error cause");
        let io_err = source
            .downcast_ref::<std::io::Error>()
            .expect("cause should be std::io::Error");
        assert_eq!(io_err.kind(), std::io::ErrorKind::PermissionDenied);

        // Verify content of first file was indeed written
        let cpus_content = fs::read_to_string(&cpus_path).unwrap();
        assert_eq!(cpus_content.trim(), "0-1");
    }

    #[test]
    fn test_blkio_apply_missing_file_fails() {
        crate::skip_if_root!();

        let ro_fixture = TestDir::new("blkio_ro_dir");
        let ro_dir = ro_fixture.path();
        fs::set_permissions(ro_dir, Permissions::from_mode(0o555)).unwrap();

        let ro_controller = BlkIoController::new(ro_dir.clone(), ro_dir.clone(), false);
        let mut resources = Resources::default();
        resources.blkio.weight = Some(500);

        let ro_result = ro_controller.apply(&resources);
        assert!(
            ro_result.is_err(),
            "apply should fail when file cannot be created in read-only dir"
        );

        let err = ro_result.unwrap_err();
        assert!(
            matches!(
                err.kind(),
                ErrorKind::WriteFailed(..) | ErrorKind::PartialWriteFailed { .. }
            ),
            "expected write error, got {:?}",
            err.kind()
        );
        assert!(err.succeeded().is_empty(), "no files should have succeeded");
    }

    #[test]
    fn test_distinguish_failed_reads_from_zero_values() {
        crate::skip_if_root!();

        let fixture = TestDir::new("read_failure");
        let dir = fixture.path();

        // 1. Missing cpuacct.usage file
        let cpuacct = CpuAcctController::new(dir.clone(), dir.clone());
        let res = cpuacct.try_cpuacct();
        assert!(
            res.is_err(),
            "try_cpuacct() must return Err on missing file, not zero usage"
        );
        match res.unwrap_err().kind() {
            ErrorKind::ReadFailed(file) => {
                assert!(file.contains("cpuacct.stat") || file.contains("cpuacct.usage"));
            }
            other => panic!("expected ReadFailed, got {:?}", other),
        }
        #[allow(deprecated)]
        let legacy_usage = cpuacct.cpuacct().usage;
        assert_eq!(
            legacy_usage, 0,
            "deprecated cpuacct() should return default zero value on error"
        );

        // 2. Unreadable cgroup.procs file (mode 0000)
        let procs_path = dir.join("cgroup.procs");
        {
            let mut f = File::create(&procs_path).unwrap();
            writeln!(f, "1234").unwrap();
        }
        fs::set_permissions(&procs_path, Permissions::from_mode(0o000)).unwrap();

        let controller = CpuSetController::new(dir.clone(), dir.clone(), false);
        let procs_res = controller.try_procs();
        assert!(
            procs_res.is_err(),
            "try_procs() must return Err on unreadable file, not empty vec"
        );
        let err = procs_res.unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::ReadFailed(..)));
        #[allow(deprecated)]
        let legacy_procs = controller.procs();
        assert!(
            legacy_procs.is_empty(),
            "deprecated procs() must return empty vec on error"
        );

        // 3. Unreadable tasks file (mode 0000)
        let tasks_path = dir.join("tasks");
        {
            let mut f = File::create(&tasks_path).unwrap();
            writeln!(f, "5678").unwrap();
        }
        fs::set_permissions(&tasks_path, Permissions::from_mode(0o000)).unwrap();

        let tasks_res = controller.try_tasks();
        assert!(
            tasks_res.is_err(),
            "try_tasks() must return Err on unreadable file, not empty vec"
        );
        #[allow(deprecated)]
        let legacy_tasks = controller.tasks();
        assert!(
            legacy_tasks.is_empty(),
            "deprecated tasks() must return empty vec on error"
        );
    }

    #[test]
    fn test_membership_reads_return_valid_pids_when_readable() {
        let fixture = TestDir::new("read_success");
        let dir = fixture.path();

        let procs_path = dir.join("cgroup.procs");
        {
            let mut f = File::create(&procs_path).unwrap();
            writeln!(f, "100").unwrap();
            writeln!(f, "200").unwrap();
        }

        let controller = CpuSetController::new(dir.clone(), dir.clone(), false);
        let procs = controller
            .try_procs()
            .expect("reading valid procs should succeed");
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 100);
        assert_eq!(procs[1].pid, 200);

        #[allow(deprecated)]
        {
            let legacy_procs = controller.procs();
            assert_eq!(legacy_procs.len(), 2);
        }
    }
}
