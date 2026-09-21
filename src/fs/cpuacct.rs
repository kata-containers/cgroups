// Copyright (c) 2018 Levente Kurusa
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module contains the implementation of the `cpuacct` cgroup subsystem.
//!
//! See the Kernel's documentation for more information about this subsystem, found at:
//!  [Documentation/cgroup-v1/cpuacct.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/cpuacct.txt)
use std::path::PathBuf;

use crate::fs::error::*;

use crate::fs::optional_read;
use crate::fs::{ControllIdentifier, ControllerInternal, Controllers, Resources, Subsystem};

/// A controller that allows controlling the `cpuacct` subsystem of a Cgroup.
///
/// In essence, this control group provides accounting (hence the name `cpuacct`) for CPU usage of
/// the tasks in the control group.
#[derive(Debug, Clone)]
pub struct CpuAcctController {
    base: PathBuf,
    path: PathBuf,
}

/// Represents the statistics retrieved from the control group.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CpuAcct {
    /// Divides the time used by the tasks into `user` time and `system` time.
    pub stat: String,
    /// Total CPU time (in nanoseconds) spent by the tasks.
    pub usage: u64,
    /// Total CPU time (in nanoseconds) spent by the tasks, broken down by CPU and by whether the
    /// time spent is `user` time or `system` time.
    ///
    /// An example is as follows:
    /// ```text
    /// cpu user system
    /// 0 8348363768 0
    /// 1 8324369100 0
    /// 2 8598185449 0
    /// 3 8648262473 0
    /// ```
    pub usage_all: String,
    /// CPU time (in nanoseconds) spent by the tasks, broken down by each CPU.
    /// Times spent in each CPU are separated by a space.
    pub usage_percpu: String,
    /// As for `usage_percpu`, but the `system` time spent.
    pub usage_percpu_sys: String,
    /// As for `usage_percpu`, but the `user` time spent.
    pub usage_percpu_user: String,
    /// CPU time (in nanoseconds) spent by the tasks that counted for `system` time.
    pub usage_sys: u64,
    /// CPU time (in nanoseconds) spent by the tasks that counted for `user` time.
    pub usage_user: u64,
}

impl ControllerInternal for CpuAcctController {
    fn control_type(&self) -> Controllers {
        Controllers::CpuAcct
    }
    fn get_path(&self) -> &PathBuf {
        &self.path
    }
    fn get_path_mut(&mut self) -> &mut PathBuf {
        &mut self.path
    }
    fn get_base(&self) -> &PathBuf {
        &self.base
    }

    fn apply(&self, _res: &Resources) -> Result<()> {
        Ok(())
    }
}

impl ControllIdentifier for CpuAcctController {
    fn controller_type() -> Controllers {
        Controllers::CpuAcct
    }
}

impl<'a> From<&'a Subsystem> for &'a CpuAcctController {
    fn from(sub: &'a Subsystem) -> &'a CpuAcctController {
        unsafe {
            match sub {
                Subsystem::CpuAcct(c) => c,
                _ => {
                    assert_eq!(1, 0);
                    let v = std::mem::MaybeUninit::uninit();
                    v.assume_init()
                }
            }
        }
    }
}

impl CpuAcctController {
    /// Contructs a new `CpuAcctController` with `root` serving as the root of the control group.
    pub fn new(point: PathBuf, root: PathBuf) -> Self {
        Self {
            base: root,
            path: point,
        }
    }

    /// Gathers the statistics that are available in the control group into a `CpuAcct` structure, or an error if reading failed.
    ///
    /// `cpuacct.stat`, `cpuacct.usage`, and `cpuacct.usage_percpu` are required.
    /// Other kernel-dependent fields default only when their files are absent;
    /// other I/O errors and malformed numeric values are propagated.
    pub fn cpuacct(&self) -> Result<CpuAcct> {
        Ok(CpuAcct {
            stat: self.read_value("cpuacct.stat", str::parse::<String>)?,
            usage: self.read_value("cpuacct.usage", str::parse::<u64>)?,
            usage_all: optional_read(self.read_value("cpuacct.usage_all", str::parse::<String>))?,
            usage_percpu: self.read_value("cpuacct.usage_percpu", str::parse::<String>)?,
            usage_percpu_sys: optional_read(
                self.read_value("cpuacct.usage_percpu_sys", str::parse::<String>),
            )?,
            usage_percpu_user: optional_read(
                self.read_value("cpuacct.usage_percpu_user", str::parse::<String>),
            )?,
            usage_sys: optional_read(self.read_value("cpuacct.usage_sys", str::parse::<u64>))?,
            usage_user: optional_read(self.read_value("cpuacct.usage_user", str::parse::<u64>))?,
        })
    }

    /// Reset the statistics the kernel has gathered about the control group.
    pub fn reset(&self) -> Result<()> {
        self.write_value("cpuacct.usage", "0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::error::ErrorKind::*;
    use crate::tests::TestDir;
    use std::fs;

    #[test]
    fn test_cpuacct_read_errors_preserve_path_input_and_source() {
        use std::error::Error as _;
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let fixture = TestDir::new("cpuacct_read_context");
        let dir = fixture.join(OsStr::from_bytes(b"group-\xff"));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("cpuacct.stat"), "user 1\nsystem 2\n").unwrap();
        fs::write(dir.join("cpuacct.usage"), "3\n").unwrap();
        fs::write(dir.join("cpuacct.usage_percpu"), "1 2\n").unwrap();
        fs::write(dir.join("cpuacct.usage_sys"), "0\n").unwrap();
        let controller = CpuAcctController::new(dir.clone(), dir.clone());

        for (name, valid) in [
            ("cpuacct.stat", "user 1\nsystem 2\n"),
            ("cpuacct.usage", "3\n"),
            ("cpuacct.usage_sys", "0\n"),
        ] {
            let path = dir.join(name);
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            let error = controller.cpuacct().unwrap_err();
            assert_eq!(error.kind(), &ReadFailed(path.display().to_string()));
            assert!(error.to_string().contains(name));
            assert!(matches!(
                error.source().unwrap().downcast_ref::<ReadFileError>().unwrap(),
                ReadFileError::Read { path: target, cause }
                    if target == &path && cause.raw_os_error() == Some(libc::EISDIR)
            ));
            fs::remove_dir(&path).unwrap();

            if name != "cpuacct.stat" {
                fs::write(&path, " invalid\n").unwrap();
                let error = controller.cpuacct().unwrap_err();
                assert_eq!(error.kind(), &ParseError);
                assert!(error.to_string().contains(name));
                let ReadFileError::Parse {
                    path: target,
                    input,
                    cause,
                } = error
                    .source()
                    .unwrap()
                    .downcast_ref::<ReadFileError>()
                    .unwrap()
                else {
                    panic!("expected contextual parse error");
                };
                assert_eq!(target, &path);
                assert_eq!(input, " invalid\n");
                assert!(cause.downcast_ref::<std::num::ParseIntError>().is_some());
            }
            fs::write(&path, valid).unwrap();
        }
    }

    #[test]
    fn test_cpuacct_required_files_and_zero_usage() {
        use std::error::Error as _;

        let dir = TestDir::new("cpuacct");
        let controller = CpuAcctController::new(dir.path().to_path_buf(), dir.path().to_path_buf());
        let required = [
            ("cpuacct.stat", "user 0\nsystem 0\n"),
            ("cpuacct.usage", "0\n"),
            ("cpuacct.usage_percpu", "0\n"),
        ];
        for (file, contents) in required {
            fs::write(dir.path().join(file), contents).unwrap();
        }
        assert_eq!(controller.cpuacct().unwrap().usage, 0);

        for (file, contents) in required {
            let path = dir.path().join(file);
            fs::remove_file(&path).unwrap();
            let error = controller.cpuacct().unwrap_err();
            assert_eq!(error.kind(), &ReadFailed(path.display().to_string()));
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<ReadFileError>()
                    .unwrap()
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
            fs::write(&path, contents).unwrap();
        }

        fs::write(dir.path().join("cpuacct.usage"), "invalid\n").unwrap();
        assert_eq!(controller.cpuacct().unwrap_err().kind(), &ParseError);
    }

    #[test]
    fn test_cpuacct_defaults_only_missing_optional_files() {
        let dir = TestDir::new("cpuacct");
        fs::write(dir.path().join("cpuacct.stat"), "user 1\nsystem 2\n").unwrap();
        fs::write(dir.path().join("cpuacct.usage"), "3\n").unwrap();
        fs::write(dir.path().join("cpuacct.usage_percpu"), "1 2\n").unwrap();
        let controller = CpuAcctController::new(dir.path().to_path_buf(), dir.path().to_path_buf());

        let stats = controller.cpuacct().unwrap();
        assert_eq!(stats.usage, 3);
        assert_eq!(stats.usage_sys, 0);
        assert!(stats.usage_all.is_empty());

        fs::write(dir.path().join("cpuacct.usage_sys"), "not-a-number\n").unwrap();
        assert_eq!(
            controller.cpuacct().unwrap_err().kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_distinguish_failed_reads_from_zero_values() {
        let dir = TestDir::new("cpuacct_read_failure");
        // Seed the first required file so the failure comes from cpuacct.usage.
        fs::write(dir.path().join("cpuacct.stat"), "user 0\nsystem 0\n").unwrap();
        let controller = CpuAcctController::new(dir.path().to_path_buf(), dir.path().to_path_buf());
        let error = controller
            .cpuacct()
            .expect_err("missing cpuacct.usage must fail, not return zero usage");
        assert_eq!(
            error.kind(),
            &ReadFailed(dir.path().join("cpuacct.usage").display().to_string())
        );
    }
}
