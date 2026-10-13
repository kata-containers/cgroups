// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! String-based compatibility readers with an explicit host configuration.

use std::collections::HashMap;
use std::fs;

use crate::core::{discover, parse_membership, CoreError, HostPaths};
use crate::fs::error::{Error, ErrorKind, Result};
use crate::fs::hierarchies::V1;
use crate::fs::Hierarchy;

/// Read membership and map existing paths using one host configuration.
///
/// Construction performs no I/O. Each operation reads the configured files
/// again, so process migration is visible to subsequent membership reads.
/// These compatibility readers return string maps and require UTF-8 input.
/// For byte-preserving observations, use the core membership parser instead.
///
/// ```no_run
/// use cgroups_rs::core::HostPaths;
/// use cgroups_rs::fs::CgroupReader;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let reader = CgroupReader::new(HostPaths::default());
/// let current = reader.memberships(None)?;
/// let other = reader.memberships(Some(1234))?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct CgroupReader {
    host_paths: HostPaths,
}

impl CgroupReader {
    /// Configure the reader without discovering or modifying cgroups.
    pub fn new(host_paths: HostPaths) -> Self {
        Self { host_paths }
    }

    /// Read `<procfs>/self/cgroup` for `None`, or `<procfs>/<pid>/cgroup`.
    ///
    /// Returns raw membership paths, including their leading `/`. A v1 record
    /// with multiple controllers contributes one entry per controller. Named
    /// hierarchies keep keys such as `name=systemd`; the unified v2 record uses
    /// the empty string key. No entries are filtered to the controllers a
    /// cgroup handle manages.
    ///
    /// Observed paths may contain namespace-relative `..`; they are not
    /// mutation-safe [`crate::core::CgroupPath`] values and cannot be passed
    /// directly to [`crate::fs::CgroupBuilder::v1_prefixes`]. Select keys that
    /// match [`crate::fs::Subsystem::controller_name`] and express paths relative
    /// to the visible controller mounts. When a controller's mount root is `/`,
    /// [`crate::core::CgroupPath::from_proc_cgroup_path`] strips the leading `/`
    /// and validates the remainder, rejecting `..`. Other mount roots require
    /// mapping the observed path to the visible mount first.
    ///
    /// Read and parse errors propagate with the source file path and underlying
    /// cause.
    pub fn memberships(&self, pid: Option<u32>) -> Result<HashMap<String, String>> {
        let process = pid.map_or_else(|| "self".to_string(), |pid| pid.to_string());
        let path = self.host_paths.procfs.join(process).join("cgroup");
        let content = fs::read_to_string(&path).map_err(|cause| {
            Error::with_cause(ErrorKind::ReadFailed(path.display().to_string()), cause)
        })?;
        let membership = parse_membership(&content).map_err(|cause| {
            Error::with_cause(
                ErrorKind::InvalidPath,
                CoreError::ParseMembershipInFile {
                    path: path.clone(),
                    cause,
                },
            )
        })?;

        let mut paths = HashMap::new();
        for record in membership.records() {
            let path_str = record.path.to_string_lossy().into_owned();
            if record.controllers.is_empty() {
                paths.insert(String::new(), path_str);
            } else {
                for controller in &record.controllers {
                    paths.insert(controller.clone(), path_str.clone());
                }
            }
        }
        Ok(paths)
    }

    /// Apply the legacy v1 path mapping using strictly discovered host mounts.
    ///
    /// Discovery failures propagate rather than selecting a default layout.
    /// This compatibility mapping does not establish existence, ownership,
    /// or confinement of an attachment destination.
    pub fn existing_path(&self, paths: HashMap<String, String>) -> Result<HashMap<String, String>> {
        let topology = discover(&self.host_paths)
            .map_err(|cause| Error::with_cause(ErrorKind::FsError, cause))?;
        let hierarchy = V1::from(topology);
        let mut mapped = HashMap::new();
        for subsystem in hierarchy.subsystems() {
            let controller = subsystem.controller_name();
            let membership = paths.get(&controller).ok_or_else(|| {
                Error::new(ErrorKind::Common(format!(
                    "controller {} found in mountinfo, but not found in cgroup.",
                    controller
                )))
            })?;
            let base = subsystem
                .to_controller()
                .base()
                .to_string_lossy()
                .to_string();
            let prefix = if base == "/" { "" } else { &base };
            mapped.insert(
                controller,
                membership.trim_start_matches(prefix).to_string(),
            );
        }
        Ok(mapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;
    use std::path::PathBuf;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "cgroups-reader-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn reader(&self) -> CgroupReader {
            CgroupReader::new(HostPaths::new(self.0.clone(), self.0.join("hugepages")))
        }

        fn write(&self, process: &str, content: &[u8]) {
            let dir = self.0.join(process);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("cgroup"), content).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_memberships_select_source_and_process_and_read_fresh_membership() {
        let first = Fixture::new();
        first.write(
            "self",
            b"1:memory:/user.slice\n2:cpu,cpuacct:/test.slice:colon_path:scope\n\
              3:pids:/../sibling.slice\n4:name=systemd:/user.slice\n0::/../sibling.slice\n",
        );
        first.write("17", b"0::/another-process\n");
        let second = Fixture::new();
        second.write("self", b"0::/another-source\n");
        let reader = first.reader();
        let map = reader.memberships(None).unwrap();
        assert_eq!(map["memory"], "/user.slice");
        assert_eq!(map["cpu"], "/test.slice:colon_path:scope");
        assert_eq!(map["cpuacct"], "/test.slice:colon_path:scope");
        assert_eq!(map["pids"], "/../sibling.slice");
        assert_eq!(map["name=systemd"], "/user.slice");
        assert_eq!(map[""], "/../sibling.slice");
        assert_eq!(
            reader.memberships(Some(17)).unwrap()[""],
            "/another-process"
        );
        assert_eq!(
            second.reader().memberships(None).unwrap()[""],
            "/another-source"
        );

        first.write("self", b"0::/after-migration\n");
        assert_eq!(reader.memberships(None).unwrap()[""], "/after-migration");
    }

    #[test]
    fn test_memberships_preserve_read_and_parse_error_context() {
        let fixture = Fixture::new();
        let reader = fixture.reader();
        let path = fixture.0.join("17/cgroup");
        let error = reader.memberships(Some(17)).unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::ReadFailed(path.display().to_string())
        );
        let cause = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(cause.raw_os_error(), Some(libc::ENOENT));

        fixture.write("17", b"0::/valid\nbad_line_without_colons\n");
        let error = reader.memberships(Some(17)).unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::InvalidPath);
        match error.source().unwrap().downcast_ref::<CoreError>().unwrap() {
            CoreError::ParseMembershipInFile {
                path: actual,
                cause,
            } => {
                assert_eq!(actual, &path);
                assert!(matches!(
                    cause,
                    crate::core::ParseMembershipError::MissingFields { line: 2, .. }
                ));
            }
            error => panic!("unexpected error: {:?}", error),
        }

        fixture.write("17", b"0::/\xff\n");
        let error = reader.memberships(Some(17)).unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::ReadFailed(path.display().to_string())
        );
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn test_existing_path_propagates_discovery_error() {
        let fixture = Fixture::new();
        let paths = HashMap::from([("memory".to_string(), "/test".to_string())]);
        let error = fixture.reader().existing_path(paths).unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::FsError);
        match error.source().unwrap().downcast_ref::<CoreError>().unwrap() {
            CoreError::ReadProcFile { path, cause } => {
                assert_eq!(path, &fixture.0.join("self/mountinfo"));
                assert_eq!(cause.raw_os_error(), Some(libc::ENOENT));
            }
            error => panic!("unexpected error: {:?}", error),
        }
    }

    #[test]
    fn test_existing_path_uses_the_configured_v1_mounts() {
        let fixture = Fixture::new();
        fixture.write("self", b"1:memory:/delegated/current\n");
        fs::write(
            fixture.0.join("self/mountinfo"),
            b"43 33 0:38 /delegated /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
        )
        .unwrap();
        let cgroupfs = fixture.0.join("cgroupfs");
        let reader = CgroupReader::new(
            HostPaths::new(fixture.0.clone(), fixture.0.join("hugepages"))
                .with_fixture_root(cgroupfs.clone()),
        );
        // Membership is measured from the hierarchy's mount root, independently
        // of where that root is mounted in filesystem coordinates.
        let paths = HashMap::from([("memory".to_string(), "/delegated/task".to_string())]);
        assert_eq!(reader.existing_path(paths).unwrap()["memory"], "/task");
    }
}
