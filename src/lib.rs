// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020-2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

#![doc = include_str!("../README.md")]

pub mod core;
pub use core::{CgroupPid, FreezerState, CPU_SHARES_V1_MAX, CPU_WEIGHT_V2_MAX};
pub mod fs;
#[cfg(feature = "oci")]
pub mod oci;
#[cfg(feature = "oci")]
pub use oci::{FsManager, Manager, SystemdManager};
pub mod stats;
pub use stats::CgroupStats;
pub mod systemd;

/// Return early from a test that requires effective root privileges.
///
/// This is exported so integration tests can share the same privilege check.
/// CI runners must independently verify that privilege elevation succeeded,
/// because an early return is reported by Rust's test harness as a pass.
#[doc(hidden)]
#[macro_export]
macro_rules! skip_if_not_root {
    () => {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping test: requires effective UID 0 (root)");
            return;
        }
    };
}

/// Return early from a test that does not support a cgroup v1 hierarchy.
///
/// A discovery failure is a test failure rather than a skip: controlled
/// root/QEMU environments preflight their hierarchy, so silently returning
/// here would hide parser or discovery regressions.
#[doc(hidden)]
#[macro_export]
macro_rules! skip_if_cgroups_v1 {
    () => {
        match $crate::core::discover(&$crate::core::discovery::HostPaths::default()) {
            Ok(topology) if topology.version() == $crate::core::CgroupVersion::V2 => {}
            Ok(_) => {
                eprintln!("Skipping test in cgroups v1 mode");
                return;
            }
            Err(e) => {
                panic!("cgroup discovery failed while selecting a v2 test: {}", e);
            }
        }
    };
}

/// Return early from a test that does not support a cgroup v2 hierarchy.
///
/// A discovery failure is a test failure rather than a skip: controlled
/// root/QEMU environments preflight their hierarchy, so silently returning
/// here would hide parser or discovery regressions.
#[doc(hidden)]
#[macro_export]
macro_rules! skip_if_cgroups_v2 {
    () => {
        match $crate::core::discover(&$crate::core::discovery::HostPaths::default()) {
            Ok(topology) if topology.version() == $crate::core::CgroupVersion::V1 => {}
            Ok(_) => {
                eprintln!("Skipping test in cgroups v2 mode");
                return;
            }
            Err(e) => {
                panic!("cgroup discovery failed while selecting a v1 test: {}", e);
            }
        }
    };
}

#[cfg(test)]
pub mod tests {
    use std::fs;
    use std::process::{Child, Command, Stdio};

    /// Own synthetic discovery files for topology-based handle tests.
    #[cfg(feature = "fixtures")]
    pub(crate) struct TopologyFixture {
        pub(crate) topology: std::sync::Arc<crate::core::CgroupTopology>,
        root: std::path::PathBuf,
    }

    #[cfg(feature = "fixtures")]
    impl TopologyFixture {
        pub(crate) fn new(mountinfo: &[u8], membership: &[u8], controllers: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "cgroups-topology-fixture-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir_all(root.join("proc/self")).unwrap();
            fs::create_dir_all(root.join("cgroup")).unwrap();
            fs::create_dir_all(root.join("hugepages")).unwrap();
            fs::write(root.join("proc/self/mountinfo"), mountinfo).unwrap();
            fs::write(root.join("proc/self/cgroup"), membership).unwrap();
            fs::write(root.join("cgroup/cgroup.controllers"), controllers).unwrap();
            fs::write(root.join("cgroup/cgroup.subtree_control"), b"").unwrap();
            let paths = crate::core::HostPaths::new(root.join("proc"), root.join("hugepages"))
                .with_fixture_root(root.join("cgroup"));
            let topology = crate::core::discover(&paths).unwrap();
            Self { topology, root }
        }
    }

    #[cfg(feature = "fixtures")]
    impl Drop for TopologyFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(feature = "fixtures")]
    pub(crate) fn topology_fixture(
        version: crate::core::CgroupVersion,
        controllers: &str,
    ) -> TopologyFixture {
        match version {
            crate::core::CgroupVersion::V1 => TopologyFixture::new(
                b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
                b"1:memory:/\n",
                controllers,
            ),
            crate::core::CgroupVersion::V2 => TopologyFixture::new(
                b"47 44 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
                b"0::/\n",
                controllers,
            ),
        }
    }

    /// Start a mock subprocess that will sleep forever
    pub fn spawn_sleep_inf() -> Child {
        let child = Command::new("sleep")
            .arg("infinity")
            .spawn()
            .expect("Failed to start mock subprocess");
        child
    }

    pub fn spawn_yes() -> Child {
        let devnull = fs::File::create("/dev/null").expect("cannot open /dev/null");
        let child = Command::new("yes")
            .stdout(Stdio::from(devnull))
            .spawn()
            .expect("Failed to start mock subprocess");
        child
    }

    pub fn systemd_version() -> Option<String> {
        let output = Command::new("systemd").arg("--version").output().ok()?; // Return None if command execution fails
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
