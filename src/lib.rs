// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020-2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

#![doc = include_str!("../README.md")]

pub mod fs;
#[cfg(feature = "oci")]
pub mod manager;
#[cfg(feature = "oci")]
pub use manager::{FsManager, Manager, SystemdManager};
pub mod stats;
pub use stats::CgroupStats;
pub mod systemd;

pub mod discovery;
pub mod error;
pub mod model;

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
        match $crate::fs::hierarchies::is_cgroup2_unified_mode_with_paths(
            &$crate::discovery::HostPaths::default(),
        ) {
            Ok(true) => {} // unified v2 — proceed
            Ok(false) => {
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
        match $crate::fs::hierarchies::is_cgroup2_unified_mode_with_paths(
            &$crate::discovery::HostPaths::default(),
        ) {
            Ok(false) => {} // v1 or hybrid — proceed
            Ok(true) => {
                eprintln!("Skipping test in cgroups v2 mode");
                return;
            }
            Err(e) => {
                panic!("cgroup discovery failed while selecting a v1 test: {}", e);
            }
        }
    };
}

/// The maximum value for CPU shares in cgroups v1
pub const CPU_SHARES_V1_MAX: u64 = 262144;
/// The maximum value for CPU weight in cgroups v2
pub const CPU_WEIGHT_V2_MAX: u64 = 10000;

/// The current state of the control group
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FreezerState {
    /// The processes in the control group are _not_ frozen.
    Thawed,
    /// The processes in the control group are in the processes of being frozen.
    Freezing,
    /// The processes in the control group are frozen.
    Frozen,
}

/// A structure representing a `pid`. Currently implementations exist for `u64` and
/// `std::process::Child`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct CgroupPid {
    /// The process identifier
    pub pid: u64,
}

impl From<u64> for CgroupPid {
    fn from(u: u64) -> CgroupPid {
        CgroupPid { pid: u }
    }
}

impl From<&std::process::Child> for CgroupPid {
    fn from(u: &std::process::Child) -> CgroupPid {
        CgroupPid { pid: u.id() as u64 }
    }
}

#[cfg(test)]
pub mod tests {
    use std::fs;
    use std::process::{Child, Command, Stdio};

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
