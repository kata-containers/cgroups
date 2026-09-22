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
#[doc(hidden)]
#[macro_export]
macro_rules! skip_if_cgroups_v1 {
    () => {
        if !$crate::fs::hierarchies::is_cgroup2_unified_mode() {
            eprintln!("Skipping test in cgroups v1 mode");
            return;
        }
    };
}

/// Return early from a test that does not support a cgroup v2 hierarchy.
#[doc(hidden)]
#[macro_export]
macro_rules! skip_if_cgroups_v2 {
    () => {
        if $crate::fs::hierarchies::is_cgroup2_unified_mode() {
            eprintln!("Skipping test in cgroups v2 mode");
            return;
        }
    };
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
