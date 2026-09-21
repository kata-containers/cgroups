// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

mod error;
use std::collections::HashMap;
use std::path::PathBuf;

pub use error::{Error, Result};
mod fs;
pub use fs::FsManager;
mod systemd;
pub use systemd::SystemdManager;
mod conv;

use oci_spec::runtime::LinuxResources;

use crate::core::CgroupMembership;
use crate::systemd::SLICE_SUFFIX;
use crate::{CgroupPid, CgroupStats, FreezerState};

/// Check if the cgroups path is a systemd cgroup.
pub fn is_systemd_cgroup(cgroups_path: &str) -> bool {
    let parts: Vec<&str> = cgroups_path.split(':').collect();
    parts.len() == 3 && parts[0].ends_with(SLICE_SUFFIX)
}

/// Manage cgroups designed for OCI containers.
pub trait Manager: Send + Sync {
    /// Add a process specified by its tgid.
    fn add_proc(&mut self, tgid: CgroupPid) -> Result<()>;

    /// Add a thread specified by its pid.
    fn add_thread(&mut self, pid: CgroupPid) -> Result<()>;

    /// Get the list of pids joint to the cgroups.
    fn pids(&self) -> Result<Vec<CgroupPid>>;

    /// Set the freezer cgroup to the specified state.
    fn freeze(&self, state: FreezerState) -> Result<()>;

    /// Remove the cgroups.
    fn destroy(&mut self) -> Result<()>;

    /// Set the resources to the cgroups.
    fn set(&mut self, resources: &LinuxResources) -> Result<()>;

    /// Get a cgroup path without converting its bytes to UTF-8.
    ///
    /// On v1, this returns the selected controller's process membership from
    /// the discovery snapshot, retaining its leading `/` and possible `..`
    /// components. It is not a mutation-safe path or the managed cgroup's
    /// filesystem path. On v2, this returns the unified filesystem mount
    /// joined with the managed base.
    ///
    /// # Arguments
    ///
    /// - `subsystem`: cgroup subsystem, for cgroup v1 the value should not
    ///   be empty, while for cgroup v2 the only valid value is `None`.
    fn cgroup_path(&self, subsystem: Option<&str>) -> Result<PathBuf>;

    /// Enable CPUs, topdown from root in cgroup hierarchy, this would be
    /// useful for CPU hotplug in the guest.
    ///
    /// The caller should update cgroup resources manually, in particular
    /// cpuset, after this, in order to use the new CPUs (or avoid using
    /// offline CPUs).
    ///
    /// # Arguments
    ///
    /// - `cpus`: online CPUs in the same format with `cat
    ///   /sys/devices/system/cpu/online`, e.g. "0-3,6-7".
    fn enable_cpus_topdown(&self, cpus: &str) -> Result<()>;

    /// Get cgroup stats.
    fn stats(&self) -> CgroupStats;

    /// Borrow the process membership records captured by discovery.
    ///
    /// Records retain their hierarchy IDs, controller groups, and original
    /// path bytes, including a leading `/` and possible namespace-relative
    /// `..`. These are observations, not validated mutation paths. This
    /// snapshot does not reflect later process migration.
    fn memberships(&self) -> &CgroupMembership;

    /// Build a mapping from observed v1 controllers to filesystem mount points.
    ///
    /// Each call derives an owned map from the topology without I/O. Duplicate
    /// controller mounts select the first match in mountinfo order, consistent
    /// with cgroup handles. A pure unified-v2 topology has no v1 controller
    /// entries; use `cgroup_path(None)` for its managed filesystem path.
    fn mounts(&self) -> HashMap<String, PathBuf>;

    /// Indicate whether the cgroup manager is using systemd.
    fn systemd(&self) -> bool;

    /// Indicate whether the cgroup manager is using cgroup v2.
    fn v2(&self) -> bool;
}

#[cfg(test)]
mod tests {
    pub const MEMORY_512M: i64 = 512 * 1024 * 1024; // 512 MiB
    pub const MEMORY_1G: i64 = 1024 * 1024 * 1024; // 1 GiB
    pub const MEMORY_2G: i64 = 2 * 1024 * 1024 * 1024; // 2 GiB
}
