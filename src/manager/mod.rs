// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

mod error;
use std::collections::HashMap;

pub use error::{Error, Result};
mod fs;
pub use fs::FsManager;
mod systemd;
pub use systemd::SystemdManager;
mod conv;

use oci_spec::runtime::LinuxResources;

pub use crate::model::{
    AttachDestination, BlkIoPatch, BlockDeviceThrottle, BlockDeviceWeight, CpuPatch, CpuSetPatch,
    DevicePatch, DeviceRule, HugePageLimit, HugePagePatch, InterfacePriority, MemoryPatch,
    NetworkPatch, PidsPatch, ResourcePatch, Update,
};
use crate::systemd::SLICE_SUFFIX;
use crate::{CgroupPid, CgroupStats, FreezerState};

/// Check if the cgroups path is a systemd cgroup.
pub fn is_systemd_cgroup(cgroups_path: &str) -> bool {
    let parts: Vec<&str> = cgroups_path.split(':').collect();
    parts.len() == 3 && parts[0].ends_with(SLICE_SUFFIX)
}

/// Manage cgroups designed for OCI containers.
pub trait Manager: Send + Sync {
    /// Add a process specified by its tgid using the default destination.
    fn add_proc(&mut self, tgid: CgroupPid) -> Result<()>;

    /// Add a process specified by its tgid to an explicit attachment destination.
    ///
    /// The default implementation forwards [`AttachDestination::ManagedCgroup`]
    /// to [`Manager::add_proc`] and returns [`Error::Unsupported`] for custom
    /// destinations, preserving source compatibility for third-party implementors.
    fn add_proc_to(&mut self, tgid: CgroupPid, destination: &AttachDestination) -> Result<()> {
        match destination {
            AttachDestination::ManagedCgroup => self.add_proc(tgid),
            _ => Err(Error::Unsupported(
                "custom attachment destination is not supported by this manager".to_string(),
            )),
        }
    }

    /// Add a thread specified by its pid using the default destination.
    fn add_thread(&mut self, pid: CgroupPid) -> Result<()>;

    /// Add a thread specified by its pid to an explicit attachment destination.
    ///
    /// The default implementation forwards [`AttachDestination::ManagedCgroup`]
    /// to [`Manager::add_thread`] and returns [`Error::Unsupported`] for custom
    /// destinations, preserving source compatibility for third-party implementors.
    fn add_thread_to(&mut self, pid: CgroupPid, destination: &AttachDestination) -> Result<()> {
        match destination {
            AttachDestination::ManagedCgroup => self.add_thread(pid),
            _ => Err(Error::Unsupported(
                "custom attachment destination is not supported by this manager".to_string(),
            )),
        }
    }

    /// Get the list of pids joint to the cgroups.
    fn pids(&self) -> Result<Vec<CgroupPid>>;

    /// Set the freezer cgroup to the specified state.
    fn freeze(&self, state: FreezerState) -> Result<()>;

    /// Remove the cgroups.
    fn destroy(&mut self) -> Result<()>;

    /// Set the resources to the cgroups using a cgroup-native [`ResourcePatch`].
    fn set_resources(&mut self, resources: &ResourcePatch) -> Result<()>;

    /// Set the resources to the cgroups using OCI [`LinuxResources`].
    ///
    /// This is an adapter method that translates OCI specification resources
    /// into a cgroup-native [`ResourcePatch`] before applying.
    fn set(&mut self, resources: &LinuxResources) -> Result<()> {
        let patch = conv::oci_to_resource_patch(resources, self.v2())?;
        self.set_resources(&patch)
    }

    /// Get the cgroup path.
    ///
    /// # Arguments
    ///
    /// - `subsystem`: cgroup subsystem, for cgroup v1 the value should not
    ///   be empty, while for cgroup v2 the only valid value is `None`.
    fn cgroup_path(&self, subsystem: Option<&str>) -> Result<String>;

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

    /// Get cgroup stats while preserving controller read failures.
    ///
    /// The default keeps existing third-party `Manager` implementations
    /// source-compatible. Built-in managers override it with fallible reads.
    fn try_stats(&self) -> Result<CgroupStats> {
        Ok(self.stats())
    }

    /// Get the mappings of subsystems to their relative path. The full
    /// path would be something like "{mountpoint}/{relative_path}". The
    /// mappings of mountpoints see "mounts()".
    fn paths(&self) -> &HashMap<String, String>;

    /// Get the mappings of subsystems to their mountpoints. The full
    /// path would be something like "{mountpoint}/{relative_path}". The
    /// mappings of relative paths see "paths()".
    fn mounts(&self) -> &HashMap<String, String>;

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
