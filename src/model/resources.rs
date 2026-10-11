// Copyright (c) 2026 Ant Group
// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Cgroup-native resource limit specifications.
//!
//! This module defines pure data structures for specifying resource limits
//! and updates directly in terms of Linux cgroup controllers, without
//! depending on the OCI (Open Container Initiative) runtime specification.

use std::collections::HashMap;

/// Tri-state update for cgroup resource limits.
///
/// Many cgroup files accept either a concrete numeric limit or the string
/// `"max"` (unlimited). `Update<T>` distinguishes:
/// - [`Update::Unchanged`]: do not touch the existing kernel limit.
/// - [`Update::Set`]: set the limit to a concrete value.
/// - [`Update::Max`]: reset the limit to maximum / unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Update<T> {
    /// Leave the current limit unchanged.
    #[default]
    Unchanged,
    /// Set the limit to the specified value.
    Set(T),
    /// Set the limit to maximum / unlimited.
    Max,
}

impl<T> Update<T> {
    /// Returns `true` if this update leaves the setting unchanged.
    pub fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged)
    }

    /// Returns a reference to the contained value, if this is [`Update::Set`].
    pub fn as_set(&self) -> Option<&T> {
        match self {
            Self::Set(v) => Some(v),
            _ => None,
        }
    }

    /// Convert to an `Option<T>`, mapping `Unchanged` and `Max` to `None`.
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Set(v) => Some(v),
            _ => None,
        }
    }
}

impl<T> From<Option<T>> for Update<T> {
    fn from(opt: Option<T>) -> Self {
        match opt {
            Some(v) => Self::Set(v),
            None => Self::Unchanged,
        }
    }
}

/// CPU controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CpuPatch {
    /// CPU shares (cgroup v1: [2..262144], default 1024; cgroup v2 weight: [1..10000], default 100).
    pub shares: Update<u64>,
    /// CFS bandwidth quota in microseconds (-1 or Max for unlimited).
    pub quota: Update<i64>,
    /// CFS bandwidth period in microseconds (default 100,000 us).
    pub period: Update<u64>,
    /// Realtime runtime in microseconds.
    pub realtime_runtime: Update<i64>,
    /// Realtime period in microseconds.
    pub realtime_period: Update<u64>,
}

/// Cpuset controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CpuSetPatch {
    /// List or range of CPUs to execute on (e.g. `"0-3,5"`).
    pub cpus: Update<String>,
    /// List or range of memory NUMA nodes to allocate memory from (e.g. `"0-1"`).
    pub mems: Update<String>,
}

/// Memory controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryPatch {
    /// Hard limit on memory in bytes.
    pub limit: Update<i64>,
    /// Soft limit on memory in bytes (v1: `soft_limit_in_bytes`, v2: `memory.low`).
    pub soft_limit: Update<i64>,
    /// Hierarchy-native swap limit in bytes.
    ///
    /// This is the combined memory+swap limit on cgroup v1
    /// (`memory.memsw.limit_in_bytes`), but swap alone on cgroup v2
    /// (`memory.swap.max`). OCI's combined-limit conversion is performed by
    /// the OCI adapter before a native patch reaches a backend.
    pub swap: Update<i64>,
    /// Kernel memory limit in bytes (cgroup v1).
    pub kernel: Update<i64>,
    /// Kernel TCP buffer memory limit in bytes (cgroup v1).
    pub kernel_tcp: Update<i64>,
    /// Memory swappiness value [0..100].
    pub swappiness: Update<u64>,
    /// Disable the OOM killer for this cgroup (cgroup v1 only).
    pub disable_oom_killer: Update<bool>,
}

/// PIDs (process number) controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PidsPatch {
    /// Maximum number of processes/threads in the cgroup.
    pub limit: Update<i64>,
}

/// Block I/O device weight specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDeviceWeight {
    pub major: u64,
    pub minor: u64,
    pub weight: Option<u16>,
    pub leaf_weight: Option<u16>,
}

/// Block I/O device throttle rate specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDeviceThrottle {
    pub major: u64,
    pub minor: u64,
    pub rate: u64,
}

/// Block I/O controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlkIoPatch {
    /// Global block I/O weight [10..1000].
    pub weight: Update<u16>,
    /// Weight used while competing with child cgroups (cgroup v1 CFQ only).
    pub leaf_weight: Update<u16>,
    /// Per-device block I/O weights.
    pub weight_device: Vec<BlockDeviceWeight>,
    /// Throttled read bytes per second per device.
    pub throttle_read_bps_device: Vec<BlockDeviceThrottle>,
    /// Throttled write bytes per second per device.
    pub throttle_write_bps_device: Vec<BlockDeviceThrottle>,
    /// Throttled read IO operations per second per device.
    pub throttle_read_iops_device: Vec<BlockDeviceThrottle>,
    /// Throttled write IO operations per second per device.
    pub throttle_write_iops_device: Vec<BlockDeviceThrottle>,
}

/// Hugepage limit specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HugePageLimit {
    /// Page size (e.g. `"2MB"`, `"1GB"`).
    pub page_size: String,
    /// Limit in bytes.
    pub limit: u64,
}

/// HugeTLB controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HugePagePatch {
    /// Hugepage limits by page size.
    pub limits: Vec<HugePageLimit>,
}

/// Device access rule.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceRule {
    /// Whether access is allowed.
    pub allow: bool,
    /// Device type: 'c' (char), 'b' (block), or 'a' (all).
    pub dev_type: Option<char>,
    /// Major device number.
    pub major: Option<i64>,
    /// Minor device number.
    pub minor: Option<i64>,
    /// Access permissions (e.g. "rwm").
    pub access: String,
}

/// Device controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DevicePatch {
    /// Device rules to apply.
    pub rules: Vec<DeviceRule>,
}

/// Network interface priority specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfacePriority {
    /// Network interface name.
    pub name: String,
    /// Priority level.
    pub priority: u64,
}

/// Network controller configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkPatch {
    /// Network class identifier (`net_cls.classid`).
    pub class_id: Update<u64>,
    /// Network interface priorities (`net_prio.ifpriomap`).
    pub priorities: Vec<InterfacePriority>,
}

/// Unified, cgroup-native resource configuration patch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourcePatch {
    /// CPU scheduling constraints.
    pub cpu: CpuPatch,
    /// CPU and NUMA node affinity constraints.
    pub cpuset: CpuSetPatch,
    /// Memory consumption limits.
    pub memory: MemoryPatch,
    /// Process/thread count limits.
    pub pids: PidsPatch,
    /// Block I/O bandwidth and weight constraints.
    pub blkio: BlkIoPatch,
    /// Hugepage memory allocation limits.
    pub hugepages: HugePagePatch,
    /// Network controller settings.
    pub network: NetworkPatch,
    /// Device controller rules.
    pub devices: DevicePatch,
    /// Additional custom key-value attributes for cgroupfs.
    pub custom_attributes: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_states() {
        let u: Update<i64> = Update::default();
        assert!(u.is_unchanged());
        assert_eq!(u.as_set(), None);
        assert_eq!(u.into_option(), None);

        let u: Update<i64> = Update::Set(42);
        assert!(!u.is_unchanged());
        assert_eq!(u.as_set(), Some(&42));
        assert_eq!(u.into_option(), Some(42));

        let u: Update<i64> = Update::Max;
        assert!(!u.is_unchanged());
        assert_eq!(u.as_set(), None);
        assert_eq!(u.into_option(), None);
    }

    #[test]
    fn test_resource_patch_default() {
        let patch = ResourcePatch::default();
        assert!(patch.cpu.shares.is_unchanged());
        assert!(patch.memory.limit.is_unchanged());
        assert!(patch.pids.limit.is_unchanged());
        assert!(patch.cpuset.cpus.is_unchanged());
        assert!(patch.blkio.weight.is_unchanged());
        assert!(patch.hugepages.limits.is_empty());
    }
}
