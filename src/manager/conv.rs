// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use oci_spec::runtime::LinuxResources;

use crate::manager::error::{Error, Result};
use crate::model::resources::{
    BlockDeviceThrottle, BlockDeviceWeight, HugePageLimit, ResourcePatch, Update,
};
use crate::{CPU_SHARES_V1_MAX, CPU_WEIGHT_V2_MAX};

// Converts CPU shares, used by cgroup v1, to CPU weight, used by cgroup
// v2.
//
// Cgroup v1 CPU shares has a range of [2^1...2^18], i.e. [2...262144],
// and the default value is 1024.
//
// Cgroup v2 CPU weight has a range of [10^0...10^4], i.e. [1...10000],
// and the default value is 100.
pub(crate) fn cpu_shares_to_cgroup_v2(shares: u64) -> u64 {
    if shares == 0 {
        return 0;
    }
    if shares <= 2 {
        return 1;
    }
    if shares >= CPU_SHARES_V1_MAX {
        return CPU_WEIGHT_V2_MAX;
    }

    (((shares - 2) * 9999) / 262142) + 1
}

// ConvertMemorySwapToCgroupV2Value converts MemorySwap value from OCI spec
// for use by cgroup v2 drivers. A conversion is needed since
// Resources.MemorySwap is defined as memory+swap combined, while in cgroup
// v2 swap is a separate value.
pub(crate) fn memory_swap_to_cgroup_v2(memswap_limit: i64, mem_limit: i64) -> Result<i64> {
    // For compatibility with cgroup1 controller, set swap to unlimited in
    // case the memory is set to unlimited, and swap is not explicitly set,
    // treating the request as "set both memory and swap to unlimited".
    if mem_limit == -1 && memswap_limit == 0 {
        return Ok(-1);
    }

    // -1 is "max", 0 is "unset", so treat as is
    if memswap_limit == -1 || memswap_limit == 0 {
        return Ok(memswap_limit);
    }

    // Unlimited memory, so treat swap as is.
    if mem_limit == -1 {
        return Ok(memswap_limit);
    }

    // Unset or unknown memory, can't calculate swap.
    if mem_limit == 0 {
        return Err(Error::InvalidLinuxResource);
    }

    // Does not make sense to subtract a negative value.
    if mem_limit < 0 {
        return Err(Error::InvalidLinuxResource);
    }

    // Sanity check.
    if memswap_limit < mem_limit {
        return Err(Error::InvalidLinuxResource);
    }

    Ok(memswap_limit - mem_limit)
}

/// Convert an OCI [`LinuxResources`] specification into a cgroup-native
/// [`ResourcePatch`] for the selected hierarchy.
///
/// OCI defines `memory.swap` as a memory+swap combined limit, while cgroup v2
/// exposes swap alone in `memory.swap.max`.  That policy conversion belongs at
/// this boundary; native backends must apply the resulting patch literally.
pub fn oci_to_resource_patch(resources: &LinuxResources, v2: bool) -> Result<ResourcePatch> {
    let mut patch = ResourcePatch::default();

    if let Some(cpu) = resources.cpu() {
        if let Some(cpus) = cpu.cpus() {
            patch.cpuset.cpus = Update::Set(cpus.clone());
        }
        if let Some(mems) = cpu.mems() {
            patch.cpuset.mems = Update::Set(mems.clone());
        }
        if let Some(shares) = cpu.shares() {
            patch.cpu.shares = Update::Set(shares);
        }
        if let Some(quota) = cpu.quota() {
            patch.cpu.quota = if quota == -1 {
                Update::Max
            } else {
                Update::Set(quota)
            };
        }
        if let Some(period) = cpu.period() {
            patch.cpu.period = Update::Set(period);
        }
        if let Some(rt_runtime) = cpu.realtime_runtime() {
            patch.cpu.realtime_runtime = Update::Set(rt_runtime);
        }
        if let Some(rt_period) = cpu.realtime_period() {
            patch.cpu.realtime_period = Update::Set(rt_period);
        }
    }

    if let Some(memory) = resources.memory() {
        let memory_limit = memory.limit().unwrap_or(0);
        if let Some(limit) = memory.limit() {
            patch.memory.limit = match limit {
                -1 => Update::Max,
                // Preserve the legacy OCI contract in which zero meant
                // "unspecified". Native callers can still request Set(0).
                0 => Update::Unchanged,
                value => Update::Set(value),
            };
        }
        if let Some(reservation) = memory.reservation() {
            patch.memory.soft_limit = if reservation == -1 {
                Update::Max
            } else {
                Update::Set(reservation)
            };
        }
        if let Some(swap) = memory.swap() {
            let swap = if v2 {
                memory_swap_to_cgroup_v2(swap, memory_limit)?
            } else {
                swap
            };
            patch.memory.swap = match swap {
                -1 => Update::Max,
                0 => Update::Unchanged,
                value => Update::Set(value),
            };
        } else if v2 && memory_limit == -1 {
            // cgroup v2 exposes swap separately, so unlimited memory with no
            // OCI swap limit also means an unlimited memory.swap.max.
            patch.memory.swap = Update::Max;
        }
        if let Some(kernel) = memory.kernel() {
            patch.memory.kernel = if kernel == -1 {
                Update::Max
            } else {
                Update::Set(kernel)
            };
        }
        if let Some(kernel_tcp) = memory.kernel_tcp() {
            patch.memory.kernel_tcp = if kernel_tcp == -1 {
                Update::Max
            } else {
                Update::Set(kernel_tcp)
            };
        }
        if let Some(swappiness) = memory.swappiness() {
            patch.memory.swappiness = Update::Set(swappiness);
        }
        if let Some(disable_oom_killer) = memory.disable_oom_killer() {
            patch.memory.disable_oom_killer = Update::Set(disable_oom_killer);
        }
    }

    if let Some(pids) = resources.pids() {
        patch.pids.limit = if pids.limit() > 0 {
            Update::Set(pids.limit())
        } else {
            Update::Max
        };
    }

    if let Some(blkio) = resources.block_io() {
        if let Some(weight) = blkio.weight() {
            patch.blkio.weight = Update::Set(weight);
        }
        if let Some(leaf_weight) = blkio.leaf_weight() {
            patch.blkio.leaf_weight = Update::Set(leaf_weight);
        }
        if let Some(weights) = blkio.weight_device() {
            patch.blkio.weight_device = weights
                .iter()
                .map(|w| BlockDeviceWeight {
                    major: w.major() as u64,
                    minor: w.minor() as u64,
                    weight: w.weight(),
                    leaf_weight: w.leaf_weight(),
                })
                .collect();
        }
        if let Some(throttles) = blkio.throttle_read_bps_device() {
            patch.blkio.throttle_read_bps_device = throttles
                .iter()
                .map(|t| BlockDeviceThrottle {
                    major: t.major() as u64,
                    minor: t.minor() as u64,
                    rate: t.rate(),
                })
                .collect();
        }
        if let Some(throttles) = blkio.throttle_write_bps_device() {
            patch.blkio.throttle_write_bps_device = throttles
                .iter()
                .map(|t| BlockDeviceThrottle {
                    major: t.major() as u64,
                    minor: t.minor() as u64,
                    rate: t.rate(),
                })
                .collect();
        }
        if let Some(throttles) = blkio.throttle_read_iops_device() {
            patch.blkio.throttle_read_iops_device = throttles
                .iter()
                .map(|t| BlockDeviceThrottle {
                    major: t.major() as u64,
                    minor: t.minor() as u64,
                    rate: t.rate(),
                })
                .collect();
        }
        if let Some(throttles) = blkio.throttle_write_iops_device() {
            patch.blkio.throttle_write_iops_device = throttles
                .iter()
                .map(|t| BlockDeviceThrottle {
                    major: t.major() as u64,
                    minor: t.minor() as u64,
                    rate: t.rate(),
                })
                .collect();
        }
    }

    if let Some(hugepage_limits) = resources.hugepage_limits() {
        patch.hugepages.limits = hugepage_limits
            .iter()
            .map(|h| HugePageLimit {
                page_size: h.page_size().clone(),
                limit: h.limit() as u64,
            })
            .collect();
    }

    if let Some(network) = resources.network() {
        if let Some(class_id) = network.class_id() {
            patch.network.class_id = Update::Set(class_id as u64);
        }
        if let Some(priorities) = network.priorities() {
            patch.network.priorities = priorities
                .iter()
                .map(|p| crate::model::resources::InterfacePriority {
                    name: p.name().clone(),
                    priority: p.priority() as u64,
                })
                .collect();
        }
    }

    if let Some(devices) = resources.devices() {
        patch.devices.rules = devices
            .iter()
            .map(|d| crate::model::resources::DeviceRule {
                allow: d.allow(),
                dev_type: d.typ().and_then(|t| t.as_str().chars().next()),
                major: d.major(),
                minor: d.minor(),
                access: d.access().clone().unwrap_or_default(),
            })
            .collect();
    }

    if let Some(unified) = resources.unified() {
        patch.custom_attributes = unified.clone();
    }

    Ok(patch)
}

/// Convert OCI resources for the direct cgroupfs backend.
///
/// On cgroup v1, the historical cgroupfs contract treats a missing or zero
/// OCI `memory.swap` as unspecified. When memory itself becomes unlimited the
/// combined `memory.memsw.limit_in_bytes` must therefore become unlimited as
/// well; otherwise the kernel can reject the memory update while the old
/// finite memsw ceiling remains in force. This is a cgroupfs compatibility
/// rule, not a hierarchy-wide rule: systemd v1 cannot express a swap update.
pub(crate) fn oci_to_cgroupfs_resource_patch(
    resources: &LinuxResources,
    v2: bool,
) -> Result<ResourcePatch> {
    let mut patch = oci_to_resource_patch(resources, v2)?;

    if !v2 {
        if let Some(memory) = resources.memory() {
            if memory.limit() == Some(-1) && memory.swap().unwrap_or(0) == 0 {
                patch.memory.swap = Update::Max;
            }
        }
    }

    Ok(patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_shares_to_cgroup_v2() {
        assert_eq!(cpu_shares_to_cgroup_v2(0), 0);
        assert_eq!(cpu_shares_to_cgroup_v2(1), 1);
        assert_eq!(cpu_shares_to_cgroup_v2(2), 1);
        assert_eq!(cpu_shares_to_cgroup_v2(100), 4);
        assert_eq!(
            cpu_shares_to_cgroup_v2(CPU_SHARES_V1_MAX),
            CPU_WEIGHT_V2_MAX
        );
        assert_eq!(
            cpu_shares_to_cgroup_v2(CPU_SHARES_V1_MAX - 1),
            CPU_WEIGHT_V2_MAX - 1
        );
        assert_eq!(cpu_shares_to_cgroup_v2(u64::MAX), CPU_WEIGHT_V2_MAX);
    }

    #[test]
    fn test_cpu_shares_to_cgroup_v2_table() {
        // v1 CPU shares -> v2 CPU weight conversion table covering boundary
        // and saturation cases: the documented v1 range begins at 2, where 2 -> 1
        // is the expected lower-bound mapping (with values <= 2 mapping to 1,
        // and 0 mapping to 0), and values at or above CPU_SHARES_V1_MAX
        // deliberately saturate at CPU_WEIGHT_V2_MAX.
        const CASES: &[(u64, u64)] = &[
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 1),
            (128, 5),
            (1024, 39),
            (4096, 157),
            (65536, 2500),
            (262144, 10000),
            (300000, 10000),
        ];
        for &(shares, expected) in CASES {
            assert_eq!(
                cpu_shares_to_cgroup_v2(shares),
                expected,
                "shares={}",
                shares
            );
        }
    }

    #[test]
    fn test_memory_swap_to_cgroup_v2() {
        // memory no limit and swap is 0, treat it as no limit
        assert_eq!(memory_swap_to_cgroup_v2(0, -1).unwrap(), -1);
        // -1 is "max", 0 is "unset", so treat as is
        assert_eq!(memory_swap_to_cgroup_v2(-1, 0).unwrap(), -1);
        assert_eq!(memory_swap_to_cgroup_v2(0, 0).unwrap(), 0);

        // Now swap cannot be 0 or -1

        // Unlimited memory, so treat swap as is.
        assert_eq!(memory_swap_to_cgroup_v2(100, -1).unwrap(), 100);
        // Unset or unknown memory, can't calculate swap.
        assert!(memory_swap_to_cgroup_v2(100, 0).is_err());
        // Does not make sense to subtract a negative value.
        assert!(memory_swap_to_cgroup_v2(100, -2).is_err());
        // Swap + mem < mem
        assert!(memory_swap_to_cgroup_v2(50, 100).is_err());
        // Real swap
        assert_eq!(memory_swap_to_cgroup_v2(200, 100).unwrap(), 100);
    }

    #[test]
    fn test_oci_to_resource_patch() {
        use oci_spec::runtime::{
            LinuxBlockIoBuilder, LinuxCpuBuilder, LinuxMemoryBuilder, LinuxResourcesBuilder,
        };

        let cpu = LinuxCpuBuilder::default()
            .shares(2048u64)
            .cpus("0-3".to_string())
            .build()
            .unwrap();

        let memory = LinuxMemoryBuilder::default()
            .limit(1024 * 1024 * 1024i64)
            .swap(2 * 1024 * 1024 * 1024i64)
            .build()
            .unwrap();

        let blkio = LinuxBlockIoBuilder::default()
            .leaf_weight(300u16)
            .build()
            .unwrap();

        let oci = LinuxResourcesBuilder::default()
            .cpu(cpu)
            .memory(memory)
            .block_io(blkio)
            .build()
            .unwrap();

        let patch = oci_to_resource_patch(&oci, true).unwrap();
        assert_eq!(patch.cpu.shares, Update::Set(2048));
        assert_eq!(patch.cpuset.cpus, Update::Set("0-3".to_string()));
        assert_eq!(patch.memory.limit, Update::Set(1024 * 1024 * 1024));
        assert_eq!(patch.memory.swap, Update::Set(1024 * 1024 * 1024));
        assert_eq!(patch.blkio.leaf_weight, Update::Set(300));
        assert!(patch.pids.limit.is_unchanged());
    }

    #[test]
    fn test_unlimited_memory_swap_policy_is_backend_specific() {
        use oci_spec::runtime::{LinuxMemoryBuilder, LinuxResourcesBuilder};

        for swap in [None, Some(0)] {
            let mut memory = LinuxMemoryBuilder::default().limit(-1i64);
            if let Some(swap) = swap {
                memory = memory.swap(swap);
            }
            let resources = LinuxResourcesBuilder::default()
                .memory(memory.build().unwrap())
                .build()
                .unwrap();

            let systemd_v1 = oci_to_resource_patch(&resources, false).unwrap();
            assert_eq!(systemd_v1.memory.limit, Update::Max);
            assert_eq!(systemd_v1.memory.swap, Update::Unchanged);

            let cgroupfs_v1 = oci_to_cgroupfs_resource_patch(&resources, false).unwrap();
            assert_eq!(cgroupfs_v1.memory.limit, Update::Max);
            assert_eq!(cgroupfs_v1.memory.swap, Update::Max);

            let v2 = oci_to_resource_patch(&resources, true).unwrap();
            assert_eq!(v2.memory.limit, Update::Max);
            assert_eq!(v2.memory.swap, Update::Max);
        }
    }
}
