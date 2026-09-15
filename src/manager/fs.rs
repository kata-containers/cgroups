// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use oci_spec::runtime::{
    LinuxBlockIo, LinuxCpu, LinuxDeviceCgroup, LinuxHugepageLimit, LinuxMemory, LinuxNetwork,
    LinuxPids, LinuxResources,
};

use crate::discovery::membership::Membership;
use crate::discovery::topology::{discover, CgroupTopology, HostPaths};
use crate::fs::blkio::{BlkIoController, BlkIoData, IoService, IoStat};
use crate::fs::cpu::CpuController;
use crate::fs::cpuacct::CpuAcctController;
use crate::fs::cpuset::CpuSetController;
use crate::fs::devices::{DevicePermissions, DeviceType, DevicesController};
use crate::fs::error::{Error as FsError, ErrorKind as FsErrorKind, Result as FsResult};
use crate::fs::freezer::FreezerController;
use crate::fs::hugetlb::HugeTlbController;
use crate::fs::memory::MemController;
use crate::fs::net_cls::NetClsController;
use crate::fs::net_prio::NetPrioController;
use crate::fs::pid::PidController;
use crate::fs::{hierarchies, Cgroup, ControllIdentifier, Controller, MaxValue, Subsystem};
use crate::manager::error::Error;
use crate::manager::{conv, Manager, Result};
use crate::model::CgroupPath;
use crate::stats::{
    BlkioCgroupStats, BlkioStat, CpuAcctStats, CpuCgroupStats, CpuThrottlingStats,
    HugeTlbCgroupStats, HugeTlbStat, MemoryCgroupStats, MemoryStats, PidsCgroupStats,
};
use crate::{CgroupPid, CgroupStats, FreezerState};

/// FsManager manages cgroups using the cgroup filesystem (cgroupfs).
///
/// This manager deals with `LinuxResources` conformed to the OCI runtime
/// specification, so that it allows users not to do type conversions.
#[derive(Debug, Clone)]
pub struct FsManager {
    /// Cgroup subsystem paths read from `/proc/self/cgroup`
    /// - cgroup v1: <subsystem> -> <path>
    /// - cgroup v2: "" -> <path>
    paths: HashMap<String, String>,
    /// Cgroup mountpoints read from `/proc/self/mountinfo`.
    mounts: HashMap<String, String>,
    /// The discovered host topology, shared with the managed cgroup and
    /// every clone of this manager.
    topology: Arc<CgroupTopology>,
    /// Base path of the cgroup filesystem in validated relative form;
    /// the complete path would be:
    /// - cgroup v1: "<cgroupfs_root>/<subsystem>/<base>"
    /// - cgroup v2: "<cgroupfs_root>/<base>"
    base: CgroupPath,
    /// Cgroup managed by this manager.
    cgroup: Cgroup,
}

impl FsManager {
    /// Check if the cgroup exists or not.
    pub fn exists(&self) -> bool {
        self.cgroup.exists()
    }

    /// Create an instance of FsManager. The cgroups won't be created until
    /// `apply()` is called.
    ///
    /// The base is validated through [`CgroupPath`]: an absolute,
    /// escaping, or otherwise invalid base is rejected with a
    /// [`CoreError`](crate::error::CoreError) instead of being silently
    /// mangled. Host discovery runs exactly once and its topology is
    /// shared by the manager and the managed cgroup.
    pub fn new(base: &str) -> Result<Self> {
        Self::with_host_paths(base, &HostPaths::default())
    }

    /// Create an instance of FsManager with explicit [`HostPaths`].
    pub fn with_host_paths(base: &str, host_paths: &HostPaths) -> Result<Self> {
        let topology = discover(host_paths)?;
        Self::with_topology(base, topology)
    }

    /// Create an instance of FsManager with an already-discovered [`CgroupTopology`].
    pub fn with_topology(base: &str, topology: Arc<CgroupTopology>) -> Result<Self> {
        let base = crate::fs::cgroup::parse_cgroup_path(base)?;
        let paths = membership_to_subsystem_paths(&topology.membership);
        let mounts = controller_mounts(&topology, &paths);
        let cgroup = Cgroup::load_validated_with_topology(topology.clone(), base.clone());

        Ok(Self {
            paths,
            mounts,
            topology,
            base,
            cgroup,
        })
    }

    /// Return the topology snapshot held by this manager.
    pub fn topology(&self) -> &Arc<CgroupTopology> {
        &self.topology
    }
}

impl FsManager {
    /// Create the cgroups if they are not created yet.
    pub(crate) fn create_cgroups(&mut self) -> Result<()> {
        if self.exists() {
            return Ok(());
        }
        self.cgroup.create()?;
        Ok(())
    }

    /// Get the subcgroup path, which is useful for Docker-in-Docker (DinD)
    /// with cgroup v2, see [1].
    ///
    /// 1: https://github.com/kata-containers/kata-containers/issues/10733
    pub fn subcgroup(&self) -> &str {
        // Check if we're in a Docker-in-Docker setup by verifying:
        // 1. We're using cgroups v2 (which restricts direct process control)
        // 2. An "init" subdirectory exists (used by DinD for process
        //    delegation)
        let init_exists = self
            .topology
            .cgroupfs_root
            .join(self.base.as_path())
            .join("init")
            .exists();
        let is_dind = self.v2() && init_exists;

        if is_dind {
            "/init/"
        } else {
            "/"
        }
    }

    fn controller<'a, T>(&'a self) -> FsResult<&'a T>
    where
        &'a T: From<&'a Subsystem>,
        T: Controller + ControllIdentifier,
    {
        let controller: &T = self
            .cgroup
            .controller_of()
            .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))?;

        Ok(controller)
    }

    fn has_controller<'a, T>(&'a self) -> bool
    where
        &'a T: From<&'a Subsystem>,
        T: Controller + ControllIdentifier + 'a,
    {
        self.cgroup.controller_of::<T>().is_some()
    }

    fn set_cpuset(&self, linux_cpu: &LinuxCpu) -> Result<()> {
        let controller: &CpuSetController = self.controller()?;

        if let Some(cpus) = linux_cpu.cpus() {
            controller.set_cpus(cpus)?;
        }

        if let Some(mems) = linux_cpu.mems() {
            controller.set_mems(mems)?;
        }

        Ok(())
    }

    fn set_cpu(&self, linux_cpu: &LinuxCpu) -> Result<()> {
        let controller: &CpuController = self.controller()?;

        if let Some(shares) = linux_cpu.shares() {
            let shares = if self.v2() {
                conv::cpu_shares_to_cgroup_v2(shares)
            } else {
                shares
            };
            if shares != 0 {
                controller.set_shares(shares)?;
            }
        }

        if let Some(quota) = linux_cpu.quota() {
            controller.set_cfs_quota(quota)?;
        }

        if let Some(period) = linux_cpu.period() {
            controller.set_cfs_period(period)?;
        }

        if let Some(rt_runtime) = linux_cpu.realtime_runtime() {
            controller.set_rt_runtime(rt_runtime)?;
        }

        if let Some(rt_period) = linux_cpu.realtime_period() {
            controller.set_rt_period_us(rt_period)?;
        }

        Ok(())
    }

    fn set_mem_and_memswap_v1(&self, limit: i64, mut swap_limit: i64) -> Result<()> {
        let controller: &MemController = self.controller()?;

        // If the memory update is set to -1 and the swap is not set
        // explicitly, we should also set swap to -1, it means
        // unlimited memory.
        if limit == -1 && swap_limit == 0 {
            swap_limit = -1;
        }

        if limit != 0 && swap_limit != 0 {
            let memory = controller.try_memory_stat().map_err(Error::Cgroupfs)?;
            let limit_actual = memory.limit_in_bytes;

            // When update memory limit, we should adapt the write sequence
            // for memory and swap memory, so it won't fail because the new
            // value and the old value don't fit kernel's validation.
            if swap_limit == -1 || limit_actual < swap_limit {
                controller.set_memswap_limit(swap_limit)?;
                controller.set_limit(limit)?;

                return Ok(());
            }
        }

        if limit != 0 {
            controller.set_limit(limit)?;
        }
        if swap_limit != 0 {
            controller.set_memswap_limit(swap_limit)?;
        }

        Ok(())
    }

    fn set_memory_v1(&self, linux_memory: &LinuxMemory) -> Result<()> {
        let controller: &MemController = self.controller()?;

        let mem_limit = linux_memory.limit().unwrap_or(0);
        let memswap_limit = linux_memory.swap().unwrap_or(0);

        self.set_mem_and_memswap_v1(mem_limit, memswap_limit)?;

        if let Some(reservation) = linux_memory.reservation() {
            controller.set_soft_limit(reservation)?;
        }

        if linux_memory.disable_oom_killer().unwrap_or_default() {
            controller.disable_oom_killer()?;
        }

        if let Some(swappiness) = linux_memory.swappiness() {
            if swappiness <= 100 {
                controller.set_swappiness(swappiness)?;
            } else {
                return Err(Error::InvalidLinuxResource);
            };
        }

        Ok(())
    }

    fn set_memory_v2(&self, linux_memory: &LinuxMemory) -> Result<()> {
        let controller: &MemController = self.controller()?;

        if linux_memory.reservation().is_none()
            && linux_memory.limit().is_none()
            && linux_memory.swap().is_none()
        {
            return Ok(());
        }

        let mem_limit = linux_memory.limit().unwrap_or(0);
        let memswap_limit = linux_memory.swap().unwrap_or(0);

        // Check memory usage
        if mem_limit <= 0 && memswap_limit <= 0 {
            return Ok(());
        }

        let memory_stat = controller.try_memory_stat().map_err(Error::Cgroupfs)?;
        let usage_actual = memory_stat.usage_in_bytes;

        // Rejecting: memory+swap limit <= usage
        if memswap_limit > 0 && memswap_limit as u64 <= usage_actual {
            return Err(Error::InvalidLinuxResource);
        }

        // Rejecting: memory limit <= usage
        if mem_limit > 0 && mem_limit as u64 <= usage_actual {
            return Err(Error::InvalidLinuxResource);
        }

        let swap_limit = conv::memory_swap_to_cgroup_v2(memswap_limit, mem_limit)?;
        controller.set_memswap_limit(swap_limit)?;

        if mem_limit != 0 {
            controller.set_limit(mem_limit)?;
        }

        if let Some(reservation) = linux_memory.reservation() {
            controller.set_soft_limit(reservation)?;
        }

        Ok(())
    }

    /// Set memory resources.
    ///
    /// Ignore kernel memory and kernel memory TCP, as runc does, see [1].
    ///
    /// 1: https://github.com/opencontainers/cgroups/blob/d36d371fe756a30d2e21d83c6b42e86af77bf4a2/fs/memory.go#L36
    fn set_memory(&self, linux_memory: &LinuxMemory) -> Result<()> {
        if self.v2() {
            self.set_memory_v2(linux_memory)?;
        } else {
            self.set_memory_v1(linux_memory)?;
        }

        Ok(())
    }

    fn set_pids(&self, pids: &LinuxPids) -> Result<()> {
        let controller: &PidController = self.controller()?;
        let value = if pids.limit() > 0 {
            MaxValue::Value(pids.limit())
        } else {
            MaxValue::Max
        };
        controller.set_pid_max(value)?;

        Ok(())
    }

    fn set_blkio(&self, blkio: &LinuxBlockIo) -> Result<()> {
        let controller: &BlkIoController = self.controller()?;

        if let Some(weight) = blkio.weight() {
            controller.set_weight(weight as u64)?;
        }

        if let Some(leaf_weight) = blkio.leaf_weight() {
            controller.set_leaf_weight(leaf_weight as u64)?;
        }

        if let Some(devices) = blkio.weight_device() {
            for device in devices.iter() {
                let major = device.major() as u64;
                let minor = device.minor() as u64;
                if let Some(weight) = device.weight() {
                    controller.set_weight_for_device(major, minor, weight as u64)?;
                }
                if let Some(leaf_weight) = device.leaf_weight() {
                    controller.set_leaf_weight_for_device(major, minor, leaf_weight as u64)?;
                }
            }
        }

        if let Some(devices) = blkio.throttle_read_bps_device() {
            for device in devices.iter() {
                let major = device.major() as u64;
                let minor = device.minor() as u64;
                let rate = device.rate();
                controller.throttle_read_bps_for_device(major, minor, rate)?;
            }
        }

        if let Some(devices) = blkio.throttle_write_bps_device() {
            for device in devices.iter() {
                let major = device.major() as u64;
                let minor = device.minor() as u64;
                let rate = device.rate();
                controller.throttle_write_bps_for_device(major, minor, rate)?;
            }
        }

        if let Some(devices) = blkio.throttle_read_iops_device() {
            for device in devices.iter() {
                let major = device.major() as u64;
                let minor = device.minor() as u64;
                let rate = device.rate();
                controller.throttle_read_iops_for_device(major, minor, rate)?;
            }
        }

        if let Some(devices) = blkio.throttle_write_iops_device() {
            for device in devices.iter() {
                let major = device.major() as u64;
                let minor = device.minor() as u64;
                let rate = device.rate();
                controller.throttle_write_iops_for_device(major, minor, rate)?;
            }
        }

        Ok(())
    }

    fn set_hugepages(&self, hugepage_limits: &[LinuxHugepageLimit]) -> Result<()> {
        let controller: &HugeTlbController = self.controller()?;

        for limit in hugepage_limits.iter() {
            // ignore not supported page size
            if !controller.size_supported(limit.page_size()) {
                continue;
            }
            let page_size = limit.page_size();
            let limit = limit.limit() as u64;
            controller.set_limit_in_bytes(page_size, limit)?;
        }

        Ok(())
    }

    fn set_network(&self, network: &LinuxNetwork) -> Result<()> {
        if let Some(class_id) = network.class_id() {
            let controller: &NetClsController = self.controller()?;
            controller.set_class(class_id as u64)?;
        }

        if let Some(priorities) = network.priorities() {
            let controller: &NetPrioController = self.controller()?;
            for priority in priorities.iter() {
                let eif = priority.name();
                let prio = priority.priority() as u64;
                controller.set_if_prio(eif, prio)?;
            }
        }

        Ok(())
    }

    fn set_devices(&self, devices: &[LinuxDeviceCgroup]) -> Result<()> {
        let controller: &DevicesController = self.controller()?;

        for device in devices.iter() {
            let devtype =
                DeviceType::from_char(device.typ().unwrap_or_default().as_str().chars().next())
                    .ok_or(Error::InvalidLinuxResource)?;

            let perm = device
                .access()
                .as_ref()
                .unwrap_or(&String::new())
                .chars()
                .filter_map(|perm| match perm {
                    'r' => Some(DevicePermissions::Read),
                    'w' => Some(DevicePermissions::Write),
                    'm' => Some(DevicePermissions::MkNod),
                    _ => None,
                })
                .collect::<Vec<_>>();

            let major = device.major().unwrap_or(0);
            let minor = device.minor().unwrap_or(0);

            if device.allow() {
                controller.allow_device(devtype, major, minor, &perm)?;
            } else {
                controller.deny_device(devtype, major, minor, &perm)?;
            }
        }

        Ok(())
    }

    /// Set the controller topdown from root in cgroup hierarchy. The `f`
    /// is going to be applied to:
    /// -> root [not included]
    ///   -> root's child
    ///     -> ...
    ///       -> self.cgroup's parent
    ///         -> self.cgroup [not included]
    ///
    /// Please see `enable_cpus_topdown()` for more details.
    ///
    /// Please note that `self.cgroup` is not included. If you really want
    /// that, you should do it manually.
    fn set_controller_topdown<T, F>(&self, f: F) -> Result<()>
    where
        for<'a> &'a T: From<&'a Subsystem>,
        T: Controller + ControllIdentifier,
        for<'a> F: Fn(&'a T) -> Result<()>,
    {
        let root = hierarchies::auto_with_topology(self.topology.clone()).root_control_group();
        let controller: &T = root
            .controller_of()
            .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))?;
        let root_path = Path::new(controller.path());

        let controller: &T = self.controller()?;
        let path = Path::new(controller.path());

        // Push path's ancestors onto a stack, so the stack looks like:
        // path's parent, path's grandparent, ..., root
        let mut path_stack = vec![];
        for parent in path.ancestors() {
            if parent == root_path {
                break;
            }
            path_stack.push(parent);
        }

        // Pop from the stack
        while let Some(p) = path_stack.pop() {
            let relative_path = p
                .strip_prefix(root_path)
                .map_err(|e| FsError::with_cause(FsErrorKind::InvalidPath, e))?;
            let cgroup = Cgroup::new(
                hierarchies::auto_with_topology(self.topology.clone()),
                relative_path,
            )?;
            let controller: &T = cgroup
                .controller_of()
                .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))?;
            f(controller)?;
        }

        Ok(())
    }

    fn cpu_acct_stats_from(cpu_acct: &crate::fs::cpuacct::CpuAcct) -> CpuAcctStats {
        let user_usage = parse_value_from_tuples(&cpu_acct.stat, "user").unwrap_or_default();
        let system_usage = parse_value_from_tuples(&cpu_acct.stat, "system").unwrap_or_default();
        let usage_percpu = cpu_acct
            .usage_percpu
            .lines()
            .filter_map(|line| line.parse::<u64>().ok())
            .collect();

        CpuAcctStats {
            user_usage,
            system_usage,
            total_usage: cpu_acct.usage,
            usage_percpu,
        }
    }

    #[allow(deprecated)]
    fn cpu_acct_stats(&self) -> Result<CpuAcctStats> {
        let controller: &CpuAcctController = self.controller()?;
        Ok(Self::cpu_acct_stats_from(&controller.cpuacct()))
    }

    fn try_cpu_acct_stats(&self) -> Result<CpuAcctStats> {
        let controller: &CpuAcctController = self.controller()?;
        let cpu_acct = controller.try_cpuacct().map_err(Error::Cgroupfs)?;
        Ok(Self::cpu_acct_stats_from(&cpu_acct))
    }

    #[allow(deprecated)]
    fn cpu_throttling_stats(&self) -> Result<CpuThrottlingStats> {
        let controller: &CpuController = self.controller()?;
        Ok(Self::cpu_throttling_stats_from(&controller.cpu().stat))
    }

    fn cpu_throttling_stats_from(stats: &str) -> CpuThrottlingStats {
        let periods = parse_value_from_tuples(stats, "nr_periods").unwrap_or_default();
        let throttled_periods = parse_value_from_tuples(stats, "nr_throttled").unwrap_or_default();
        let throttled_time = parse_value_from_tuples(stats, "throttled_time").unwrap_or_default();

        CpuThrottlingStats {
            periods,
            throttled_periods,
            throttled_time,
        }
    }

    fn try_cpu_throttling_stats(&self) -> Result<CpuThrottlingStats> {
        let controller: &CpuController = self.controller()?;
        let cpu = controller.try_cpu().map_err(Error::Cgroupfs)?;
        Ok(Self::cpu_throttling_stats_from(&cpu.stat))
    }

    fn cpu_cgroup_stats(&self) -> CpuCgroupStats {
        CpuCgroupStats {
            cpu_acct: self.cpu_acct_stats().ok(),
            cpu_throttling: self.cpu_throttling_stats().ok(),
        }
    }

    fn try_cpu_cgroup_stats(&self) -> Result<CpuCgroupStats> {
        Ok(CpuCgroupStats {
            cpu_acct: if self.has_controller::<CpuAcctController>() {
                Some(self.try_cpu_acct_stats()?)
            } else {
                None
            },
            cpu_throttling: if self.has_controller::<CpuController>() {
                Some(self.try_cpu_throttling_stats()?)
            } else {
                None
            },
        })
    }

    fn memory_stats_from(usage: u64, max_usage: u64, limit: i64, fail_cnt: u64) -> MemoryStats {
        MemoryStats {
            usage,
            max_usage,
            limit,
            fail_cnt,
        }
    }

    #[allow(deprecated)]
    fn memory_stats(&self) -> Result<MemoryStats> {
        let controller: &MemController = self.controller()?;
        let memory_stats = controller.memory_stat();

        Ok(Self::memory_stats_from(
            memory_stats.usage_in_bytes,
            memory_stats.max_usage_in_bytes,
            memory_stats.limit_in_bytes,
            memory_stats.fail_cnt,
        ))
    }

    #[allow(deprecated)]
    fn memory_swap_stats(&self) -> Result<MemoryStats> {
        let controller: &MemController = self.controller()?;
        let memory_swap_stats = controller.memswap();

        Ok(Self::memory_stats_from(
            memory_swap_stats.usage_in_bytes,
            memory_swap_stats.max_usage_in_bytes,
            memory_swap_stats.limit_in_bytes,
            memory_swap_stats.fail_cnt,
        ))
    }

    #[allow(deprecated)]
    fn kernel_memory_stats(&self) -> Result<MemoryStats> {
        let controller: &MemController = self.controller()?;
        let kmem_stats = controller.kmem_stat();

        Ok(Self::memory_stats_from(
            kmem_stats.usage_in_bytes,
            kmem_stats.max_usage_in_bytes,
            kmem_stats.limit_in_bytes,
            kmem_stats.fail_cnt,
        ))
    }

    fn populate_memory_details(
        memory: &mut MemoryCgroupStats,
        memstats: &crate::fs::memory::Memory,
    ) {
        memory.use_hierarchy = memstats.use_hierarchy == 1;
        memory.cache = memstats.stat.cache;
        memory.rss = memstats.stat.rss;
        memory.rss_huge = memstats.stat.rss_huge;
        memory.shmem = memstats.stat.shmem;
        memory.mapped_file = memstats.stat.mapped_file;
        memory.dirty = memstats.stat.dirty;
        memory.writeback = memstats.stat.writeback;
        memory.swap = memstats.stat.swap;
        memory.pgpgin = memstats.stat.pgpgin;
        memory.pgpgout = memstats.stat.pgpgout;
        memory.pgfault = memstats.stat.pgfault;
        memory.pgmajfault = memstats.stat.pgmajfault;
        memory.inactive_anon = memstats.stat.inactive_anon;
        memory.active_anon = memstats.stat.active_anon;
        memory.inactive_file = memstats.stat.inactive_file;
        memory.active_file = memstats.stat.active_file;
        memory.unevictable = memstats.stat.unevictable;
        memory.hierarchical_memory_limit = memstats.stat.hierarchical_memory_limit;
        memory.hierarchical_memsw_limit = memstats.stat.hierarchical_memsw_limit;
        memory.total_cache = memstats.stat.total_cache;
        memory.total_rss = memstats.stat.total_rss;
        memory.total_rss_huge = memstats.stat.total_rss_huge;
        memory.total_shmem = memstats.stat.total_shmem;
        memory.total_mapped_file = memstats.stat.total_mapped_file;
        memory.total_dirty = memstats.stat.total_dirty;
        memory.total_writeback = memstats.stat.total_writeback;
        memory.total_swap = memstats.stat.total_swap;
        memory.total_pgpgin = memstats.stat.total_pgpgin;
        memory.total_pgpgout = memstats.stat.total_pgpgout;
        memory.total_pgfault = memstats.stat.total_pgfault;
        memory.total_pgmajfault = memstats.stat.total_pgmajfault;
        memory.total_inactive_anon = memstats.stat.total_inactive_anon;
        memory.total_active_anon = memstats.stat.total_active_anon;
        memory.total_inactive_file = memstats.stat.total_inactive_file;
        memory.total_active_file = memstats.stat.total_active_file;
        memory.total_unevictable = memstats.stat.total_unevictable;
    }

    #[allow(deprecated)]
    fn memory_cgroup_stats(&self) -> MemoryCgroupStats {
        let mut memory = MemoryCgroupStats {
            memory: self.memory_stats().ok(),
            memory_swap: self.memory_swap_stats().ok(),
            kernel_memory: self.kernel_memory_stats().ok(),
            ..Default::default()
        };

        if let Some(memstats) = self
            .controller::<MemController>()
            .ok()
            .map(|controller| controller.memory_stat())
        {
            Self::populate_memory_details(&mut memory, &memstats);
        }
        memory
    }

    fn try_memory_cgroup_stats(&self) -> Result<MemoryCgroupStats> {
        if !self.has_controller::<MemController>() {
            return Ok(MemoryCgroupStats::default());
        }

        let controller: &MemController = self.controller()?;
        let memstats = controller.try_memory_stat().map_err(Error::Cgroupfs)?;
        let memory_swap = match controller.try_memswap() {
            Ok(stats) => Some(Self::memory_stats_from(
                stats.usage_in_bytes,
                stats.max_usage_in_bytes,
                stats.limit_in_bytes,
                stats.fail_cnt,
            )),
            Err(error) if error.is_not_found() => None,
            Err(error) => return Err(Error::Cgroupfs(error)),
        };
        let kernel_memory = if self.v2() {
            None
        } else {
            match controller.try_kmem_stat() {
                Ok(stats) => Some(Self::memory_stats_from(
                    stats.usage_in_bytes,
                    stats.max_usage_in_bytes,
                    stats.limit_in_bytes,
                    stats.fail_cnt,
                )),
                Err(error) if error.is_not_found() => None,
                Err(error) => return Err(Error::Cgroupfs(error)),
            }
        };
        let mut memory = MemoryCgroupStats {
            memory: Some(Self::memory_stats_from(
                memstats.usage_in_bytes,
                memstats.max_usage_in_bytes,
                memstats.limit_in_bytes,
                memstats.fail_cnt,
            )),
            memory_swap,
            kernel_memory,
            ..Default::default()
        };
        Self::populate_memory_details(&mut memory, &memstats);
        Ok(memory)
    }

    fn pids_cgroup_stats(&self) -> PidsCgroupStats {
        let controller: &PidController = match self.controller() {
            Ok(controller) => controller,
            Err(_) => return PidsCgroupStats::default(),
        };
        let current = controller.get_pid_current().unwrap_or_default();
        let limit = controller
            .get_pid_max()
            .map(|mv| match mv {
                MaxValue::Value(limit) => limit,
                MaxValue::Max => 0,
            })
            .unwrap_or_default();

        PidsCgroupStats { current, limit }
    }

    fn try_pids_cgroup_stats(&self) -> Result<PidsCgroupStats> {
        if !self.has_controller::<PidController>() {
            return Ok(PidsCgroupStats::default());
        }
        let controller: &PidController = self.controller()?;
        let current = controller.get_pid_current().map_err(Error::Cgroupfs)?;
        let limit = match controller.get_pid_max().map_err(Error::Cgroupfs)? {
            MaxValue::Value(limit) => limit,
            MaxValue::Max => 0,
        };
        Ok(PidsCgroupStats { current, limit })
    }

    fn blkio_stats_v1_from(blkio: &crate::fs::blkio::BlkIo) -> BlkioCgroupStats {
        if blkio.io_serviced_recursive.is_empty() {
            BlkioCgroupStats {
                io_service_bytes_recursive: BlkioStat::from_io_services(
                    &blkio.throttle.io_service_bytes,
                ),
                io_serviced_recursive: BlkioStat::from_io_services(&blkio.throttle.io_serviced),
                ..Default::default()
            }
        } else {
            BlkioCgroupStats {
                io_service_bytes_recursive: BlkioStat::from_io_services(
                    &blkio.io_service_bytes_recursive,
                ),
                io_serviced_recursive: BlkioStat::from_io_services(&blkio.io_serviced_recursive),
                io_queued_recursive: BlkioStat::from_io_services(&blkio.io_queued_recursive),
                io_service_time_recursive: BlkioStat::from_io_services(
                    &blkio.io_service_time_recursive,
                ),
                io_wait_time_recursive: BlkioStat::from_io_services(&blkio.io_wait_time_recursive),
                io_merged_recursive: BlkioStat::from_io_services(&blkio.io_merged_recursive),
                io_time_recursive: BlkioStat::from_blk_io_data(&blkio.time_recursive),
                sectors_recursive: BlkioStat::from_blk_io_data(&blkio.sectors_recursive),
            }
        }
    }

    fn blkio_stats_v2_from(blkio: &crate::fs::blkio::BlkIo) -> BlkioCgroupStats {
        BlkioCgroupStats {
            io_service_bytes_recursive: BlkioStat::from_io_stats(&blkio.io_stat),
            ..Default::default()
        }
    }

    #[allow(deprecated)]
    fn blkio_stats_v1(&self) -> Result<BlkioCgroupStats> {
        let controller: &BlkIoController = self.controller()?;
        Ok(Self::blkio_stats_v1_from(&controller.blkio()))
    }

    #[allow(deprecated)]
    fn blkio_stats_v2(&self) -> Result<BlkioCgroupStats> {
        let controller: &BlkIoController = self.controller()?;
        Ok(Self::blkio_stats_v2_from(&controller.blkio()))
    }

    fn try_blkio_stats_v1(&self) -> Result<BlkioCgroupStats> {
        let controller: &BlkIoController = self.controller()?;
        let blkio = controller.try_blkio().map_err(Error::Cgroupfs)?;
        Ok(Self::blkio_stats_v1_from(&blkio))
    }

    fn try_blkio_stats_v2(&self) -> Result<BlkioCgroupStats> {
        let controller: &BlkIoController = self.controller()?;
        let blkio = controller.try_blkio().map_err(Error::Cgroupfs)?;
        Ok(Self::blkio_stats_v2_from(&blkio))
    }

    fn blkio_cgroup_stats(&self) -> BlkioCgroupStats {
        if self.v2() {
            self.blkio_stats_v2()
        } else {
            self.blkio_stats_v1()
        }
        .unwrap_or_default()
    }

    fn try_blkio_cgroup_stats(&self) -> Result<BlkioCgroupStats> {
        if !self.has_controller::<BlkIoController>() {
            return Ok(BlkioCgroupStats::default());
        }
        if self.v2() {
            self.try_blkio_stats_v2()
        } else {
            self.try_blkio_stats_v1()
        }
    }

    fn huge_tlb_cgroup_stats(&self) -> HugeTlbCgroupStats {
        let controller: &HugeTlbController = match self.controller() {
            Ok(controller) => controller,
            Err(_) => return HugeTlbCgroupStats::default(),
        };

        let sizes = controller.get_sizes();
        sizes
            .iter()
            .map(|s| {
                let usage = controller.usage_in_bytes(s).unwrap_or_default();
                let max_usage = controller.max_usage_in_bytes(s).unwrap_or_default();
                let fail_cnt = controller.failcnt(s).unwrap_or_default();

                let stat = HugeTlbStat {
                    usage,
                    max_usage,
                    fail_cnt,
                };

                (s.to_string(), stat)
            })
            .collect()
    }

    fn try_huge_tlb_cgroup_stats(&self) -> Result<HugeTlbCgroupStats> {
        if !self.has_controller::<HugeTlbController>() {
            return Ok(HugeTlbCgroupStats::default());
        }
        let controller: &HugeTlbController = self.controller()?;
        controller
            .get_sizes()
            .iter()
            .map(|size| {
                let stat = HugeTlbStat {
                    usage: controller.usage_in_bytes(size).map_err(Error::Cgroupfs)?,
                    max_usage: controller
                        .max_usage_in_bytes(size)
                        .map_err(Error::Cgroupfs)?,
                    fail_cnt: controller.failcnt(size).map_err(Error::Cgroupfs)?,
                };
                Ok((size.to_string(), stat))
            })
            .collect()
    }
}

impl Manager for FsManager {
    fn add_proc(&mut self, tgid: CgroupPid) -> Result<()> {
        self.create_cgroups()?;
        self.cgroup.add_task_by_tgid(tgid)?;
        Ok(())
    }

    fn add_thread(&mut self, pid: CgroupPid) -> Result<()> {
        self.create_cgroups()?;

        self.cgroup.add_task(pid).or_else(|err| {
            // Try to add_proc with the pid when threaded cgroup is
            // disabled in cgroup v2.
            if err.kind() == &FsErrorKind::CgroupMode && self.v2() {
                self.add_proc(pid)
            } else {
                Err(Error::Cgroupfs(err))
            }
        })
    }

    fn pids(&self) -> Result<Vec<CgroupPid>> {
        self.controller::<MemController>()
            .map_err(Error::Cgroupfs)?
            .try_tasks()
            .map_err(Error::Cgroupfs)
    }

    fn freeze(&self, state: FreezerState) -> Result<()> {
        let controller: &FreezerController = self.controller()?;

        match state {
            FreezerState::Thawed => controller.thaw()?,
            FreezerState::Frozen => controller.freeze()?,
            FreezerState::Freezing => return Err(Error::InvalidArgument),
        }

        Ok(())
    }

    fn destroy(&mut self) -> Result<()> {
        if !self.exists() {
            return Ok(());
        }

        // Before deleting the cgroup, we should move processes in the
        // cgroup to the root cgroup. Otherwise, we'll have a "Device or
        // resource busy" error.
        if self.v2() {
            if let Ok(procs) = self.cgroup.try_procs() {
                for tgid in procs {
                    // Ignore all errors as long as the cgroup is deleted.
                    let _ = self.cgroup.remove_task_by_tgid(tgid);
                }
            }
        } else if let Ok(tasks) = self.cgroup.try_tasks() {
            for pid in tasks {
                // Ditto.
                let _ = self.cgroup.remove_task(pid);
            }
        }

        self.cgroup.delete()?;
        Ok(())
    }

    fn set(&mut self, resources: &LinuxResources) -> Result<()> {
        if let Some(cpu) = resources.cpu() {
            self.set_cpuset(cpu)?;
            self.set_cpu(cpu)?;
        }

        if let Some(memory) = resources.memory() {
            self.set_memory(memory)?;
        }

        if let Some(pid) = resources.pids() {
            self.set_pids(pid)?;
        }

        if let Some(blkio) = resources.block_io() {
            self.set_blkio(blkio)?;
        }

        if let Some(hugepage_limits) = resources.hugepage_limits() {
            self.set_hugepages(hugepage_limits)?;
        }

        if let Some(network) = resources.network() {
            self.set_network(network)?;
        }

        if let Some(devices) = resources.devices() {
            self.set_devices(devices)?;
        }

        Ok(())
    }

    fn cgroup_path(&self, subsystem: Option<&str>) -> Result<String> {
        if self.v2() {
            let full = join_cgroup_path(&self.topology.cgroupfs_root, &self.base);
            return Ok(full.to_string_lossy().into_owned());
        }

        let subsystem = subsystem
            .ok_or_else(|| FsError::new(FsErrorKind::InvalidPath))
            .map_err(Error::Cgroupfs)?;
        let path = self
            .paths
            .get(subsystem)
            .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))
            .map_err(Error::Cgroupfs)?;

        Ok(path.clone())
    }

    fn enable_cpus_topdown(&self, cpus: &str) -> Result<()> {
        if cpus.is_empty() {
            return Ok(());
        }

        self.set_controller_topdown(|c: &CpuSetController| {
            c.set_cpus(cpus).map_err(Error::Cgroupfs)
        })?;

        Ok(())
    }

    fn stats(&self) -> CgroupStats {
        CgroupStats {
            cpu: self.cpu_cgroup_stats(),
            memory: self.memory_cgroup_stats(),
            pids: self.pids_cgroup_stats(),
            blkio: self.blkio_cgroup_stats(),
            hugetlb: self.huge_tlb_cgroup_stats(),
        }
    }

    fn try_stats(&self) -> Result<CgroupStats> {
        Ok(CgroupStats {
            cpu: self.try_cpu_cgroup_stats()?,
            memory: self.try_memory_cgroup_stats()?,
            pids: self.try_pids_cgroup_stats()?,
            blkio: self.try_blkio_cgroup_stats()?,
            hugetlb: self.try_huge_tlb_cgroup_stats()?,
        })
    }

    fn paths(&self) -> &HashMap<String, String> {
        &self.paths
    }

    fn mounts(&self) -> &HashMap<String, String> {
        &self.mounts
    }

    fn systemd(&self) -> bool {
        false
    }

    fn v2(&self) -> bool {
        self.cgroup.v2()
    }
}

/// Convert membership records into the legacy subsystem path map.
///
/// View conversion over [`Membership`]: colons inside a cgroup path
/// survive, and unified-hierarchy records keep the legacy
/// `"" -> <path>` entry documented on [`FsManager`].
fn membership_to_subsystem_paths(membership: &Membership) -> HashMap<String, String> {
    let mut cgroup_paths = HashMap::new();
    for record in membership.records() {
        let path = record.path.to_string_lossy().into_owned();
        if record.controllers.is_empty() {
            // Unified-hierarchy records bind no controllers; they are
            // exposed through the legacy empty-string key.
            cgroup_paths.insert(String::new(), path);
        } else {
            for controller in &record.controllers {
                cgroup_paths.insert(controller.clone(), path.clone());
            }
        }
    }
    cgroup_paths
}

/// Convert the parsed mount table into the legacy controller mountpoint
/// map, restricted to controllers present in `paths`.
fn controller_mounts(
    topology: &CgroupTopology,
    paths: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut controller_mounts = HashMap::new();
    for record in topology
        .mounts
        .cgroup_mounts()
        .iter()
        .chain(topology.mounts.unified_mounts().iter())
    {
        let mut resolved = None;
        for opt in &record.super_opts {
            // If opt matches one of the cgroup subsystems
            if paths.contains_key(opt) {
                let point = resolved.get_or_insert_with(|| {
                    topology
                        .resolve_mount_point(&record.mount_point)
                        .to_string_lossy()
                        .into_owned()
                });
                controller_mounts.insert(opt.clone(), point.clone());
            }
        }
    }
    controller_mounts
}

/// Join a base path with a validated [`CgroupPath`].
pub(crate) fn join_cgroup_path(base: &Path, rel: &CgroupPath) -> PathBuf {
    base.join(rel.as_path())
}

/// Join a base path string with a relative cgroup path string safely,
/// preventing leading slashes from discarding the base path and rejecting
/// path traversal components like `..`.
pub(crate) fn join_path(base: &str, path: &str) -> crate::error::CoreResult<String> {
    let base_path = Path::new(base);
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Ok(base.to_string());
    }
    let cpath = CgroupPath::new(trimmed)?;
    Ok(join_cgroup_path(base_path, &cpath)
        .to_string_lossy()
        .into_owned())
}

/// Parse the value of an item from a tuple string split by whitespace.
///
/// For example, we have a tuple string like:
///
/// let tuple_str: &str = "system 100000\nuser 200000";
///
/// assert_eq!(
///     parse_value_from_tuples::<u64>(tuple_str, "user"),
///     Some(200000),
/// );
/// assert_eq!(
///     parse_value_from_tuples::<u64>(tuple_str, "user1"),
///     None,
/// );
fn parse_value_from_tuples<T>(tuple_str: &str, item: &str) -> Option<T>
where
    T: FromStr,
{
    tuple_str.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let current_item = parts.next()?;
        let value = parts.next()?;
        if current_item != item {
            return None;
        }
        value.parse::<T>().ok()
    })
}

impl BlkioStat {
    fn from_io_services(io_services: &[IoService]) -> Vec<Self> {
        let mut stats = Vec::new();

        for service in io_services.iter() {
            let major = service.major as u64;
            let minor = service.minor as u64;

            stats.push(BlkioStat {
                major,
                minor,
                op: "read".to_string(),
                value: service.read,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "write".to_string(),
                value: service.write,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "sync".to_string(),
                value: service.sync,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "async".to_string(),
                value: service.r#async,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "total".to_string(),
                value: service.total,
            });
        }

        stats
    }

    fn from_io_stats(io_stats: &[IoStat]) -> Vec<Self> {
        let mut stats = Vec::new();

        for stat in io_stats.iter() {
            let major = stat.major as u64;
            let minor = stat.minor as u64;

            stats.push(BlkioStat {
                major,
                minor,
                op: "read".to_string(),
                value: stat.rbytes,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "write".to_string(),
                value: stat.wbytes,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "rios".to_string(),
                value: stat.rios,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "wios".to_string(),
                value: stat.wios,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "dbytes".to_string(),
                value: stat.dbytes,
            });

            stats.push(BlkioStat {
                major,
                minor,
                op: "dios".to_string(),
                value: stat.dios,
            });
        }

        stats
    }

    fn from_blk_io_data(blkiodata: &[BlkIoData]) -> Vec<Self> {
        let op = String::new();

        blkiodata
            .iter()
            .map(|item| BlkioStat {
                major: item.major as u64,
                minor: item.minor as u64,
                op: op.clone(),
                value: item.data,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the `FsManager` implementation of the `Manager` trait.
    //!
    //! Don't run tests in parallel, use `--test-threads=1`!
    //!

    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use oci_spec::runtime::{LinuxCpuBuilder, LinuxMemoryBuilder, LinuxResourcesBuilder};

    use crate::discovery::CgroupVersion;
    use crate::fs::cgroup::UNIFIED_MOUNTPOINT;
    use crate::manager::fs::*;
    use crate::manager::tests::{MEMORY_1G, MEMORY_2G, MEMORY_512M};
    use crate::tests::spawn_sleep_inf;

    use crate::{skip_if_cgroups_v1, skip_if_cgroups_v2, skip_if_not_root};
    use std::fs;

    const TEST_BASE: &str = "cgroupsrs/pod";

    impl FsManager {
        pub fn cgroup(&self) -> &Cgroup {
            &self.cgroup
        }
    }

    fn clean_cgroups(path: &str) {
        let dirs = path.split("/").fold(vec![], |mut acc, dir| {
            if let Some(last) = acc.last() {
                acc.push(format!("{}/{}", last, dir));
            } else {
                acc.push(dir.to_string());
            }
            acc
        });

        let topology = discover(&HostPaths::default()).unwrap();
        let paths = membership_to_subsystem_paths(&topology.membership);
        let mounts = controller_mounts(&topology, &paths);
        let is_v2 = topology.version == CgroupVersion::V2;

        for dir in dirs.iter().rev() {
            if is_v2 {
                let full = join_path(UNIFIED_MOUNTPOINT, dir).unwrap();
                let path = Path::new(&full);
                if path.exists() {
                    // kill processes in cgroup.procs
                    let processes =
                        fs::read_to_string(path.join("cgroup.procs")).unwrap_or_default();
                    for pid in processes.lines() {
                        if let Ok(pid) = pid.parse() {
                            // kill the process
                            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                        }
                    }
                    fs::remove_dir(path).unwrap();
                }
            } else {
                for (subsystem, mountpoint) in mounts.iter() {
                    let full = join_path(mountpoint, paths.get(subsystem).unwrap()).unwrap();
                    let full = join_path(&full, dir).unwrap();
                    let path = Path::new(&full);
                    if path.exists() {
                        // kill processes in the cgroup, by going through
                        // `tasks`
                        let tasks = fs::read_to_string(path.join("tasks")).unwrap_or_default();
                        for pid in tasks.lines() {
                            if let Ok(pid) = pid.parse() {
                                // kill the process
                                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                            }
                        }
                        fs::remove_dir(path).unwrap();
                    }
                }
            }
        }
    }

    fn new_manager() -> FsManager {
        clean_cgroups(TEST_BASE);
        FsManager::new(TEST_BASE).unwrap()
    }

    fn managed_cgroup_path(manager: &FsManager, subsystem: Option<&str>) -> String {
        let base = manager.base.as_path().to_string_lossy();
        if manager.v2() {
            return join_path(UNIFIED_MOUNTPOINT, &base).unwrap();
        }

        let subsystem = subsystem.expect("cgroup v1 requires a subsystem");
        let mountpoint = manager
            .mounts
            .get(subsystem)
            .expect("cgroup v1 subsystem mountpoint should exist");
        join_path(mountpoint, &base).unwrap()
    }

    fn run_set_resources_failed(resources: LinuxResources) {
        let mut child = spawn_sleep_inf();
        let mut manager = new_manager();
        manager
            .add_proc(CgroupPid {
                pid: child.id() as u64,
            })
            .unwrap();
        assert!(manager.set(&resources).is_err());
        manager.destroy().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    fn run_set_resources<F>(linux_resources: LinuxResources, test_fn: F)
    where
        F: FnOnce(&mut FsManager),
    {
        let mut child = spawn_sleep_inf();
        let mut manager = new_manager();
        manager
            .add_proc(CgroupPid {
                pid: child.id() as u64,
            })
            .unwrap();
        manager.set(&linux_resources).unwrap();
        test_fn(&mut manager);
        manager.destroy().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// Kernel-drift canary: read the real `/proc/self/mountinfo` and confirm
    /// the parser still copes with whatever the running kernel produces.
    ///
    /// Fixtures lock our changes to the parser; this locks the parser against
    /// the live host. The realistic risk is not format breakage (`/proc` is
    /// userspace ABI) but additions: new controllers, new fields. If a kernel
    /// change makes `parse_mountinfo_for_line` reject every cgroup line, this
    /// fails at the source instead of surfacing indirectly as "couldn't find
    /// the memory controller" in a downstream integration test.
    ///
    /// `mountinfo_self()` keeps only v1 `cgroup` mounts (it drops `cgroup2`),
    /// so it is legitimately empty on a unified v2 host; on v1/hybrid it must
    /// be non-empty. The line-parser canary covers both versions.
    #[test]
    fn test_live_mountinfo_canary() {
        let data = fs::read_to_string("/proc/self/mountinfo")
            .expect("canary: /proc/self/mountinfo must be readable");

        let table = crate::discovery::parse_mountinfo(&data)
            .expect("canary: /proc/self/mountinfo must parse cleanly");
        assert!(
            !table.cgroup_mounts().is_empty() || !table.unified_mounts().is_empty(),
            "canary: no cgroup/cgroup2 mounts parsed from live /proc/self/mountinfo; \
             parser may have regressed on a kernel format change"
        );

        let mounts = hierarchies::mountinfo_self();
        if hierarchies::is_cgroup2_unified_mode() {
            assert!(
                mounts.is_empty(),
                "canary: mountinfo_self() drops cgroup2 on a unified v2 host, got {:?}",
                mounts
            );
        } else {
            assert!(
                !mounts.is_empty(),
                "canary: mountinfo_self() found no v1 cgroup mounts on a v1/hybrid host; \
                 parser may have regressed"
            );
        }
    }

    #[test]
    fn test_parse_value_from_tuples() {
        let tuple_str = "system 100000\nuser 200000";
        assert_eq!(
            parse_value_from_tuples::<u64>(tuple_str, "user"),
            Some(200000)
        );
        assert_eq!(
            parse_value_from_tuples::<u64>(tuple_str, "system"),
            Some(100000)
        );
        assert_eq!(parse_value_from_tuples::<u64>(tuple_str, "user1"), None);
    }

    #[test]
    fn test_paths_and_mounts() {
        skip_if_not_root!();

        let mut manager = new_manager();

        for (subsystem, mountpoint) in manager.mounts() {
            let path = manager.paths().get(subsystem).unwrap();
            let path = join_path(mountpoint, path.trim_start_matches('/')).unwrap();
            assert!(Path::new(&path).exists(), "Cgroup {} does not exist", path);
        }

        manager.destroy().unwrap();
    }

    #[test]
    fn test_destroy() {
        skip_if_not_root!();

        let mut manager = new_manager();
        manager.create_cgroups().unwrap();

        let cgroup_path = managed_cgroup_path(&manager, (!manager.v2()).then_some("memory"));
        assert!(
            Path::new(&cgroup_path).exists(),
            "Cgroup should exist before destroy"
        );

        manager.destroy().unwrap();
        assert!(
            !Path::new(&cgroup_path).exists(),
            "Cgroup should not exist after destroy"
        );
    }

    #[test]
    fn test_set_cpu() {
        skip_if_not_root!();

        // 1024 shares, every 100ms allows to use 1 CPU
        let linux_cpu = LinuxCpuBuilder::default()
            .shares(1024u64)
            .quota(100000i64)
            .period(100000u64)
            .quota(100000i64)
            .build()
            .unwrap();

        let linux_resources = LinuxResourcesBuilder::default()
            .cpu(linux_cpu)
            .build()
            .unwrap();

        run_set_resources(linux_resources, |manager| {
            let controller: &CpuController = manager.controller().unwrap();
            let shares = controller.shares().unwrap();
            let period = controller.cfs_period().unwrap();
            let quota = controller.cfs_quota().unwrap();

            if manager.v2() {
                assert_eq!(shares, conv::cpu_shares_to_cgroup_v2(1024));
            } else {
                assert_eq!(shares, 1024);
            }

            assert_eq!(period, 100000);
            assert_eq!(quota, 100000);
        })
    }

    #[test]
    fn test_set_memory_v2() {
        skip_if_not_root!();
        skip_if_cgroups_v1!();

        // expected failure: swap < limit
        let linux_memory = LinuxMemoryBuilder::default()
            .limit(MEMORY_1G)
            .swap(MEMORY_512M)
            .build()
            .unwrap();
        let linux_resources = LinuxResourcesBuilder::default()
            .memory(linux_memory)
            .build()
            .unwrap();
        run_set_resources_failed(linux_resources);

        let linux_memory = LinuxMemoryBuilder::default()
            .limit(MEMORY_512M)
            .swap(MEMORY_1G)
            .reservation(MEMORY_2G)
            .build()
            .unwrap();
        let linux_resources = LinuxResourcesBuilder::default()
            .memory(linux_memory)
            .build()
            .unwrap();
        run_set_resources(linux_resources, |manager| {
            let controller: &MemController = manager.controller().unwrap();
            let memory_stat = controller.try_memory_stat().unwrap();
            let memory_swap_stat = controller.try_memswap().unwrap();

            assert_eq!(memory_stat.limit_in_bytes, MEMORY_512M);
            assert_eq!(memory_swap_stat.limit_in_bytes, MEMORY_512M);
            assert_eq!(memory_stat.soft_limit_in_bytes, MEMORY_2G);
        });
    }

    #[test]
    fn test_set_memory_v1() {
        skip_if_not_root!();
        skip_if_cgroups_v2!();

        let linux_memory = LinuxMemoryBuilder::default()
            .limit(MEMORY_512M)
            .swap(MEMORY_512M)
            .reservation(MEMORY_512M)
            .disable_oom_killer(true)
            .swappiness(50u64)
            .build()
            .unwrap();
        let linux_resources = LinuxResourcesBuilder::default()
            .memory(linux_memory)
            .build()
            .unwrap();
        run_set_resources(linux_resources, |manager| {
            let controller: &MemController = manager.controller().unwrap();
            let memory_stat = controller.try_memory_stat().unwrap();
            let memory_swap_stat = controller.try_memswap().unwrap();

            assert_eq!(memory_stat.limit_in_bytes, MEMORY_512M);
            assert_eq!(memory_swap_stat.limit_in_bytes, MEMORY_512M);
            assert_eq!(memory_stat.soft_limit_in_bytes, MEMORY_512M);
            assert_eq!(memory_stat.swappiness, 50);
            assert!(memory_stat.oom_control.oom_kill_disable);
        });

        // expected failure: swapiness too high
        let linux_memory = LinuxMemoryBuilder::default()
            .swappiness(101u64)
            .build()
            .unwrap();
        let linux_resources = LinuxResourcesBuilder::default()
            .memory(linux_memory)
            .build()
            .unwrap();
        run_set_resources_failed(linux_resources);
    }

    fn parse_cpu_list(online_str: &str) -> Vec<u32> {
        let mut cpus = Vec::new();
        for part in online_str.trim().split(',') {
            if let Some((start, end)) = part.split_once('-') {
                let start: u32 = start.parse().unwrap();
                let end: u32 = end.parse().unwrap();
                cpus.extend(start..=end);
            } else {
                cpus.push(part.parse().unwrap());
            }
        }
        cpus
    }

    #[test]
    fn test_enable_cpus_topdown() {
        skip_if_not_root!();

        let online_cpus = fs::read_to_string("/sys/devices/system/cpu/online").unwrap();
        let cpus = parse_cpu_list(&online_cpus);

        // Skip this test if there are less than 2 CPUs online
        if cpus.len() < 2 {
            return;
        }

        let linux_cpu = LinuxCpuBuilder::default()
            .cpus(format!("{}", cpus[0]))
            .build()
            .unwrap();
        let linux_resources = LinuxResourcesBuilder::default()
            .cpu(linux_cpu)
            .build()
            .unwrap();
        run_set_resources(linux_resources, |manager| {
            let managed_path = managed_cgroup_path(manager, (!manager.v2()).then_some("cpuset"));
            let cpuset_cpus_path = join_path(&managed_path, "cpuset.cpus").unwrap();
            let cpus1 = fs::read_to_string(&cpuset_cpus_path).unwrap();
            let cpus1 = parse_cpu_list(&cpus1);
            assert_eq!(cpus[..1], cpus1);

            manager
                .enable_cpus_topdown(&format!("{},{}", cpus[0], cpus[1]))
                .unwrap();
            let cpuset_cpus = fs::read_to_string(&cpuset_cpus_path).unwrap();
            let cpus2 = parse_cpu_list(&cpuset_cpus);
            assert_eq!(cpus[..2], cpus2);
        });
    }

    #[test]
    fn test_systemd() {
        skip_if_not_root!();

        let mut manager = new_manager();
        assert!(!manager.systemd(), "FsManager should not be systemd");
        manager.destroy().unwrap();
    }
}

/// Host-independent parser tests for the discovery-backed compatibility views.
///
/// Input and expectation are kept adjacent in inline tables so failures pin an
/// exact (controller, path) pair instead of a vague "is_empty" / "contains_key".
#[cfg(test)]
mod parse_tests {
    use super::{controller_mounts, membership_to_subsystem_paths};
    use crate::discovery::{CgroupTopology, CgroupVersion, ControllerSet};
    use crate::error::CoreError;
    use crate::fs::hierarchies;
    use crate::manager::error::Error;
    use std::collections::HashMap;
    use std::fs;

    /// One `/proc/<pid>/cgroup` input plus the expected controller->path map.
    /// `expect` is the full HashMap the parser must produce; `None` means
    /// the input is malformed and must be rejected with a parse error.
    struct Case {
        name: &'static str,
        input: &'static str,
        expect: Option<&'static [(&'static str, &'static str)]>,
    }

    const CASES: &[Case] = &[
        Case {
            name: "v2-single: unified record maps to the legacy empty key",
            input: "0::/user.slice/user-1001.slice/user@1001.service/app.slice/snap.opencode.scope",
            expect: Some(&[("", "/user.slice/user-1001.slice/user@1001.service/app.slice/snap.opencode.scope")]),
        },
        Case {
            name: "v1-multi: multi-line file merges into one map",
            input: "\
13:pids:/user.slice/user-1000.slice/session-4.scope
12:cpu,cpuacct:/user.slice
11:perf_event:/
10:misc:/
9:rdma:/
8:freezer:/
7:memory:/user.slice/user-1000.slice/session-4.scope
6:devices:/user.slice
5:blkio:/user.slice
4:cpuset:/
3:net_cls,net_prio:/
2:hugetlb:/
1:name=systemd:/user.slice/user-1000.slice/session-4.scope
0::/user.slice/user-1000.slice/session-4.scope",
            expect: Some(&[
                ("pids", "/user.slice/user-1000.slice/session-4.scope"),
                ("cpu", "/user.slice"),
                ("cpuacct", "/user.slice"),
                ("perf_event", "/"),
                ("misc", "/"),
                ("rdma", "/"),
                ("freezer", "/"),
                ("memory", "/user.slice/user-1000.slice/session-4.scope"),
                ("devices", "/user.slice"),
                ("blkio", "/user.slice"),
                ("cpuset", "/"),
                ("net_cls", "/"),
                ("net_prio", "/"),
                ("hugetlb", "/"),
                ("name=systemd", "/user.slice/user-1000.slice/session-4.scope"),
                ("", "/user.slice/user-1000.slice/session-4.scope"),
            ]),
        },
        Case {
            name: "colon-path: colons survive, v2 path exposed via the empty key",
            input: "0::/user.slice/session:c1.scope\n6:memory:/docker/ab:cd/init\n0::/a:b:c",
            expect: Some(&[("memory", "/docker/ab:cd/init"), ("", "/a:b:c")]),
        },
        Case {
            name: "v2-only: last unified line wins for the empty key",
            input: "0::/kubepods/burstable/pod-abc123/cri-containerd-xyz/init\n0::/kubepods/burstable/pod-abc123/cri-containerd-xyz/exec",
            expect: Some(&[("", "/kubepods/burstable/pod-abc123/cri-containerd-xyz/exec")]),
        },
        Case {
            name: "malformed: missing path field is rejected",
            input: "8:memory",
            expect: None,
        },
        Case {
            name: "malformed: one bad line rejects the whole stream",
            input: "10:memory:/user.slice\nnot a cgroup line",
            expect: None,
        },
    ];

    #[test]
    fn test_parse_cgroup_subsystems_str_table() {
        for case in CASES {
            let got = crate::discovery::parse_membership(case.input)
                .map(|m| membership_to_subsystem_paths(&m))
                .map_err(Error::Core);
            match case.expect {
                None => assert!(
                    matches!(got, Err(Error::Core(CoreError::ParseError { .. }))),
                    "{}: expected a propagated parse error, got `{:?}`",
                    case.name,
                    got
                ),
                Some(expect) => {
                    let got = got.unwrap_or_else(|err| panic!("{}: {}", case.name, err));
                    let want: HashMap<String, String> = expect
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    assert_eq!(got, want, "{}", case.name);
                }
            }
        }
    }

    #[test]
    fn test_controller_mounts() {
        let mut paths = HashMap::new();
        paths.insert("memory".to_string(), "/user.slice".to_string());
        paths.insert("cpu".to_string(), "/user.slice".to_string());
        paths.insert("cpuacct".to_string(), "/user.slice".to_string());
        paths.insert("pids".to_string(), "/user.slice".to_string());

        let input = "\
31 22 0:26 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,memory
32 22 0:27 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,cpu,cpuacct
";

        let topology = CgroupTopology {
            version: CgroupVersion::V1,
            v2_available: false,
            mounts: crate::discovery::parse_mountinfo(input).unwrap(),
            membership: crate::discovery::parse_membership("1:memory:/user.slice").unwrap(),
            controllers: ControllerSet::default(),
            cgroupfs_root: "/sys/fs/cgroup".into(),
            hugepages: "/sys/kernel/mm/hugepages".into(),
        };
        let mounts = controller_mounts(&topology, &paths);
        assert_eq!(
            mounts.get("memory"),
            Some(&"/sys/fs/cgroup/memory".to_string())
        );
        assert_eq!(
            mounts.get("cpu"),
            Some(&"/sys/fs/cgroup/cpu,cpuacct".to_string())
        );
        assert_eq!(
            mounts.get("cpuacct"),
            Some(&"/sys/fs/cgroup/cpu,cpuacct".to_string())
        );
        assert_eq!(mounts.get("pids"), None);
        assert_eq!(mounts.len(), 3);
    }

    /// In cgroup v2 (unified hierarchy), `/proc/self/cgroup` contains `0::<path>`,
    /// which the compatibility view exposes through the empty key.
    /// However, a normal cgroup2 mount in `/proc/self/mountinfo`:
    ///   `47 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw,nsdelegate`
    /// has super-options such as `rw,nsdelegate` (never `""`).
    ///
    /// Because `controller_mounts` matches mount super-options against
    /// keys in `paths` (`paths.contains_key(opt)`), it never matches the `""`
    /// key. Therefore, `controller_mounts` currently returns no mount
    /// mapping for unified v2, even though `cgroup2` is explicitly recognized in
    /// `mi.fs_type.0`.
    ///
    /// This characterization test pins the current counterintuitive behavior so
    /// any future fix to the `mounts()` contract for cgroup v2 can flip this
    /// expectation intentionally.
    #[test]
    fn test_controller_mounts_cgroup2() {
        let cgroup_data = "0::/user.slice/user-1000.slice/session-4.scope";
        let membership = crate::discovery::parse_membership(cgroup_data).unwrap();
        let paths = membership_to_subsystem_paths(&membership);
        assert_eq!(
            paths.get(""),
            Some(&"/user.slice/user-1000.slice/session-4.scope".to_string())
        );

        let mountinfo_data = "\
47 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw,nsdelegate
";
        let topology = CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(mountinfo_data).unwrap(),
            membership,
            controllers: ControllerSet::default(),
            cgroupfs_root: "/sys/fs/cgroup".into(),
            hugepages: "/sys/kernel/mm/hugepages".into(),
        };
        let mounts = controller_mounts(&topology, &paths);

        // Counterintuitive branch: returns no mount mapping for unified v2.
        assert_eq!(mounts.get(""), None);
        assert!(mounts.is_empty());
    }

    /// Kernel-drift canary: read the real `/proc/self/mountinfo` and confirm
    /// the parser still copes with whatever the running kernel produces.
    ///
    /// Fixtures lock our changes to the parser; this locks the parser against
    /// the live host. The realistic risk is not format breakage (`/proc` is
    /// userspace ABI) but additions: new controllers, new fields. If a kernel
    /// change makes the discovery parser reject every cgroup line, this
    /// fails at the source instead of surfacing indirectly as "couldn't find
    /// the memory controller" in a downstream integration test.
    ///
    /// `mountinfo_self()` keeps only v1 `cgroup` mounts (it drops `cgroup2`),
    /// so it is legitimately empty on a unified v2 host; on v1/hybrid it must
    /// be non-empty. The line-parser canary covers both versions.
    #[test]
    #[ignore = "requires a controlled cgroup hierarchy; run explicitly in QEMU"]
    fn test_live_mountinfo_canary() {
        let data = fs::read_to_string("/proc/self/mountinfo")
            .expect("canary: /proc/self/mountinfo must be readable");

        let mount_table = crate::discovery::parse_mountinfo(&data)
            .expect("canary: /proc/self/mountinfo must parse cleanly");
        let cgroup_mounts: Vec<_> = mount_table
            .records()
            .iter()
            .filter(|mi| mi.fs_type.0 == "cgroup" || mi.fs_type.0 == "cgroup2")
            .collect();
        assert!(
            !cgroup_mounts.is_empty(),
            "canary: no cgroup/cgroup2 mounts parsed from live /proc/self/mountinfo; \
             parser may have regressed on a kernel format change"
        );

        let mounts = hierarchies::mountinfo_self();
        if hierarchies::is_cgroup2_unified_mode() {
            assert!(
                mounts.is_empty(),
                "canary: mountinfo_self() drops cgroup2 on a unified v2 host, got {:?}",
                mounts
            );
        } else {
            assert!(
                !mounts.is_empty(),
                "canary: mountinfo_self() found no v1 cgroup mounts on a v1/hybrid host; \
                 parser may have regressed"
            );
        }
    }

    #[test]
    fn test_fs_manager_with_topology() {
        use super::FsManager;
        use crate::discovery::CgroupTopology;
        use std::path::{Path, PathBuf};
        use std::sync::Arc;

        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let temp_dir = std::env::temp_dir().join(format!("fs-mgr-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _guard = TempGuard(temp_dir.clone());
        let custom_cgroupfs = temp_dir.join("cgroupfs");
        std::fs::create_dir_all(&custom_cgroupfs).unwrap();

        let mountinfo = "\
43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory";
        let mounts = crate::discovery::parse_mountinfo(mountinfo).unwrap();
        let membership = crate::discovery::parse_membership("1:memory:/user.slice").unwrap();

        let topology = Arc::new(CgroupTopology {
            version: crate::discovery::CgroupVersion::V1,
            v2_available: false,
            mounts,
            membership,
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: custom_cgroupfs.clone(),
            hugepages: PathBuf::from("/nonexistent"),
        });

        let manager = FsManager::with_topology("test/subgroup", topology).unwrap();
        assert_eq!(manager.base.as_path(), Path::new("test/subgroup"));
        assert_eq!(
            manager.mounts.get("memory").unwrap(),
            &custom_cgroupfs.join("memory").to_string_lossy().to_string()
        );
    }

    #[test]
    fn test_join_path_safe_from_leading_slash() {
        use super::{join_cgroup_path, join_path};
        use crate::model::CgroupPath;
        use std::path::Path;

        // Standard Path::join discards base when second operand starts with slash:
        // Path::new("/sys/fs/cgroup").join("/mycgroup") -> "/mycgroup"
        // join_path MUST NOT discard the base:
        let joined = join_path("/sys/fs/cgroup", "/mycgroup/sub").unwrap();
        assert_eq!(joined, "/sys/fs/cgroup/mycgroup/sub");

        let joined_empty = join_path("/sys/fs/cgroup", "").unwrap();
        assert_eq!(joined_empty, "/sys/fs/cgroup");

        // Traversal paths MUST be rejected:
        assert!(join_path("/sys/fs/cgroup", "../escape").is_err());
        assert!(join_path("/sys/fs/cgroup", "sub/../escape").is_err());

        let cp = CgroupPath::new("mycgroup/sub").unwrap();
        let typed = join_cgroup_path(Path::new("/sys/fs/cgroup"), &cp);
        assert_eq!(typed, Path::new("/sys/fs/cgroup/mycgroup/sub"));
    }
}
