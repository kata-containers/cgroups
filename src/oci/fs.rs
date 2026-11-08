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

use crate::core::discovery::{CgroupMembership, CgroupTopology};
use crate::core::error::CoreError;
use crate::core::path::CgroupPath;
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
use crate::fs::{
    hierarchies, Cgroup, ControllIdentifier, Controller, ControllerSelection, MaxValue, Subsystem,
};
use crate::oci::error::Error;
use crate::oci::{conv, Manager, Result};
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
    /// The discovered host topology, shared with the managed cgroup and
    /// every clone of this manager.
    topology: Arc<CgroupTopology>,
    /// Base path of the cgroup filesystem in validated relative form;
    /// the complete path would be:
    /// - cgroup v1: "<controller mount>/<base>"
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

    /// Create an instance of FsManager from a shared topology and validated base.
    /// The cgroups won't be created until `apply()` is called.
    ///
    /// Discover the topology explicitly with [`crate::core::discovery::discover`]
    /// and share its [`Arc`] with other managers. This constructor performs no
    /// discovery. Use [`CgroupPath::root`] to manage the hierarchy root.
    ///
    /// This currently always returns `Ok`; `Result` is retained so future
    /// constructor validation can report errors without changing the signature.
    pub fn new(topology: Arc<CgroupTopology>, base: CgroupPath) -> Result<Self> {
        let cgroup = Cgroup::load(hierarchies::from_topology(topology.clone()), base.clone());

        Ok(Self {
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
    // Keep the read boundary injectable to exercise concurrent removal and
    // permission failures without depending on host privileges.
    fn pids_with(
        &self,
        read_tasks: impl FnOnce(&MemController) -> FsResult<Vec<CgroupPid>>,
    ) -> Result<Vec<CgroupPid>> {
        let controller = self.controller::<MemController>()?;
        match read_tasks(controller) {
            Ok(pids) => Ok(pids),
            Err(error)
                if error.is_not_found()
                    && matches!(
                        std::fs::metadata(controller.path()),
                        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound
                    ) =>
            {
                // An uncreated or removed cgroup has no members. A missing
                // membership file in an existing directory remains an error.
                Ok(Vec::new())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Create the cgroups if they are not created yet.
    pub(crate) fn create_cgroups(&mut self) -> Result<()> {
        if self.exists() {
            return Ok(());
        }
        self.cgroup.create()?;
        Ok(())
    }

    // Keep deletion separate from membership reads and migration. Filesystem
    // fixtures can then remove ordinary files before rmdir, unlike cgroupfs.
    fn destroy_with(&self, delete: impl FnOnce(&Cgroup) -> FsResult<()>) -> Result<()> {
        // Membership read failures propagate; individual migration failures
        // remain best effort, and deletion reports its own failure.
        if self.v2() {
            return self.destroy_v2_with(Cgroup::procs, delete);
        }

        let mut controllers = Vec::new();
        let mut tasks = Vec::new();
        for subsystem in self.cgroup.subsystems() {
            let controller = subsystem.to_controller();
            match controller.tasks() {
                Ok(mut members) => tasks.append(&mut members),
                Err(error)
                    if error.is_not_found()
                        && matches!(
                            std::fs::metadata(controller.path()),
                            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound
                        ) =>
                {
                    // A previous create or delete may have left only a subset
                    // of the v1 directories. A missing tasks file in an
                    // existing directory is still an error.
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            controllers.push(subsystem.controller_name());
        }

        // Finish every read before migrating anything, then use the same
        // controller subset for migration and deletion. An absent controller
        // must not stop migration out of a surviving hierarchy.
        let cgroup = Cgroup::builder(self.cgroup.hierarchy().clone(), self.base.clone())
            .controllers(ControllerSelection::Only(controllers))
            .load();
        tasks.sort_unstable();
        tasks.dedup();
        for pid in tasks {
            // PID 0 can denote a task outside the reader's PID namespace.
            // Writing it back would attach the caller instead.
            if pid.pid == 0 {
                continue;
            }
            let _ = cgroup.remove_task(pid);
        }
        delete(&cgroup)?;
        Ok(())
    }

    // Keep the read boundary injectable to exercise removal after exists().
    fn destroy_v2_with(
        &self,
        read_procs: impl FnOnce(&Cgroup) -> FsResult<Vec<CgroupPid>>,
        delete: impl FnOnce(&Cgroup) -> FsResult<()>,
    ) -> Result<()> {
        if !self.exists() {
            return Ok(());
        }
        let procs = match read_procs(&self.cgroup) {
            Ok(procs) => procs,
            Err(error)
                if error.io_error().and_then(std::io::Error::raw_os_error)
                    == Some(libc::EOPNOTSUPP) =>
            {
                // Threaded cgroups reject cgroup.procs reads: their processes
                // belong to the thread root. Still attempt rmdir, which checks
                // that no threads or descendants remain in this cgroup.
                Vec::new()
            }
            Err(error)
                if error.is_not_found()
                    && matches!(
                        std::fs::metadata(
                            self.cgroup.hierarchy().root()?.join(self.base.as_path())
                        ),
                        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound
                    ) =>
            {
                // Another remover won the race after exists(). A missing
                // cgroup.procs in an existing directory remains an error.
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        for tgid in procs {
            // PID 0 can denote a process outside the reader's PID namespace.
            // Writing it back would migrate the caller instead.
            if tgid.pid == 0 {
                continue;
            }
            let _ = self.cgroup.remove_task_by_tgid(tgid);
        }
        delete(&self.cgroup)?;
        Ok(())
    }

    /// Get the subcgroup path, which is useful for Docker-in-Docker (DinD)
    /// with cgroup v2, see [1].
    ///
    /// 1: https://github.com/kata-containers/kata-containers/issues/10733
    /// Returns an error if the v2 hierarchy cannot provide its unified mount.
    pub fn subcgroup(&self) -> Result<&str> {
        if !self.v2() {
            return Ok("/");
        }
        // Check if we're in a Docker-in-Docker setup by verifying:
        // 1. We're using cgroups v2 (which restricts direct process control)
        // 2. An "init" subdirectory exists (used by DinD for process
        //    delegation)
        let init_exists = self
            .cgroup
            .hierarchy()
            .root()?
            .join(self.base.as_path())
            .join("init")
            .exists();
        if init_exists {
            Ok("/init/")
        } else {
            Ok("/")
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
            let memory = controller.memory_stat();
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

        let memory_stat = controller.memory_stat();
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
        let root = Cgroup::load(self.cgroup.hierarchy().clone(), CgroupPath::root());
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
                self.cgroup.hierarchy().clone(),
                CgroupPath::new(relative_path).map_err(CoreError::from)?,
            )?;
            let controller: &T = cgroup
                .controller_of()
                .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))?;
            f(controller)?;
        }

        Ok(())
    }

    fn cpu_acct_stats(&self) -> Result<CpuAcctStats> {
        let controller: &CpuAcctController = self.controller()?;
        let cpu_acct = controller.cpuacct()?;

        let user_usage = parse_value_from_tuples(&cpu_acct.stat, "user").unwrap_or_default();

        let system_usage = parse_value_from_tuples(&cpu_acct.stat, "system").unwrap_or_default();

        let usage_percpu: Vec<u64> = cpu_acct
            .usage_percpu
            .lines()
            .filter_map(|line| line.parse::<u64>().ok())
            .collect();

        Ok(CpuAcctStats {
            user_usage,
            system_usage,
            total_usage: cpu_acct.usage,
            usage_percpu,
        })
    }

    fn cpu_throttling_stats(&self) -> Result<CpuThrottlingStats> {
        let controller: &CpuController = self.controller()?;
        let stats = controller.cpu().stat;

        let periods = parse_value_from_tuples(&stats, "nr_periods").unwrap_or_default();
        let throttled_periods = parse_value_from_tuples(&stats, "nr_throttled").unwrap_or_default();
        let throttled_time = parse_value_from_tuples(&stats, "throttled_time").unwrap_or_default();

        Ok(CpuThrottlingStats {
            periods,
            throttled_periods,
            throttled_time,
        })
    }

    fn cpu_cgroup_stats(&self) -> CpuCgroupStats {
        CpuCgroupStats {
            cpu_acct: self.cpu_acct_stats().ok(),
            cpu_throttling: self.cpu_throttling_stats().ok(),
        }
    }

    fn memory_stats(&self) -> Result<MemoryStats> {
        let controller: &MemController = self.controller()?;
        let memory_stats = controller.memory_stat();

        Ok(MemoryStats {
            usage: memory_stats.usage_in_bytes,
            max_usage: memory_stats.max_usage_in_bytes,
            limit: memory_stats.limit_in_bytes,
            fail_cnt: memory_stats.fail_cnt,
        })
    }

    fn memory_swap_stats(&self) -> Result<MemoryStats> {
        let controller: &MemController = self.controller()?;
        let memory_swap_stats = controller.memswap();

        Ok(MemoryStats {
            usage: memory_swap_stats.usage_in_bytes,
            max_usage: memory_swap_stats.max_usage_in_bytes,
            limit: memory_swap_stats.limit_in_bytes,
            fail_cnt: memory_swap_stats.fail_cnt,
        })
    }

    fn kernel_memory_stats(&self) -> Result<MemoryStats> {
        let controller: &MemController = self.controller()?;
        let kmem_stats = controller.kmem_stat();

        Ok(MemoryStats {
            usage: kmem_stats.usage_in_bytes,
            max_usage: kmem_stats.max_usage_in_bytes,
            limit: kmem_stats.limit_in_bytes,
            fail_cnt: kmem_stats.fail_cnt,
        })
    }

    fn memory_cgroup_stats(&self) -> MemoryCgroupStats {
        let memory = self.memory_stats().ok();
        let memory_swap = self.memory_swap_stats().ok();
        let kernel_memory = self.kernel_memory_stats().ok();

        let mut memory = MemoryCgroupStats {
            memory,
            memory_swap,
            kernel_memory,
            ..Default::default()
        };

        let memory_stats = self
            .controller::<MemController>()
            .map(|c| c.memory_stat())
            .ok();
        if let Some(memstats) = &memory_stats {
            memory.use_hierarchy = memstats.use_hierarchy == 1;
            // Copy items from memstats.stat
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

        memory
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

    fn blkio_stats_v1(&self) -> Result<BlkioCgroupStats> {
        let controller: &BlkIoController = self.controller()?;
        let blkio = controller.blkio();

        if blkio.io_serviced_recursive.is_empty() {
            Ok(BlkioCgroupStats {
                io_service_bytes_recursive: BlkioStat::from_io_services(
                    &blkio.throttle.io_service_bytes,
                ),
                io_serviced_recursive: BlkioStat::from_io_services(&blkio.throttle.io_serviced),
                ..Default::default()
            })
        } else {
            Ok(BlkioCgroupStats {
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
            })
        }
    }

    fn blkio_stats_v2(&self) -> Result<BlkioCgroupStats> {
        let controller: &BlkIoController = self.controller()?;
        let blkio = controller.blkio();

        Ok(BlkioCgroupStats {
            io_service_bytes_recursive: BlkioStat::from_io_stats(&blkio.io_stat),
            ..Default::default()
        })
    }

    fn blkio_cgroup_stats(&self) -> BlkioCgroupStats {
        if self.v2() {
            self.blkio_stats_v2()
        } else {
            self.blkio_stats_v1()
        }
        .unwrap_or_default()
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
        self.pids_with(MemController::tasks)
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
        self.destroy_with(Cgroup::delete)
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

    fn cgroup_path(&self, subsystem: Option<&str>) -> Result<PathBuf> {
        if self.v2() {
            return Ok(join_cgroup_path(
                &self.cgroup.hierarchy().root()?,
                &self.base,
            ));
        }

        let subsystem = subsystem
            .ok_or_else(|| FsError::new(FsErrorKind::InvalidPath))
            .map_err(Error::Cgroupfs)?;
        let record = self
            .memberships()
            .records()
            .iter()
            .find(|record| record.controllers.iter().any(|name| name == subsystem))
            .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))
            .map_err(Error::Cgroupfs)?;

        Ok(record.path.clone())
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

    fn memberships(&self) -> &CgroupMembership {
        self.topology.membership()
    }

    fn mounts(&self) -> HashMap<String, PathBuf> {
        let mut mounts = HashMap::new();
        for controller in self
            .memberships()
            .records()
            .iter()
            .flat_map(|record| &record.controllers)
        {
            if let Some(mount) = self.topology.mounts().find_v1_record(controller) {
                mounts.insert(controller.clone(), mount.mount_point.clone());
            }
        }
        mounts
    }

    fn systemd(&self) -> bool {
        false
    }

    fn v2(&self) -> bool {
        self.cgroup.v2()
    }
}

/// Join a base path with a validated [`CgroupPath`].
pub(crate) fn join_cgroup_path(base: &Path, rel: &CgroupPath) -> PathBuf {
    base.join(rel.as_path())
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
    use std::error::Error as _;

    use crate::core::{discover, CgroupVersion, HostPaths};
    use crate::oci::fs::*;
    use crate::oci::tests::{MEMORY_1G, MEMORY_2G, MEMORY_512M};
    use crate::tests::spawn_sleep_inf;
    use crate::{skip_if_cgroups_v1, skip_if_cgroups_v2, skip_if_not_root};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    const TEST_BASE: &str = "cgroupsrs/pod";

    fn v1_cleanup_fixture() -> (crate::tests::TopologyFixture, FsManager) {
        let fixture = crate::tests::TopologyFixture::new(
            b"41 33 0:31 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              42 33 0:32 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n",
            b"1:memory:/\n2:pids:/\n",
            "",
        );
        let manager = FsManager::new(
            fixture.topology.clone(),
            CgroupPath::new("cleanup").unwrap(),
        )
        .unwrap();
        (fixture, manager)
    }

    fn delete_fixture_cgroup(cgroup: &Cgroup) -> FsResult<()> {
        // Real cgroupfs rmdir removes the pseudo-files automatically.
        for subsystem in cgroup.subsystems() {
            fs::remove_file(subsystem.to_controller().path().join("tasks")).unwrap();
        }
        cgroup.delete()
    }

    #[test]
    fn test_destroy_v1_after_partial_creation() {
        for present in ["memory", "pids"] {
            let (fixture, mut manager) = v1_cleanup_fixture();
            let root = fixture.topology.fixture_root().unwrap();
            let mount = root.join(present);
            let directory = mount.join("cleanup");
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("tasks"), "123\n123\n").unwrap();

            manager
                .destroy_with(|cgroup| {
                    assert_eq!(cgroup.subsystems().len(), 1);
                    assert_eq!(cgroup.subsystems()[0].controller_name(), present);
                    assert_eq!(fs::read_to_string(mount.join("tasks")).unwrap(), "123");
                    delete_fixture_cgroup(cgroup)
                })
                .unwrap();

            assert!(!directory.exists());
            let absent = if present == "memory" {
                "pids"
            } else {
                "memory"
            };
            assert!(!root.join(absent).exists());
            manager.destroy().unwrap();
        }
    }

    #[test]
    fn test_destroy_v1_retries_after_partial_deletion() {
        use std::error::Error as _;

        let (fixture, mut manager) = v1_cleanup_fixture();
        let root = fixture.topology.fixture_root().unwrap();
        let memory = root.join("memory/cleanup");
        let pids = root.join("pids/cleanup");
        for directory in [&memory, &pids] {
            fs::create_dir_all(directory).unwrap();
            fs::write(directory.join("tasks"), "").unwrap();
        }

        let error = manager
            .destroy_with(|cgroup| {
                assert_eq!(cgroup.subsystems().len(), 2);
                fs::remove_file(memory.join("tasks")).unwrap();
                fs::remove_dir(&memory).unwrap();
                Err(FsError::with_cause(
                    FsErrorKind::RemoveFailed,
                    std::io::Error::from_raw_os_error(libc::EBUSY),
                ))
            })
            .unwrap_err();
        let Error::Cgroupfs(error) = error else {
            panic!("expected cgroupfs deletion failure");
        };
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EBUSY)
        );
        assert!(!memory.exists());
        assert!(pids.is_dir());

        fs::write(root.join("memory/tasks"), "untouched").unwrap();
        fs::write(pids.join("tasks"), "456\n").unwrap();
        manager
            .destroy_with(|cgroup| {
                assert_eq!(cgroup.subsystems().len(), 1);
                assert_eq!(cgroup.subsystems()[0].controller_name(), "pids");
                assert_eq!(fs::read_to_string(root.join("pids/tasks")).unwrap(), "456");
                assert_eq!(
                    fs::read_to_string(root.join("memory/tasks")).unwrap(),
                    "untouched"
                );
                delete_fixture_cgroup(cgroup)
            })
            .unwrap();
        assert!(!pids.exists());
        manager.destroy().unwrap();
    }

    #[test]
    fn test_destroy_v1_read_failures_precede_all_migration() {
        use std::error::Error as _;

        for errno in [libc::ENOENT, libc::EISDIR] {
            let (fixture, mut manager) = v1_cleanup_fixture();
            let root = fixture.topology.fixture_root().unwrap();
            let memory = root.join("memory/cleanup");
            let pids = root.join("pids/cleanup");
            fs::create_dir_all(&memory).unwrap();
            fs::create_dir_all(&pids).unwrap();
            fs::write(memory.join("tasks"), "123\n").unwrap();
            fs::write(root.join("memory/tasks"), "untouched").unwrap();
            if errno == libc::EISDIR {
                fs::create_dir(pids.join("tasks")).unwrap();
            }

            let error = manager.destroy().unwrap_err();
            let Error::Cgroupfs(error) = error else {
                panic!("expected cgroupfs membership failure");
            };
            assert_eq!(
                error.kind(),
                &FsErrorKind::ReadFailed(pids.join("tasks").display().to_string())
            );
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(errno)
            );
            assert_eq!(
                fs::read_to_string(root.join("memory/tasks")).unwrap(),
                "untouched"
            );
            assert!(!root.join("pids/tasks").exists());
            assert!(memory.is_dir());
            assert!(pids.is_dir());
        }
    }

    #[test]
    fn test_destroy_v2_does_not_replay_pid_zero() {
        for (members, expected_root) in [("0\n", "unchanged"), ("123\n0\n123\n", "123")] {
            let fixture = crate::tests::topology_fixture(CgroupVersion::V2, "memory");
            let manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("cleanup").unwrap(),
            )
            .unwrap();
            let root_procs = fixture
                .topology
                .fixture_root()
                .unwrap()
                .join("cgroup.procs");
            let directory = manager.controller::<MemController>().unwrap().path();
            let procs = directory.join("cgroup.procs");
            fs::create_dir_all(directory).unwrap();
            fs::write(&procs, members).unwrap();

            // Reading a namespace placeholder and explicitly requesting PID 0
            // remain valid; automatic migration must not replay that value.
            assert!(manager
                .cgroup
                .procs()
                .unwrap()
                .contains(&CgroupPid::from(0)));
            manager
                .cgroup
                .remove_task_by_tgid(CgroupPid::from(0))
                .unwrap();
            assert_eq!(fs::read_to_string(&root_procs).unwrap(), "0");
            fs::write(&root_procs, "unchanged").unwrap();

            manager
                .destroy_with(|cgroup| {
                    // These ordinary files prove which values are written,
                    // not kernel process migration or namespace visibility.
                    assert_eq!(fs::read_to_string(&root_procs).unwrap(), expected_root);
                    fs::remove_file(&procs).unwrap();
                    cgroup.delete()
                })
                .unwrap();
            assert!(!directory.exists());
        }
    }

    #[test]
    fn test_destroy_v1_does_not_replay_pid_zero() {
        for (members, expected_root) in [("0\n", "unchanged"), ("123\n0\n123\n", "123")] {
            let fixture = crate::tests::topology_fixture(CgroupVersion::V1, "memory");
            let manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("cleanup").unwrap(),
            )
            .unwrap();
            let root_tasks = fixture
                .topology
                .fixture_root()
                .unwrap()
                .join("memory")
                .join("tasks");
            let directory = manager.controller::<MemController>().unwrap().path();
            let tasks = directory.join("tasks");
            fs::create_dir_all(directory).unwrap();
            fs::write(&tasks, members).unwrap();

            assert!(manager
                .cgroup
                .tasks()
                .unwrap()
                .contains(&CgroupPid::from(0)));
            manager.cgroup.remove_task(CgroupPid::from(0)).unwrap();
            assert_eq!(fs::read_to_string(&root_tasks).unwrap(), "0");
            fs::write(&root_tasks, "unchanged").unwrap();

            manager
                .destroy_with(|cgroup| {
                    assert_eq!(fs::read_to_string(&root_tasks).unwrap(), expected_root);
                    fs::remove_file(&tasks).unwrap();
                    cgroup.delete()
                })
                .unwrap();
            assert!(!directory.exists());
        }
    }

    #[test]
    fn test_destroy_v2_after_concurrent_removal() {
        let fixture = crate::tests::topology_fixture(CgroupVersion::V2, "memory");
        let mut manager = FsManager::new(
            fixture.topology.clone(),
            CgroupPath::new("cleanup").unwrap(),
        )
        .unwrap();
        let directory = manager.controller::<MemController>().unwrap().path();
        fs::create_dir_all(directory).unwrap();

        manager
            .destroy_v2_with(
                |cgroup| {
                    // Model another remover winning after the existence check
                    // but before cgroup.procs is opened.
                    fs::remove_dir(directory).unwrap();
                    cgroup.procs()
                },
                |_| panic!("an already removed cgroup needs no deletion"),
            )
            .unwrap();
        assert!(!manager.exists());
        manager.destroy().unwrap();
    }

    #[test]
    fn test_destroy_v2_propagates_procs_io_failure() {
        let fixture = crate::tests::topology_fixture(CgroupVersion::V2, "memory");
        let manager = FsManager::new(
            fixture.topology.clone(),
            CgroupPath::new("cleanup").unwrap(),
        )
        .unwrap();
        let directory = manager.controller::<MemController>().unwrap().path();
        fs::create_dir_all(directory.join("cgroup.procs")).unwrap();

        let error = manager
            .destroy_with(|_| panic!("a failed membership read must prevent deletion"))
            .unwrap_err();
        let Error::Cgroupfs(error) = error else {
            panic!("expected cgroupfs membership failure");
        };
        assert_eq!(
            error.kind(),
            &FsErrorKind::ReadFailed(directory.join("cgroup.procs").display().to_string())
        );
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EISDIR)
        );
        assert!(directory.is_dir());
    }

    #[test]
    fn test_destroy_v2_threaded_cgroup_eopnotsupp() {
        let fixture = crate::tests::topology_fixture(CgroupVersion::V2, "memory");
        let manager = FsManager::new(
            fixture.topology.clone(),
            CgroupPath::new("cleanup").unwrap(),
        )
        .unwrap();
        let directory = manager.controller::<MemController>().unwrap().path();
        fs::create_dir_all(directory).unwrap();

        let mut deleted = false;
        manager
            .destroy_v2_with(
                |_| {
                    Err(FsError::with_cause(
                        FsErrorKind::ReadFailed(
                            directory.join("cgroup.procs").display().to_string(),
                        ),
                        std::io::Error::from_raw_os_error(libc::EOPNOTSUPP),
                    ))
                },
                |cgroup| {
                    deleted = true;
                    cgroup.delete()
                },
            )
            .unwrap();
        assert!(deleted);
        assert!(!directory.exists());
    }

    #[test]
    fn test_pids_before_creation_and_after_removal() {
        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("members").unwrap(),
            )
            .unwrap();
            let controller = manager.controller::<MemController>().unwrap();
            let directory = controller.path();
            let tasks = directory.join(if manager.v2() {
                "cgroup.threads"
            } else {
                "tasks"
            });

            assert!(manager.pids().unwrap().is_empty());
            // The lifecycle exception belongs only to the manager API.
            assert!(controller.tasks().unwrap_err().is_not_found());
            assert!(manager.cgroup.tasks().unwrap_err().is_not_found());

            fs::create_dir_all(directory).unwrap();
            fs::write(&tasks, "100\n101\n").unwrap();
            assert_eq!(
                manager.pids().unwrap(),
                [CgroupPid::from(100), CgroupPid::from(101)]
            );
            fs::remove_file(&tasks).unwrap();
            assert!(matches!(
                manager.pids().unwrap_err(),
                Error::Cgroupfs(error) if error.is_not_found()
            ));
            fs::remove_dir(directory).unwrap();
            assert!(manager.pids().unwrap().is_empty());
        }
    }

    #[test]
    fn test_pids_after_concurrent_removal() {
        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("members").unwrap(),
            )
            .unwrap();
            let directory = manager.controller::<MemController>().unwrap().path();
            fs::create_dir_all(directory).unwrap();

            let pids = manager
                .pids_with(|controller| {
                    // Model removal after the controller is selected and
                    // before its membership file is opened.
                    fs::remove_dir(controller.path()).unwrap();
                    controller.tasks()
                })
                .unwrap();
            assert!(pids.is_empty());
            assert!(!directory.exists());
        }
    }

    #[test]
    fn test_pids_preserves_other_read_errors_after_removal() {
        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("members").unwrap(),
            )
            .unwrap();
            // Even if the directory is now absent, an earlier permission or
            // I/O failure must not be downgraded to an empty membership list.
            for errno in [libc::EACCES, libc::EIO] {
                let error = manager
                    .pids_with(|_| {
                        Err(FsError::with_cause(
                            FsErrorKind::ReadFailed("membership".into()),
                            std::io::Error::from_raw_os_error(errno),
                        ))
                    })
                    .unwrap_err();
                let Error::Cgroupfs(error) = error else {
                    panic!("expected cgroupfs membership failure");
                };
                assert_eq!(
                    error
                        .source()
                        .unwrap()
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .raw_os_error(),
                    Some(errno)
                );
            }
        }
    }

    #[test]
    fn test_membership_errors_propagate_from_pids_and_destroy() {
        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let mut manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("membership-errors").unwrap(),
            )
            .unwrap();
            let directory = manager
                .controller::<MemController>()
                .unwrap()
                .path()
                .to_path_buf();
            fs::create_dir_all(&directory).unwrap();
            let tasks = directory.join(if manager.v2() {
                "cgroup.threads"
            } else {
                "tasks"
            });
            let procs = directory.join("cgroup.procs");
            fs::write(&tasks, "100\n101\n").unwrap();
            fs::write(&procs, "100\n").unwrap();
            assert_eq!(
                manager.pids().unwrap(),
                [CgroupPid::from(100), CgroupPid::from(101)]
            );

            for path in [&tasks, &procs] {
                fs::write(path, "100\ninvalid\n").unwrap();
            }
            for error in [manager.pids().unwrap_err(), manager.destroy().unwrap_err()] {
                assert!(
                    matches!(error, Error::Cgroupfs(ref error) if error.kind() == &FsErrorKind::ParseError)
                );
            }
            assert!(directory.is_dir());

            for path in [&tasks, &procs] {
                fs::remove_file(path).unwrap();
            }
            for error in [manager.pids().unwrap_err(), manager.destroy().unwrap_err()] {
                assert!(matches!(error, Error::Cgroupfs(ref error) if error.is_not_found()));
            }
            assert!(directory.is_dir());

            for path in [&tasks, &procs] {
                fs::create_dir(path).unwrap();
            }
            for error in [manager.pids().unwrap_err(), manager.destroy().unwrap_err()] {
                let Error::Cgroupfs(error) = error else {
                    panic!("expected cgroupfs membership failure");
                };
                assert!(matches!(error.kind(), FsErrorKind::ReadFailed(_)));
                assert_eq!(
                    error
                        .source()
                        .unwrap()
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .raw_os_error(),
                    Some(libc::EISDIR)
                );
            }
        }
    }

    #[test]
    fn test_stats_omit_cpu_accounting_when_required_reads_fail() {
        let fixture = crate::tests::TopologyFixture::new(
            b"41 33 0:31 / /sys/fs/cgroup/cpuacct rw - cgroup cgroup rw,cpuacct\n",
            b"1:cpuacct:/\n",
            "",
        );
        let manager = FsManager::new(
            fixture.topology.clone(),
            CgroupPath::new("accounting").unwrap(),
        )
        .unwrap();
        let directory = manager.controller::<CpuAcctController>().unwrap().path();
        fs::create_dir_all(directory).unwrap();
        assert!(manager.stats().cpu.cpu_acct.is_none());

        fs::write(directory.join("cpuacct.stat"), "user 0\nsystem 0\n").unwrap();
        fs::write(directory.join("cpuacct.usage"), "0\n").unwrap();
        fs::write(directory.join("cpuacct.usage_percpu"), "0\n").unwrap();
        assert_eq!(manager.stats().cpu.cpu_acct.unwrap().total_usage, 0);
    }

    #[test]
    fn test_managers_use_the_controller_selected_duplicate_v1_mount() {
        for duplicate_root in ["/", "/delegated"] {
            for reverse in [false, true] {
                for fixture_mapping in [false, true] {
                    let fixture = crate::tests::topology_fixture(CgroupVersion::V1, "memory");
                    let tree = fixture.topology.fixture_root().unwrap();
                    let primary = tree.join("memory");
                    let duplicate = tree.join("cpu");
                    for mount in [&primary, &duplicate] {
                        fs::create_dir_all(mount.join("workloads")).unwrap();
                        fs::write(mount.join("workloads/memory.limit_in_bytes"), "8192").unwrap();
                    }
                    let mount_points = if fixture_mapping {
                        [
                            Path::new("/sys/fs/cgroup/memory"),
                            Path::new("/sys/fs/cgroup/cpu"),
                        ]
                    } else {
                        [primary.as_path(), duplicate.as_path()]
                    };
                    let mut mounts = [
                        format!(
                            "30 26 0:26 / {} rw - cgroup cgroup rw,memory,cpu",
                            mount_points[0].display(),
                        ),
                        format!(
                            "31 26 0:26 {duplicate_root} {} rw - cgroup cgroup rw,memory,cpu",
                            mount_points[1].display(),
                        ),
                    ];
                    if reverse {
                        mounts.reverse();
                    }
                    let proc_self = fixture.topology.mountinfo_path().parent().unwrap();
                    fs::write(proc_self.join("mountinfo"), mounts.join("\n")).unwrap();
                    fs::write(
                        proc_self.join("cgroup"),
                        "1:memory,cpu:/delegated/current\n",
                    )
                    .unwrap();
                    let mut host_paths = HostPaths::new(
                        proc_self.parent().unwrap().to_path_buf(),
                        fixture.topology.hugepages().to_path_buf(),
                    );
                    if fixture_mapping {
                        host_paths = host_paths.with_fixture_root(tree.to_path_buf());
                    }
                    let topology = discover(&host_paths).unwrap();
                    fs::remove_dir_all(proc_self).unwrap();
                    let manager =
                        FsManager::new(topology, CgroupPath::new("workloads").unwrap()).unwrap();
                    let (selected, other, selected_root) = if reverse {
                        (&duplicate, &primary, duplicate_root)
                    } else {
                        (&primary, &duplicate, "/")
                    };
                    let selected_mounts = manager.mounts();
                    assert_eq!(selected_mounts.len(), 2);
                    assert_eq!(manager.cgroup.subsystems().len(), 2);
                    for subsystem in manager.cgroup.subsystems() {
                        let controller = subsystem.to_controller();
                        let mount = &selected_mounts[&subsystem.controller_name()];
                        assert_eq!(mount, selected);
                        assert_eq!(mount.join("workloads"), controller.path());
                        assert_eq!(controller.base(), Path::new(selected_root));
                    }
                    // Ordinary files verify the write destination, not kernel
                    // resource enforcement or bind-mount aliasing.
                    let memory = LinuxMemoryBuilder::default().limit(4096).build().unwrap();
                    manager.set_memory(&memory).unwrap();
                    assert_eq!(
                        fs::read_to_string(selected.join("workloads/memory.limit_in_bytes"))
                            .unwrap(),
                        "4096",
                    );
                    assert_eq!(
                        fs::read_to_string(other.join("workloads/memory.limit_in_bytes")).unwrap(),
                        "8192",
                    );

                    let systemd = crate::oci::SystemdManager::new(
                        manager.topology().clone(),
                        "test.slice:scope:unit",
                    )
                    .unwrap();
                    assert_eq!(systemd.mounts(), manager.mounts());
                    assert!(Arc::ptr_eq(systemd.topology(), manager.topology()));
                }
            }
        }
    }

    #[test]
    fn test_managers_preserve_disjoint_v1_mounts_without_rediscovery() {
        for reverse in [false, true] {
            for optional_v2 in [false, true] {
                let fixture = crate::tests::topology_fixture(CgroupVersion::V1, "memory");
                let scratch = fixture.topology.fixture_root().unwrap();
                let memory_mount = scratch.join("cgroups/memory");
                let cpu_mount = scratch.join("external/cpu");
                let unified_mount = scratch.join("unified");
                for mount in [&memory_mount, &cpu_mount, &unified_mount] {
                    fs::create_dir_all(mount).unwrap();
                }
                let mut mounts = vec![
                    format!(
                        "30 26 0:26 / {} rw - cgroup cgroup rw,memory",
                        memory_mount.display(),
                    ),
                    format!(
                        "31 26 0:27 / {} rw - cgroup cgroup rw,cpu",
                        cpu_mount.display(),
                    ),
                ];
                let mut membership = "1:memory:/current\n2:cpu:/current\n".to_string();
                if optional_v2 {
                    // An ordinary directory fails cgroup2 statfs verification.
                    // This optional failure must leave both v1 mounts usable.
                    mounts.push(format!(
                        "32 26 0:28 / {} rw - cgroup2 cgroup2 rw",
                        unified_mount.display(),
                    ));
                    membership.push_str("0::/\n");
                }
                if reverse {
                    mounts.reverse();
                }
                let mountinfo_path = fixture.topology.mountinfo_path();
                let proc_self = mountinfo_path.parent().unwrap();
                fs::write(mountinfo_path, mounts.join("\n")).unwrap();
                fs::write(proc_self.join("cgroup"), membership).unwrap();
                // The mount points already name temporary directories, so no
                // fixture-root mapping is requested on this discovery path.
                let host_paths = HostPaths::new(
                    proc_self.parent().unwrap().to_path_buf(),
                    fixture.topology.hugepages().to_path_buf(),
                );
                let topology = discover(&host_paths).unwrap();
                fs::remove_dir_all(proc_self).unwrap();
                let manager =
                    FsManager::new(topology, CgroupPath::new("workloads").unwrap()).unwrap();
                assert_eq!(manager.topology().version(), CgroupVersion::V1);
                assert!(manager.topology().cgroupfs_root().is_none());
                assert!(!manager.topology().v2_available());
                assert_eq!(manager.mounts()["memory"], memory_mount);
                assert_eq!(manager.mounts()["cpu"], cpu_mount);
                let memory: &MemController = manager.cgroup.controller_of().unwrap();
                let cpu: &CpuController = manager.cgroup.controller_of().unwrap();
                assert_eq!(memory.path(), memory_mount.join("workloads"));
                assert_eq!(cpu.path(), cpu_mount.join("workloads"));

                let systemd = crate::oci::SystemdManager::new(
                    manager.topology().clone(),
                    "test.slice:scope:unit",
                )
                .unwrap();
                assert_eq!(systemd.mounts(), manager.mounts());
                assert!(Arc::ptr_eq(systemd.topology(), manager.topology()));
                assert!(Arc::ptr_eq(
                    &manager.cgroup.topology().unwrap(),
                    manager.topology(),
                ));
            }
        }
    }

    #[test]
    fn test_new_preserves_non_utf8_base() {
        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let root = fixture.topology.fixture_root().unwrap();
            let (mount, limit_file) = match version {
                CgroupVersion::V1 => (root.join("memory"), "memory.limit_in_bytes"),
                CgroupVersion::V2 => (root.to_path_buf(), "memory.max"),
            };
            let base = CgroupPath::new(OsStr::from_bytes(b"workloads/\xff")).unwrap();
            let path = mount.join(base.as_path());
            let manager = FsManager::new(fixture.topology.clone(), base).unwrap();
            let memory: &MemController = manager.cgroup.controller_of().unwrap();
            assert_eq!(memory.path(), path);

            // Ordinary files verify the write destination, not kernel enforcement.
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join(limit_file), "8192").unwrap();
            let resources = LinuxMemoryBuilder::default().limit(4096).build().unwrap();
            manager.set_memory(&resources).unwrap();
            assert_eq!(fs::read_to_string(path.join(limit_file)).unwrap(), "4096");
        }
    }

    #[test]
    fn test_subcgroup_uses_only_the_unified_mount() {
        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let root = fixture.topology.fixture_root().unwrap();
            let manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("workloads").unwrap(),
            )
            .unwrap();
            assert!(Arc::ptr_eq(manager.topology(), &fixture.topology));
            assert!(Arc::ptr_eq(
                &manager.cgroup.topology().unwrap(),
                &fixture.topology
            ));
            assert_eq!(manager.subcgroup().unwrap(), "/");
            // This ordinary directory only verifies the legacy path policy;
            // it does not model kernel delegation or process migration.
            fs::create_dir_all(root.join("workloads/init")).unwrap();
            assert_eq!(
                manager.subcgroup().unwrap(),
                if version == CgroupVersion::V2 {
                    "/init/"
                } else {
                    "/"
                }
            );
        }
    }

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
        let manager = FsManager::new(topology, CgroupPath::root()).unwrap();
        let mounts = manager.mounts();

        for dir in dirs.iter().rev() {
            let dir = CgroupPath::new(dir).unwrap();
            if manager.v2() {
                let path = manager
                    .topology()
                    .cgroupfs_root()
                    .unwrap()
                    .join(dir.as_path());
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
                for mountpoint in mounts.values() {
                    let path = mountpoint.join(dir.as_path());
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
        let topology = discover(&HostPaths::default()).unwrap();
        FsManager::new(topology, CgroupPath::new(TEST_BASE).unwrap()).unwrap()
    }

    fn managed_cgroup_path(manager: &FsManager, subsystem: Option<&str>) -> PathBuf {
        if manager.v2() {
            return manager
                .topology
                .cgroupfs_root()
                .unwrap()
                .join(manager.base.as_path());
        }

        let subsystem = subsystem.expect("cgroup v1 requires a subsystem");
        manager
            .mounts()
            .get(subsystem)
            .expect("cgroup v1 subsystem mountpoint should exist")
            .join(manager.base.as_path())
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
    fn test_memberships_and_mounts() {
        skip_if_not_root!();

        let mut manager = new_manager();

        for (subsystem, mountpoint) in manager.mounts() {
            let observed = manager.cgroup_path(Some(&subsystem)).unwrap();
            let path = CgroupPath::from_proc_cgroup_path(&observed).unwrap();
            let path = mountpoint.join(path.as_path());
            assert!(path.exists(), "Cgroup {} does not exist", path.display());
        }

        manager.destroy().unwrap();
    }

    #[test]
    fn test_destroy() {
        skip_if_not_root!();

        let mut manager = new_manager();
        manager.create_cgroups().unwrap();

        let cgroup_path = managed_cgroup_path(&manager, (!manager.v2()).then_some("memory"));
        assert!(cgroup_path.exists(), "Cgroup should exist before destroy");

        manager.destroy().unwrap();
        assert!(
            !cgroup_path.exists(),
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
            let memory_stat = controller.memory_stat();
            let memory_swap_stat = controller.memswap();

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
            let memory_stat = controller.memory_stat();
            let memory_swap_stat = controller.memswap();

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
            let cpuset_cpus_path = managed_path.join("cpuset.cpus");
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

/// Byte-preserving manager queries over supplied topology snapshots.
#[cfg(test)]
mod parse_tests {
    use super::FsManager;
    use crate::core::{discover, parse_mountinfo_bytes, CgroupPath, CgroupVersion, HostPaths};
    use crate::fs::error::ErrorKind;
    use crate::fs::hierarchies;
    use crate::fs::memory::MemController;
    use crate::fs::Controller;
    use crate::oci::{Error, Manager, SystemdManager};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn test_memberships_borrow_raw_snapshot_without_rediscovery() {
        for observed in [
            b"/scope:\xff".as_slice(),
            b"/../sibling.scope".as_slice(),
            b"/a/../sibling.scope".as_slice(),
            b"/scope-with-cr\r".as_slice(),
        ] {
            let mut membership = b"7:memory,cpu:".to_vec();
            membership.extend_from_slice(observed);
            membership.extend_from_slice(b"\n8:name=systemd:/system.slice\n0::/\n");
            let fixture = crate::tests::TopologyFixture::new(
                b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory,cpu\n\
                  44 33 0:39 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd\n",
                &membership,
                "",
            );
            fs::remove_dir_all(fixture.topology.mountinfo_path().parent().unwrap()).unwrap();
            let fs_manager = FsManager::new(
                fixture.topology.clone(),
                CgroupPath::new("workloads").unwrap(),
            )
            .unwrap();
            let systemd_manager =
                SystemdManager::new(fixture.topology.clone(), "test.slice:scope:unit").unwrap();

            // Exercise the trait through both backends, with procfs unavailable.
            for manager in [&fs_manager as &dyn Manager, &systemd_manager] {
                let memberships = manager.memberships();
                assert!(std::ptr::eq(memberships, fixture.topology.membership()));
                let records = memberships.records();
                assert_eq!(records.len(), 3);
                assert_eq!(records[0].hierarchy_id, 7);
                assert_eq!(records[0].controllers, ["memory", "cpu"]);
                assert_eq!(records[0].path.as_os_str().as_bytes(), observed);
                assert_eq!(records[1].controllers, ["name=systemd"]);
                assert_eq!(memberships.unified().unwrap().hierarchy_id, 0);
                for controller in ["memory", "cpu"] {
                    assert_eq!(
                        manager
                            .cgroup_path(Some(controller))
                            .unwrap()
                            .as_os_str()
                            .as_bytes(),
                        observed
                    );
                }
                assert_eq!(
                    manager.cgroup_path(Some("name=systemd")).unwrap(),
                    std::path::Path::new("/system.slice")
                );
                assert!(matches!(
                    manager.cgroup_path(None),
                    Err(Error::Cgroupfs(error)) if matches!(error.kind(), ErrorKind::InvalidPath)
                ));
                assert!(matches!(
                    manager.cgroup_path(Some("pids")),
                    Err(Error::Cgroupfs(error)) if matches!(error.kind(), ErrorKind::SubsystemsEmpty)
                ));
            }
        }
    }

    #[test]
    fn test_managers_preserve_non_utf8_mount_and_membership_paths() {
        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let mount_point = fixture
                .topology
                .fixture_root()
                .unwrap()
                .join(OsStr::from_bytes(b"mount-\xff"));
            fs::create_dir_all(&mount_point).unwrap();
            fs::write(mount_point.join("cgroup.controllers"), "memory").unwrap();
            fs::write(mount_point.join("cgroup.subtree_control"), "").unwrap();
            let proc_self = fixture.topology.mountinfo_path().parent().unwrap();
            let mut mountinfo = b"47 44 0:30 / ".to_vec();
            mountinfo.extend_from_slice(mount_point.as_os_str().as_bytes());
            let (options, membership) = match version {
                CgroupVersion::V1 => (
                    b" rw - cgroup cgroup rw,memory\n".as_slice(),
                    b"7:memory:/current:\xfe\r\n".as_slice(),
                ),
                CgroupVersion::V2 => (
                    b" rw - cgroup2 cgroup2 rw\n".as_slice(),
                    b"0::/current:\xfe\r\n".as_slice(),
                ),
            };
            mountinfo.extend_from_slice(options);
            fs::write(proc_self.join("mountinfo"), mountinfo).unwrap();
            fs::write(proc_self.join("cgroup"), membership).unwrap();
            let mut host_paths = HostPaths::new(
                proc_self.parent().unwrap().to_path_buf(),
                fixture.topology.hugepages().to_path_buf(),
            );
            if version == CgroupVersion::V2 {
                // An ordinary directory needs fixture mode to skip cgroup2 statfs.
                host_paths = host_paths.with_fixture_root(mount_point.clone());
            }
            let topology = discover(&host_paths).unwrap();
            fs::remove_dir_all(proc_self).unwrap();
            let base = CgroupPath::new(OsStr::from_bytes(b"workloads/base-\xfe")).unwrap();
            let fs_manager = FsManager::new(topology.clone(), base.clone()).unwrap();
            let systemd_manager =
                SystemdManager::new(topology.clone(), "test.slice:scope:unit").unwrap();
            let controller: &MemController = fs_manager.cgroup.controller_of().unwrap();
            assert_eq!(controller.path(), mount_point.join(base.as_path()));

            for manager in [&fs_manager as &dyn Manager, &systemd_manager] {
                assert!(std::ptr::eq(manager.memberships(), topology.membership()));
                assert_eq!(
                    manager.memberships().records()[0]
                        .path
                        .as_os_str()
                        .as_bytes(),
                    b"/current:\xfe\r"
                );
                if version == CgroupVersion::V1 {
                    assert_eq!(manager.mounts().get("memory"), Some(&mount_point));
                    assert_eq!(
                        manager
                            .cgroup_path(Some("memory"))
                            .unwrap()
                            .as_os_str()
                            .as_bytes(),
                        b"/current:\xfe\r"
                    );
                } else {
                    assert!(manager.mounts().is_empty());
                }
            }
            if version == CgroupVersion::V2 {
                assert_eq!(
                    fs_manager.cgroup_path(None).unwrap(),
                    mount_point.join(base.as_path())
                );
                assert_eq!(
                    systemd_manager.cgroup_path(None).unwrap(),
                    mount_point.join("test.slice/scope-unit.scope")
                );
            }
        }
    }

    /// Kernel-drift canary: read the real `/proc/self/mountinfo` and confirm
    /// the parser still copes with whatever the running kernel produces.
    ///
    /// Fixtures lock our changes to the parser; this locks the parser against
    /// the live host. The realistic risk is not format breakage (`/proc` is
    /// userspace ABI) but additions: new controllers, new fields. If a kernel
    /// change makes the strict stream parser reject the mount table, this
    /// fails at the source instead of surfacing indirectly as "couldn't find
    /// the memory controller" in a downstream integration test.
    ///
    /// Parse the complete byte stream, then verify that strict discovery
    /// retains mounts for the primary hierarchy. Named v1 mounts may remain
    /// visible on a v2-primary host.
    #[test]
    #[ignore = "requires a controlled cgroup hierarchy; run explicitly in QEMU"]
    fn test_live_mountinfo_canary() {
        let data = fs::read("/proc/self/mountinfo")
            .expect("canary: /proc/self/mountinfo must be readable");

        let mounts = parse_mountinfo_bytes(&data)
            .expect("canary: the complete live mountinfo stream must parse");
        assert!(
            !mounts.cgroup_mounts().is_empty() || !mounts.unified_mounts().is_empty(),
            "canary: no cgroup/cgroup2 mounts parsed from live /proc/self/mountinfo; \
             parser may have regressed on a kernel format change"
        );

        let hierarchy = hierarchies::auto().expect("canary: strict host discovery must succeed");
        let topology = hierarchy
            .topology()
            .expect("built-in hierarchies have a snapshot");
        if hierarchy.v2() {
            assert!(
                !topology.mounts().unified_mounts().is_empty(),
                "canary: no unified mount retained on a v2-primary host"
            );
        } else {
            assert!(
                !topology.mounts().cgroup_mounts().is_empty(),
                "canary: no v1 cgroup mounts retained on a v1/hybrid host; \
                 parser may have regressed"
            );
        }
    }
}
