// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use oci_spec::runtime::{
    LinuxBlockIo, LinuxCpu, LinuxDeviceCgroup, LinuxHugepageLimit, LinuxMemory, LinuxNetwork,
    LinuxPids, LinuxResources,
};

use crate::core::discovery::membership::{parse_membership_bytes, CgroupMembership};
use crate::core::discovery::mountinfo::parse_mountinfo_bytes;
use crate::core::error::{CoreError, ParseMembershipError, ParseMountError};
use crate::core::path::CgroupPath;
use crate::fs::blkio::{BlkIoController, BlkIoData, IoService, IoStat};
use crate::fs::cgroup::UNIFIED_MOUNTPOINT;
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
use crate::oci::error::Error;
use crate::oci::{conv, Manager, Result};
use crate::stats::{
    BlkioCgroupStats, BlkioStat, CpuAcctStats, CpuCgroupStats, CpuThrottlingStats,
    HugeTlbCgroupStats, HugeTlbStat, MemoryCgroupStats, MemoryStats, PidsCgroupStats,
};
use crate::{CgroupPid, CgroupStats, FreezerState};

const CGROUP_PATH: &str = "/proc/self/cgroup";
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

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
    /// Base path of the cgroup filesystem, the complete path would be:
    /// - cgroup v1: "/sys/fs/cgroup/<subsystem>/<base>"
    /// - cgroup v2: "/sys/fs/cgroup/<base>"
    base: String,
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
    pub fn new(base: &str) -> Result<Self> {
        let paths = parse_cgroup_subsystems()?;
        let mounts = parse_cgroup_mountinfo(&paths)?;
        let cgroup = Cgroup::load(hierarchies::auto(), base);
        let base = base.to_string();

        Ok(Self {
            paths,
            mounts,
            base,
            cgroup,
        })
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
        let init_exists = hierarchies::auto()
            .root()
            .join(&self.base)
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
        let root = hierarchies::auto().root_control_group();
        let controller: &T = root
            .controller_of()
            .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))?;
        let root_path = Path::new(controller.path());
        let root_path_str = root_path.to_string_lossy().to_string();

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
                .to_str()
                .unwrap()
                .trim_start_matches(&root_path_str)
                // Makes sure the starting slash is removed
                .trim_start_matches("/");
            let cgroup = Cgroup::new(hierarchies::auto(), relative_path)?;
            let controller: &T = cgroup
                .controller_of()
                .ok_or(FsError::new(FsErrorKind::SubsystemsEmpty))?;
            f(controller)?;
        }

        Ok(())
    }

    fn cpu_acct_stats(&self) -> Result<CpuAcctStats> {
        let controller: &CpuAcctController = self.controller()?;
        let cpu_acct = controller.cpuacct();

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
        Ok(self
            .controller::<MemController>()
            .map_err(Error::Cgroupfs)?
            .tasks())
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
            for tgid in self.cgroup.procs() {
                // Ignore all errors as long as the cgroup is deleted.
                let _ = self.cgroup.remove_task_by_tgid(tgid);
            }
        } else {
            for pid in self.cgroup.tasks() {
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
            return Ok(join_path(UNIFIED_MOUNTPOINT, &self.base));
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

/// Parse cgroup subsystem paths from a `/proc/self/cgroup` content string.
///
/// Transitional view conversion over [`parse_membership_bytes`]: parse errors
/// are propagated (preserved as the error cause), colons inside a cgroup
/// path survive, and unified-hierarchy records keep the legacy
/// `"" -> <path>` entry documented on [`FsManager`]. Paths that cannot be
/// used for cgroup mutation, including namespace-relative `..` paths, fail
/// conversion even though they remain valid procfs observations.
#[cfg(test)]
fn parse_cgroup_subsystems_str(input: &str) -> Result<HashMap<String, String>> {
    parse_cgroup_subsystems_bytes(input.as_bytes())
}

fn parse_cgroup_subsystems_bytes(input: &[u8]) -> Result<HashMap<String, String>> {
    let membership = parse_membership_bytes(input).map_err(CoreError::from)?;
    membership_to_legacy_paths(&membership)
}

fn membership_to_legacy_paths(membership: &CgroupMembership) -> Result<HashMap<String, String>> {
    let mut cgroup_paths = HashMap::new();
    for (index, record) in membership.records().iter().enumerate() {
        // A membership path is only an observation until it passes the
        // mutation-path check; FsManager exposes the converted paths to callers.
        let path = CgroupPath::from_proc_cgroup_path(&record.path).map_err(CoreError::from)?;
        let path = path.as_path().to_str().ok_or_else(|| {
            CoreError::ParseMembershipError(ParseMembershipError::LegacyPathNotUtf8 {
                line: index + 1,
                input: record.path.clone(),
            })
        })?;
        let path = format!("/{path}");
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
    Ok(cgroup_paths)
}

/// Parse cgroup subsystem paths from `/proc/self/cgroup`.
///
/// Malformed content is a discovery error, not an empty map.
fn parse_cgroup_subsystems() -> Result<HashMap<String, String>> {
    let data = fs::read(CGROUP_PATH)
        .map_err(|err| FsError::with_cause(FsErrorKind::FsError, err))
        .map_err(Error::Cgroupfs)?;
    parse_cgroup_subsystems_bytes(&data)
}

/// Parse cgroup mount information from a `/proc/self/mountinfo` content string.
#[cfg(test)]
fn parse_cgroup_mountinfo_str(
    data: &str,
    paths: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    parse_cgroup_mountinfo_bytes(data.as_bytes(), paths)
}

fn parse_cgroup_mountinfo_bytes(
    data: &[u8],
    paths: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut mounts = HashMap::new();
    let mountinfo = parse_mountinfo_bytes(data).map_err(CoreError::from)?;

    for (index, mi) in mountinfo.records().iter().enumerate() {
        if mi.fs_type.0 != "cgroup" && mi.fs_type.0 != "cgroup2" {
            continue;
        }
        let mountpoint = mi.mount_point.to_str().ok_or_else(|| {
            CoreError::ParseMountError(ParseMountError::LegacyMountPointNotUtf8 {
                line: index + 1,
                input: mi.mount_point.clone(),
            })
        })?;
        for opt in &mi.super_opts {
            if let Some(controller) = paths.keys().find(|name| name.as_bytes() == opt.as_slice()) {
                mounts.insert(controller.to_string(), mountpoint.to_string());
            }
        }
    }

    Ok(mounts)
}

/// Parse cgroup mount information from `/proc/self/mountinfo`.
fn parse_cgroup_mountinfo(paths: &HashMap<String, String>) -> Result<HashMap<String, String>> {
    let data = fs::read(MOUNTINFO_PATH)
        .map_err(|err| FsError::with_cause(FsErrorKind::FsError, err))
        .map_err(Error::Cgroupfs)?;

    parse_cgroup_mountinfo_bytes(&data, paths)
}

pub(crate) fn join_path(base: &str, path: &str) -> String {
    let base = Path::new(base);
    base.join(path).to_string_lossy().to_string()
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

    use crate::oci::fs::*;
    use crate::oci::tests::{MEMORY_1G, MEMORY_2G, MEMORY_512M};
    use crate::tests::spawn_sleep_inf;
    use crate::{skip_if_cgroups_v1, skip_if_cgroups_v2, skip_if_not_root};

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

        for dir in dirs.iter().rev() {
            let paths = parse_cgroup_subsystems().unwrap();
            let mounts = parse_cgroup_mountinfo(&paths).unwrap();

            if hierarchies::is_cgroup2_unified_mode() {
                let full = join_path(UNIFIED_MOUNTPOINT, dir);
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
                    let full = join_path(mountpoint, paths.get(subsystem).unwrap());
                    let full = join_path(&full, dir);
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
        if manager.v2() {
            return join_path(UNIFIED_MOUNTPOINT, &manager.base);
        }

        let subsystem = subsystem.expect("cgroup v1 requires a subsystem");
        let mountpoint = manager
            .mounts
            .get(subsystem)
            .expect("cgroup v1 subsystem mountpoint should exist");
        join_path(mountpoint, &manager.base)
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
    fn test_paths_and_mounts() {
        skip_if_not_root!();

        let mut manager = new_manager();

        for (subsystem, mountpoint) in manager.mounts() {
            let path = manager.paths().get(subsystem).unwrap();
            let path = join_path(mountpoint, path.trim_start_matches('/'));
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
            let cpuset_cpus_path = join_path(&managed_path, "cpuset.cpus");
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

/// Host-independent parser tests for `parse_cgroup_subsystems_str`.
///
/// Input and expectation are kept adjacent in inline tables so failures pin an
/// exact (controller, path) pair instead of a vague "is_empty" / "contains_key".
#[cfg(test)]
mod parse_tests {
    use super::{
        parse_cgroup_mountinfo_bytes, parse_cgroup_mountinfo_str, parse_cgroup_subsystems_bytes,
        parse_cgroup_subsystems_str,
    };
    use crate::core::discovery::membership::parse_membership_bytes;
    use crate::core::error::{CoreError, ParseMountError, PathError};
    use crate::fs::hierarchies;
    use crate::oci::error::Error;
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
            input: "0::/user.slice/session:c1.scope\n6:memory:/docker/ab:cd/init",
            expect: Some(&[
                ("", "/user.slice/session:c1.scope"),
                ("memory", "/docker/ab:cd/init"),
            ]),
        },
        Case {
            name: "malformed: duplicate unified hierarchy is rejected",
            input: "0::/kubepods/burstable/pod-abc123/cri-containerd-xyz/init\n0::/kubepods/burstable/pod-abc123/cri-containerd-xyz/exec",
            expect: None,
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
            let got = parse_cgroup_subsystems_str(case.input);
            match case.expect {
                None => assert!(
                    matches!(got, Err(Error::Core(CoreError::ParseMembershipError(_)))),
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
    fn test_parse_cgroup_subsystems_bytes_preserves_trailing_carriage_return() {
        let paths = parse_cgroup_subsystems_bytes(b"0::/scope-with-cr\r\n").unwrap();
        assert_eq!(paths.get(""), Some(&"/scope-with-cr\r".to_string()));

        assert!(matches!(
            parse_cgroup_subsystems_bytes(b"0::/non-utf8-\xff\n"),
            Err(Error::Core(CoreError::ParseMembershipError(_)))
        ));
    }

    #[test]
    fn test_parse_cgroup_subsystems_rejects_observed_parent_paths() {
        for input in [
            b"0::/../sibling.scope\n".as_slice(),
            b"7:memory:/a/../sibling.scope\n".as_slice(),
        ] {
            let membership = parse_membership_bytes(input).unwrap();
            let observed_path = membership.records()[0].path.clone();
            assert!(matches!(
                parse_cgroup_subsystems_bytes(input),
                Err(Error::Core(CoreError::PathError(
                    PathError::ParentComponent { input, operation }
                ))) if input == observed_path && operation == "CgroupPath::from_proc_cgroup_path"
            ));
        }
    }

    #[test]
    fn test_parse_cgroup_mountinfo_str() {
        let mut paths = HashMap::new();
        paths.insert("memory".to_string(), "/user.slice".to_string());
        paths.insert("cpu".to_string(), "/user.slice".to_string());
        paths.insert("cpuacct".to_string(), "/user.slice".to_string());
        paths.insert("pids".to_string(), "/user.slice".to_string());

        let input = "\
31 22 0:26 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,memory
32 22 0:27 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,cpu,cpuacct
121 1731 0:42 / /shm rw,nosuid,nodev,noexec,relatime shared:68 master:66 - tmpfs shm rw,size=65536k
";

        let mounts = parse_cgroup_mountinfo_str(input, &paths).unwrap();
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

    #[test]
    fn test_parse_cgroup_mountinfo_rejects_malformed_line() {
        let paths = HashMap::from([("memory".to_string(), "/user.slice".to_string())]);
        let input = b"31 22 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
bad mountinfo line\n";

        assert!(matches!(
            parse_cgroup_mountinfo_bytes(input, &paths),
            Err(Error::Core(CoreError::ParseMountError(
                ParseMountError::MissingSeparator { line: 2 }
            )))
        ));
    }

    #[test]
    fn test_parse_cgroup_mountinfo_bytes_matches_ascii_controller() {
        let paths = HashMap::from([("memory".to_string(), "/user.slice".to_string())]);
        let input = b"31 22 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory,release_agent=/tmp/agent-\xff\n\
32 22 0:27 / /sys/fs/cgroup/other rw - cgroup cgroup rw,memory\xff\n";

        let mounts = parse_cgroup_mountinfo_bytes(input, &paths).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(
            mounts.get("memory"),
            Some(&"/sys/fs/cgroup/memory".to_string())
        );
    }

    /// TODO: deferred `mounts()` contract defect.
    ///
    /// In cgroup v2 (unified hierarchy), `/proc/self/cgroup` contains `0::<path>`,
    /// which `parse_cgroup_subsystems_str` parses into the key `""`.
    /// However, a normal cgroup2 mount in `/proc/self/mountinfo`:
    ///   `47 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw,nsdelegate`
    /// has super-options such as `rw,nsdelegate` (never `""`).
    ///
    /// Because `parse_cgroup_mountinfo_str` matches mount super-options against
    /// keys in `paths` (`paths.contains_key(opt)`), it never matches the `""`
    /// key. Therefore, `parse_cgroup_mountinfo_str` currently returns no mount
    /// mapping for unified v2, even though `cgroup2` is explicitly recognized in
    /// `mi.fs_type.0`.
    ///
    /// This characterization test pins the current counterintuitive behavior so
    /// any future fix to the `mounts()` contract for cgroup v2 can flip this
    /// expectation intentionally.
    #[test]
    fn test_parse_cgroup_mountinfo_str_cgroup2() {
        let cgroup_data = "0::/user.slice/user-1000.slice/session-4.scope";
        let paths = parse_cgroup_subsystems_str(cgroup_data).unwrap();
        assert_eq!(
            paths.get(""),
            Some(&"/user.slice/user-1000.slice/session-4.scope".to_string())
        );

        let mountinfo_data = "\
47 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw,nsdelegate
";
        let mounts = parse_cgroup_mountinfo_str(mountinfo_data, &paths).unwrap();

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
    /// change makes `parse_mountinfo_for_line` reject every cgroup line, this
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

        let cgroup_mounts: Vec<_> = data
            .lines()
            .filter_map(hierarchies::parse_mountinfo_for_line)
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
}
