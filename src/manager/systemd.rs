use crate::model::AttachDestination;
// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::collections::HashMap;
use std::sync::Arc;

use oci_spec::runtime::{LinuxCpu, LinuxMemory, LinuxPids, LinuxResources};
use zbus::zvariant::Value as ZbusValue;

use crate::discovery::{discover, CgroupTopology, CgroupVersion, HostPaths};
use crate::manager::conv;
use crate::manager::error::{Error, Result};
use crate::manager::fs::{join_path, FsManager};
use crate::systemd::props::PropertiesBuilder;
use crate::systemd::utils::expand_slice;
use crate::systemd::{
    cpu, cpuset, memory, pids, Property, SystemdClient, DEFAULT_SLICE, SCOPE_SUFFIX, SLICE_SUFFIX,
    TIMEOUT_STOP_USEC,
};
use crate::{CgroupPid, CgroupStats, FreezerState, Manager};

/// Default kernel value for cpu quota period is 100000 us (100 ms), same
/// for v1 [1] and v2 [2].
///
/// 1: https://www.kernel.org/doc/html/latest/scheduler/sched-bwc.html
/// 2: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
const DEFAULT_CPU_QUOTA_PERIOD: u64 = 100_000; // 100ms

pub struct SystemdManager<'a> {
    /// The name of slice
    slice: String,
    /// The name of unit
    unit: String,
    /// Systemd client
    systemd_client: SystemdClient<'a>,
    /// Cgroupfs manager
    fs_manager: FsManager,
    /// Default destination
    default_destination: AttachDestination,
}

impl SystemdManager<'_> {
    fn parse_slice_and_unit(path: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = path.split(':').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidArgument);
        }

        let slice = if parts[0].is_empty() {
            DEFAULT_SLICE.to_string()
        } else {
            parts[0].to_string()
        };

        let unit = new_unit_name(parts[1], parts[2]);

        Ok((slice, unit))
    }

    /// Create a new `SystemdManager` from a cgroup path.
    ///
    /// # Arguments
    ///
    /// * `path` - A string slice that holds the cgroup path in the format
    ///   "parent:scope_prefix:name".
    pub fn new(path: &str) -> Result<Self> {
        Self::with_host_paths(path, &HostPaths::default())
    }

    /// Create a `SystemdManager` from a cgroup path using explicit host paths for discovery.
    pub fn with_host_paths(path: &str, host_paths: &HostPaths) -> Result<Self> {
        let topology = discover(host_paths).map_err(Error::Core)?;
        Self::with_topology_and_host_paths(path, topology, host_paths.clone())
    }

    /// Create a `SystemdManager` using an already-discovered topology snapshot.
    pub fn with_topology(path: &str, topology: Arc<CgroupTopology>) -> Result<Self> {
        Self::with_topology_and_host_paths(path, topology, HostPaths::default())
    }

    /// Create a `SystemdManager` using an already-discovered topology snapshot
    /// and explicit host paths for later process-membership lookups.
    pub fn with_topology_and_host_paths(
        path: &str,
        topology: Arc<CgroupTopology>,
        host_paths: HostPaths,
    ) -> Result<Self> {
        let (slice, unit) = Self::parse_slice_and_unit(path)?;
        let v2 = topology.version == CgroupVersion::V2;
        let props = PropertiesBuilder::default_cgroup(&slice, &unit).build_with_v2(v2);
        let slice_base = expand_slice(&slice)?;

        let fs_base = join_path(&slice_base, &unit)?;
        let fs_manager = FsManager::with_topology_and_host_paths(&fs_base, topology, host_paths)?;

        let cgroup = SystemdClient::new(&unit, props)?;

        Ok(Self {
            slice,
            unit,
            fs_manager,
            systemd_client: cgroup,
            default_destination: AttachDestination::default(),
        })
    }

    /// Return the topology snapshot held by this manager.
    pub fn topology(&self) -> &Arc<CgroupTopology> {
        self.fs_manager.topology()
    }

    /// Set the default attachment destination used by [`Manager::add_proc`]
    /// and [`Manager::add_thread`].
    pub fn set_default_destination(&mut self, destination: AttachDestination) {
        self.default_destination = destination;
    }

    /// Builder method to set the default attachment destination.
    pub fn with_default_destination(mut self, destination: AttachDestination) -> Self {
        self.default_destination = destination;
        self
    }

    /// Return the current default attachment destination.
    pub fn default_destination(&self) -> &AttachDestination {
        &self.default_destination
    }
}

impl SystemdManager<'_> {
    /// Get the slice name.
    pub fn slice(&self) -> &str {
        &self.slice
    }

    /// Get the unit name.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    fn set_cpuset(&self, props: &mut Vec<Property>, linux_cpu: &LinuxCpu) -> Result<()> {
        if let Some(cpus) = linux_cpu.cpus().as_ref() {
            let (id, value) = cpuset::cpus(cpus)?;
            props.push((id, value.into()));
        }

        if let Some(mems) = linux_cpu.mems().as_ref() {
            let (id, value) = cpuset::mems(mems)?;
            props.push((id, value.into()));
        }

        Ok(())
    }

    fn set_cpu(&self, props: &mut Vec<Property>, linux_cpu: &LinuxCpu) -> Result<()> {
        if let Some(shares) = linux_cpu.shares() {
            let shares = if self.v2() {
                conv::cpu_shares_to_cgroup_v2(shares)
            } else {
                shares
            };
            let (id, value) = cpu::shares(shares, self.v2())?;
            props.push((id, value.into()));
        }

        let period = linux_cpu.period().unwrap_or(0);
        let quota = linux_cpu.quota().unwrap_or(0);

        if period != 0 {
            let (id, value) = cpu::period(period)?;
            props.push((id, value.into()));
        }

        if period != 0 || quota != 0 {
            // Corresponds to USEC_INFINITY in systemd
            let mut quota_systemd = u64::MAX;
            let mut period = period;
            if quota > 0 {
                if period == 0 {
                    period = DEFAULT_CPU_QUOTA_PERIOD;
                }
                // systemd converts CPUQuotaPerSecUSec (microseconds per
                // CPU second) to CPUQuota (integer percentage of CPU)
                // internally. This means that if a fractional percent of
                // CPU is indicated by Resources.CpuQuota, we need to round
                // up to the nearest 10ms (1% of a second) such that child
                // cgroups can set the cpu.cfs_quota_us they expect.
                quota_systemd = ((quota as u64) * s_to_us(1)) / period;
                if quota_systemd % ms_to_us(10) != 0 {
                    quota_systemd = (quota_systemd / ms_to_us(10) + 1) * ms_to_us(10);
                }
            }
            let (id, value) = cpu::quota(quota_systemd)?;
            props.push((id, value.into()));
        }

        Ok(())
    }

    fn set_memory(&self, props: &mut Vec<Property>, linux_memory: &LinuxMemory) -> Result<()> {
        let v2 = self.v2();

        let mem_limit = linux_memory.limit().unwrap_or(0);
        if mem_limit != 0 {
            let (id, value) = memory::limit(mem_limit, v2)?;
            props.push((id, value.into()));
        }

        let reservation = linux_memory.reservation().unwrap_or(0);
        if reservation != 0 && v2 {
            let (id, value) = memory::low(reservation, v2)?;
            props.push((id, value.into()));
        }

        let memswap_limit = linux_memory.swap().unwrap_or(0);
        if memswap_limit != 0 && v2 {
            let memswap_limit = conv::memory_swap_to_cgroup_v2(memswap_limit, mem_limit)?;
            let (id, value) = memory::swap(memswap_limit, v2)?;
            props.push((id, value.into()));
        }

        Ok(())
    }

    fn set_pids(&self, props: &mut Vec<Property>, linux_pids: &LinuxPids) -> Result<()> {
        let limit = linux_pids.limit();
        if limit == -1 || limit > 0 {
            let (id, value) = pids::max(limit)?;
            props.push((id, value.into()));
        }

        Ok(())
    }

    /// The systemd sends SIGTERM to processes in the unit on stop. Once a
    /// timeout occurs, SIGKILL will be sent to the processes.
    ///
    /// The item could be retrieved by:
    ///
    /// ```bash
    /// $ systemctl show <unit> -p TimeoutStopUSec
    /// ```
    pub fn set_term_timeout(&mut self, timeout_in_sec: u64) -> Result<()> {
        let timeout_in_usec = timeout_in_sec * 1_000_000;
        let prop = (TIMEOUT_STOP_USEC, ZbusValue::U64(timeout_in_usec));
        self.systemd_client.set_properties(&[prop])?;
        Ok(())
    }
}

impl Manager for SystemdManager<'_> {
    fn add_proc(&mut self, pid: CgroupPid) -> Result<()> {
        let dest = self.default_destination.clone();
        self.add_proc_to(pid, &dest)
    }

    fn add_proc_to(&mut self, pid: CgroupPid, destination: &AttachDestination) -> Result<()> {
        let sub = self.fs_manager.resolve_destination(destination)?;
        let subcgroup = if sub.is_root() {
            "/".to_string()
        } else {
            format!("/{}", sub.as_path().display())
        };

        if !self.systemd_client.exists() {
            self.systemd_client.set_pid_prop(pid)?;
            self.systemd_client.start()?;
            if !sub.is_root() {
                // StartTransientUnit has already placed this PID in the unit
                // root. AttachProcessesToUnit deliberately treats any PID
                // already belonging to the unit as a no-op, so move it through
                // the delegated cgroupfs subtree instead.
                self.fs_manager
                    .add_proc_to_delegated_destination(pid, &sub)?;
            }
            return Ok(());
        }

        self.fs_manager.prepare_delegated_destination(&sub)?;

        // systemd ignores the requested subgroup when the process is already
        // anywhere inside this unit. Detect that case and perform the
        // intra-unit move through the delegated cgroupfs tree. Processes
        // outside the unit still go through systemd so it can perform the
        // privileged cross-cgroup migration.
        let current = self
            .fs_manager
            .resolve_destination(&AttachDestination::SameCgroupAs(pid));
        match current {
            Ok(current) if current == sub => return Ok(()),
            Ok(_) => self
                .fs_manager
                .add_proc_to_delegated_destination(pid, &sub)?,
            Err(_) => self.systemd_client.add_process(pid, &subcgroup)?,
        }

        Ok(())
    }

    /// `add_thread()` is unsupported on `SystemdManager` because systemd does not
    /// expose an API to attach individual threads. Thread-level attachment cannot
    /// be safely downgraded to process-level migration.
    fn add_thread(&mut self, pid: CgroupPid) -> Result<()> {
        let dest = self.default_destination.clone();
        self.add_thread_to(pid, &dest)
    }

    fn add_thread_to(&mut self, _pid: CgroupPid, _destination: &AttachDestination) -> Result<()> {
        Err(Error::Unsupported(
            "systemd manager does not support thread-level attachment".to_string(),
        ))
    }

    fn cgroup_path(&self, subsystem: Option<&str>) -> Result<String> {
        self.fs_manager.cgroup_path(subsystem)
    }

    /// Destroy the cgroup and stop the transient unit.
    ///
    /// Please note that if the current manager is in the cgroup, the
    /// manager will be killed with SIGTERM signal. If you do not intend
    /// that, please ignore the signal and do cleanup things immediately.
    /// Systemd will forcibly terminate the process with SIGKILL after a
    /// while.
    fn destroy(&mut self) -> Result<()> {
        self.systemd_client.stop()?;
        Ok(())
    }

    fn enable_cpus_topdown(&self, cpus: &str) -> Result<()> {
        self.fs_manager.enable_cpus_topdown(cpus)
    }

    fn freeze(&self, state: FreezerState) -> Result<()> {
        match state {
            FreezerState::Thawed => self.systemd_client.thaw()?,
            FreezerState::Frozen => self.systemd_client.freeze()?,
            FreezerState::Freezing => return Err(Error::InvalidArgument),
        }

        Ok(())
    }

    fn pids(&self) -> Result<Vec<CgroupPid>> {
        self.fs_manager.pids()
    }

    fn set(&mut self, resources: &LinuxResources) -> Result<()> {
        let mut props = vec![];

        if let Some(linux_cpu) = resources.cpu() {
            self.set_cpuset(&mut props, linux_cpu)?;
            self.set_cpu(&mut props, linux_cpu)?;
        }

        if let Some(linux_memory) = resources.memory() {
            self.set_memory(&mut props, linux_memory)?;
        }

        if let Some(linux_pids) = resources.pids() {
            self.set_pids(&mut props, linux_pids)?;
        }

        self.systemd_client.set_properties(&props)?;

        Ok(())
    }

    fn stats(&self) -> CgroupStats {
        self.fs_manager.stats()
    }

    fn try_stats(&self) -> Result<CgroupStats> {
        self.fs_manager.try_stats()
    }

    fn paths(&self) -> &HashMap<String, String> {
        self.fs_manager.paths()
    }

    fn mounts(&self) -> &HashMap<String, String> {
        self.fs_manager.mounts()
    }

    fn systemd(&self) -> bool {
        true
    }

    fn v2(&self) -> bool {
        self.fs_manager.v2()
    }
}

fn new_unit_name(scope_prefix: &str, name: &str) -> String {
    // By default, we create a scope unless the user explicitly asks
    // for a slice.
    if !name.ends_with(SLICE_SUFFIX) {
        if scope_prefix.is_empty() {
            // {name}.scope
            return format!("{}{}", name, SCOPE_SUFFIX);
        }
        // {scope_prefix}-{name}.scope
        return format!("{}-{}{}", scope_prefix, name, SCOPE_SUFFIX);
    }

    name.to_string()
}

#[inline]
/// Convert milliseconds to microseconds.
fn ms_to_us(ms: u64) -> u64 {
    ms * 1_000
}

#[inline]
/// Convert seconds to microseconds.
fn s_to_us(s: u64) -> u64 {
    s * 1_000_000
}

#[cfg(test)]
mod tests {
    //! Tests for the `SystemdManager` implementation of the `Manager`
    //! trait.
    //!
    //! Don't run tests in parallel, use `--test-threads=1`!
    //!

    use std::path::{Path, PathBuf};
    use std::thread::sleep;
    use std::time::Duration;

    use oci_spec::runtime::{LinuxCpuBuilder, LinuxMemoryBuilder, LinuxResourcesBuilder};
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    use crate::fs::cpu::CpuController;
    use crate::fs::memory::MemController;
    use crate::fs::{ControllIdentifier, Controller, Subsystem};
    use crate::manager::systemd::*;
    use crate::manager::tests::{MEMORY_1G, MEMORY_2G, MEMORY_512M};
    use crate::tests::spawn_sleep_inf;
    use crate::{skip_if_cgroups_v1, skip_if_cgroups_v2, skip_if_no_systemd, skip_if_not_root};

    fn new_cgroups_path() -> (String, String, String) {
        let rand_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();
        (
            "cgroupsrs-test.slice".to_string(),
            "cri".to_string(),
            format!("pod{}", rand_string),
        )
    }

    fn new_systemd_manager<'a>() -> SystemdManager<'a> {
        let (slice, scope_prefix, name) = new_cgroups_path();
        SystemdManager::new(&format!("{}:{}:{}", slice, scope_prefix, name)).unwrap()
    }

    fn managed_cgroup_path(manager: &SystemdManager<'_>, subsystem: Option<&str>) -> String {
        if manager.v2() {
            return manager.cgroup_path(None).unwrap();
        }

        let subsystem = subsystem.expect("cgroup v1 requires a subsystem");
        let mountpoint = manager
            .mounts()
            .get(subsystem)
            .expect("cgroup v1 subsystem mountpoint should exist");
        let slice_base = expand_slice(manager.slice()).unwrap();
        join_path(mountpoint, &join_path(&slice_base, manager.unit()).unwrap()).unwrap()
    }

    fn run_set_resources_failed(resources: LinuxResources) {
        let mut child = spawn_sleep_inf();
        let mut manager = new_systemd_manager();
        manager
            .add_proc(CgroupPid {
                pid: child.id() as u64,
            })
            .unwrap();
        assert!(manager.set(&resources).is_err());
        manager.destroy().unwrap();
        child.wait().unwrap();
    }

    fn run_set_resources<F>(linux_resources: LinuxResources, test_fn: F)
    where
        F: FnOnce(&mut SystemdManager),
    {
        let mut manager = new_systemd_manager();
        let mut child = spawn_sleep_inf();

        manager
            .add_proc(CgroupPid {
                pid: child.id() as u64,
            })
            .unwrap();
        manager.set(&linux_resources).unwrap();

        test_fn(&mut manager);

        manager.destroy().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn test_new_unit_name() {
        assert_eq!(new_unit_name("test", "unit"), "test-unit.scope");
        assert_eq!(new_unit_name("test", "unit.slice"), "unit.slice");
        assert_eq!(new_unit_name("", "unit"), "unit.scope");
        assert_eq!(new_unit_name("", "unit.slice"), "unit.slice");
        assert_eq!(new_unit_name("prefix", "unit"), "prefix-unit.scope");
    }

    #[test]
    fn test_slice_and_unit() {
        let (slice, scope_prefix, name) = new_cgroups_path();
        let (actual_slice, actual_unit) =
            SystemdManager::parse_slice_and_unit(&format!("{}:{}:{}", slice, scope_prefix, name))
                .unwrap();

        assert_eq!(actual_slice, "cgroupsrs-test.slice");
        assert_eq!(actual_unit, format!("{scope_prefix}-{name}.scope"));
    }

    #[test]
    fn test_destory() {
        skip_if_not_root!();
        skip_if_no_systemd!();

        let (slice, scope_prefix, name) = new_cgroups_path();
        let mut manager =
            SystemdManager::new(&format!("{}:{}:{}", slice, scope_prefix, name)).unwrap();

        let cgroup_path = managed_cgroup_path(&manager, (!manager.v2()).then_some("memory"));
        // Before starting the unit, no cgroup should exist.
        assert!(!Path::new(&cgroup_path).exists());

        let mut child = spawn_sleep_inf();
        manager
            .add_proc(CgroupPid {
                pid: child.id() as u64,
            })
            .unwrap();

        // Now cgroup should exist.
        assert!(Path::new(&cgroup_path).exists());

        manager.destroy().unwrap();

        // This process should be killed.
        child.wait().unwrap();

        // No cgroup should exist after destroy, retry 5 times at 1-second
        // intervals.
        for _ in 0..5 {
            if !Path::new(&cgroup_path).exists() {
                break;
            }
            sleep(Duration::from_secs(1));
        }
        assert!(!Path::new(&cgroup_path).exists());
        // Unit should be stopped.
        assert!(!manager.systemd_client.exists());
    }

    #[test]
    fn test_add_proc_to_exact_subgroups_v2() {
        skip_if_not_root!();
        skip_if_no_systemd!();
        skip_if_cgroups_v1!();

        fn assert_contains_pid(path: &Path, pid: u32) {
            let content = std::fs::read_to_string(path).unwrap();
            assert!(
                content.lines().any(|line| line == pid.to_string()),
                "{} does not contain pid {}: {:?}",
                path.display(),
                pid,
                content
            );
        }

        let mut manager = new_systemd_manager();
        let managed_path = PathBuf::from(managed_cgroup_path(&manager, None));
        let mut initial = spawn_sleep_inf();
        let initial_pid = CgroupPid::from(initial.id() as u64);

        // Starting a scope requires the initial PID in the unit root. The
        // manager must then move it directly into the requested leaf because
        // AttachProcessesToUnit ignores subgroup paths for same-unit PIDs.
        let first = AttachDestination::subgroup("first").unwrap();
        manager.add_proc_to(initial_pid, &first).unwrap();
        assert_contains_pid(&managed_path.join("first/cgroup.procs"), initial.id());

        // Moving a PID already in the unit to another missing leaf exercises
        // the same-unit path on an existing scope.
        let second = AttachDestination::subgroup("second").unwrap();
        manager.add_proc_to(initial_pid, &second).unwrap();
        assert_contains_pid(&managed_path.join("second/cgroup.procs"), initial.id());

        // A process outside the unit still uses systemd for the privileged
        // cross-cgroup migration, after the destination leaf is created.
        let mut external = spawn_sleep_inf();
        let external_pid = CgroupPid::from(external.id() as u64);
        let third = AttachDestination::subgroup("third").unwrap();
        manager.add_proc_to(external_pid, &third).unwrap();
        assert_contains_pid(&managed_path.join("third/cgroup.procs"), external.id());

        manager.destroy().unwrap();
        initial.wait().unwrap();
        external.wait().unwrap();
    }

    fn controller<'a, T>(fs_manager: &'a FsManager) -> &'a T
    where
        &'a T: From<&'a Subsystem>,
        T: Controller + ControllIdentifier,
    {
        let controller: &T = fs_manager.cgroup().controller_of().unwrap();

        controller
    }

    #[test]
    fn test_set_cpu() {
        skip_if_not_root!();
        skip_if_no_systemd!();

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
            let controller: &CpuController = controller(&manager.fs_manager);
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
        skip_if_no_systemd!();
        skip_if_cgroups_v1!();

        // Expected failure: swap < limit
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

        // Expected success
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
            let controller: &MemController = controller(&manager.fs_manager);
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
        skip_if_no_systemd!();
        skip_if_cgroups_v2!();

        // Expected success
        let linux_memory = LinuxMemoryBuilder::default()
            .limit(MEMORY_512M)
            .build()
            .unwrap();
        let linux_resources = LinuxResourcesBuilder::default()
            .memory(linux_memory)
            .build()
            .unwrap();
        run_set_resources(linux_resources, |manager| {
            let controller: &MemController = controller(&manager.fs_manager);
            let memory_stat = controller.try_memory_stat().unwrap();
            assert_eq!(memory_stat.limit_in_bytes, MEMORY_512M);
        });
    }
}

#[cfg(test)]
mod topology_tests {
    use super::SystemdManager;
    use crate::discovery::{CgroupTopology, CgroupVersion, HostPaths};
    use crate::model::AttachDestination;
    use crate::CgroupPid;
    use crate::Manager;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn test_systemd_manager_with_topology() {
        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let temp_dir =
            std::env::temp_dir().join(format!("systemd-mgr-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _guard = TempGuard(temp_dir.clone());
        let custom_cgroupfs = temp_dir.join("cgroupfs");
        std::fs::create_dir_all(&custom_cgroupfs).unwrap();

        let mountinfo = "\
43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory";
        let mounts = crate::discovery::parse_mountinfo(mountinfo).unwrap();
        let membership = crate::discovery::parse_membership("1:memory:/user.slice").unwrap();

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V1,
            v2_available: false,
            mounts,
            membership,
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: custom_cgroupfs.clone(),
            hugepages: PathBuf::from("/nonexistent"),
        });

        // Path format: parent:scope_prefix:name
        let manager =
            SystemdManager::with_topology("test.slice:scope:unit", topology.clone()).unwrap();
        assert_eq!(manager.slice(), "test.slice");
        assert_eq!(manager.unit(), "scope-unit.scope");
        assert_eq!(
            manager.mounts().get("memory").unwrap(),
            &custom_cgroupfs.join("memory").to_string_lossy().to_string()
        );
        assert!(Arc::ptr_eq(manager.topology(), &topology));
    }

    #[test]
    fn test_systemd_manager_preserves_injected_host_paths() {
        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let temp_dir = std::env::temp_dir().join(format!(
            "systemd-host-paths-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _guard = TempGuard(temp_dir.clone());
        let procfs = temp_dir.join("proc");
        let cgroupfs = temp_dir.join("cgroupfs");
        std::fs::create_dir_all(procfs.join("4242")).unwrap();
        std::fs::create_dir_all(&cgroupfs).unwrap();
        std::fs::write(
            procfs.join("4242/cgroup"),
            "0::/test.slice/scope-unit.scope/worker\n",
        )
        .unwrap();

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: cgroupfs.clone(),
            hugepages: PathBuf::from("/nonexistent"),
        });
        let host_paths = HostPaths {
            procfs,
            cgroupfs_override: Some(cgroupfs),
            hugepages: PathBuf::from("/nonexistent"),
        };

        let manager = SystemdManager::with_topology_and_host_paths(
            "test.slice:scope:unit",
            topology,
            host_paths.clone(),
        )
        .unwrap();
        assert_eq!(manager.fs_manager.host_paths(), &host_paths);

        let destination = AttachDestination::SameCgroupAs(CgroupPid::from(4242u64));
        let resolved = manager
            .fs_manager
            .resolve_destination(&destination)
            .unwrap();
        assert_eq!(resolved.as_path(), std::path::Path::new("worker"));
    }

    #[test]
    fn test_systemd_add_thread_unsupported() {
        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/nonexistent"),
        });

        let mut manager = SystemdManager::with_topology("test.slice:scope:unit", topology).unwrap();
        let pid = crate::CgroupPid { pid: 42 };
        match manager.add_thread(pid) {
            Err(crate::manager::error::Error::Unsupported(msg)) => {
                assert!(msg.contains("thread-level attachment"))
            }
            other => panic!("expected Unsupported error, got {:?}", other),
        }
        match manager.add_thread_to(pid, &crate::model::AttachDestination::ManagedCgroup) {
            Err(crate::manager::error::Error::Unsupported(msg)) => {
                assert!(msg.contains("thread-level attachment"))
            }
            other => panic!("expected Unsupported error, got {:?}", other),
        }
    }
}
