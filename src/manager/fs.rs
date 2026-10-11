// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use oci_spec::runtime::LinuxResources;

use crate::discovery::membership::{parse_membership, Membership};
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
use std::convert::TryFrom;

use crate::discovery::attachment::{
    plan_attachment as pure_plan_attachment, AttachmentPlan, CreationPolicy, Placement,
};
use crate::error::AttachmentError;
use crate::fs::net_prio::NetPrioController;
use crate::fs::pid::PidController;
use crate::fs::{hierarchies, Cgroup, ControllIdentifier, Controller, MaxValue, Subsystem};
use crate::manager::error::Error;
use crate::manager::{conv, Manager, Result};
use crate::model::pid::ProcessId;
use crate::model::{
    AttachDestination, BlkIoPatch, CgroupPath, CpuPatch, CpuSetPatch, DevicePatch, HugePagePatch,
    MemoryPatch, NetworkPatch, PidsPatch, ResourcePatch, Update,
};
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
    /// Host paths used to discover the topology; stored so that
    /// [`FsManager::refresh`] can re-discover from the same procfs /
    /// cgroupfs source without the caller needing to remember them.
    host_paths: HostPaths,
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
    ///
    /// The provided host paths are stored so that [`FsManager::refresh`]
    /// can re-discover from the same source.
    pub fn with_host_paths(base: &str, host_paths: &HostPaths) -> Result<Self> {
        let topology = discover(host_paths)?;
        let base = crate::fs::cgroup::parse_cgroup_path(base)?;
        Ok(Self::from_topology(base, topology, host_paths.clone()))
    }

    /// Create an instance of FsManager with an already-discovered [`CgroupTopology`].
    ///
    /// Because no [`HostPaths`] are given, [`FsManager::refresh`] will
    /// re-discover from [`HostPaths::default()`]. Use
    /// [`FsManager::with_topology_and_host_paths`] to pair a
    /// pre-discovered topology with specific host paths.
    pub fn with_topology(base: &str, topology: Arc<CgroupTopology>) -> Result<Self> {
        Self::with_topology_and_host_paths(base, topology, HostPaths::default())
    }

    /// Create an instance of FsManager with an already-discovered
    /// [`CgroupTopology`] and explicit [`HostPaths`].
    ///
    /// The topology is used immediately; the host paths are stored so
    /// that [`FsManager::refresh`] can re-discover from the same source.
    pub fn with_topology_and_host_paths(
        base: &str,
        topology: Arc<CgroupTopology>,
        host_paths: HostPaths,
    ) -> Result<Self> {
        let base = crate::fs::cgroup::parse_cgroup_path(base)?;
        Ok(Self::from_topology(base, topology, host_paths))
    }

    /// Return the topology snapshot held by this manager.
    pub fn topology(&self) -> &Arc<CgroupTopology> {
        &self.topology
    }

    /// Return the host paths this manager was constructed with.
    ///
    /// These are the paths that [`FsManager::refresh`] will use to
    /// re-discover the topology.
    pub fn host_paths(&self) -> &HostPaths {
        &self.host_paths
    }

    /// Re-discover the host topology from the stored host paths and
    /// rebuild all derived state (`paths`, `mounts`, `cgroup`).
    ///
    /// The validated `base` path is preserved. The old topology snapshot
    /// remains valid for any other `Arc` holders; this manager and its
    /// managed cgroup switch to the new snapshot.
    ///
    /// # When to call
    ///
    /// After a namespace transition (`setns(CLONE_NEWCGROUP)`,
    /// `unshare(CLONE_NEWCGROUP)`) or after cgroup controller mounts
    /// change, the manager's cached view of `/proc/self/cgroup` and
    /// `/proc/self/mountinfo` becomes stale. Calling `refresh()` reads
    /// those files again and rebuilds the manager's state.
    pub fn refresh(&mut self) -> Result<()> {
        let topology = discover(&self.host_paths)?;
        self.apply_topology(topology);
        Ok(())
    }

    /// Re-discover the host topology from explicit host paths, update
    /// the stored paths, and rebuild all derived state.
    ///
    /// Subsequent calls to [`FsManager::refresh`] will use the new
    /// `host_paths`.
    pub fn refresh_with_host_paths(&mut self, host_paths: &HostPaths) -> Result<()> {
        let topology = discover(host_paths)?;
        self.host_paths = host_paths.clone();
        self.apply_topology(topology);
        Ok(())
    }

    /// Rebuild all derived state from an externally-provided topology
    /// snapshot. The stored host paths are not modified.
    ///
    /// Use this when the caller has already run discovery (e.g. to
    /// inspect the result before committing) or when injecting a
    /// synthetic topology in tests.
    pub fn refresh_with_topology(&mut self, topology: Arc<CgroupTopology>) {
        self.apply_topology(topology);
    }

    // -- private helpers --------------------------------------------------

    /// Construct an FsManager directly from a discovered or synthetic
    /// topology and host paths, without any redundant host I/O.
    fn from_topology(
        base: CgroupPath,
        topology: Arc<CgroupTopology>,
        host_paths: HostPaths,
    ) -> Self {
        let paths = membership_to_subsystem_paths(&topology.membership);
        let mounts = controller_mounts(&topology, &paths);
        let cgroup = Cgroup::load_validated_with_topology(topology.clone(), base.clone());
        Self {
            paths,
            mounts,
            topology,
            host_paths,
            base,
            cgroup,
        }
    }

    /// Replace the topology and rebuild all derived state from it.
    ///
    /// This is the single point where `paths`, `mounts`, `cgroup`, and
    /// `topology` are updated, shared between constructors and refresh
    /// methods.
    fn apply_topology(&mut self, topology: Arc<CgroupTopology>) {
        let paths = membership_to_subsystem_paths(&topology.membership);
        let mounts = controller_mounts(&topology, &paths);
        let cgroup = Cgroup::load_validated_with_topology(topology.clone(), self.base.clone());
        self.paths = paths;
        self.mounts = mounts;
        self.cgroup = cgroup;
        self.topology = topology;
    }
}

/// A destination below a delegated (systemd-owned) cgroup, flattened to a
/// single subgroup path but still carrying the complete execution plan.
///
/// The plan preserves both `SameCgroupAs`'s creation policy and the selected
/// hierarchies. Execution must not widen systemd's selection to every mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DelegatedDestination {
    /// Subgroup relative to the managed cgroup; [`CgroupPath::root`] means
    /// the managed cgroup itself.
    pub subgroup: CgroupPath,
    /// Validated placement, selected hierarchies, and creation policy.
    pub plan: AttachmentPlan,
}

impl FsManager {
    /// Return the validated base path of this manager.
    pub fn base(&self) -> &CgroupPath {
        &self.base
    }

    /// Read one membership snapshot from the configured procfs.
    pub(crate) fn read_membership(&self, pid: ProcessId) -> Result<Membership> {
        let path = self.host_paths.procfs.join(pid.to_string()).join("cgroup");
        let content = std::fs::read_to_string(&path)
            .map_err(|source| AttachmentError::ReadMembership { pid, path, source })?;
        parse_membership(&content)
            .map_err(|source| AttachmentError::ParseMembership { pid, source }.into())
    }

    /// Only mounted hierarchies are managed; a procfs record alone does not
    /// make a hierarchy visible in the caller's mount namespace.
    pub(crate) fn managed_subsystems(&self) -> Vec<String> {
        let mut subsystems: Vec<_> = self.mounts.keys().cloned().collect();
        subsystems.sort();
        subsystems
    }

    /// Generate a resolved plan before creating or migrating anything.
    pub(crate) fn plan_attachment(
        &self,
        destination: &AttachDestination,
    ) -> Result<AttachmentPlan> {
        self.plan_attachment_in(destination, &self.managed_subsystems())
    }

    fn plan_attachment_in(
        &self,
        destination: &AttachDestination,
        subsystems: &[String],
    ) -> Result<AttachmentPlan> {
        let membership = match destination {
            AttachDestination::SameCgroupAs(pid) => Some(self.read_membership(*pid)?),
            _ => None,
        };
        pure_plan_attachment(
            &self.topology,
            &self.base,
            subsystems,
            destination,
            membership.as_ref(),
        )
        .map_err(Error::Attachment)
    }

    /// Resolve a destination to one subgroup below the managed cgroup.
    /// Divergent v1 hierarchy placements cannot be represented by this API.
    pub fn resolve_destination(&self, destination: &AttachDestination) -> Result<CgroupPath> {
        self.resolve_delegated_destination(destination, &self.managed_subsystems())
            .map(|resolved| resolved.subgroup)
    }

    /// Preserve creation policy while converting a plan to the single subgroup
    /// accepted by systemd. Never select an arbitrary v1 hierarchy.
    pub(crate) fn resolve_delegated_destination(
        &self,
        destination: &AttachDestination,
        subsystems: &[String],
    ) -> Result<DelegatedDestination> {
        let plan = self.plan_attachment_in(destination, subsystems)?;
        let target = match &plan.placement {
            Placement::Unified(target) => target,
            Placement::Legacy(targets) => {
                let target = targets.values().next().ok_or_else(|| {
                    Error::Attachment(AttachmentError::Unsupported {
                        backend: "systemd",
                        operation: "attachment requires a visible managed hierarchy",
                    })
                })?;
                if targets.values().any(|path| path != target) {
                    return Err(Error::Attachment(AttachmentError::Unsupported {
                        backend: "systemd",
                        operation:
                            "different v1 hierarchy destinations cannot be encoded as one subgroup",
                    }));
                }
                target
            }
        };
        let sub = target
            .as_path()
            .strip_prefix(self.base.as_path())
            .map_err(|_| {
                Error::Core(crate::error::CoreError::InvalidPath {
                    input: target.as_path().to_path_buf(),
                    reason: crate::error::PathReason::ContainmentViolation,
                    operation: "resolve_delegated_destination",
                })
            })?;
        Ok(DelegatedDestination {
            subgroup: if sub.as_os_str().is_empty() {
                CgroupPath::root()?
            } else {
                CgroupPath::new(sub)?
            },
            plan,
        })
    }

    /// Resolve the plan using the same mount selector as discovery. Co-mounted
    /// controllers share one directory and therefore one membership write.
    fn attachment_targets(
        &self,
        plan: &AttachmentPlan,
    ) -> Result<std::collections::BTreeMap<PathBuf, Vec<String>>> {
        let mut resolved = std::collections::BTreeMap::new();
        match &plan.placement {
            Placement::Unified(path) => {
                let cg = Cgroup::load_validated_with_topology(self.topology.clone(), path.clone());
                for dir in cg.attachment_leaf_dirs() {
                    resolved.insert(dir, vec!["0::".to_string()]);
                }
            }
            Placement::Legacy(targets) => {
                for (controller, path) in targets {
                    let mount = self
                        .topology
                        .mounts
                        .controller_mount(controller)
                        .ok_or_else(|| AttachmentError::MissingHierarchyMount {
                            hierarchy: controller.clone(),
                            root: self.topology.cgroupfs_root.clone(),
                        })?;
                    let dir = self
                        .topology
                        .resolve_mount_point(&mount.mount_point)
                        .join(path.as_path());
                    resolved
                        .entry(dir)
                        .or_insert_with(Vec::new)
                        .push(controller.clone());
                }
            }
        }
        Ok(resolved)
    }

    fn check_attachment_directory(
        pid: ProcessId,
        target: &Path,
        controllers: &[String],
    ) -> Result<()> {
        match std::fs::metadata(target) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            result => {
                let source = match result {
                    Ok(_) => std::io::Error::from_raw_os_error(libc::ENOTDIR),
                    Err(source) => source,
                };
                if source.kind() == std::io::ErrorKind::NotFound {
                    Err(AttachmentError::MissingResolvedTarget {
                        pid,
                        target: target.to_path_buf(),
                        source,
                    }
                    .into())
                } else {
                    Err(AttachmentError::TargetIo {
                        backend: "cgroupfs",
                        pid,
                        operation: "inspect attachment directory",
                        target: target.to_path_buf(),
                        controllers: controllers.to_vec(),
                        source,
                    }
                    .into())
                }
            }
        }
    }

    fn prepare_attachment_plan(&self, plan: &AttachmentPlan, pid: ProcessId) -> Result<()> {
        for (target, controllers) in self.attachment_targets(plan)? {
            if plan.creation == CreationPolicy::MayCreateLeaf {
                std::fs::create_dir_all(&target).map_err(|source| AttachmentError::TargetIo {
                    backend: "cgroupfs",
                    pid,
                    operation: "create attachment directory",
                    target: target.clone(),
                    controllers: controllers.clone(),
                    source,
                })?;
            }
            Self::check_attachment_directory(pid, &target, &controllers)?;
        }
        Ok(())
    }

    fn execute_attachment_plan(
        &self,
        plan: &AttachmentPlan,
        pid: ProcessId,
        is_proc: bool,
    ) -> Result<()> {
        self.prepare_attachment_plan(plan, pid)?;
        match &plan.placement {
            Placement::Unified(path) => {
                let cg = Cgroup::load_validated_with_topology(self.topology.clone(), path.clone());
                let raw_pid = CgroupPid::from(u64::from(pid.get()));
                if is_proc {
                    cg.add_task_by_tgid(raw_pid)?;
                } else {
                    cg.add_task(raw_pid)?;
                }
            }
            Placement::Legacy(_) => {
                let mut completed = Vec::new();
                let file_name = if is_proc { "cgroup.procs" } else { "tasks" };
                for (target, controllers) in self.attachment_targets(plan)? {
                    let file = target.join(file_name);
                    // Kernel membership files must already exist. Opening without
                    // O_CREAT also prevents a missing pseudo-file from being faked.
                    use std::io::Write;
                    let write = std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(&file)
                        .and_then(|mut file| file.write_all(pid.to_string().as_bytes()));
                    if let Err(source) = write {
                        return Err(AttachmentError::WriteMembership {
                            backend: "cgroupfs",
                            pid,
                            operation: if is_proc {
                                "attach process"
                            } else {
                                "attach thread"
                            },
                            controllers,
                            target: file,
                            completed,
                            source,
                        }
                        .into());
                    }
                    completed.push(controllers);
                }
            }
        }
        Ok(())
    }

    fn delegated_root_plan(&self, destination: &DelegatedDestination) -> Result<AttachmentPlan> {
        let subsystems = match &destination.plan.placement {
            Placement::Unified(_) => Vec::new(),
            Placement::Legacy(targets) => targets.keys().cloned().collect(),
        };
        let mut plan = self.plan_attachment_in(&AttachDestination::ManagedCgroup, &subsystems)?;
        plan.creation = CreationPolicy::MustExist;
        Ok(plan)
    }

    /// Prepare a delegated leaf without enabling controllers on the unit root.
    /// The managed unit must already exist on every selected hierarchy.
    pub(crate) fn prepare_delegated_destination(
        &self,
        pid: ProcessId,
        destination: &DelegatedDestination,
    ) -> Result<()> {
        self.prepare_attachment_plan(&self.delegated_root_plan(destination)?, pid)?;
        self.prepare_attachment_plan(&destination.plan, pid)
    }

    /// Check every selected hierarchy, preserving metadata failures and errno.
    pub(crate) fn ensure_delegated_destination_exists(
        &self,
        pid: ProcessId,
        destination: &DelegatedDestination,
    ) -> Result<()> {
        let mut plan = destination.plan.clone();
        plan.creation = CreationPolicy::MustExist;
        self.prepare_attachment_plan(&plan, pid)
    }

    /// Migrate within a delegated unit using the resolved creation policy.
    pub(crate) fn add_proc_to_delegated_destination(
        &self,
        pid: ProcessId,
        destination: &DelegatedDestination,
    ) -> Result<()> {
        self.prepare_delegated_destination(pid, destination)?;
        self.execute_attachment_plan(&destination.plan, pid, true)
    }

    /// Create the cgroups if they are not created yet.
    pub(crate) fn create_cgroups(&mut self) -> Result<()> {
        if self.exists() {
            return Ok(());
        }
        self.cgroup.create()?;
        Ok(())
    }

    /// Get the subcgroup path.
    ///
    /// This is a backwards-compatibility shim that unconditionally returns `"/"`.
    /// Callers that need to attach to a leaf subgroup must use
    /// [`AttachDestination::subgroup`] or [`AttachDestination::same_cgroup_as`]
    /// with [`Manager::add_proc_to`].
    #[deprecated(
        since = "0.5.2",
        note = "use explicit AttachDestination with add_proc_to"
    )]
    pub fn subcgroup(&self) -> &str {
        "/"
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

    fn set_mem_and_memswap_v1(&self, limit: Option<i64>, swap_limit: Option<i64>) -> Result<()> {
        let controller: &MemController = self.controller()?;

        if let (Some(limit), Some(swap_limit)) = (limit, swap_limit) {
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

        if let Some(limit) = limit {
            controller.set_limit(limit)?;
        }
        if let Some(swap_limit) = swap_limit {
            controller.set_memswap_limit(swap_limit)?;
        }

        Ok(())
    }

    fn set_cpuset_patch(&self, patch: &CpuSetPatch) -> Result<()> {
        if matches!(&patch.cpus, Update::Max) || matches!(&patch.mems, Update::Max) {
            return Err(Error::Unsupported(
                "cpuset values do not support Update::Max".to_string(),
            ));
        }
        if patch.cpus.is_unchanged() && patch.mems.is_unchanged() {
            return Ok(());
        }
        let controller: &CpuSetController = self.controller()?;
        if let Update::Set(cpus) = &patch.cpus {
            controller.set_cpus(cpus)?;
        }
        if let Update::Set(mems) = &patch.mems {
            controller.set_mems(mems)?;
        }
        Ok(())
    }

    fn set_cpu_patch(&self, patch: &CpuPatch) -> Result<()> {
        if matches!(patch.shares, Update::Max)
            || matches!(patch.period, Update::Max)
            || matches!(patch.realtime_period, Update::Max)
        {
            return Err(Error::Unsupported(
                "cpu shares, period, and realtime period do not support Update::Max".to_string(),
            ));
        }
        if patch.shares.is_unchanged()
            && patch.quota.is_unchanged()
            && patch.period.is_unchanged()
            && patch.realtime_runtime.is_unchanged()
            && patch.realtime_period.is_unchanged()
        {
            return Ok(());
        }
        let controller: &CpuController = self.controller()?;
        if let Update::Set(shares) = patch.shares {
            let shares = if self.v2() {
                conv::cpu_shares_to_cgroup_v2(shares)
            } else {
                shares
            };
            controller.set_shares(shares)?;
        }
        match patch.quota {
            Update::Set(quota) => controller.set_cfs_quota(quota)?,
            Update::Max => controller.set_cfs_quota(-1)?,
            Update::Unchanged => {}
        }
        if let Update::Set(period) = patch.period {
            controller.set_cfs_period(period)?;
        }
        match patch.realtime_runtime {
            Update::Set(rt_runtime) => controller.set_rt_runtime(rt_runtime)?,
            Update::Max => controller.set_rt_runtime(-1)?,
            Update::Unchanged => {}
        }
        if let Update::Set(rt_period) = patch.realtime_period {
            controller.set_rt_period_us(rt_period)?;
        }
        Ok(())
    }

    fn set_memory_patch(&self, patch: &MemoryPatch) -> Result<()> {
        if patch.limit.is_unchanged()
            && patch.soft_limit.is_unchanged()
            && patch.swap.is_unchanged()
            && patch.kernel.is_unchanged()
            && patch.kernel_tcp.is_unchanged()
            && patch.swappiness.is_unchanged()
            && patch.disable_oom_killer.is_unchanged()
        {
            return Ok(());
        }
        if [
            patch.limit,
            patch.soft_limit,
            patch.swap,
            patch.kernel,
            patch.kernel_tcp,
        ]
        .iter()
        .any(|update| matches!(update, Update::Set(value) if *value < 0))
        {
            return Err(Error::InvalidArgument);
        }
        if self.v2() {
            self.set_memory_v2_patch(patch)
        } else {
            self.set_memory_v1_patch(patch)
        }
    }

    fn set_memory_v1_patch(&self, patch: &MemoryPatch) -> Result<()> {
        if matches!(patch.swappiness, Update::Max)
            || matches!(patch.disable_oom_killer, Update::Max)
        {
            return Err(Error::Unsupported(
                "memory swappiness and OOM-killer state do not support Update::Max".to_string(),
            ));
        }
        if matches!(patch.swappiness, Update::Set(swappiness) if swappiness > 100) {
            return Err(Error::InvalidArgument);
        }
        let controller: &MemController = self.controller()?;
        let mem_limit = match patch.limit {
            Update::Set(v) => Some(v),
            Update::Max => Some(-1),
            Update::Unchanged => None,
        };
        let memswap_limit = match patch.swap {
            Update::Set(v) => Some(v),
            Update::Max => Some(-1),
            Update::Unchanged => None,
        };
        self.set_mem_and_memswap_v1(mem_limit, memswap_limit)?;

        match patch.soft_limit {
            Update::Set(reservation) => controller.set_soft_limit(reservation)?,
            Update::Max => controller.set_soft_limit(-1)?,
            Update::Unchanged => {}
        }
        match patch.kernel {
            Update::Set(kernel) => controller.set_kmem_limit(kernel)?,
            Update::Max => controller.set_kmem_limit(-1)?,
            Update::Unchanged => {}
        }
        match patch.kernel_tcp {
            Update::Set(kernel_tcp) => controller.set_tcp_limit(kernel_tcp)?,
            Update::Max => controller.set_tcp_limit(-1)?,
            Update::Unchanged => {}
        }
        if let Update::Set(swappiness) = patch.swappiness {
            controller.set_swappiness(swappiness)?;
        }
        if let Update::Set(disabled) = patch.disable_oom_killer {
            controller.set_oom_killer_disabled(disabled)?;
        }
        Ok(())
    }

    fn set_memory_v2_patch(&self, patch: &MemoryPatch) -> Result<()> {
        if !patch.kernel.is_unchanged()
            || !patch.kernel_tcp.is_unchanged()
            || !patch.swappiness.is_unchanged()
            || !patch.disable_oom_killer.is_unchanged()
        {
            return Err(Error::Unsupported(
                "kernel/tcp/swappiness/OOM-killer memory settings are unavailable on cgroup v2"
                    .to_string(),
            ));
        }
        if matches!(patch.soft_limit, Update::Max) {
            return Err(Error::Unsupported(
                "memory.low does not support Update::Max through this backend".to_string(),
            ));
        }
        let controller: &MemController = self.controller()?;
        match patch.limit {
            Update::Set(limit) => controller.set_limit(limit)?,
            Update::Max => controller.set_limit(-1)?,
            Update::Unchanged => {}
        }
        match patch.swap {
            Update::Set(swap) => controller.set_memswap_limit(swap)?,
            Update::Max => controller.set_memswap_limit(-1)?,
            Update::Unchanged => {}
        }
        if let Update::Set(soft_limit) = patch.soft_limit {
            controller.set_soft_limit(soft_limit)?;
        }
        Ok(())
    }

    fn set_pids_patch(&self, patch: &PidsPatch) -> Result<()> {
        if patch.limit.is_unchanged() {
            return Ok(());
        }
        let controller: &PidController = self.controller()?;
        let value = match patch.limit {
            Update::Set(limit) if limit >= 0 => MaxValue::Value(limit),
            Update::Set(_) => return Err(Error::InvalidArgument),
            Update::Max => MaxValue::Max,
            Update::Unchanged => return Ok(()),
        };
        controller.set_pid_max(value)?;
        Ok(())
    }

    fn set_blkio_patch(&self, patch: &BlkIoPatch) -> Result<()> {
        if patch.weight.is_unchanged()
            && patch.leaf_weight.is_unchanged()
            && patch.weight_device.is_empty()
            && patch.throttle_read_bps_device.is_empty()
            && patch.throttle_write_bps_device.is_empty()
            && patch.throttle_read_iops_device.is_empty()
            && patch.throttle_write_iops_device.is_empty()
        {
            return Ok(());
        }
        if matches!(patch.weight, Update::Max) || matches!(patch.leaf_weight, Update::Max) {
            return Err(Error::Unsupported(
                "blkio weight values do not support Update::Max".to_string(),
            ));
        }
        if self.v2()
            && (!patch.leaf_weight.is_unchanged()
                || patch
                    .weight_device
                    .iter()
                    .any(|device| device.leaf_weight.is_some()))
        {
            return Err(Error::Unsupported(
                "blkio leaf_weight is only available on cgroup v1".to_string(),
            ));
        }
        let controller: &BlkIoController = self.controller()?;
        if let Update::Set(weight) = patch.weight {
            controller.set_weight(weight as u64)?;
        }
        if let Update::Set(leaf_weight) = patch.leaf_weight {
            controller.set_leaf_weight(leaf_weight as u64)?;
        }
        for dev in &patch.weight_device {
            let major = dev.major;
            let minor = dev.minor;
            if let Some(w) = dev.weight {
                controller.set_weight_for_device(major, minor, w as u64)?;
            }
            if let Some(lw) = dev.leaf_weight {
                controller.set_leaf_weight_for_device(major, minor, lw as u64)?;
            }
        }
        for dev in &patch.throttle_read_bps_device {
            controller.throttle_read_bps_for_device(dev.major, dev.minor, dev.rate)?;
        }
        for dev in &patch.throttle_write_bps_device {
            controller.throttle_write_bps_for_device(dev.major, dev.minor, dev.rate)?;
        }
        for dev in &patch.throttle_read_iops_device {
            controller.throttle_read_iops_for_device(dev.major, dev.minor, dev.rate)?;
        }
        for dev in &patch.throttle_write_iops_device {
            controller.throttle_write_iops_for_device(dev.major, dev.minor, dev.rate)?;
        }
        Ok(())
    }

    fn set_hugepages_patch(&self, patch: &HugePagePatch) -> Result<()> {
        if patch.limits.is_empty() {
            return Ok(());
        }
        let controller: &HugeTlbController = self.controller()?;
        for limit in &patch.limits {
            if !controller.size_supported(&limit.page_size) {
                return Err(Error::Unsupported(format!(
                    "hugetlb page size {} is not supported",
                    limit.page_size
                )));
            }
            controller.set_limit_in_bytes(&limit.page_size, limit.limit)?;
        }
        Ok(())
    }

    fn set_network_patch(&self, patch: &NetworkPatch) -> Result<()> {
        if matches!(patch.class_id, Update::Max) {
            return Err(Error::Unsupported(
                "network class_id does not support Update::Max".to_string(),
            ));
        }
        if patch.class_id.is_unchanged() && patch.priorities.is_empty() {
            return Ok(());
        }
        if let Update::Set(class_id) = patch.class_id {
            let controller: &NetClsController = self.controller()?;
            controller.set_class(class_id)?;
        }
        if !patch.priorities.is_empty() {
            let controller: &NetPrioController = self.controller()?;
            for prio in &patch.priorities {
                controller.set_if_prio(&prio.name, prio.priority)?;
            }
        }
        Ok(())
    }

    fn set_devices_patch(&self, patch: &DevicePatch) -> Result<()> {
        if patch.rules.is_empty() {
            return Ok(());
        }
        let controller: &DevicesController = self.controller()?;
        for device in &patch.rules {
            let devtype = DeviceType::from_char(device.dev_type).ok_or(Error::InvalidArgument)?;

            let perm = device
                .access
                .chars()
                .map(|p| match p {
                    'r' => Ok(DevicePermissions::Read),
                    'w' => Ok(DevicePermissions::Write),
                    'm' => Ok(DevicePermissions::MkNod),
                    _ => Err(Error::InvalidArgument),
                })
                .collect::<Result<Vec<_>>>()?;
            if perm.is_empty() {
                return Err(Error::InvalidArgument);
            }

            let major = device.major.unwrap_or(-1);
            let minor = device.minor.unwrap_or(-1);

            if device.allow {
                controller.allow_device(devtype, major, minor, &perm)?;
            } else {
                controller.deny_device(devtype, major, minor, &perm)?;
            }
        }
        Ok(())
    }

    fn set_custom_attributes(&self, attrs: &HashMap<String, String>) -> Result<()> {
        if attrs.is_empty() {
            return Ok(());
        }
        if !self.v2() {
            return Err(Error::Unsupported(
                "custom attributes (unified) are only supported on cgroup v2".to_string(),
            ));
        }
        for (k, v) in attrs {
            crate::model::validate_attribute_name(k, "set_custom_attributes")?;
            let path = self
                .topology
                .cgroupfs_root
                .join(self.base.as_path())
                .join(k);
            std::fs::write(&path, v.as_bytes()).map_err(|e| {
                Error::Cgroupfs(FsError::with_cause(
                    FsErrorKind::WriteFailed(path.display().to_string(), v.clone()),
                    e,
                ))
            })?;
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
        self.add_proc_to(tgid, &AttachDestination::ManagedCgroup)
    }

    fn add_proc_to(&mut self, tgid: CgroupPid, destination: &AttachDestination) -> Result<()> {
        let pid = ProcessId::try_from(tgid)
            .map_err(|_| AttachmentError::InvalidProcessId { value: tgid.pid })?;
        let plan = self.plan_attachment(destination)?;
        if plan.creation == CreationPolicy::MayCreateLeaf {
            self.create_cgroups()?;
        }
        self.execute_attachment_plan(&plan, pid, true)
    }

    fn add_thread(&mut self, pid: CgroupPid) -> Result<()> {
        self.add_thread_to(pid, &AttachDestination::ManagedCgroup)
    }

    fn add_thread_to(&mut self, pid: CgroupPid, destination: &AttachDestination) -> Result<()> {
        let pid = ProcessId::try_from(pid)
            .map_err(|_| AttachmentError::InvalidProcessId { value: pid.pid })?;
        let plan = self.plan_attachment(destination)?;
        if plan.creation == CreationPolicy::MayCreateLeaf {
            self.create_cgroups()?;
        }
        self.execute_attachment_plan(&plan, pid, false)
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

    fn set_resources(&mut self, resources: &ResourcePatch) -> Result<()> {
        self.set_cpuset_patch(&resources.cpuset)?;
        self.set_cpu_patch(&resources.cpu)?;
        self.set_memory_patch(&resources.memory)?;
        self.set_pids_patch(&resources.pids)?;
        self.set_blkio_patch(&resources.blkio)?;
        self.set_hugepages_patch(&resources.hugepages)?;
        self.set_network_patch(&resources.network)?;
        self.set_devices_patch(&resources.devices)?;
        self.set_custom_attributes(&resources.custom_attributes)?;
        Ok(())
    }

    fn set(&mut self, resources: &LinuxResources) -> Result<()> {
        let patch = conv::oci_to_cgroupfs_resource_patch(resources, self.v2())?;
        self.set_resources(&patch)
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
    paths
        .keys()
        .filter_map(|controller| {
            topology.mounts.controller_mount(controller).map(|record| {
                (
                    controller.clone(),
                    topology
                        .resolve_mount_point(&record.mount_point)
                        .to_string_lossy()
                        .into_owned(),
                )
            })
        })
        .collect()
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
    use super::{controller_mounts, membership_to_subsystem_paths, FsManager};
    use crate::discovery::topology::HostPaths;
    use crate::discovery::{CgroupTopology, CgroupVersion, ControllerSet};
    use crate::error::CoreError;
    use crate::fs::hierarchies;
    use crate::manager::error::Error;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

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
            input: "0::/user.slice/session:c1.scope\n6:memory:/org:dept/ab:cd/leaf",
            expect: Some(&[("memory", "/org:dept/ab:cd/leaf"), ("", "/user.slice/session:c1.scope")]),
        },
        Case {
            name: "malformed: duplicate unified records are rejected",
            input: "0::/tenant/burstable/pod-abc123/sandbox-xyz/init\n0::/tenant/burstable/pod-abc123/sandbox-xyz/exec",
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

    /// Build a synthetic v1 topology with the given cgroupfs root,
    /// a single `memory` controller, and a membership path.
    fn synthetic_v1_topology(
        cgroupfs_root: PathBuf,
        membership_line: &str,
        mountinfo_line: &str,
    ) -> Arc<CgroupTopology> {
        let mounts = crate::discovery::parse_mountinfo(mountinfo_line).unwrap();
        let membership = crate::discovery::parse_membership(membership_line).unwrap();
        Arc::new(CgroupTopology {
            version: crate::discovery::CgroupVersion::V1,
            v2_available: false,
            mounts,
            membership,
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root,
            hugepages: PathBuf::from("/nonexistent"),
        })
    }

    #[test]
    fn test_refresh_with_topology_replaces_derived_state() {
        // Initial topology: memory controller, membership at /user.slice
        let root_a = PathBuf::from("/tmp/cg-refresh-a");
        let topo_a = synthetic_v1_topology(
            root_a.clone(),
            "1:memory:/user.slice",
            "43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory",
        );

        let mut manager = FsManager::with_topology("test/child", topo_a.clone()).unwrap();
        assert_eq!(
            manager.mounts.get("memory").unwrap(),
            &root_a.join("memory").to_string_lossy().to_string(),
        );
        assert!(Arc::ptr_eq(manager.topology(), &topo_a));

        // Refresh with a different topology: different cgroupfs root,
        // different membership path.
        let root_b = PathBuf::from("/tmp/cg-refresh-b");
        let topo_b = synthetic_v1_topology(
            root_b.clone(),
            "2:memory:/container.slice",
            "44 33 0:39 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,memory",
        );

        manager.refresh_with_topology(topo_b.clone());

        // Derived state must reflect the new topology.
        assert!(Arc::ptr_eq(manager.topology(), &topo_b));
        assert_eq!(
            manager.mounts.get("memory").unwrap(),
            &root_b.join("memory").to_string_lossy().to_string(),
        );
        assert_eq!(manager.paths.get("memory").unwrap(), "/container.slice",);
        // Cgroup must also use the new topology.
        assert!(manager.cgroup.topology().is_some());
        assert!(Arc::ptr_eq(&manager.cgroup.topology().unwrap(), &topo_b,));
    }

    #[test]
    fn test_refresh_preserves_base() {
        let topo = synthetic_v1_topology(
            PathBuf::from("/tmp/cg-base-test"),
            "1:memory:/",
            "43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory",
        );

        let mut manager = FsManager::with_topology("my/group", topo).unwrap();
        assert_eq!(manager.base.as_path(), Path::new("my/group"));

        // Refresh with a completely different topology.
        let topo2 = synthetic_v1_topology(
            PathBuf::from("/tmp/cg-base-test-2"),
            "2:memory:/other",
            "44 33 0:39 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory",
        );
        manager.refresh_with_topology(topo2);

        // Base must be unchanged.
        assert_eq!(manager.base.as_path(), Path::new("my/group"));
    }

    #[test]
    fn test_refresh_with_host_paths_updates_stored_paths() {
        let topo = synthetic_v1_topology(
            PathBuf::from("/tmp/cg-hp-test"),
            "1:memory:/",
            "43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory",
        );

        let original_hp = HostPaths {
            procfs: PathBuf::from("/proc"),
            cgroupfs_override: None,
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let manager =
            FsManager::with_topology_and_host_paths("test/sub", topo, original_hp.clone()).unwrap();

        // Stored host_paths should match what we provided.
        assert_eq!(manager.host_paths(), &original_hp);

        // refresh_with_host_paths will try to discover from a
        // non-existent procfs and fail — but the stored host_paths
        // should NOT be updated on failure.
        let bad_hp = HostPaths {
            procfs: PathBuf::from("/nonexistent/proc"),
            cgroupfs_override: None,
            hugepages: PathBuf::from("/nonexistent/hugepages"),
        };
        // We need a mutable binding to call refresh.
        let mut manager = manager;
        let result = manager.refresh_with_host_paths(&bad_hp);
        assert!(
            result.is_err(),
            "refresh from nonexistent procfs should fail"
        );
        // On failure, the stored host_paths must still be the original.
        assert_eq!(manager.host_paths(), &original_hp);
    }
}

#[cfg(test)]
mod attachment_tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::discovery::{CgroupTopology, CgroupVersion, ControllerSet, HostPaths};
    use crate::error::AttachmentError;
    use crate::manager::{Error, FsManager, Manager};
    use crate::model::pid::ProcessId;
    use crate::model::{AttachDestination, CgroupPath};
    use crate::CgroupPid;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let rand_id: u64 = rand::random();
            let path = std::env::temp_dir().join(format!("cgroup_test_{}_{}", prefix, rand_id));
            fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn path(&self) -> &PathBuf {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn make_test_topology_v2(cgroupfs_root: PathBuf) -> Arc<CgroupTopology> {
        Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
            membership: Default::default(),
            controllers: ControllerSet::default(),
            cgroupfs_root,
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        })
    }

    #[test]
    fn test_attach_destination_managed_cgroup_and_subgroup() {
        let fixture = TestDir::new("attach_dest");
        let cgroupfs_root = fixture.path().join("cgroup");
        fs::create_dir_all(&cgroupfs_root).unwrap();

        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        // Resolve ManagedCgroup -> root CgroupPath
        let resolved = manager
            .resolve_destination(&AttachDestination::ManagedCgroup)
            .unwrap();
        assert!(resolved.is_root());

        // Resolve explicit Subgroup
        let sub = CgroupPath::new("init.scope").unwrap();
        let resolved = manager
            .resolve_destination(&AttachDestination::Subgroup(sub.clone()))
            .unwrap();
        assert_eq!(resolved, sub);
    }

    #[test]
    fn test_resolve_same_cgroup_as_descendant_v2() {
        let fixture = TestDir::new("same_cgroup_descendant");
        let procfs = fixture.path().join("proc");
        let cgroupfs_root = fixture.path().join("cgroup");
        fs::create_dir_all(&cgroupfs_root).unwrap();

        // Create mock /proc/12345/cgroup
        let pid_dir = procfs.join("12345");
        fs::create_dir_all(&pid_dir).unwrap();
        let mut f = File::create(pid_dir.join("cgroup")).unwrap();
        writeln!(f, "0::/container.slice/init").unwrap();

        let host_paths = HostPaths {
            procfs,
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        let pid = ProcessId::new(12345).unwrap();
        let dest = AttachDestination::same_cgroup_as(pid);
        let resolved = manager.resolve_destination(&dest).unwrap();
        assert_eq!(resolved, CgroupPath::new("init").unwrap());
    }

    #[test]
    fn test_resolve_same_cgroup_as_same_base_v2() {
        let fixture = TestDir::new("same_cgroup_exact");
        let procfs = fixture.path().join("proc");
        let cgroupfs_root = fixture.path().join("cgroup");
        fs::create_dir_all(&cgroupfs_root).unwrap();

        // Create mock /proc/23456/cgroup with exact same base path
        let pid_dir = procfs.join("23456");
        fs::create_dir_all(&pid_dir).unwrap();
        let mut f = File::create(pid_dir.join("cgroup")).unwrap();
        writeln!(f, "0::/container.slice").unwrap();

        let host_paths = HostPaths {
            procfs,
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        let pid = ProcessId::new(23456).unwrap();
        let dest = AttachDestination::same_cgroup_as(pid);
        let resolved = manager.resolve_destination(&dest).unwrap();
        assert!(resolved.is_root());
    }

    #[test]
    fn test_resolve_same_cgroup_as_outside_managed_cgroup_fails() {
        let fixture = TestDir::new("same_cgroup_outside");
        let procfs = fixture.path().join("proc");
        let cgroupfs_root = fixture.path().join("cgroup");
        fs::create_dir_all(&cgroupfs_root).unwrap();

        // Create mock /proc/34567/cgroup pointing to a completely different slice
        let pid_dir = procfs.join("34567");
        fs::create_dir_all(&pid_dir).unwrap();
        let mut f = File::create(pid_dir.join("cgroup")).unwrap();
        writeln!(f, "0::/system.slice/other.service").unwrap();

        let host_paths = HostPaths {
            procfs,
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        let pid = ProcessId::new(34567).unwrap();
        let dest = AttachDestination::same_cgroup_as(pid);
        let result = manager.resolve_destination(&dest);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Attachment(AttachmentError::OutsideManagedCgroup { pid: err_pid, .. }) => {
                assert_eq!(err_pid, pid);
            }
            other => panic!(
                "expected AttachmentError::OutsideManagedCgroup, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_resolve_same_cgroup_as_nonexistent_pid_fails() {
        let fixture = TestDir::new("same_cgroup_missing_pid");
        let procfs = fixture.path().join("proc");
        let cgroupfs_root = fixture.path().join("cgroup");
        fs::create_dir_all(&cgroupfs_root).unwrap();

        let host_paths = HostPaths {
            procfs,
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        let pid = ProcessId::new(999999).unwrap();
        let dest = AttachDestination::same_cgroup_as(pid);
        let result = manager.resolve_destination(&dest);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Attachment(AttachmentError::ReadMembership { pid: err_pid, .. }) => {
                assert_eq!(err_pid, pid);
            }
            other => panic!("expected AttachmentError::ReadMembership, got {:?}", other),
        }
    }

    #[test]
    fn test_subcgroup_returns_root_regardless_of_init_directory() {
        let fixture = TestDir::new("subcgroup_shim");
        let cgroupfs_root = fixture.path().join("cgroup");
        let init_dir = cgroupfs_root.join("container.slice/init");
        fs::create_dir_all(&init_dir).unwrap();

        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        // Even though container.slice/init exists, subcgroup must return "/" unconditionally
        #[allow(deprecated)]
        let sub = manager.subcgroup();
        assert_eq!(sub, "/");
    }

    #[test]
    fn test_same_cgroup_as_dynamic_membership_change() {
        let fixture = TestDir::new("dynamic_membership");
        let procfs = fixture.path().join("proc");
        let cgroupfs_root = fixture.path().join("cgroup");

        let worker1_dir = cgroupfs_root.join("container.slice/worker1");
        let worker2_dir = cgroupfs_root.join("container.slice/worker2");
        fs::create_dir_all(&worker1_dir).unwrap();
        fs::create_dir_all(&worker2_dir).unwrap();
        File::create(worker1_dir.join("cgroup.procs")).unwrap();
        File::create(worker2_dir.join("cgroup.procs")).unwrap();

        let pid_dir = procfs.join("1111");
        fs::create_dir_all(&pid_dir).unwrap();
        let cgroup_file = pid_dir.join("cgroup");

        // Initially worker1
        fs::write(
            &cgroup_file,
            "0::/container.slice/worker1
",
        )
        .unwrap();

        let host_paths = HostPaths {
            procfs,
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let mut manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        let ref_pid = ProcessId::new(1111).unwrap();
        let dest = AttachDestination::same_cgroup_as(ref_pid);

        // First attach -> worker1
        manager.add_proc_to(CgroupPid::from(100u64), &dest).unwrap();
        assert_eq!(
            fs::read_to_string(worker1_dir.join("cgroup.procs"))
                .unwrap()
                .trim(),
            "100"
        );

        // Now reference process moves to worker2!
        fs::write(
            &cgroup_file,
            "0::/container.slice/worker2
",
        )
        .unwrap();

        // Second attach -> worker2 (re-read per attach, not cached!)
        manager.add_proc_to(CgroupPid::from(200u64), &dest).unwrap();
        assert_eq!(
            fs::read_to_string(worker2_dir.join("cgroup.procs"))
                .unwrap()
                .trim(),
            "200"
        );
    }

    #[test]
    fn test_same_cgroup_as_must_exist_does_not_recreate_vanished_target() {
        let fixture = TestDir::new("must_exist_vanished");
        let procfs = fixture.path().join("proc");
        let cgroupfs_root = fixture.path().join("cgroup");
        let container_dir = cgroupfs_root.join("container.slice");
        fs::create_dir_all(&container_dir).unwrap();
        File::create(container_dir.join("cgroup.procs")).unwrap();

        let pid_dir = procfs.join("2222");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("cgroup"),
            "0::/container.slice/vanished
",
        )
        .unwrap();

        let host_paths = HostPaths {
            procfs,
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let mut manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        let ref_pid = ProcessId::new(2222).unwrap();
        let dest = AttachDestination::same_cgroup_as(ref_pid);

        let result = manager.add_proc_to(CgroupPid::from(42u64), &dest);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Attachment(AttachmentError::MissingResolvedTarget { pid, .. }) => {
                assert_eq!(pid, ProcessId::new(42).unwrap());
            }
            other => panic!("expected MissingResolvedTarget, got {:?}", other),
        }

        // Must NOT create vanished directory!
        assert!(!container_dir.join("vanished").exists());
    }

    #[test]
    fn test_invalid_process_id_rejected() {
        let fixture = TestDir::new("invalid_pid");
        let cgroupfs_root = fixture.path().join("cgroup");
        fs::create_dir_all(&cgroupfs_root).unwrap();

        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let mut manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        let err = manager.add_proc(CgroupPid::from(0u64)).unwrap_err();
        match err {
            Error::Attachment(AttachmentError::InvalidProcessId { value: 0 }) => {}
            other => panic!("expected InvalidProcessId, got {:?}", other),
        }
    }

    #[test]
    fn test_fs_manager_add_proc_to_explicit_subgroup() {
        let fixture = TestDir::new("add_proc_subgroup");
        let cgroupfs_root = fixture.path().join("cgroup");
        let container_dir = cgroupfs_root.join("container.slice");
        let init_dir = container_dir.join("init");
        fs::create_dir_all(&init_dir).unwrap();

        // Create cgroup.procs inside both container and init
        File::create(container_dir.join("cgroup.procs")).unwrap();
        let init_procs = init_dir.join("cgroup.procs");
        File::create(&init_procs).unwrap();

        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let mut manager =
            FsManager::with_topology_and_host_paths("container.slice", topo, host_paths).unwrap();

        // Attach to explicit subgroup "init"
        let dest = AttachDestination::subgroup("init").unwrap();
        manager.add_proc_to(CgroupPid::from(42u64), &dest).unwrap();

        // Verify 42 was written to container.slice/init/cgroup.procs
        let content = fs::read_to_string(&init_procs).unwrap();
        assert_eq!(content.trim(), "42");
    }

    #[test]
    fn test_delegated_attachment_creates_v2_leaf_without_enabling_controllers() {
        let fixture = TestDir::new("delegated_attachment");
        let cgroupfs_root = fixture.path().join("cgroup");
        let managed_dir = cgroupfs_root.join("test.slice/scope-unit.scope");
        fs::create_dir_all(&managed_dir).unwrap();

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
            membership: Default::default(),
            controllers: vec!["memory".to_string()].into_iter().collect(),
            cgroupfs_root: cgroupfs_root.clone(),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        });
        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let manager = FsManager::with_topology_and_host_paths(
            "test.slice/scope-unit.scope",
            topology,
            host_paths,
        )
        .unwrap();
        let destination = manager
            .resolve_delegated_destination(&AttachDestination::subgroup("worker").unwrap(), &[])
            .unwrap();

        manager
            .add_proc_to_delegated_destination(ProcessId::new(42).unwrap(), &destination)
            .unwrap();

        assert_eq!(
            fs::read_to_string(managed_dir.join("worker/cgroup.procs"))
                .unwrap()
                .trim(),
            "42"
        );
        assert!(!cgroupfs_root.join("cgroup.subtree_control").exists());
        assert!(!managed_dir.join("cgroup.subtree_control").exists());
    }
}
#[cfg(all(test, feature = "oci"))]
mod resource_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::discovery::{CgroupTopology, CgroupVersion, ControllerSet, HostPaths, MountTable};
    use crate::manager::{FsManager, Manager};
    use crate::model::{CpuPatch, MemoryPatch, PidsPatch, ResourcePatch, Update};
    use crate::stats::{BlkioCgroupStats, CpuThrottlingStats, HugeTlbCgroupStats};
    use oci_spec::runtime::{LinuxCpuBuilder, LinuxPidsBuilder, LinuxResourcesBuilder};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let rand_id: u64 = rand::random();
            let path = std::env::temp_dir().join(format!("cgroup_res_test_{}_{}", prefix, rand_id));
            fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn path(&self) -> &PathBuf {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn make_test_topology_v2(cgroupfs_root: PathBuf) -> Arc<CgroupTopology> {
        let controllers: ControllerSet = vec![
            "cpu".to_string(),
            "memory".to_string(),
            "pids".to_string(),
            "cpuset".to_string(),
        ]
        .into_iter()
        .collect();

        Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
            membership: Default::default(),
            controllers,
            cgroupfs_root,
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        })
    }

    fn make_test_topology_v1_memory(cgroupfs_root: PathBuf) -> Arc<CgroupTopology> {
        let mounts = crate::discovery::parse_mountinfo(
            "43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime \
             shared:20 - cgroup cgroup rw,memory",
        )
        .unwrap();
        let membership = crate::discovery::parse_membership("1:memory:/").unwrap();

        Arc::new(CgroupTopology {
            version: CgroupVersion::V1,
            v2_available: false,
            mounts,
            membership,
            controllers: ControllerSet::default(),
            cgroupfs_root,
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        })
    }

    #[test]
    fn test_set_resources_native_patch_v2() {
        let fixture = TestDir::new("set_native");
        let cgroupfs_root = fixture.path().join("cgroup");
        let cgroup_dir = cgroupfs_root.join("test_slice.slice");
        fs::create_dir_all(&cgroup_dir).unwrap();

        // Seed mock controller pseudo-files
        fs::write(cgroup_dir.join("cgroup.procs"), "").unwrap();
        fs::write(cgroup_dir.join("cpu.max"), "max 100000\n").unwrap();
        fs::write(cgroup_dir.join("cpu.weight"), "100\n").unwrap();
        fs::write(cgroup_dir.join("memory.max"), "max\n").unwrap();
        fs::write(cgroup_dir.join("memory.low"), "0\n").unwrap();
        fs::write(cgroup_dir.join("memory.swap.max"), "max\n").unwrap();
        fs::write(cgroup_dir.join("pids.max"), "max\n").unwrap();

        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let mut manager =
            FsManager::with_topology_and_host_paths("test_slice.slice", topo, host_paths).unwrap();

        // 1. Apply concrete limits via pure native ResourcePatch
        let patch = ResourcePatch {
            cpu: CpuPatch {
                shares: Update::Set(2000),
                quota: Update::Set(50000),
                period: Update::Set(100000),
                ..Default::default()
            },
            memory: MemoryPatch {
                limit: Update::Set(1024 * 1024 * 1024),     // 1 GiB
                soft_limit: Update::Set(512 * 1024 * 1024), // 512 MiB
                // Native v2 patches describe memory.swap.max directly.
                swap: Update::Set(2 * 1024 * 1024 * 1024), // 2 GiB swap
                ..Default::default()
            },
            pids: PidsPatch {
                limit: Update::Set(256),
            },
            ..Default::default()
        };

        manager.set_resources(&patch).expect("set_resources failed");

        // Verify values written to cgroup pseudo-files
        let cpu_max = fs::read_to_string(cgroup_dir.join("cpu.max")).unwrap();
        assert_eq!(cpu_max.trim(), "50000 100000");

        let cpu_weight = fs::read_to_string(cgroup_dir.join("cpu.weight")).unwrap();
        assert_eq!(cpu_weight.trim(), "77"); // 1 + ((2000 - 2) * 9999) / 262142 = 77

        let mem_max = fs::read_to_string(cgroup_dir.join("memory.max")).unwrap();
        assert_eq!(mem_max.trim(), "1073741824");

        let mem_low = fs::read_to_string(cgroup_dir.join("memory.low")).unwrap();
        assert_eq!(mem_low.trim(), "536870912");

        let mem_swap = fs::read_to_string(cgroup_dir.join("memory.swap.max")).unwrap();
        assert_eq!(mem_swap.trim(), "2147483648");

        let pids_max = fs::read_to_string(cgroup_dir.join("pids.max")).unwrap();
        assert_eq!(pids_max.trim(), "256");

        // Set(0) is an explicit native update, not the OCI "unspecified"
        // sentinel, so every zero must reach the corresponding control file.
        let zero_patch = ResourcePatch {
            memory: MemoryPatch {
                limit: Update::Set(0),
                soft_limit: Update::Set(0),
                swap: Update::Set(0),
                ..Default::default()
            },
            pids: PidsPatch {
                limit: Update::Set(0),
            },
            ..Default::default()
        };
        manager
            .set_resources(&zero_patch)
            .expect("explicit zero patch failed");
        assert_eq!(
            fs::read_to_string(cgroup_dir.join("memory.max"))
                .unwrap()
                .trim(),
            "0"
        );
        assert_eq!(
            fs::read_to_string(cgroup_dir.join("memory.low"))
                .unwrap()
                .trim(),
            "0"
        );
        assert_eq!(
            fs::read_to_string(cgroup_dir.join("memory.swap.max"))
                .unwrap()
                .trim(),
            "0"
        );
        assert_eq!(
            fs::read_to_string(cgroup_dir.join("pids.max"))
                .unwrap()
                .trim(),
            "0"
        );

        // A swap-only native patch is valid on v2 and must not require a
        // memory limit for OCI combined-limit arithmetic.
        let mut swap_only = ResourcePatch::default();
        swap_only.memory.swap = Update::Set(4096);
        manager
            .set_resources(&swap_only)
            .expect("native swap-only patch failed");
        assert_eq!(
            fs::read_to_string(cgroup_dir.join("memory.swap.max"))
                .unwrap()
                .trim(),
            "4096"
        );

        // 2. Reset limits to Max
        let reset_patch = ResourcePatch {
            cpu: CpuPatch {
                quota: Update::Max,
                period: Update::Set(100000),
                ..Default::default()
            },
            memory: MemoryPatch {
                limit: Update::Max,
                swap: Update::Max,
                ..Default::default()
            },
            pids: PidsPatch { limit: Update::Max },
            ..Default::default()
        };

        manager
            .set_resources(&reset_patch)
            .expect("reset patch failed");

        let cpu_max = fs::read_to_string(cgroup_dir.join("cpu.max")).unwrap();
        assert_eq!(cpu_max.trim(), "max 100000");

        let mem_max = fs::read_to_string(cgroup_dir.join("memory.max")).unwrap();
        assert_eq!(mem_max.trim(), "max");

        let mem_swap = fs::read_to_string(cgroup_dir.join("memory.swap.max")).unwrap();
        assert_eq!(mem_swap.trim(), "max");

        let pids_max = fs::read_to_string(cgroup_dir.join("pids.max")).unwrap();
        assert_eq!(pids_max.trim(), "max");
    }

    #[test]
    fn test_set_oci_delegates_to_set_resources() {
        let fixture = TestDir::new("set_oci");
        let cgroupfs_root = fixture.path().join("cgroup");
        let cgroup_dir = cgroupfs_root.join("oci_slice.slice");
        fs::create_dir_all(&cgroup_dir).unwrap();

        fs::write(cgroup_dir.join("cgroup.procs"), "").unwrap();
        fs::write(cgroup_dir.join("cpu.max"), "max 100000\n").unwrap();
        fs::write(cgroup_dir.join("cpu.weight"), "100\n").unwrap();
        fs::write(cgroup_dir.join("memory.max"), "max\n").unwrap();
        fs::write(cgroup_dir.join("memory.low"), "0\n").unwrap();
        fs::write(cgroup_dir.join("memory.swap.max"), "max\n").unwrap();
        fs::write(cgroup_dir.join("pids.max"), "max\n").unwrap();

        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };

        let topo = make_test_topology_v2(cgroupfs_root);
        let mut manager =
            FsManager::with_topology_and_host_paths("oci_slice.slice", topo, host_paths).unwrap();

        let oci_cpu = LinuxCpuBuilder::default()
            .shares(1024u64)
            .quota(20000i64)
            .period(50000u64)
            .build()
            .unwrap();

        let oci_pids = LinuxPidsBuilder::default().limit(64i64).build().unwrap();

        let oci_res = LinuxResourcesBuilder::default()
            .cpu(oci_cpu)
            .pids(oci_pids)
            .build()
            .unwrap();

        // Call legacy manager.set(&LinuxResources) -> should translate and write via set_resources
        manager.set(&oci_res).expect("manager.set failed");

        let cpu_max = fs::read_to_string(cgroup_dir.join("cpu.max")).unwrap();
        assert_eq!(cpu_max.trim(), "20000 50000");

        let pids_max = fs::read_to_string(cgroup_dir.join("pids.max")).unwrap();
        assert_eq!(pids_max.trim(), "64");
    }

    #[test]
    fn test_set_custom_attributes_security() {
        let fixture = TestDir::new("custom_attrs_sec");
        let cgroupfs_root = fixture.path().join("cgroup");
        let cgroup_dir = cgroupfs_root.join("sec_slice.slice");
        fs::create_dir_all(&cgroup_dir).unwrap();

        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let topo = make_test_topology_v2(cgroupfs_root.clone());
        let mut manager =
            FsManager::with_topology_and_host_paths("sec_slice.slice", topo, host_paths).unwrap();

        let invalid_keys = vec![
            "/tmp/escaped_file",
            "../../escaped_file",
            "subdir/file",
            ".",
            "..",
            "",
            "bad\0name",
        ];

        for key in invalid_keys {
            let mut patch = ResourcePatch::default();
            patch
                .custom_attributes
                .insert(key.to_string(), "malicious_payload".to_string());
            let err = manager
                .set_resources(&patch)
                .expect_err(&format!("key `{}` must be rejected", key));
            assert!(
                matches!(
                    err,
                    crate::manager::error::Error::Core(crate::error::CoreError::InvalidPath { .. })
                ),
                "key `{}` must produce InvalidPath, got: {:?}",
                key,
                err
            );
        }

        // Valid attribute name succeeds and writes strictly inside cgroup_dir
        let mut valid_patch = ResourcePatch::default();
        valid_patch
            .custom_attributes
            .insert("memory.custom_file".to_string(), "valid_data".to_string());
        manager
            .set_resources(&valid_patch)
            .expect("valid custom attribute should succeed");

        let written = fs::read_to_string(cgroup_dir.join("memory.custom_file")).unwrap();
        assert_eq!(written, "valid_data");
    }

    #[test]
    fn test_set_custom_attributes_rejects_v1() {
        let fixture = TestDir::new("custom_attrs_v1");
        let cgroupfs_root = fixture.path().join("cgroup");
        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root.clone()),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let topo_v1 = Arc::new(CgroupTopology {
            version: CgroupVersion::V1,
            v2_available: false,
            mounts: MountTable::default(),
            membership: Default::default(),
            controllers: ControllerSet::default(),
            cgroupfs_root,
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        });

        let mut manager =
            FsManager::with_topology_and_host_paths("v1_slice.slice", topo_v1, host_paths).unwrap();

        let mut patch = ResourcePatch::default();
        patch
            .custom_attributes
            .insert("memory.high".to_string(), "1000".to_string());
        let err = manager
            .set_resources(&patch)
            .expect_err("v1 must reject custom_attributes");
        assert!(
            matches!(err, crate::manager::error::Error::Unsupported(_)),
            "expected Unsupported on v1, got: {:?}",
            err
        );
    }

    #[test]
    fn test_with_topology_zero_io_with_invalid_host_paths() {
        // Points to an entirely non-existent procfs path that would error if accessed
        let invalid_host_paths = HostPaths {
            procfs: PathBuf::from("/proc/definitely_does_not_exist_12345"),
            cgroupfs_override: Some(PathBuf::from(
                "/sys/fs/cgroup/definitely_does_not_exist_12345",
            )),
            hugepages: PathBuf::from("/nonexistent/hugepages"),
        };
        let topo = make_test_topology_v2(PathBuf::from("/sys/fs/cgroup/mock"));

        // Must succeed without performing I/O or attempting to discover against the invalid procfs path
        let mgr = FsManager::with_topology_and_host_paths("test.slice", topo, invalid_host_paths);
        assert!(
            mgr.is_ok(),
            "with_topology_and_host_paths must not perform host I/O"
        );
    }

    #[test]
    fn test_native_patch_rejects_unrepresentable_updates() {
        let fixture = TestDir::new("native_memory_validation");
        let cgroupfs_root = fixture.path().join("cgroup");
        let topo = make_test_topology_v2(cgroupfs_root.clone());
        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let mut manager =
            FsManager::with_topology_and_host_paths("test.slice", topo, host_paths).unwrap();

        let mut patch = ResourcePatch::default();
        patch.memory.limit = Update::Set(-1);
        assert!(matches!(
            manager.set_resources(&patch),
            Err(crate::manager::error::Error::InvalidArgument)
        ));

        let mut patch = ResourcePatch::default();
        patch.memory.kernel = Update::Set(1);
        assert!(matches!(
            manager.set_resources(&patch),
            Err(crate::manager::error::Error::Unsupported(_))
        ));

        let mut patch = ResourcePatch::default();
        patch.memory.soft_limit = Update::Max;
        assert!(matches!(
            manager.set_resources(&patch),
            Err(crate::manager::error::Error::Unsupported(_))
        ));

        let mut patch = ResourcePatch::default();
        patch.blkio.leaf_weight = Update::Set(300);
        assert!(matches!(
            manager.set_resources(&patch),
            Err(crate::manager::error::Error::Unsupported(_))
        ));
    }

    #[test]
    fn test_v1_memory_patch_validates_swappiness_before_writes() {
        let fixture = TestDir::new("v1_memory_preflight");
        let cgroupfs_root = fixture.path().join("cgroup");
        let cgroup_dir = cgroupfs_root.join("memory/test.slice");
        fs::create_dir_all(&cgroup_dir).unwrap();
        let limit_path = cgroup_dir.join("memory.limit_in_bytes");
        fs::write(&limit_path, "4096\n").unwrap();

        let topology = make_test_topology_v1_memory(cgroupfs_root.clone());
        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let mut manager =
            FsManager::with_topology_and_host_paths("test.slice", topology, host_paths).unwrap();
        let patch = ResourcePatch {
            memory: MemoryPatch {
                limit: Update::Set(1024),
                swappiness: Update::Set(101),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(matches!(
            manager.set_resources(&patch),
            Err(crate::manager::error::Error::InvalidArgument)
        ));
        assert_eq!(fs::read_to_string(limit_path).unwrap(), "4096\n");
    }

    #[test]
    fn test_try_stats_reports_controller_failures() {
        let fixture = TestDir::new("try_stats_error");
        let cgroupfs_root = fixture.path().join("cgroup");
        let cgroup_dir = cgroupfs_root.join("stats.slice");
        fs::create_dir_all(&cgroup_dir).unwrap();
        let topo = make_test_topology_v2(cgroupfs_root.clone());
        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let manager =
            FsManager::with_topology_and_host_paths("stats.slice", topo, host_paths).unwrap();

        // Legacy stats remain a best-effort compatibility view.
        let legacy_stats = manager.stats();
        assert!(legacy_stats.memory.memory.is_some());
        assert!(legacy_stats.memory.memory_swap.is_some());
        // The fallible API preserves missing-file errors for controllers that
        // are present, while controllers absent from the discovered topology
        // are represented by their empty/default statistics.
        assert!(manager.try_stats().is_err());
        assert!(manager.try_cpu_cgroup_stats().is_err());
        assert!(manager.try_memory_cgroup_stats().is_err());
        assert!(manager.try_pids_cgroup_stats().is_err());
        let blkio: BlkioCgroupStats = manager.try_blkio_cgroup_stats().unwrap();
        assert!(blkio.io_service_bytes_recursive.is_empty());
        let hugetlb: HugeTlbCgroupStats = manager.try_huge_tlb_cgroup_stats().unwrap();
        assert!(hugetlb.is_empty());
        let legacy = manager.pids_cgroup_stats();
        assert_eq!(legacy.current, 0);
        assert_eq!(legacy.limit, 0);
    }

    #[test]
    fn test_try_cpu_stats_v2_does_not_require_cpuacct_controller() {
        let fixture = TestDir::new("try_cpu_stats_v2");
        let cgroupfs_root = fixture.path().join("cgroup");
        let cgroup_dir = cgroupfs_root.join("stats.slice");
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::write(
            cgroup_dir.join("cpu.stat"),
            "nr_periods 3\nnr_throttled 1\nthrottled_time 7\n",
        )
        .unwrap();
        let topo = make_test_topology_v2(cgroupfs_root.clone());
        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let manager =
            FsManager::with_topology_and_host_paths("stats.slice", topo, host_paths).unwrap();

        let stats = manager.try_cpu_cgroup_stats().unwrap();
        assert!(stats.cpu_acct.is_none());
        let throttling: CpuThrottlingStats = stats.cpu_throttling.unwrap();
        assert_eq!(throttling.periods, 3);
        assert_eq!(throttling.throttled_periods, 1);
        assert_eq!(throttling.throttled_time, 7);
    }

    #[test]
    fn test_try_stats_v2_reads_only_discovered_controllers() {
        let fixture = TestDir::new("try_stats_v2_subset");
        let cgroupfs_root = fixture.path().join("cgroup");
        let cgroup_dir = cgroupfs_root.join("stats.slice");
        fs::create_dir_all(&cgroup_dir).unwrap();
        for (file, value) in [
            ("cpu.stat", "nr_periods 3\nnr_throttled 1\n"),
            ("memory.high", "max\n"),
            ("memory.low", "0\n"),
            ("memory.max", "max\n"),
            ("memory.min", "0\n"),
            ("memory.current", "42\n"),
            ("memory.stat", "anon 42\n"),
            ("memory.swap.max", "max\n"),
            ("memory.swap.current", "0\n"),
            ("pids.current", "2\n"),
            ("pids.max", "10\n"),
        ] {
            fs::write(cgroup_dir.join(file), value).unwrap();
        }
        let topo = make_test_topology_v2(cgroupfs_root.clone());
        let host_paths = HostPaths {
            procfs: fixture.path().join("proc"),
            cgroupfs_override: Some(cgroupfs_root),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        };
        let manager =
            FsManager::with_topology_and_host_paths("stats.slice", topo, host_paths).unwrap();

        let stats = manager.try_stats().unwrap();
        assert!(stats.cpu.cpu_acct.is_none());
        assert_eq!(stats.memory.memory.unwrap().usage, 42);
        assert_eq!(stats.memory.memory_swap.unwrap().limit, -1);
        assert_eq!(stats.pids.current, 2);
        assert!(stats.blkio.io_service_bytes_recursive.is_empty());
        assert!(stats.hugetlb.is_empty());
    }
}

#[cfg(test)]
mod attachment_regression_tests {
    use super::*;
    use crate::discovery::{parse_mountinfo, CgroupVersion, ControllerSet};
    use std::os::unix::fs::PermissionsExt;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "p2-probe-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn manager(
            &self,
            version: CgroupVersion,
            mounts: &str,
            own: &str,
            base: &str,
        ) -> FsManager {
            let cg = self.0.join("cg");
            let topo = Arc::new(CgroupTopology {
                version,
                v2_available: version == CgroupVersion::V2,
                mounts: parse_mountinfo(mounts).unwrap(),
                membership: parse_membership(own).unwrap(),
                controllers: ControllerSet::default(),
                cgroupfs_root: cg.clone(),
                hugepages: self.0.join("hugepages"),
            });
            FsManager::with_topology_and_host_paths(
                base,
                topo,
                HostPaths {
                    procfs: self.0.join("proc"),
                    cgroupfs_override: Some(cg),
                    hugepages: self.0.join("hugepages"),
                },
            )
            .unwrap()
        }
        fn reference(&self, contents: &str) -> AttachDestination {
            std::fs::create_dir_all(self.0.join("proc/100")).unwrap();
            std::fs::write(self.0.join("proc/100/cgroup"), contents).unwrap();
            AttachDestination::same_cgroup_as(ProcessId::new(100).unwrap())
        }
        fn procs(&self, path: &str) -> PathBuf {
            let dir = self.0.join("cg").join(path);
            std::fs::create_dir_all(&dir).unwrap();
            let file = dir.join("cgroup.procs");
            std::fs::write(&file, "").unwrap();
            file
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    const V2: &str = "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";

    const V1: &str = "31 23 0:27 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n32 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";

    #[test]
    fn test_split_v1_process_and_thread_placement() {
        let f = Fixture::new();
        let mut manager = f.manager(
            CgroupVersion::V1,
            V1,
            "1:cpu,cpuacct:/\n2:memory:/\n",
            "app",
        );
        let cpu = f.procs("cpu,cpuacct/app/cpu_leaf");
        let memory = f.procs("memory/app/mem_leaf");
        let cpu_tasks = cpu.with_file_name("tasks");
        let memory_tasks = memory.with_file_name("tasks");
        std::fs::write(&cpu_tasks, "").unwrap();
        std::fs::write(&memory_tasks, "").unwrap();
        let destination = f.reference("1:cpu,cpuacct:/app/cpu_leaf\n2:memory:/app/mem_leaf\n");
        manager
            .add_proc_to(CgroupPid::from(42u64), &destination)
            .unwrap();
        manager
            .add_thread_to(CgroupPid::from(43u64), &destination)
            .unwrap();
        assert_eq!(std::fs::read_to_string(&cpu).unwrap(), "42");
        assert_eq!(std::fs::read_to_string(&memory).unwrap(), "42");
        assert_eq!(std::fs::read_to_string(cpu_tasks).unwrap(), "43");
        assert_eq!(std::fs::read_to_string(memory_tasks).unwrap(), "43");
        let plan = manager.plan_attachment(&destination).unwrap();
        let targets = manager.attachment_targets(&plan).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[&cpu.parent().unwrap().to_path_buf()],
            ["cpu", "cpuacct"]
        );
        assert!(matches!(
            manager.resolve_destination(&destination),
            Err(Error::Attachment(AttachmentError::Unsupported { .. }))
        ));
    }

    #[test]
    fn test_missing_v1_target_prevents_all_writes() {
        let f = Fixture::new();
        let mut manager = f.manager(
            CgroupVersion::V1,
            V1,
            "1:cpu,cpuacct:/\n2:memory:/\n",
            "app",
        );
        let cpu = f.procs("cpu,cpuacct/app/leaf");
        let destination = f.reference("1:cpu,cpuacct:/app/leaf\n2:memory:/app/gone\n");
        assert!(matches!(
            manager.add_proc_to(CgroupPid::from(42u64), &destination),
            Err(Error::Attachment(
                AttachmentError::MissingResolvedTarget { .. }
            ))
        ));
        assert_eq!(std::fs::read_to_string(cpu).unwrap(), "");
        assert!(!f.0.join("cg/memory/app").exists());
    }

    #[test]
    fn test_invalid_membership_does_not_create_managed_root() {
        let f = Fixture::new();
        let mut manager = f.manager(CgroupVersion::V2, V2, "0::/\n", "app");
        let destination = f.reference("0::/app/leaf\n0::/outside\n");
        assert!(matches!(
            manager.add_proc_to(CgroupPid::from(42u64), &destination),
            Err(Error::Attachment(AttachmentError::ParseMembership { .. }))
        ));
        assert!(!f.0.join("cg/app").exists());
    }

    #[test]
    fn test_non_directory_preserves_enotdir() {
        let f = Fixture::new();
        let mut manager = f.manager(CgroupVersion::V2, V2, "0::/\n", "app");
        f.procs("app");
        std::fs::write(f.0.join("cg/app/leaf"), "").unwrap();
        let destination = f.reference("0::/app/leaf\n");
        match manager
            .add_proc_to(CgroupPid::from(42u64), &destination)
            .unwrap_err()
        {
            Error::Attachment(AttachmentError::TargetIo { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::ENOTDIR));
            }
            error => panic!("unexpected error: {:?}", error),
        }
    }

    #[test]
    fn test_missing_membership_file_is_not_created() {
        let f = Fixture::new();
        let mut manager = f.manager(
            CgroupVersion::V1,
            V1,
            "1:cpu,cpuacct:/\n2:memory:/\n",
            "app",
        );
        std::fs::create_dir_all(f.0.join("cg/cpu,cpuacct/app/leaf")).unwrap();
        f.procs("memory/app/leaf");
        let destination = f.reference("1:cpu,cpuacct:/app/leaf\n2:memory:/app/leaf\n");
        match manager
            .add_proc_to(CgroupPid::from(42u64), &destination)
            .unwrap_err()
        {
            Error::Attachment(AttachmentError::WriteMembership {
                controllers,
                completed,
                source,
                ..
            }) => {
                assert_eq!(controllers, ["cpu", "cpuacct"]);
                assert!(completed.is_empty());
                assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
            }
            error => panic!("unexpected error: {:?}", error),
        }
        assert!(!f.0.join("cg/cpu,cpuacct/app/leaf/cgroup.procs").exists());
    }

    #[test]
    fn test_reject_direct_root_subgroup() {
        let f = Fixture::new();
        let mut m = f.manager(CgroupVersion::V2, V2, "0::/\n", "app");
        let result = m.add_proc_to(
            CgroupPid::from(42u64),
            &AttachDestination::Subgroup(CgroupPath::root().unwrap()),
        );
        assert!(matches!(
            result,
            Err(Error::Attachment(
                AttachmentError::InvalidDestination { .. }
            ))
        ));
        assert!(!f.0.join("cg/app").exists());
    }

    #[test]
    fn test_use_selected_v2_mount() {
        let f = Fixture::new();
        let mounts = "31 23 0:27 /tenant /bind/cgroup rw - cgroup2 cgroup2 rw\n32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        let m = f.manager(CgroupVersion::V2, mounts, "0::/\n", "app");
        let dest = f.reference("0::/tenant/app/leaf\n");
        let result = m.resolve_destination(&dest);
        assert!(
            matches!(
                result,
                Err(Error::Attachment(
                    AttachmentError::OutsideManagedCgroup { .. }
                ))
            ),
            "reference outside app was accepted via first bind mount: {:?}",
            result
        );
    }

    #[test]
    fn test_v1_mount_plan_and_execution_agree() {
        let f = Fixture::new();
        let mounts = "31 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n32 23 0:27 /tenant /sys/fs/cgroup/cpu-view rw - cgroup cgroup rw,cpu\n33 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
        let mut m = f.manager(CgroupVersion::V1, mounts, "1:cpu:/\n2:memory:/\n", "app");
        f.procs("cpu/app");
        f.procs("memory/app");
        let expected = f.procs("cpu/app/leaf");
        let wrong = f.procs("cpu-view/app/leaf");
        f.procs("memory/app/leaf");
        let dest = f.reference("1:cpu:/app/leaf\n2:memory:/app/leaf\n");
        m.add_proc_to(CgroupPid::from(42u64), &dest).unwrap();
        assert_eq!(
            std::fs::read_to_string(expected).unwrap(),
            "42",
            "wrong bind-mount path received {:?}",
            std::fs::read_to_string(wrong).unwrap()
        );
    }

    #[test]
    fn test_do_not_fabricate_unmounted_v1_controller() {
        let f = Fixture::new();
        let mounts = "32 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
        let mut m = f.manager(CgroupVersion::V1, mounts, "1:cpu:/\n2:memory:/\n", "app");
        f.procs("memory/app");
        let memory = f.procs("memory/app/leaf");
        assert!(!m.mounts.contains_key("cpu"));
        let result = m.add_proc_to(
            CgroupPid::from(42u64),
            &AttachDestination::subgroup("leaf").unwrap(),
        );
        result.unwrap();
        assert_eq!(std::fs::read_to_string(memory).unwrap(), "42");
        assert!(!f.0.join("cg/cpu").exists());
    }

    #[test]
    fn test_preserve_target_permission_errno() {
        crate::skip_if_root!();
        let f = Fixture::new();
        let mut m = f.manager(CgroupVersion::V2, V2, "0::/\n", "app");
        f.procs("app");
        f.procs("app/locked/leaf");
        let dest = f.reference("0::/app/locked/leaf\n");
        let locked = f.0.join("cg/app/locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o0)).unwrap();
        let result = m.add_proc_to(CgroupPid::from(42u64), &dest);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        match result.unwrap_err() {
            Error::Attachment(AttachmentError::TargetIo {
                pid,
                target,
                controllers,
                source,
                ..
            }) => {
                assert_eq!(pid.get(), 42);
                assert_eq!(target, locked.join("leaf"));
                assert_eq!(controllers, ["0::"]);
                assert_eq!(source.raw_os_error(), Some(libc::EACCES));
            }
            err => panic!("unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_reject_ambiguous_reference_membership() {
        let f = Fixture::new();
        let m = f.manager(CgroupVersion::V2, V2, "0::/\n", "app");
        let dest = f.reference("0::/app/leaf\n0::/outside\n");
        let result = m.resolve_destination(&dest);
        assert!(
            result.is_err(),
            "contradictory unified records accepted: {:?}",
            result
        );
    }

    #[test]
    fn test_report_partial_v1_migration() {
        let f = Fixture::new();
        let mounts = "31 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n32 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
        let mut m = f.manager(CgroupVersion::V1, mounts, "1:cpu:/\n2:memory:/\n", "app");
        f.procs("cpu/app");
        f.procs("memory/app");
        let cpu = f.procs("cpu/app/leaf");
        std::fs::create_dir_all(f.0.join("cg/memory/app/leaf/cgroup.procs")).unwrap();
        let dest = f.reference("1:cpu:/app/leaf\n2:memory:/app/leaf\n");
        let err = m.add_proc_to(CgroupPid::from(42u64), &dest).unwrap_err();
        assert_eq!(std::fs::read_to_string(cpu).unwrap(), "42");
        match err {
            Error::Attachment(AttachmentError::WriteMembership {
                controllers,
                target,
                completed,
                source,
                ..
            }) => {
                assert_eq!(controllers, ["memory"]);
                assert_eq!(target, f.0.join("cg/memory/app/leaf/cgroup.procs"));
                assert_eq!(completed, vec![vec!["cpu".to_string()]]);
                assert_eq!(source.raw_os_error(), Some(libc::EISDIR));
            }
            other => panic!("expected partial migration error, got {:?}", other),
        }
    }
}
