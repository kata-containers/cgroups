// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;

use oci_spec::runtime::LinuxResources;
use zbus::zvariant::Value as ZbusValue;

use crate::discovery::attachment::{plan_attachment, CreationPolicy, Placement};
use crate::discovery::membership::Membership;
use crate::discovery::{discover, CgroupTopology, CgroupVersion, HostPaths};
use crate::error::AttachmentError;
use crate::manager::conv;
use crate::manager::error::{Error, Result};
use crate::manager::fs::{join_path, FsManager};
use crate::model::path::CgroupPath;
use crate::model::pid::ProcessId;
use crate::model::{
    AttachDestination, CpuPatch, CpuSetPatch, MemoryPatch, PidsPatch, ResourcePatch, Update,
};
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

// systemd's legacy resource dialect (CGROUP_MASK_V1). In particular, a v1
// cpuset or freezer mount is not a hierarchy systemd realizes for each unit.
const SYSTEMD_V1_CONTROLLERS: &[&str] = &["cpu", "cpuacct", "blkio", "memory", "devices", "pids"];

pub struct SystemdManager<'a> {
    /// The name of slice
    slice: String,
    /// The name of unit
    unit: String,
    /// Systemd client
    systemd_client: SystemdClient<'a>,
    /// Cgroupfs manager
    fs_manager: FsManager,
}

impl SystemdManager<'_> {
    /// Select only delegated, realized v1 resource hierarchies, plus the named
    /// unit hierarchy. DelegateControllers can also name v2-only controllers.
    /// A missing unit root is normal for an unrealized resource controller;
    /// missing descendant targets and other metadata errors remain failures.
    fn attachment_subsystems(
        &self,
        pid: ProcessId,
        delegated_controllers: &[String],
    ) -> Result<Vec<String>> {
        if self.topology().version == CgroupVersion::V2 {
            return Ok(Vec::new());
        }

        let cpu_delegated = delegated_controllers
            .iter()
            .any(|controller| controller == "cpu" || controller == "cpuacct");
        let mut subsystems = vec!["name=systemd".to_string()];
        for controller in SYSTEMD_V1_CONTROLLERS {
            let delegated = match *controller {
                // systemd extends either CPU bit to both co-mounted controllers.
                "cpu" | "cpuacct" => cpu_delegated,
                _ => delegated_controllers.iter().any(|name| name == controller),
            };
            if !delegated {
                continue;
            }
            let Some(mount) = self.topology().mounts.controller_mount(controller) else {
                continue;
            };
            let target = self
                .topology()
                .resolve_mount_point(&mount.mount_point)
                .join(self.fs_manager.base().as_path());
            let source = match std::fs::metadata(&target) {
                Ok(metadata) if metadata.is_dir() => {
                    subsystems.push((*controller).to_string());
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => error,
                Ok(_) => std::io::Error::from_raw_os_error(libc::ENOTDIR),
            };
            return Err(AttachmentError::TargetIo {
                backend: "systemd",
                pid,
                operation: "inspect delegated unit hierarchy",
                target,
                controllers: vec![(*controller).to_string()],
                source,
            }
            .into());
        }
        subsystems.sort();
        Ok(subsystems)
    }

    fn delegated_subsystems(&self, pid: ProcessId, is_delegated: bool) -> Result<Vec<String>> {
        let controllers = if is_delegated && self.topology().version == CgroupVersion::V1 {
            self.systemd_client.try_delegated_controllers()?
        } else {
            Vec::new()
        };
        self.attachment_subsystems(pid, &controllers)
    }

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
        })
    }

    /// Return the topology snapshot held by this manager.
    pub fn topology(&self) -> &Arc<CgroupTopology> {
        self.fs_manager.topology()
    }
}

/// Classification of a process's current cgroup location relative to this unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessLocation {
    /// Process is inside the managed unit cgroup tree at the specified subpath.
    Inside(CgroupPath),
    /// The process is inside the unit on all managed v1 hierarchies, but at
    /// different subpaths. A single path cannot establish an attachment no-op.
    InsideDifferentHierarchies,
    /// Process is completely outside the managed unit cgroup tree.
    Outside,
}

/// Action to execute for attaching a process to a systemd unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SystemdAttachAction {
    /// Unit does not exist yet; start transient unit with initial PID, then
    /// move to subgroup if not unit root.
    StartUnitWithSubgroup { subgroup: CgroupPath },
    /// Process is outside unit; attach via D-Bus AttachProcessesToUnit.
    AttachOutsideViaDbus { dbus_subgroup: String },
    /// Process is already at the target destination inside the unit.
    AlreadyAtDestination,
    /// Process is inside the unit but in a different subgroup; migrate
    /// directly within delegated subtree.
    MigrateInsideDelegatedSubgroup { subgroup: CgroupPath },
}

/// Encode a [`CgroupPath`] into a systemd D-Bus subgroup argument.
///
/// Returns an empty string for the unit root, or a leading-slash absolute path
/// for descendant subgroups. Fails if the subgroup path contains invalid UTF-8.
pub(crate) fn encode_dbus_subgroup(path: &CgroupPath) -> Result<String> {
    if path.is_root() {
        return Ok(String::new());
    }
    let s = path.as_path().to_str().ok_or_else(|| {
        Error::Attachment(AttachmentError::NonUtf8SystemdSubgroup { path: path.clone() })
    })?;
    Ok(format!("/{}", s.trim_start_matches('/')))
}

/// Plan the attach action to take given the unit existence state,
/// process location, target subgroup, and delegation capability.
pub(crate) fn plan_attach_action(
    pid: ProcessId,
    unit_exists: bool,
    location: Option<&ProcessLocation>,
    target_subgroup: &CgroupPath,
    is_delegated: bool,
) -> Result<SystemdAttachAction> {
    // Subgroup placement requires delegation.  Non-delegated units (e.g.
    // slices) must not have their cgroup tree mutated directly — systemd is
    // the single writer.  Reject early, regardless of unit existence or
    // process location.
    if !is_delegated && !target_subgroup.is_root() {
        return Err(Error::Unsupported(
            "cannot place processes in a subgroup of a non-delegated systemd unit".to_string(),
        ));
    }

    if !unit_exists {
        return Ok(SystemdAttachAction::StartUnitWithSubgroup {
            subgroup: target_subgroup.clone(),
        });
    }

    let location = location.ok_or_else(|| {
        Error::Attachment(AttachmentError::AmbiguousMembership {
            pid,
            detail: "process location must be provided when unit exists".to_string(),
        })
    })?;

    match location {
        ProcessLocation::Outside => {
            if !is_delegated {
                return Err(Error::Unsupported(
                    "systemd process attachment requires a delegated unit".to_string(),
                ));
            }
            let dbus_subgroup = encode_dbus_subgroup(target_subgroup)?;
            Ok(SystemdAttachAction::AttachOutsideViaDbus { dbus_subgroup })
        }
        ProcessLocation::Inside(current) => {
            if current == target_subgroup {
                Ok(SystemdAttachAction::AlreadyAtDestination)
            } else {
                if !is_delegated {
                    return Err(Error::Unsupported(
                        "cannot migrate processes within a non-delegated systemd unit".to_string(),
                    ));
                }
                Ok(SystemdAttachAction::MigrateInsideDelegatedSubgroup {
                    subgroup: target_subgroup.clone(),
                })
            }
        }
        ProcessLocation::InsideDifferentHierarchies => {
            if !is_delegated {
                return Err(Error::Unsupported(
                    "cannot migrate processes within a non-delegated systemd unit".to_string(),
                ));
            }
            Ok(SystemdAttachAction::MigrateInsideDelegatedSubgroup {
                subgroup: target_subgroup.clone(),
            })
        }
    }
}

/// Classify every managed hierarchy. On v1, systemd decides whether a process
/// belongs to a unit using name=systemd, independently of resource controllers.
fn classify_process_location(
    topology: &CgroupTopology,
    base: &CgroupPath,
    subsystems: &[String],
    pid: ProcessId,
    membership: &Membership,
) -> Result<ProcessLocation> {
    let destination = AttachDestination::same_cgroup_as(pid);
    if topology.version == CgroupVersion::V1 {
        match plan_attachment(
            topology,
            base,
            &["name=systemd".to_string()],
            &destination,
            Some(membership),
        ) {
            Err(AttachmentError::OutsideManagedCgroup { .. }) => {
                return Ok(ProcessLocation::Outside)
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
    }
    let plan = match plan_attachment(topology, base, subsystems, &destination, Some(membership)) {
        Ok(plan) => plan,
        Err(AttachmentError::OutsideManagedCgroup { .. })
            if topology.version == CgroupVersion::V2 =>
        {
            return Ok(ProcessLocation::Outside);
        }
        Err(AttachmentError::OutsideManagedCgroup { .. }) => {
            return Err(AttachmentError::Unsupported {
                backend: "systemd",
                operation: "process belongs to the unit but a resource hierarchy is outside its delegated tree",
            }.into());
        }
        Err(error) => return Err(error.into()),
    };
    let target = match &plan.placement {
        Placement::Unified(target) => target,
        Placement::Legacy(targets) => {
            let target = targets
                .values()
                .next()
                .ok_or(AttachmentError::Unsupported {
                    backend: "systemd",
                    operation: "attachment requires a visible managed hierarchy",
                })?;
            // Include name=systemd even when the manager's own membership did
            // not list it: D-Bus unit membership must agree with all targets.
            let systemd_plan = plan_attachment(
                topology,
                base,
                &["name=systemd".to_string()],
                &destination,
                Some(membership),
            )?;
            let Placement::Legacy(systemd_targets) = systemd_plan.placement else {
                unreachable!()
            };
            if targets
                .values()
                .chain(systemd_targets.values())
                .any(|path| path != target)
            {
                return Ok(ProcessLocation::InsideDifferentHierarchies);
            }
            target
        }
    };
    let subgroup = target.as_path().strip_prefix(base.as_path()).map_err(|_| {
        Error::Core(crate::error::CoreError::InvalidPath {
            input: target.as_path().to_path_buf(),
            reason: crate::error::PathReason::ContainmentViolation,
            operation: "classify_process_location",
        })
    })?;
    Ok(ProcessLocation::Inside(
        if subgroup.as_os_str().is_empty() {
            CgroupPath::root()?
        } else {
            CgroupPath::new(subgroup)?
        },
    ))
}

impl SystemdManager<'_> {
    /// Existing scopes use the actual D-Bus property. For a new scope the
    /// transient-unit builder explicitly requests Delegate=true.
    fn is_delegated(&self, unit_exists: bool) -> Result<bool> {
        if !self.unit.ends_with(SCOPE_SUFFIX) {
            return Ok(false);
        }
        if unit_exists {
            Ok(self.systemd_client.try_delegated()?)
        } else {
            Ok(true)
        }
    }

    /// Locate a process relative to this managed unit.
    pub(crate) fn locate_process(
        &self,
        pid: ProcessId,
        subsystems: &[String],
    ) -> Result<ProcessLocation> {
        classify_process_location(
            self.topology(),
            self.fs_manager.base(),
            subsystems,
            pid,
            &self.fs_manager.read_membership(pid)?,
        )
    }

    /// Get the slice name.
    pub fn slice(&self) -> &str {
        &self.slice
    }

    /// Get the unit name.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    fn set_cpuset_patch(&self, props: &mut Vec<Property>, patch: &CpuSetPatch) -> Result<()> {
        if matches!(&patch.cpus, Update::Max) || matches!(&patch.mems, Update::Max) {
            return Err(Error::Unsupported(
                "cpuset values do not support Update::Max".to_string(),
            ));
        }
        if let Update::Set(ref cpus) = patch.cpus {
            let (id, value) = cpuset::cpus(cpus)?;
            props.push((id, value.into()));
        }

        if let Update::Set(ref mems) = patch.mems {
            let (id, value) = cpuset::mems(mems)?;
            props.push((id, value.into()));
        }

        Ok(())
    }

    fn set_cpu_patch(&self, props: &mut Vec<Property>, patch: &CpuPatch) -> Result<()> {
        if !patch.realtime_runtime.is_unchanged() || !patch.realtime_period.is_unchanged() {
            return Err(Error::Unsupported(
                "cpu realtime scheduling is not supported by systemd manager".to_string(),
            ));
        }
        if matches!(patch.shares, Update::Max) || matches!(patch.period, Update::Max) {
            return Err(Error::Unsupported(
                "cpu shares and period do not support Update::Max".to_string(),
            ));
        }

        if let Update::Set(shares) = patch.shares {
            let shares = if self.v2() {
                conv::cpu_shares_to_cgroup_v2(shares)
            } else {
                shares
            };
            let (id, value) = cpu::shares(shares, self.v2())?;
            props.push((id, value.into()));
        }

        let period = match patch.period {
            Update::Set(0) => return Err(Error::InvalidArgument),
            Update::Set(period) => Some(period),
            Update::Unchanged => None,
            Update::Max => unreachable!("validated above"),
        };

        if let Some(period) = period {
            let (id, value) = cpu::period(period)?;
            props.push((id, value.into()));
        }

        if !patch.quota.is_unchanged() {
            let quota_systemd = match patch.quota {
                Update::Set(quota) if quota > 0 => {
                    let period = period.unwrap_or(DEFAULT_CPU_QUOTA_PERIOD);
                    let mut value = ((quota as u64) * s_to_us(1)) / period;
                    if !value.is_multiple_of(ms_to_us(10)) {
                        value = (value / ms_to_us(10) + 1) * ms_to_us(10);
                    }
                    value
                }
                Update::Set(_) => return Err(Error::InvalidArgument),
                Update::Max => u64::MAX,
                Update::Unchanged => unreachable!("checked above"),
            };
            let (id, value) = cpu::quota(quota_systemd)?;
            props.push((id, value.into()));
        }

        Ok(())
    }

    fn set_memory_patch(&self, props: &mut Vec<Property>, patch: &MemoryPatch) -> Result<()> {
        let v2 = self.v2();

        if !patch.kernel.is_unchanged()
            || !patch.kernel_tcp.is_unchanged()
            || !patch.swappiness.is_unchanged()
            || !patch.disable_oom_killer.is_unchanged()
        {
            return Err(Error::Unsupported(
                "kernel/tcp/swappiness/oom_killer memory settings are not supported by systemd manager".to_string(),
            ));
        }

        if !v2 {
            if !patch.soft_limit.is_unchanged() {
                return Err(Error::Unsupported(
                    "memory soft_limit is not supported on cgroup v1 by systemd manager"
                        .to_string(),
                ));
            }
            if !patch.swap.is_unchanged() {
                return Err(Error::Unsupported(
                    "memory swap is not supported on cgroup v1 by systemd manager".to_string(),
                ));
            }
        }
        if matches!(patch.soft_limit, Update::Max) {
            return Err(Error::Unsupported(
                "memory soft_limit does not support Update::Max through systemd".to_string(),
            ));
        }

        if !patch.limit.is_unchanged() {
            let mem_limit = match patch.limit {
                Update::Set(v) if v >= 0 => v,
                Update::Set(_) => return Err(Error::InvalidArgument),
                Update::Max => -1,
                Update::Unchanged => unreachable!("checked above"),
            };
            let (id, value) = memory::limit(mem_limit, v2)?;
            props.push((id, value.into()));
        }

        if let Update::Set(reservation) = patch.soft_limit {
            if reservation < 0 {
                return Err(Error::InvalidArgument);
            }
            let (id, value) = memory::low(reservation, v2)?;
            props.push((id, value.into()));
        }

        if !patch.swap.is_unchanged() {
            let memswap_limit = match patch.swap {
                Update::Set(v) if v >= 0 => v,
                Update::Set(_) => return Err(Error::InvalidArgument),
                Update::Max => -1,
                Update::Unchanged => unreachable!("checked above"),
            };
            let (id, value) = memory::swap(memswap_limit, v2)?;
            props.push((id, value.into()));
        }

        Ok(())
    }

    fn set_pids_patch(&self, props: &mut Vec<Property>, patch: &PidsPatch) -> Result<()> {
        if patch.limit.is_unchanged() {
            return Ok(());
        }
        let limit = match patch.limit {
            Update::Set(v) if v >= 0 => v,
            Update::Set(_) => return Err(Error::InvalidArgument),
            Update::Max => -1,
            Update::Unchanged => unreachable!("checked above"),
        };
        let (id, value) = pids::max(limit)?;
        props.push((id, value.into()));

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
        self.add_proc_to(pid, &AttachDestination::ManagedCgroup)
    }

    fn add_proc_to(&mut self, raw_pid: CgroupPid, destination: &AttachDestination) -> Result<()> {
        let pid = ProcessId::try_from(raw_pid).map_err(|_| {
            Error::Attachment(AttachmentError::InvalidProcessId { value: raw_pid.pid })
        })?;

        let unit_exists = self.systemd_client.try_exists()?;
        let is_delegated = self.is_delegated(unit_exists)?;
        let subsystems = if unit_exists {
            self.delegated_subsystems(pid, is_delegated)?
        } else {
            // Before startup only the unit hierarchy is known. Non-reference
            // destinations are syntactic; re-plan a subgroup after completion.
            self.attachment_subsystems(pid, &[])?
        };
        let resolved = self
            .fs_manager
            .resolve_delegated_destination(destination, &subsystems)?;

        let location = if unit_exists {
            Some(self.locate_process(pid, &subsystems)?)
        } else {
            None
        };

        let action = plan_attach_action(
            pid,
            unit_exists,
            location.as_ref(),
            &resolved.subgroup,
            is_delegated,
        )?;

        match action {
            SystemdAttachAction::StartUnitWithSubgroup { subgroup } => {
                if resolved.plan.creation == CreationPolicy::MustExist {
                    self.fs_manager
                        .ensure_delegated_destination_exists(pid, &resolved)?;
                    return Err(AttachmentError::Unsupported {
                        backend: "systemd",
                        operation: "SameCgroupAs requires an existing managed systemd unit",
                    }
                    .into());
                }
                self.systemd_client.set_pid_prop(raw_pid)?;
                self.systemd_client.start()?;
                if !subgroup.is_root() {
                    if !self.systemd_client.try_delegated()? {
                        return Err(Error::Unsupported(
                            "started scope did not enable delegation".to_string(),
                        ));
                    }
                    // Startup realizes and delegates the unit hierarchies. Use
                    // the actual properties and roots, never create missing roots.
                    let subsystems = self.delegated_subsystems(pid, true)?;
                    let target = self
                        .fs_manager
                        .resolve_delegated_destination(destination, &subsystems)?;
                    self.fs_manager
                        .add_proc_to_delegated_destination(pid, &target)?;
                }
            }
            SystemdAttachAction::AttachOutsideViaDbus { dbus_subgroup } => {
                self.fs_manager
                    .prepare_delegated_destination(pid, &resolved)?;
                self.systemd_client.add_process_id(pid, &dbus_subgroup)?;
            }
            SystemdAttachAction::AlreadyAtDestination => {
                self.fs_manager
                    .ensure_delegated_destination_exists(pid, &resolved)?;
            }
            SystemdAttachAction::MigrateInsideDelegatedSubgroup { .. } => {
                self.fs_manager
                    .add_proc_to_delegated_destination(pid, &resolved)?;
            }
        }
        Ok(())
    }

    /// `add_thread()` is unsupported on `SystemdManager` because systemd does not
    /// expose an API to attach individual threads. Thread-level attachment cannot
    /// be safely downgraded to process-level migration.
    fn add_thread(&mut self, _pid: CgroupPid) -> Result<()> {
        Err(Error::Unsupported(
            "systemd manager does not support thread-level attachment".to_string(),
        ))
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

    fn set_resources(&mut self, resources: &ResourcePatch) -> Result<()> {
        let blkio = &resources.blkio;
        if !blkio.weight.is_unchanged()
            || !blkio.leaf_weight.is_unchanged()
            || !blkio.weight_device.is_empty()
            || !blkio.throttle_read_bps_device.is_empty()
            || !blkio.throttle_write_bps_device.is_empty()
            || !blkio.throttle_read_iops_device.is_empty()
            || !blkio.throttle_write_iops_device.is_empty()
        {
            return Err(Error::Unsupported(
                "blkio resources are not supported by systemd manager".to_string(),
            ));
        }

        if !resources.hugepages.limits.is_empty() {
            return Err(Error::Unsupported(
                "hugetlb resources are not supported by systemd manager".to_string(),
            ));
        }

        if !resources.network.class_id.is_unchanged() || !resources.network.priorities.is_empty() {
            return Err(Error::Unsupported(
                "network resources are not supported by systemd manager".to_string(),
            ));
        }

        if !resources.devices.rules.is_empty() {
            return Err(Error::Unsupported(
                "devices resources are not supported by systemd manager".to_string(),
            ));
        }

        if !resources.custom_attributes.is_empty() {
            return Err(Error::Unsupported(
                "custom_attributes are not supported by systemd manager".to_string(),
            ));
        }

        let mut props = vec![];

        self.set_cpuset_patch(&mut props, &resources.cpuset)?;
        self.set_cpu_patch(&mut props, &resources.cpu)?;
        self.set_memory_patch(&mut props, &resources.memory)?;
        self.set_pids_patch(&mut props, &resources.pids)?;

        self.systemd_client.set_properties(&props)?;

        Ok(())
    }

    fn set(&mut self, resources: &LinuxResources) -> Result<()> {
        let patch = conv::oci_to_resource_patch(resources, self.v2())?;
        self.set_resources(&patch)
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
    use crate::manager::conv;
    use crate::model::{AttachDestination, MemoryPatch, PidsPatch, Update};
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
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
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

        let pid = crate::model::pid::ProcessId::new(4242).unwrap();
        let destination = AttachDestination::same_cgroup_as(pid);
        let resolved = manager
            .fs_manager
            .resolve_destination(&destination)
            .unwrap();
        assert_eq!(resolved.as_path(), std::path::Path::new("worker"));
    }

    #[test]
    fn test_systemd_same_cgroup_as_must_exist_does_not_recreate_vanished_leaf() {
        use crate::discovery::attachment::CreationPolicy;
        use crate::error::AttachmentError;
        use crate::manager::Error;
        use crate::model::CgroupPath;

        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let temp_dir = std::env::temp_dir().join(format!(
            "systemd-must-exist-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _guard = TempGuard(temp_dir.clone());
        let procfs = temp_dir.join("proc");
        let cgroupfs = temp_dir.join("cgroupfs");
        let unit_dir = cgroupfs.join("test.slice/scope-unit.scope");
        std::fs::create_dir_all(&unit_dir).unwrap();
        std::fs::create_dir_all(procfs.join("4242")).unwrap();
        // The reference process was observed in `gone`, which no longer
        // exists on the (synthetic) cgroupfs.
        std::fs::write(
            procfs.join("4242/cgroup"),
            "0::/test.slice/scope-unit.scope/gone\n",
        )
        .unwrap();

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
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
            host_paths,
        )
        .unwrap();

        // SameCgroupAs keeps MustExist after being flattened to a subgroup.
        let ref_pid = crate::model::pid::ProcessId::new(4242).unwrap();
        let resolved = manager
            .fs_manager
            .resolve_delegated_destination(&AttachDestination::same_cgroup_as(ref_pid), &[])
            .unwrap();
        assert_eq!(resolved.subgroup.as_path(), std::path::Path::new("gone"));
        assert_eq!(resolved.plan.creation, CreationPolicy::MustExist);

        // The migrate-inside branch must report ENOENT, not recreate `gone`.
        let mover = crate::model::pid::ProcessId::new(77).unwrap();
        let err = manager
            .fs_manager
            .add_proc_to_delegated_destination(mover, &resolved)
            .unwrap_err();
        match err {
            Error::Attachment(AttachmentError::MissingResolvedTarget {
                pid,
                target,
                source,
            }) => {
                assert_eq!(pid, mover);
                assert_eq!(target, unit_dir.join("gone"));
                assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
            }
            other => panic!("expected MissingResolvedTarget, got {:?}", other),
        }
        // The D-Bus branch prepares the destination the same way.
        assert!(manager
            .fs_manager
            .prepare_delegated_destination(mover, &resolved)
            .is_err());
        assert!(!unit_dir.join("gone").exists());

        // Contrast: an explicit Subgroup may still create its leaf.
        let explicit = manager
            .fs_manager
            .resolve_delegated_destination(
                &AttachDestination::Subgroup(CgroupPath::new("worker").unwrap()),
                &[],
            )
            .unwrap();
        assert_eq!(explicit.plan.creation, CreationPolicy::MayCreateLeaf);
        manager
            .fs_manager
            .prepare_delegated_destination(mover, &explicit)
            .unwrap();
        assert!(unit_dir.join("worker").is_dir());

        // This fixture stays independent of the host system D-Bus.
    }

    #[test]
    fn test_systemd_native_zero_updates_become_properties() {
        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/nonexistent"),
        });
        let manager = SystemdManager::with_topology("test.slice:scope:unit", topology).unwrap();
        let mut props = Vec::new();

        manager
            .set_memory_patch(
                &mut props,
                &MemoryPatch {
                    limit: Update::Set(0),
                    swap: Update::Set(0),
                    ..Default::default()
                },
            )
            .unwrap();
        manager
            .set_pids_patch(
                &mut props,
                &PidsPatch {
                    limit: Update::Set(0),
                },
            )
            .unwrap();

        assert!(props
            .iter()
            .any(|(name, value)| *name == "MemoryMax"
                && matches!(value, &zbus::zvariant::Value::U64(0))));
        assert!(props.iter().any(|(name, value)| *name == "MemorySwapMax"
            && matches!(value, &zbus::zvariant::Value::U64(0))));
        assert!(props
            .iter()
            .any(|(name, value)| *name == "TasksMax"
                && matches!(value, &zbus::zvariant::Value::U64(0))));

        props.clear();
        manager
            .set_memory_patch(
                &mut props,
                &MemoryPatch {
                    swap: Update::Set(4096),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(props.iter().any(|(name, value)| *name == "MemorySwapMax"
            && matches!(value, &zbus::zvariant::Value::U64(4096))));
    }

    #[test]
    fn test_systemd_add_thread_unsupported() {
        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
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

    #[test]
    fn test_systemd_set_resources_unsupported() {
        use crate::manager::error::Error;
        use crate::model::{ResourcePatch, Update};

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/nonexistent"),
        });

        let mut manager = SystemdManager::with_topology("test.slice:scope:unit", topology).unwrap();

        // blkio weight
        let mut patch = ResourcePatch::default();
        patch.blkio.weight = Update::Set(500);
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("blkio"))
        );

        // hugetlb
        let mut patch = ResourcePatch::default();
        patch.hugepages.limits.push(crate::model::HugePageLimit {
            page_size: "2MB".to_string(),
            limit: 1024,
        });
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("hugetlb"))
        );

        // network
        let mut patch = ResourcePatch::default();
        patch.network.class_id = Update::Set(10);
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("network"))
        );

        // devices
        let mut patch = ResourcePatch::default();
        patch.devices.rules.push(crate::model::DeviceRule {
            allow: true,
            dev_type: Some('c'),
            major: Some(1),
            minor: Some(3),
            access: "r".to_string(),
        });
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("devices"))
        );

        // custom attributes
        let mut patch = ResourcePatch::default();
        patch
            .custom_attributes
            .insert("cgroup.procs".to_string(), "1".to_string());
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("custom_attributes"))
        );

        // realtime cpu
        let mut patch = ResourcePatch::default();
        patch.cpu.realtime_runtime = Update::Set(1000);
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("realtime"))
        );

        // kernel memory
        let mut patch = ResourcePatch::default();
        patch.memory.kernel = Update::Set(1024);
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("kernel"))
        );
    }

    #[test]
    fn test_systemd_set_resources_v1_memory_unsupported() {
        use crate::manager::error::Error;
        use crate::model::{ResourcePatch, Update};

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V1,
            v2_available: false,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/nonexistent"),
        });

        let mut manager = SystemdManager::with_topology("test.slice:scope:unit", topology).unwrap();

        // soft limit on v1
        let mut patch = ResourcePatch::default();
        patch.memory.soft_limit = Update::Set(1024);
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("soft_limit"))
        );

        // swap on v1
        let mut patch = ResourcePatch::default();
        patch.memory.swap = Update::Set(2048);
        assert!(
            matches!(manager.set_resources(&patch), Err(Error::Unsupported(ref msg)) if msg.contains("swap"))
        );
    }

    #[test]
    fn test_systemd_v1_unlimited_memory_does_not_synthesize_swap() {
        use oci_spec::runtime::{LinuxMemoryBuilder, LinuxResourcesBuilder};

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V1,
            v2_available: false,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/nonexistent"),
        });
        let manager = SystemdManager::with_topology("test.slice:scope:unit", topology).unwrap();
        let resources = LinuxResourcesBuilder::default()
            .memory(LinuxMemoryBuilder::default().limit(-1i64).build().unwrap())
            .build()
            .unwrap();
        let patch = conv::oci_to_resource_patch(&resources, false).unwrap();
        let mut props = Vec::new();

        manager.set_memory_patch(&mut props, &patch.memory).unwrap();

        assert_eq!(props.len(), 1);
        assert_eq!(props[0].0, "MemoryLimit");
        assert!(matches!(&props[0].1, zbus::zvariant::Value::U64(u64::MAX)));
    }

    #[test]
    fn test_encode_dbus_subgroup() {
        use super::encode_dbus_subgroup;
        use crate::model::path::CgroupPath;

        let root = CgroupPath::root().unwrap();
        assert_eq!(encode_dbus_subgroup(&root).unwrap(), "");

        let sub = CgroupPath::new("worker").unwrap();
        assert_eq!(encode_dbus_subgroup(&sub).unwrap(), "/worker");

        let nested = CgroupPath::new("payload/init").unwrap();
        assert_eq!(encode_dbus_subgroup(&nested).unwrap(), "/payload/init");
    }

    #[test]
    fn test_plan_attach_action() {
        use super::{plan_attach_action, ProcessLocation, SystemdAttachAction};
        use crate::model::path::CgroupPath;
        use crate::model::pid::ProcessId;

        let root = CgroupPath::root().unwrap();
        let worker = CgroupPath::new("worker").unwrap();
        let pid = ProcessId::new(42).unwrap();

        // 1. Unit does not exist -> StartUnitWithSubgroup
        let action = plan_attach_action(pid, false, None, &worker, true).unwrap();
        assert_eq!(
            action,
            SystemdAttachAction::StartUnitWithSubgroup {
                subgroup: worker.clone()
            }
        );

        // 2. Unit exists, process is Outside -> AttachOutsideViaDbus
        let action =
            plan_attach_action(pid, true, Some(&ProcessLocation::Outside), &worker, true).unwrap();
        assert_eq!(
            action,
            SystemdAttachAction::AttachOutsideViaDbus {
                dbus_subgroup: "/worker".to_string()
            }
        );

        // 3. Unit exists, process is Inside at same destination -> AlreadyAtDestination
        let action = plan_attach_action(
            pid,
            true,
            Some(&ProcessLocation::Inside(worker.clone())),
            &worker,
            true,
        )
        .unwrap();
        assert_eq!(action, SystemdAttachAction::AlreadyAtDestination);

        // 4. Unit exists, process is Inside at root, target is worker, delegated -> MigrateInsideDelegatedSubgroup
        let action = plan_attach_action(
            pid,
            true,
            Some(&ProcessLocation::Inside(root.clone())),
            &worker,
            true,
        )
        .unwrap();
        assert_eq!(
            action,
            SystemdAttachAction::MigrateInsideDelegatedSubgroup {
                subgroup: worker.clone()
            }
        );

        // 5. Unit exists, process is Inside at root, target is worker, NOT delegated -> Unsupported error
        let err = plan_attach_action(
            pid,
            true,
            Some(&ProcessLocation::Inside(root.clone())),
            &worker,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, crate::manager::error::Error::Unsupported(_)));
    }

    #[test]
    fn test_locate_process() {
        use super::ProcessLocation;
        use crate::error::AttachmentError;
        use crate::model::path::CgroupPath;
        use crate::model::pid::ProcessId;

        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let temp_dir = std::env::temp_dir().join(format!(
            "systemd-locate-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _guard = TempGuard(temp_dir.clone());
        let procfs = temp_dir.join("proc");
        let cgroupfs = temp_dir.join("cgroupfs");

        // PID 1001 is inside worker
        std::fs::create_dir_all(procfs.join("1001")).unwrap();
        std::fs::write(
            procfs.join("1001/cgroup"),
            "0::/test.slice/scope-unit.scope/worker\n",
        )
        .unwrap();

        // PID 1002 is outside (different slice)
        std::fs::create_dir_all(procfs.join("1002")).unwrap();
        std::fs::write(procfs.join("1002/cgroup"), "0::/other.slice/other.scope\n").unwrap();

        let topology = Arc::new(CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::parse_mountinfo(
                "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            )
            .unwrap(),
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
            host_paths,
        )
        .unwrap();

        // Inside
        let loc = manager
            .locate_process(ProcessId::new(1001).unwrap(), &[])
            .unwrap();
        assert_eq!(
            loc,
            ProcessLocation::Inside(CgroupPath::new("worker").unwrap())
        );

        // Outside
        let loc = manager
            .locate_process(ProcessId::new(1002).unwrap(), &[])
            .unwrap();
        assert_eq!(loc, ProcessLocation::Outside);

        // Missing PID -> ReadMembership error, not Outside!
        let err = manager
            .locate_process(ProcessId::new(9999).unwrap(), &[])
            .unwrap_err();
        match err {
            crate::manager::error::Error::Attachment(AttachmentError::ReadMembership {
                pid,
                ..
            }) => {
                assert_eq!(pid, ProcessId::new(9999).unwrap());
            }
            other => panic!("expected ReadMembership error, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod attachment_regression_tests {
    use super::*;
    use crate::discovery::{parse_membership, parse_mountinfo, ControllerSet};
    use std::path::PathBuf;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "p2-systemd-probe-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn manager(&self, v: CgroupVersion, mounts: &str, own: &str) -> SystemdManager<'static> {
            let cg = self.0.join("cg");
            let mounts = parse_mountinfo(mounts).unwrap();
            let topo = Arc::new(CgroupTopology {
                version: v,
                v2_available: !mounts.unified_mounts().is_empty(),
                mounts,
                membership: parse_membership(own).unwrap(),
                controllers: ControllerSet::default(),
                cgroupfs_root: cg.clone(),
                hugepages: self.0.join("hugepages"),
            });
            SystemdManager::with_topology_and_host_paths(
                "test.slice:scope:unit",
                topo,
                HostPaths {
                    procfs: self.0.join("proc"),
                    cgroupfs_override: Some(cg),
                    hugepages: self.0.join("hugepages"),
                },
            )
            .unwrap()
        }
        fn membership(&self, pid: u32, content: &str) {
            let path = self.0.join("proc").join(pid.to_string());
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("cgroup"), content).unwrap();
        }
        fn unit_dir(&self, controller: &str) -> PathBuf {
            self.0
                .join("cg")
                .join(controller)
                .join("test.slice/scope-unit.scope")
        }
        fn realize(&self, controllers: &[&str]) {
            for controller in controllers {
                let dir = self.unit_dir(controller);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("cgroup.procs"), "root").unwrap();
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const V1: &str = "31 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n32 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n33 23 0:29 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd\n";

    const EXTRA_V1_MOUNTS: &str = "34 23 0:30 / /sys/fs/cgroup/freezer rw - cgroup cgroup rw,freezer\n35 23 0:31 / /sys/fs/cgroup/cpuset rw - cgroup cgroup rw,cpuset\n36 23 0:32 / /sys/fs/cgroup/net_cls rw - cgroup cgroup rw,net_cls\n";

    #[test]
    fn test_v1_extra_mounts_do_not_block_systemd_attachment() {
        // Exercise both a legacy table and one with an optional unified mount.
        // These files prove selection and writes, not kernel process migration.
        for unified_mount in [
            "",
            "37 23 0:33 / /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw\n",
        ] {
            let fixture = Fixture::new();
            let mounts = format!("{V1}{EXTRA_V1_MOUNTS}{unified_mount}");
            let unified_membership = if unified_mount.is_empty() {
                ""
            } else {
                "0::/\n"
            };
            let membership = format!(
                "1:cpu:/\n2:memory:/\n3:name=systemd:/\n4:freezer:/\n5:cpuset:/\n6:net_cls:/\n{unified_membership}"
            );
            let manager = fixture.manager(CgroupVersion::V1, &mounts, &membership);
            fixture.realize(&["cpu", "memory", "systemd"]);
            // Even an independently created freezer tree grants no ownership.
            fixture.realize(&["freezer"]);
            let pid = ProcessId::new(42).unwrap();
            let delegated = ["cpu", "memory", "cpuset", "freezer"].map(str::to_string);
            let subsystems = manager.attachment_subsystems(pid, &delegated).unwrap();
            assert_eq!(subsystems, ["cpu", "memory", "name=systemd"]);
            assert_eq!(manager.fs_manager.managed_subsystems().len(), 6);

            fixture.membership(42, &format!("1:cpu:/outside\n2:memory:/outside\n3:name=systemd:/outside\n4:freezer:/\n5:cpuset:/\n6:net_cls:/\n{unified_membership}"));
            let root = manager
                .fs_manager
                .resolve_delegated_destination(&AttachDestination::ManagedCgroup, &subsystems)
                .unwrap();
            let outside = manager.locate_process(pid, &subsystems).unwrap();
            assert_eq!(
                plan_attach_action(pid, true, Some(&outside), &root.subgroup, true).unwrap(),
                SystemdAttachAction::AttachOutsideViaDbus {
                    dbus_subgroup: String::new()
                },
            );
            manager
                .fs_manager
                .prepare_delegated_destination(pid, &root)
                .unwrap();

            fixture.membership(42, &format!("1:cpu:/test.slice/scope-unit.scope\n2:memory:/test.slice/scope-unit.scope\n3:name=systemd:/test.slice/scope-unit.scope\n4:freezer:/\n5:cpuset:/\n6:net_cls:/\n{unified_membership}"));
            let inside = manager.locate_process(pid, &subsystems).unwrap();
            assert_eq!(
                plan_attach_action(pid, true, Some(&inside), &root.subgroup, true).unwrap(),
                SystemdAttachAction::AlreadyAtDestination,
            );
            manager
                .fs_manager
                .ensure_delegated_destination_exists(pid, &root)
                .unwrap();

            let leaf = manager
                .fs_manager
                .resolve_delegated_destination(
                    &AttachDestination::subgroup("worker").unwrap(),
                    &subsystems,
                )
                .unwrap();
            manager
                .fs_manager
                .prepare_delegated_destination(pid, &leaf)
                .unwrap();
            for controller in ["cpu", "memory", "systemd"] {
                std::fs::write(fixture.unit_dir(controller).join("worker/cgroup.procs"), "")
                    .unwrap();
            }
            manager
                .fs_manager
                .add_proc_to_delegated_destination(pid, &leaf)
                .unwrap();
            for controller in ["cpu", "memory", "systemd"] {
                assert_eq!(
                    std::fs::read_to_string(
                        fixture.unit_dir(controller).join("worker/cgroup.procs")
                    )
                    .unwrap(),
                    "42"
                );
            }
            assert_eq!(
                std::fs::read_to_string(fixture.unit_dir("freezer").join("cgroup.procs")).unwrap(),
                "root"
            );
            assert!(!fixture.unit_dir("freezer").join("worker").exists());
            assert!(!fixture.unit_dir("cpuset").exists());
            assert!(!fixture.unit_dir("net_cls").exists());
        }
    }

    #[test]
    fn test_v1_attachment_honors_partial_delegation_and_unrealized_roots() {
        let fixture = Fixture::new();
        let mounts = "31 23 0:27 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n32 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n33 23 0:29 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd\n34 23 0:30 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n";
        let manager = fixture.manager(
            CgroupVersion::V1,
            mounts,
            "1:cpu,cpuacct:/\n2:memory:/\n3:name=systemd:/\n4:pids:/\n",
        );
        fixture.realize(&["cpu,cpuacct", "memory", "systemd"]);
        let pid = ProcessId::new(42).unwrap();
        // Memory is realized but not delegated; pids is requested but unrealized.
        let delegated = ["cpu", "pids"].map(str::to_string);
        let subsystems = manager.attachment_subsystems(pid, &delegated).unwrap();
        assert_eq!(subsystems, ["cpu", "cpuacct", "name=systemd"]);
        let leaf = manager
            .fs_manager
            .resolve_delegated_destination(
                &AttachDestination::subgroup("worker").unwrap(),
                &subsystems,
            )
            .unwrap();
        manager
            .fs_manager
            .prepare_delegated_destination(pid, &leaf)
            .unwrap();
        for controller in ["cpu,cpuacct", "systemd"] {
            let file = fixture.unit_dir(controller).join("worker/cgroup.procs");
            std::fs::write(file, "").unwrap();
        }
        manager
            .fs_manager
            .add_proc_to_delegated_destination(pid, &leaf)
            .unwrap();
        assert!(!fixture.unit_dir("memory").join("worker").exists());
        assert_eq!(
            std::fs::read_to_string(fixture.unit_dir("memory").join("cgroup.procs")).unwrap(),
            "root"
        );
        assert!(!fixture.unit_dir("pids").exists());
    }

    #[test]
    fn test_v1_selected_reference_leaf_must_exist_on_every_hierarchy() {
        let fixture = Fixture::new();
        let mounts = format!("{V1}{EXTRA_V1_MOUNTS}");
        let manager = fixture.manager(
            CgroupVersion::V1,
            &mounts,
            "1:cpu:/\n2:memory:/\n3:name=systemd:/\n4:freezer:/\n5:cpuset:/\n6:net_cls:/\n",
        );
        fixture.realize(&["cpu", "memory", "systemd"]);
        let pid = ProcessId::new(42).unwrap();
        let subsystems = manager
            .attachment_subsystems(pid, &["cpu".to_string(), "memory".to_string()])
            .unwrap();
        fixture.membership(100, "1:cpu:/test.slice/scope-unit.scope/worker\n2:memory:/test.slice/scope-unit.scope/worker\n3:name=systemd:/test.slice/scope-unit.scope/worker\n4:freezer:/\n5:cpuset:/\n6:net_cls:/\n");
        let reference = AttachDestination::same_cgroup_as(ProcessId::new(100).unwrap());
        let target = manager
            .fs_manager
            .resolve_delegated_destination(&reference, &subsystems)
            .unwrap();
        assert_eq!(target.plan.creation, CreationPolicy::MustExist);
        for controller in ["cpu", "systemd"] {
            let dir = fixture.unit_dir(controller).join("worker");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cgroup.procs"), "original").unwrap();
        }
        let missing = fixture.unit_dir("memory").join("worker");
        let error = manager
            .fs_manager
            .add_proc_to_delegated_destination(pid, &target)
            .unwrap_err();
        assert!(
            matches!(error, Error::Attachment(AttachmentError::MissingResolvedTarget { target, source, .. })
            if target == missing && source.raw_os_error() == Some(libc::ENOENT))
        );
        assert!(!missing.exists());
        assert_eq!(
            std::fs::read_to_string(fixture.unit_dir("cpu").join("worker/cgroup.procs")).unwrap(),
            "original"
        );
    }

    #[test]
    fn test_v1_unit_hierarchy_inspection_propagates_permission_errors() {
        use std::os::unix::fs::PermissionsExt;
        crate::skip_if_root!();
        let fixture = Fixture::new();
        let manager = fixture.manager(
            CgroupVersion::V1,
            V1,
            "1:cpu:/\n2:memory:/\n3:name=systemd:/\n",
        );
        fixture.realize(&["cpu", "memory", "systemd"]);
        let locked = fixture.unit_dir("memory").parent().unwrap().to_path_buf();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o0)).unwrap();
        let result =
            manager.attachment_subsystems(ProcessId::new(42).unwrap(), &["memory".to_string()]);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(result, Err(Error::Attachment(AttachmentError::TargetIo { target, source, .. }))
            if target == fixture.unit_dir("memory") && source.raw_os_error() == Some(libc::EACCES))
        );
    }

    #[test]
    fn test_v1_unit_membership_uses_systemd_hierarchy() {
        let fixture = Fixture::new();
        let manager = fixture.manager(
            CgroupVersion::V1,
            V1,
            "1:cpu:/\n2:memory:/\n3:name=systemd:/\n",
        );
        let pid = ProcessId::new(42).unwrap();
        // Matching CPU/memory does not mean the process belongs to the unit.
        let subsystems = manager.fs_manager.managed_subsystems();
        fixture.membership(42, "1:cpu:/test.slice/scope-unit.scope/leaf\n2:memory:/test.slice/scope-unit.scope/leaf\n3:name=systemd:/other.scope\n");
        assert_eq!(
            manager.locate_process(pid, &subsystems).unwrap(),
            ProcessLocation::Outside
        );
        // If systemd already considers it inside, D-Bus attach would be a
        // no-op. An outside resource hierarchy cannot be written directly.
        fixture.membership(42, "1:cpu:/other.scope\n2:memory:/test.slice/scope-unit.scope/leaf\n3:name=systemd:/test.slice/scope-unit.scope/leaf\n");
        assert!(matches!(
            manager.locate_process(pid, &subsystems),
            Err(Error::Attachment(AttachmentError::Unsupported { .. }))
        ));
        // Missing membership must not be classified as outside.
        fixture.membership(
            42,
            "1:cpu:/test.slice/scope-unit.scope/leaf\n2:memory:/test.slice/scope-unit.scope/leaf\n",
        );
        assert!(matches!(
            manager.locate_process(pid, &subsystems),
            Err(Error::Attachment(
                AttachmentError::MissingHierarchyMembership { .. }
            ))
        ));
    }

    #[test]
    fn test_non_delegated_existing_unit_actions() {
        let pid = ProcessId::new(42).unwrap();
        let root = CgroupPath::root().unwrap();
        for location in [
            ProcessLocation::Outside,
            ProcessLocation::InsideDifferentHierarchies,
        ] {
            assert!(matches!(
                plan_attach_action(pid, true, Some(&location), &root, false),
                Err(Error::Unsupported(_))
            ));
        }
        assert_eq!(
            plan_attach_action(
                pid,
                true,
                Some(&ProcessLocation::Inside(root.clone())),
                &root,
                false
            )
            .unwrap(),
            SystemdAttachAction::AlreadyAtDestination
        );
    }

    #[test]
    fn test_malformed_membership_propagates_from_location() {
        let fixture = Fixture::new();
        let manager = fixture.manager(
            CgroupVersion::V2,
            "32 23 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            "0::/\n",
        );
        fixture.membership(42, "0::/test.slice/scope-unit.scope/leaf\n0::/outside\n");
        assert!(matches!(
            manager.locate_process(ProcessId::new(42).unwrap(), &[]),
            Err(Error::Attachment(AttachmentError::ParseMembership { .. }))
        ));
    }

    #[test]
    fn test_forbid_nondelegated_move_to_root() {
        let root = CgroupPath::root().unwrap();
        let location = ProcessLocation::Inside(CgroupPath::new("leaf").unwrap());
        let result = plan_attach_action(
            ProcessId::new(42).unwrap(),
            true,
            Some(&location),
            &root,
            false,
        );
        assert!(
            matches!(result, Err(Error::Unsupported(_))),
            "nondelegated root move was planned: {:?}",
            result
        );
    }

    #[test]
    fn test_systemd_v1_compare_all_hierarchies() {
        let f = Fixture::new();
        let mounts = "31 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n32 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n33 23 0:29 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd\n";
        let m = f.manager(
            CgroupVersion::V1,
            mounts,
            "1:cpu:/\n2:memory:/\n3:name=systemd:/\n",
        );
        f.membership(100, "1:cpu:/test.slice/scope-unit.scope/cpu_leaf\n2:memory:/test.slice/scope-unit.scope/mem_leaf\n3:name=systemd:/test.slice/scope-unit.scope/sys_leaf\n");
        f.membership(42, "1:cpu:/test.slice/scope-unit.scope/cpu_leaf\n2:memory:/test.slice/scope-unit.scope/old_mem\n3:name=systemd:/test.slice/scope-unit.scope/old_sys\n");
        let reference = AttachDestination::same_cgroup_as(ProcessId::new(100).unwrap());
        let subsystems = m.fs_manager.managed_subsystems();
        assert!(matches!(
            m.fs_manager
                .resolve_delegated_destination(&reference, &subsystems),
            Err(Error::Attachment(AttachmentError::Unsupported {
                backend: "systemd",
                ..
            }))
        ));
        let current = m
            .locate_process(ProcessId::new(42).unwrap(), &subsystems)
            .unwrap();
        assert_eq!(current, ProcessLocation::InsideDifferentHierarchies);
        let desired = CgroupPath::new("cpu_leaf").unwrap();
        let action = plan_attach_action(
            ProcessId::new(42).unwrap(),
            true,
            Some(&current),
            &desired,
            true,
        )
        .unwrap();
        assert_eq!(
            action,
            SystemdAttachAction::MigrateInsideDelegatedSubgroup { subgroup: desired }
        );
    }
}
