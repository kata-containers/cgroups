// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module handles cgroup operations. Start here!

use crate::fs::error::ErrorKind::*;
use crate::fs::error::*;

use crate::core::CgroupPath;
use crate::fs::{
    CgroupPid, CgroupReader, ControllIdentifier, Controller, Hierarchy, Resources, Subsystem,
};

use std::collections::HashMap;
use std::convert::From;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::discovery::CgroupTopology;

pub const CGROUP_MODE_DOMAIN: &str = "domain";
pub const CGROUP_MODE_DOMAIN_THREADED: &str = "domain threaded";
pub const CGROUP_MODE_DOMAIN_INVALID: &str = "domain invalid";
pub const CGROUP_MODE_THREADED: &str = "threaded";

/// The controllers managed by a cgroup handle.
///
/// This selection does not describe every controller the kernel has enabled
/// for the cgroup. Selecting fewer controllers does not disable other
/// controllers enabled by the parent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ControllerSelection {
    /// Manage every controller reported by the hierarchy.
    ///
    /// On v2, creation tries available controllers one by one in each
    /// ancestor, ignoring individual enabling write errors. Each level's
    /// current `cgroup.controllers` determines which controllers are offered.
    /// Controller-state read and directory-creation errors still propagate.
    #[default]
    All,
    /// Manage only the named controllers.
    ///
    /// Names use the hierarchy's kernel spelling, such as `blkio` on v1 and
    /// `io` on v2. On v2, `freezer` selects the core freezing interface and
    /// is never enabled through `cgroup.subtree_control`.
    /// Creation requires every selected resource controller to be available
    /// through the target and propagates controller-enabling write errors.
    ///
    /// An empty list loads a handle with no subsystems, but creation rejects
    /// it with [`ErrorKind::EmptyControllerSelection`].
    Only(Vec<String>),
}

fn selection_controller_name(subsystem: &Subsystem, v2: bool) -> String {
    if v2 && matches!(subsystem, Subsystem::BlkIo(_)) {
        "io".to_string()
    } else {
        subsystem.controller_name()
    }
}

/// A control group is the central structure to this crate.
///
///
/// # What are control groups?
///
/// Lifting over from the Linux kernel sources:
///
/// > Control Groups provide a mechanism for aggregating/partitioning sets of
/// > tasks, and all their future children, into hierarchical groups with
/// > specialized behaviour.
///
/// This crate is an attempt at providing a Rust-native way of managing these cgroups.
#[derive(Debug)]
pub struct Cgroup {
    /// The list of subsystems that control this cgroup
    subsystems: Vec<Subsystem>,

    /// The hierarchy.
    hier: Arc<dyn Hierarchy>,
    /// The managed path beneath the v1 prefixes or the unified v2 mount.
    path: CgroupPath,

    /// The controllers managed by this handle.
    controllers: ControllerSelection,

    /// Prefixes beneath each v1 controller's mount, keyed by
    /// [`Subsystem::controller_name`]. Each prefix is prepended to `path` and
    /// bounds parent traversal when `path` is empty. Ignored on v2.
    v1_prefixes: HashMap<String, CgroupPath>,
}

/// Cloning preserves the hierarchy snapshot and the full selection
/// state: the underlying topology is shared through `Arc` instead of
/// re-discovered, and controller selection and v1 path prefixes are carried
/// over, so a clone behaves identically to the original.
impl Clone for Cgroup {
    fn clone(&self) -> Self {
        Cgroup {
            subsystems: self.subsystems.clone(),
            hier: self.hier.clone(),
            path: self.path.clone(),
            controllers: self.controllers.clone(),
            v1_prefixes: self.v1_prefixes.clone(),
        }
    }
}

/// Configure a cgroup handle before loading it or creating its directories.
///
/// Finish with [`Self::load`], [`Self::try_load`], or [`Self::create`]. Configure
/// resource limits separately using [`Resources`] and [`Cgroup::apply`].
/// On v1, [`Self::v1_prefixes`] sets each controller's base directory; `path`
/// names cgroups beneath those bases. On v2, `path` is relative to the unified
/// mount and v1 prefixes are ignored.
pub struct CgroupBuilder {
    hier: Arc<dyn Hierarchy>,
    /// The managed path beneath the v1 prefixes or the unified v2 mount.
    path: CgroupPath,
    controllers: ControllerSelection,
    /// Prefixes beneath each v1 controller's mount, keyed by
    /// [`Subsystem::controller_name`]. Each prefix is prepended to `path` and
    /// bounds parent traversal when `path` is empty. Ignored on v2.
    v1_prefixes: HashMap<String, CgroupPath>,
}

impl CgroupBuilder {
    /// Which controllers this handle manages. Defaults to every controller
    /// the hierarchy reports.
    ///
    /// [`ControllerSelection::Only`] restricts the handle and, on v2, limits
    /// what creation enables in the ancestors' `cgroup.subtree_control` files.
    /// It does not disable controllers already enabled by the parent. This
    /// matters for threaded cgroups, whose subtree cannot enable domain
    /// controllers. Selecting threaded controllers does not itself change
    /// `cgroup.type` or remove existing domain controllers.
    ///
    /// The selection applies at every path, including the root. Loading an
    /// empty selection yields no subsystems; creation rejects it before any
    /// filesystem changes. Unavailable names are rejected by
    /// [`Self::try_load`] and creation.
    pub fn controllers(mut self, selection: ControllerSelection) -> Self {
        self.controllers = selection;
        self
    }

    /// Set per-controller v1 prefixes to prepend to the managed `path`.
    ///
    /// Keys are controller names returned by [`Subsystem::controller_name`].
    /// For controller `c`, the directory is
    /// `<mount of c>/<v1_prefixes[c]>/<path>` when a prefix is set, otherwise
    /// `<mount of c>/<path>`. Prefixes default to an empty map. On v2 the map
    /// is ignored: the directory is always `<unified mount>/<path>`.
    ///
    /// Use prefixes for where the process already lives in each v1 hierarchy,
    /// derived from `/proc/<pid>/cgroup` and expressed relative to the visible
    /// controller mount. Put cgroups the caller creates in `path`.
    /// [`CgroupReader::memberships`] returns raw procfs observations, which
    /// require explicit conversion before use as prefixes; see that method's
    /// documentation.
    ///
    /// Each prefix is a boundary for [`Cgroup::parent`]: traversal changes only
    /// `path` and stops when it is empty, even if a prefix has more parents.
    /// [`Cgroup::remove_task`] and [`Cgroup::remove_task_by_tgid`] move tasks
    /// back to these prefixes.
    /// The caller chooses the split between prefix and path; the filesystem
    /// cannot recover it. For example, prefix `kubepods/pod1` with path `ctr1`
    /// and prefix `kubepods` with path `pod1/ctr1` reach the same directory.
    /// The first handle can walk up only to `kubepods/pod1`; the second can
    /// continue to `kubepods`.
    pub fn v1_prefixes(mut self, prefixes: HashMap<String, CgroupPath>) -> Self {
        self.v1_prefixes = prefixes;
        self
    }

    /// Construct the handle without creating or checking its directories.
    ///
    /// Unavailable controller names are silently filtered out. Use
    /// [`Self::try_load`] to reject them; creation also validates names before
    /// making filesystem changes.
    pub fn load(self) -> Cgroup {
        Cgroup::load_internal(self.hier, self.path, self.controllers, self.v1_prefixes)
    }

    /// Construct a handle after validating the requested controller names.
    ///
    /// Returns [`ErrorKind::UnsupportedController`] for any name the hierarchy
    /// does not report. Built-in hierarchies use their topology snapshot; this
    /// name validation adds no filesystem I/O. It does not check directory
    /// existence, permissions, or current controller availability at the target.
    /// `Only(Vec::new())` is valid here and loads a handle with no subsystems;
    /// creation still rejects it.
    ///
    /// ```no_run
    /// use cgroups_rs::core::CgroupPath;
    /// use cgroups_rs::fs::{hierarchies, Cgroup, ControllerSelection};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let hierarchy = hierarchies::auto()?;
    /// let cgroup = Cgroup::builder(hierarchy, CgroupPath::new("workloads/a")?)
    ///     .controllers(ControllerSelection::Only(vec!["cpu".to_string()]))
    ///     .try_load()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_load(self) -> Result<Cgroup> {
        let cgroup = self.load();
        cgroup.validate_controller_selection()?;
        Ok(cgroup)
    }

    /// Construct the handle and create its cgroup directories.
    ///
    /// See [`Cgroup::create`] for controller validation and failure semantics.
    pub fn create(self) -> Result<Cgroup> {
        let cgroup = self.load();
        cgroup.create()?;
        Ok(cgroup)
    }
}

impl Cgroup {
    pub fn v2(&self) -> bool {
        self.hier.v2()
    }

    /// Return the topology snapshot supplied by this control group's hierarchy, if available.
    pub fn topology(&self) -> Option<Arc<CgroupTopology>> {
        self.hier.topology()
    }

    /// Reuse the handle's hierarchy for related OCI manager operations.
    #[cfg(feature = "oci")]
    pub(crate) fn hierarchy(&self) -> &Arc<dyn Hierarchy> {
        &self.hier
    }

    /// Borrow the validated path relative to this control group's hierarchy root.
    ///
    /// The root path is the boundary for parent traversal. On v1 this excludes
    /// per-controller prefixes: each controller directory is
    /// `<mount>/<prefix>/<path>`.
    pub fn path(&self) -> &CgroupPath {
        &self.path
    }

    /// Create this control group.
    ///
    /// Rejects an explicitly empty selection or names absent from the
    /// hierarchy before making filesystem changes. On v2, reads each
    /// ancestor's current `cgroup.controllers` and `cgroup.subtree_control`,
    /// writing only selected resource controllers that are available but not
    /// already enabled.
    /// `Only` requires every selected resource controller to be available,
    /// including at the target, and propagates enabling write errors. `All`
    /// tries the available subset of the hierarchy's discovered controllers
    /// one by one at each level, ignoring individual enabling write errors.
    /// A non-root target's own `cgroup.subtree_control` is left unchanged;
    /// an explicit root handle enables controllers at that root.
    ///
    /// Controller-state read errors and directory-creation errors propagate
    /// for both selections. A later failure can leave earlier directories or
    /// controller settings in place.
    pub fn create(&self) -> Result<()> {
        if let ControllerSelection::Only(controllers) = &self.controllers {
            if controllers.is_empty() {
                return Err(Error::new(EmptyControllerSelection {
                    path: self.path.as_path().to_path_buf(),
                }));
            }
        }
        self.validate_controller_selection()?;
        if self.hier.v2() {
            let topology = self.topology();
            create_v2_cgroup(
                self.hier.root()?,
                &self.path,
                &self.controllers,
                topology.as_deref(),
            )
        } else {
            self.subsystems
                .iter()
                .try_for_each(|subsystem| subsystem.to_controller().create())?;
            Ok(())
        }
    }

    /// Create a control group at a validated relative path.
    ///
    /// The hierarchy is shared with other handles. Filesystem and kernel
    /// creation errors still propagate even though the path is already valid.
    pub fn new(hier: Arc<dyn Hierarchy>, path: CgroupPath) -> Result<Cgroup> {
        Self::builder(hier, path).create()
    }

    /// Construct a handle at a validated relative path without creating it.
    ///
    /// Path validation does not establish existence or ownership of the cgroup.
    /// Cloning the supplied `Arc` lets callers load different paths on the
    /// same hierarchy, including custom hierarchies that do not implement Clone.
    ///
    /// ```no_run
    /// use cgroups_rs::core::{discover, CgroupPath, HostPaths};
    /// use cgroups_rs::fs::{hierarchies, Cgroup};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let hierarchy = hierarchies::from_topology(discover(&HostPaths::default())?);
    /// let a = Cgroup::load(hierarchy.clone(), CgroupPath::new("workloads/a")?);
    /// let b = Cgroup::load(hierarchy, CgroupPath::new("workloads/b")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn load(hier: Arc<dyn Hierarchy>, path: CgroupPath) -> Cgroup {
        Self::builder(hier, path).load()
    }

    /// Configure controller selection and per-controller v1 prefixes.
    ///
    /// Finalize with [`CgroupBuilder::try_load`] to validate controller names
    /// and construct a handle, [`CgroupBuilder::load`] to filter unavailable
    /// names, or [`CgroupBuilder::create`] to also create the cgroup.
    pub fn builder(hier: Arc<dyn Hierarchy>, path: CgroupPath) -> CgroupBuilder {
        CgroupBuilder {
            hier,
            path,
            controllers: ControllerSelection::All,
            v1_prefixes: HashMap::new(),
        }
    }

    /// Return the subsystems represented by this control group handle.
    pub fn subsystems(&self) -> &[Subsystem] {
        &self.subsystems
    }

    fn load_internal(
        hier: Arc<dyn Hierarchy>,
        path: CgroupPath,
        controllers: ControllerSelection,
        v1_prefixes: HashMap<String, CgroupPath>,
    ) -> Cgroup {
        let rel = path.as_path();
        let mut subsystems = hier.subsystems();
        if let ControllerSelection::Only(selected) = &controllers {
            subsystems.retain(|subsystem| {
                selected.contains(&selection_controller_name(subsystem, hier.v2()))
            });
        }
        subsystems = subsystems
            .into_iter()
            .map(|subsystem| {
                if !hier.v2() {
                    if let Some(prefix) = v1_prefixes.get(&subsystem.controller_name()) {
                        return subsystem.enter(prefix.join(&path).as_path());
                    }
                }
                subsystem.enter(rel)
            })
            .collect();

        Cgroup {
            path,
            subsystems,
            hier,
            controllers,
            v1_prefixes,
        }
    }

    // Validate against the handle's reported subsystems without probing the
    // filesystem. Keep loading and creation diagnostics identical.
    fn validate_controller_selection(&self) -> Result<()> {
        if let ControllerSelection::Only(controllers) = &self.controllers {
            for controller in controllers {
                if !self
                    .subsystems
                    .iter()
                    .any(|subsystem| selection_controller_name(subsystem, self.v2()) == *controller)
                {
                    return Err(Error::new(UnsupportedController {
                        controller: controller.clone(),
                        path: if self.v2() {
                            Some(self.hier.root()?.join("cgroup.controllers"))
                        } else {
                            None
                        },
                    }));
                }
            }
        }
        Ok(())
    }

    // Retain controller selection while using the operation's v1 root prefixes.
    fn root_handle(&self, v1_prefixes: HashMap<String, CgroupPath>) -> Cgroup {
        Self::load_internal(
            self.hier.clone(),
            CgroupPath::root(),
            self.controllers.clone(),
            v1_prefixes,
        )
    }

    /// Deletes the control group.
    ///
    /// Note that this function makes no effort in cleaning up the descendant and the underlying
    /// system call will fail if there are any descendants. Thus, one should check whether it was
    /// actually removed, and remove the descendants first if not. In the future, this behavior
    /// will change.
    pub fn delete(&self) -> Result<()> {
        if self.v2() {
            if !self.path.is_root() {
                let p = self.hier.root()?.join(self.path.as_path());
                return fs::remove_dir(p).map_err(|e| Error::with_cause(RemoveFailed, e));
            }
            return Ok(());
        }

        self.subsystems.iter().try_for_each(|sub| match sub {
            Subsystem::Pid(pidc) => pidc.delete(),
            Subsystem::Mem(c) => c.delete(),
            Subsystem::CpuSet(c) => c.delete(),
            Subsystem::CpuAcct(c) => c.delete(),
            Subsystem::Cpu(c) => c.delete(),
            Subsystem::Devices(c) => c.delete(),
            Subsystem::Freezer(c) => c.delete(),
            Subsystem::NetCls(c) => c.delete(),
            Subsystem::BlkIo(c) => c.delete(),
            Subsystem::PerfEvent(c) => c.delete(),
            Subsystem::NetPrio(c) => c.delete(),
            Subsystem::HugeTlb(c) => c.delete(),
            Subsystem::Rdma(c) => c.delete(),
            Subsystem::Systemd(c) => c.delete(),
        })
    }

    /// Apply a set of resource limits to the control group.
    ///
    /// Updates are not rolled back; earlier writes may have taken effect.
    pub fn apply(&self, res: &Resources) -> Result<()> {
        self.subsystems
            .iter()
            .try_for_each(|subsystem| subsystem.to_controller().apply(res))
    }

    /// Retrieve a container based on type inference.
    ///
    /// ## Example:
    ///
    /// ```text
    /// let pids: &PidController = control_group.controller_of()
    ///                             .expect("No pids controller attached!");
    /// let cpu: &CpuController = control_group.controller_of()
    ///                             .expect("No cpu controller attached!");
    /// ```
    pub fn controller_of<'a, T>(&'a self) -> Option<&'a T>
    where
        &'a T: From<&'a Subsystem>,
        T: Controller + ControllIdentifier,
    {
        for i in &self.subsystems {
            if i.to_controller().control_type() == T::controller_type() {
                // N.B.:
                // https://play.rust-lang.org/?gist=978b2846bacebdaa00be62374f4f4334&version=stable&mode=debug&edition=2015
                return Some(i.into());
            }
        }
        None
    }

    /// Removes tasks from the control group by thread group id.
    ///
    /// Moves the process to the handle's root: each selected controller's
    /// configured prefix directory on v1, or its hierarchy root if no prefix
    /// is set. On v2, prefixes are ignored and the destination is the unified
    /// hierarchy root. Kernel migration restrictions still apply.
    pub fn remove_task_by_tgid(&self, tgid: CgroupPid) -> Result<()> {
        self.root_handle(self.v1_prefixes.clone())
            .add_task_by_tgid(tgid)
    }

    /// Removes a task from the control group.
    ///
    /// Moves the task to the handle's root: each selected controller's
    /// configured prefix directory on v1, or its hierarchy root if no prefix
    /// is set. On v2, prefixes are ignored and the destination is the unified
    /// hierarchy root. Kernel migration restrictions still apply.
    pub fn remove_task(&self, tid: CgroupPid) -> Result<()> {
        self.root_handle(self.v1_prefixes.clone()).add_task(tid)
    }

    /// Derive and load a handle to the immediate parent control group.
    ///
    /// Preserves the shared hierarchy, controller selection, and v1 path
    /// prefixes, including when the parent's relative path is empty. Loading
    /// the handle does not create or check the parent directory.
    ///
    /// Returns an error if this handle's relative path is empty. Parent
    /// traversal never goes above the configured per-controller v1 prefixes.
    pub fn parent(&self) -> Result<Cgroup> {
        let parent_path = self.path.parent().ok_or_else(|| {
            Error::with_cause(
                ErrorKind::InvalidPath,
                crate::core::error::PathError::RootPath {
                    input: self.path.as_path().to_path_buf(),
                    operation: "Cgroup::parent",
                },
            )
        })?;
        Ok(Self::load_internal(
            self.hier.clone(),
            parent_path,
            self.controllers.clone(),
            self.v1_prefixes.clone(),
        ))
    }

    /// Moves tasks to the parent control group by thread group id.
    pub fn move_task_to_parent_by_tgid(&self, tgid: CgroupPid) -> Result<()> {
        let parent = self.parent()?;
        parent.add_task_by_tgid(tgid)
    }

    /// Moves a task to the parent control group.
    pub fn move_task_to_parent(&self, tid: CgroupPid) -> Result<()> {
        let parent = self.parent()?;
        parent.add_task(tid)
    }

    /// Kill every process in the control group. Only supported for v2 cgroups and on
    /// kernels 5.14+. This will fail with InvalidOperation if the 'cgroup.kill' file does
    /// not exist.
    pub fn kill(&self) -> Result<()> {
        let val = "1";
        let file_name = "cgroup.kill";
        let p = self.hier.root()?.join(self.path.as_path()).join(file_name);

        // If cgroup.kill doesn't exist they're not on 5.14+ so lets
        // surface some error the caller can check against.
        if !p.exists() {
            return Err(Error::new(InvalidOperation));
        }

        fs::write(p, val)
            .map_err(|e| Error::with_cause(WriteFailed(file_name.to_string(), val.to_string()), e))
    }

    /// Attach a task to the control group.
    pub fn add_task(&self, tid: CgroupPid) -> Result<()> {
        if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                let cgroup_type = self.get_cgroup_type()?;
                // In cgroup v2, writing to the cgroup.threads file is only supported in thread mode.
                if cgroup_type == *CGROUP_MODE_DOMAIN_THREADED
                    || cgroup_type == *CGROUP_MODE_THREADED
                {
                    // It is used to move the threads of a process into a cgroup in thread mode.
                    c.add_task(&tid)
                } else {
                    // When the cgroup type is domain or domain invalid,
                    // cgroup.threads cannot be written.
                    Err(Error::new(CgroupMode))
                }
            } else {
                Err(Error::new(SubsystemsEmpty))
            }
        } else {
            self.subsystems()
                .iter()
                .try_for_each(|sub| sub.to_controller().add_task(&tid))
        }
    }

    /// Attach tasks to the control group by thread group id.
    pub fn add_task_by_tgid(&self, tgid: CgroupPid) -> Result<()> {
        if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                // It is used to move a thread of the process to a cgroup,
                // and other threads of the process will also move together.
                c.add_task_by_tgid(&tgid)
            } else {
                Err(Error::new(SubsystemsEmpty))
            }
        } else {
            self.subsystems()
                .iter()
                .try_for_each(|sub| sub.to_controller().add_task_by_tgid(&tgid))
        }
    }

    /// set cgroup.type
    pub fn set_cgroup_type(&self, cgroup_type: &str) -> Result<()> {
        if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                c.set_cgroup_type(cgroup_type)
            } else {
                Err(Error::new(SubsystemsEmpty))
            }
        } else {
            Err(Error::new(CgroupVersion))
        }
    }

    /// get cgroup.type
    pub fn get_cgroup_type(&self) -> Result<String> {
        if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                let cgroup_type = c.get_cgroup_type()?;
                Ok(cgroup_type)
            } else {
                Err(Error::new(SubsystemsEmpty))
            }
        } else {
            Err(Error::new(CgroupVersion))
        }
    }

    /// Set notify_on_release to the control group.
    pub fn set_notify_on_release(&self, enable: bool) -> Result<()> {
        self.subsystems()
            .iter()
            .try_for_each(|sub| sub.to_controller().set_notify_on_release(enable))
    }

    /// Set the release agent for the selected v1 hierarchies.
    ///
    /// Ignores per-controller path prefixes because `release_agent` exists
    /// only at each hierarchy's true root. Controllers sharing a hierarchy
    /// share its release agent.
    pub fn set_release_agent(&self, path: &str) -> Result<()> {
        self.root_handle(HashMap::new())
            .subsystems()
            .iter()
            .try_for_each(|sub| sub.to_controller().set_release_agent(path))
    }

    /// Returns the procs that are currently in the control group, or an error if reading failed.
    ///
    /// Combines the selected v1 controllers or reads the shared v2 hierarchy,
    /// then sorts and deduplicates the result. An I/O or parse failure in any
    /// selected controller fails the whole read without returning partial data.
    pub fn procs(&self) -> Result<Vec<CgroupPid>> {
        // Collect the procs from all subsystems
        let mut v = if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                c.procs()?
            } else {
                vec![]
            }
        } else {
            let mut acc = Vec::new();
            for x in self.subsystems() {
                let mut pids = x.to_controller().procs()?;
                acc.append(&mut pids);
            }
            acc
        };

        v.sort();
        v.dedup();
        Ok(v)
    }

    /// Returns the tasks that are currently in the control group, or an error if reading failed.
    ///
    /// Combines the selected v1 controllers or reads the shared v2 hierarchy,
    /// then sorts and deduplicates the result. An I/O or parse failure in any
    /// selected controller fails the whole read without returning partial data.
    pub fn tasks(&self) -> Result<Vec<CgroupPid>> {
        // Collect the tasks from all subsystems
        let mut v = if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                c.tasks()?
            } else {
                vec![]
            }
        } else {
            let mut acc = Vec::new();
            for x in self.subsystems() {
                let mut pids = x.to_controller().tasks()?;
                acc.append(&mut pids);
            }
            acc
        };

        v.sort();
        v.dedup();
        Ok(v)
    }

    /// Checks if the cgroup exists.
    ///
    /// Returns true if at least one subsystem exists.
    pub fn exists(&self) -> bool {
        self.subsystems().iter().any(|e| e.to_controller().exists())
    }
}

pub const UNIFIED_MOUNTPOINT: &str = "/sys/fs/cgroup";

fn enable_controllers(
    selection: &ControllerSelection,
    controllers: &[String],
    available: &[String],
    path: &Path,
) -> Result<()> {
    enable_controllers_with(selection, controllers, available, path, |file, body| {
        fs::write(file, body)
    })
}

// Keep the write boundary injectable so tests can exercise kernel errno
// propagation without depending on privileges or the host's cgroup layout.
fn enable_controllers_with(
    selection: &ControllerSelection,
    controllers: &[String],
    available: &[String],
    path: &Path,
    mut write: impl FnMut(&Path, &str) -> std::io::Result<()>,
) -> Result<()> {
    let controllers: Vec<_> = controllers
        .iter()
        .filter(|controller| available.contains(controller))
        .collect();
    if controllers.is_empty() {
        return Ok(());
    }
    let f = path.join("cgroup.subtree_control");
    let content = fs::read_to_string(&f)
        .map_err(|cause| Error::with_cause(ReadFailed(f.display().to_string()), cause))?;
    let mut enabled: Vec<_> = content.split_whitespace().collect();
    for c in controllers {
        // A redundant write still requires permission and can hit kernel
        // hierarchy constraints outside the caller's delegated subtree.
        if enabled.contains(&c.as_str()) {
            continue;
        }
        let body = format!("+{}", c);
        match write(&f, &body) {
            Ok(()) => enabled.push(c),
            // All is best-effort: an ancestor may offer controllers that the
            // caller cannot distribute. Descendants report what is available.
            Err(_) if matches!(selection, ControllerSelection::All) => continue,
            Err(cause) => {
                return Err(Error::with_cause(
                    WriteFailed(f.display().to_string(), body),
                    cause,
                ));
            }
        }
    }
    Ok(())
}

fn require_controllers(controllers: &[String], available: &[String], path: &Path) -> Result<()> {
    for controller in controllers {
        if !available.contains(controller) {
            return Err(Error::new(UnsupportedController {
                controller: controller.clone(),
                path: Some(path.join("cgroup.controllers")),
            }));
        }
    }
    Ok(())
}

fn supported_controllers_at(root: &Path) -> Result<Vec<String>> {
    let p = root.join("cgroup.controllers");
    let content = fs::read_to_string(&p)
        .map_err(|e| Error::with_cause(ErrorKind::ReadFailed(p.display().to_string()), e))?;
    Ok(content.split_whitespace().map(str::to_string).collect())
}

fn create_v2_cgroup(
    root: PathBuf,
    path: &CgroupPath,
    selection: &ControllerSelection,
    topology: Option<&CgroupTopology>,
) -> Result<()> {
    // Availability may change after discovery. Read it for this operation
    // without rediscovering the handle's mount topology.
    let available_controllers = supported_controllers_at(&root)?;

    let controllers = match selection {
        // Freezing is a v2 core interface, not an enableable controller.
        ControllerSelection::Only(selected) => selected
            .iter()
            .filter(|controller| controller.as_str() != "freezer")
            .cloned()
            .collect(),
        ControllerSelection::All => match topology {
            Some(topology) => topology.controllers().iter().map(str::to_string).collect(),
            // Built-in hierarchies always carry a snapshot. Only a custom
            // hierarchy can require reading its root's controller set here.
            None => available_controllers.clone(),
        },
    };
    let explicit = matches!(selection, ControllerSelection::Only(_));
    if explicit {
        require_controllers(&controllers, &available_controllers, &root)?;
    }

    let mut fp = root;

    // enable for root
    enable_controllers(selection, &controllers, &available_controllers, &fp)?;

    let components: Vec<_> = path.as_path().components().collect();
    let last_index = components.len().saturating_sub(1);
    for (i, comp) in components.iter().enumerate() {
        fp.push(comp.as_os_str());
        if let Err(e) = std::fs::create_dir_all(&fp) {
            return Err(Error::with_cause(ErrorKind::FsError, e));
        }

        if !controllers.is_empty() && (i < last_index || explicit) {
            // Availability is inherited from the immediate parent, not from
            // the real hierarchy root. Read it after enabling that parent.
            let available = supported_controllers_at(&fp)?;
            if explicit {
                require_controllers(&controllers, &available, &fp)?;
            }
            if i < last_index {
                enable_controllers(selection, &controllers, &available, &fp)?;
            }
        }
    }

    Ok(())
}

pub fn verify_supported_controllers(controllers: &[String]) -> bool {
    verify_supported_controllers_at(Path::new(UNIFIED_MOUNTPOINT), controllers)
}

pub fn verify_supported_controllers_at(root: &Path, controllers: &[String]) -> bool {
    supported_controllers_at(root)
        .map(|sc| controllers.iter().all(|c| sc.contains(c)))
        .unwrap_or(false)
}

/// Read current membership using the default host paths.
///
/// Returns raw procfs membership paths, including their leading `/` and any
/// namespace-relative `..`; these are not validated [`CgroupPath`] values.
/// Use [`CgroupReader::memberships`] to configure a different source or process.
pub fn get_cgroup_memberships() -> Result<HashMap<String, String>> {
    CgroupReader::default().memberships(None)
}

/// Read a process's membership using the default host paths.
///
/// Returns raw procfs membership paths, including their leading `/` and any
/// namespace-relative `..`; these are not validated [`CgroupPath`] values.
/// Use [`CgroupReader::memberships`] to configure the source independently.
pub fn get_cgroup_memberships_by_pid(pid: u32) -> Result<HashMap<String, String>> {
    CgroupReader::default().memberships(Some(pid))
}

/// Apply the legacy v1 mapping using the default host paths.
///
/// Use [`CgroupReader::existing_path`] with an explicitly configured reader
/// for other sources. Discovery errors propagate through this wrapper.
pub fn existing_path(paths: HashMap<String, String>) -> Result<HashMap<String, String>> {
    CgroupReader::default().existing_path(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Ordinary files model observed state only; they do not propagate a
    // parent's controller changes into its children like cgroupfs does.
    fn seed_v2_directory(root: &Path, path: &str, available: &str, enabled: &str) -> PathBuf {
        let directory = root.join(path);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("cgroup.controllers"), available).unwrap();
        fs::write(directory.join("cgroup.subtree_control"), enabled).unwrap();
        directory
    }

    fn apply_fixture() -> (crate::tests::TopologyFixture, Cgroup) {
        let fixture = crate::tests::TopologyFixture::new(
            b"41 33 0:31 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              42 33 0:32 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n\
              43 33 0:33 / /sys/fs/cgroup/cpuset rw - cgroup cgroup rw,cpuset\n\
              44 33 0:34 / /sys/fs/cgroup/cpuacct rw - cgroup cgroup rw,cpuacct\n\
              45 33 0:35 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n\
              46 33 0:36 / /sys/fs/cgroup/net_cls rw - cgroup cgroup rw,net_cls\n\
              47 33 0:37 / /sys/fs/cgroup/hugetlb rw - cgroup cgroup rw,hugetlb\n",
            b"1:memory:/\n2:pids:/\n3:cpuset:/\n4:cpuacct:/\n5:cpu:/\n6:net_cls:/\n7:hugetlb:/\n",
            "",
        );
        let cg = Cgroup::load(
            crate::fs::hierarchies::from_topology(fixture.topology.clone()),
            CgroupPath::root(),
        );
        for subsystem in cg.subsystems() {
            fs::create_dir_all(subsystem.to_controller().path()).unwrap();
        }
        (fixture, cg)
    }

    #[test]
    fn test_apply_stops_at_failure_without_rolling_back_earlier_writes() {
        let (_fixture, cg) = apply_fixture();
        let cpuset: &crate::fs::cpuset::CpuSetController = cg.controller_of().unwrap();
        let cpu: &crate::fs::cpu::CpuController = cg.controller_of().unwrap();
        fs::create_dir(cpuset.path().join("cpuset.mems")).unwrap();
        fs::write(cpu.path().join("cpu.shares"), "512").unwrap();
        let mut resources = Resources::default();
        resources.memory.memory_hard_limit = Some(1024);
        resources.pid.maximum_number_of_processes = Some(crate::fs::MaxValue::Value(10));
        resources.cpu.cpus = Some("0-1".into());
        resources.cpu.mems = Some("0".into());
        resources.cpu.shares = Some(1024);

        let error = cg.apply(&resources).unwrap_err();
        assert_eq!(error.kind(), &WriteFailed("cpuset.mems".into(), "0".into()));
        let memory: &crate::fs::memory::MemController = cg.controller_of().unwrap();
        let pids: &crate::fs::pid::PidController = cg.controller_of().unwrap();
        assert_eq!(
            fs::read_to_string(memory.path().join("memory.limit_in_bytes")).unwrap(),
            "1024"
        );
        assert_eq!(
            fs::read_to_string(pids.path().join("pids.max")).unwrap(),
            "10"
        );
        assert_eq!(
            fs::read_to_string(cpuset.path().join("cpuset.cpus")).unwrap(),
            "0-1"
        );
        assert_eq!(
            fs::read_to_string(cpu.path().join("cpu.shares")).unwrap(),
            "512"
        );
    }

    #[test]
    fn test_cgroup_preserves_non_utf8_path() {
        let non_utf8_bytes = b"\xff\xfe/test_subgroup";
        let path = CgroupPath::new(Path::new(OsStr::from_bytes(non_utf8_bytes))).unwrap();
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "");
        let hier = crate::fs::hierarchies::from_topology(fixture.topology.clone());

        let cg = Cgroup::load(hier, path);
        assert_eq!(cg.path().as_path().as_os_str().as_bytes(), non_utf8_bytes);
        assert!(cg.path().as_path().to_str().is_none());
    }

    #[test]
    fn test_v1_cpuset_creation_preserves_non_utf8_paths() {
        for (prefix, path) in [
            (b"pod-\xff".as_slice(), b"parent/child".as_slice()),
            (b"delegated".as_slice(), b"parent-\xfe/child".as_slice()),
            (b"pod-\xff".as_slice(), b"parent-\xfe/child".as_slice()),
        ] {
            let fixture = crate::tests::TopologyFixture::new(
                b"43 33 0:38 / /sys/fs/cgroup/cpuset rw - cgroup cgroup rw,cpuset\n",
                b"1:cpuset:/\n",
                "",
            );
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            let prefix = CgroupPath::new(OsStr::from_bytes(prefix)).unwrap();
            let path = CgroupPath::new(OsStr::from_bytes(path)).unwrap();
            let mount = fixture.topology.fixture_root().unwrap().join("cpuset");
            let base = mount.join(&prefix);
            fs::create_dir_all(&base).unwrap();
            for (file, root_value, prefix_value) in [
                ("cpuset.cpus", "0-7\n", "2-3\n"),
                ("cpuset.mems", "0-3\n", "1\n"),
            ] {
                fs::write(mount.join(file), root_value).unwrap();
                fs::write(base.join(file), prefix_value).unwrap();
            }

            // Ordinary mkdir does not synthesize the empty cpuset files that
            // kernel cgroups expose. Seed them before invoking creation.
            let directories: Vec<_> = path
                .as_path()
                .ancestors()
                .filter(|relative| !relative.as_os_str().is_empty())
                .map(|relative| base.join(relative))
                .collect();
            for directory in &directories {
                fs::create_dir_all(directory).unwrap();
                for file in ["cpuset.cpus", "cpuset.mems"] {
                    fs::write(directory.join(file), b"").unwrap();
                }
            }

            let handle = Cgroup::builder(hierarchy, path.clone())
                .controllers(ControllerSelection::Only(vec!["cpuset".to_string()]))
                .v1_prefixes(HashMap::from([("cpuset".to_string(), prefix)]))
                .create()
                .unwrap();
            let cpuset: &crate::fs::cpuset::CpuSetController = handle.controller_of().unwrap();
            assert_eq!(handle.path(), &path);
            assert_eq!(cpuset.path(), base.join(&path));
            for directory in directories {
                for (file, expected) in [("cpuset.cpus", "2-3"), ("cpuset.mems", "1")] {
                    assert_eq!(fs::read_to_string(directory.join(file)).unwrap(), expected);
                    assert_eq!(
                        fs::read_to_string(base.join(file)).unwrap(),
                        format!("{expected}\n"),
                    );
                }
            }
        }
    }

    #[test]
    fn test_cgroup_threads_topology() {
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "");
        let topology = fixture.topology.clone();

        let path = CgroupPath::new("a/b/c").unwrap();
        let hierarchy = crate::fs::hierarchies::from_topology(topology.clone());
        let cg = Cgroup::load(hierarchy.clone(), path);

        // 1. Cgroup exposes its hierarchy's topology
        assert!(cg.topology().is_some());
        assert_eq!(
            cg.topology().unwrap().fixture_root().unwrap(),
            topology.fixture_root().unwrap()
        );

        // 2. Clone preserves the exact same Arc<CgroupTopology>
        let cloned = cg.clone();
        assert!(std::sync::Arc::ptr_eq(
            &cg.topology().unwrap(),
            &cloned.topology().unwrap()
        ));

        // 3. Parent control group threads the same topology
        let parent = cg.parent().unwrap();
        assert_eq!(parent.path().as_path(), Path::new("a/b"));
        assert!(Arc::ptr_eq(&hierarchy, &parent.hier));
        assert!(parent.topology().is_some());
        assert!(std::sync::Arc::ptr_eq(
            &cg.topology().unwrap(),
            &parent.topology().unwrap()
        ));

        // 4. Root control group threads the same topology
        let root = parent.parent().unwrap().parent().unwrap();
        assert!(root.path().is_root());
        assert!(Arc::ptr_eq(&hierarchy, &root.hier));
        assert!(root.topology().is_some());
        assert!(std::sync::Arc::ptr_eq(
            &cg.topology().unwrap(),
            &root.topology().unwrap()
        ));
    }

    #[test]
    fn test_cgroup_clone_preserves_hierarchy_type() {
        // Create a topology with version == V2
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "");
        let topology = fixture.topology.clone();

        // Explicitly create V1 with this topology
        let v1 = crate::fs::hierarchies::V1::from(topology.clone());
        let cg_v1 = Cgroup::load(
            Arc::new(v1),
            crate::core::CgroupPath::new("test_v1").unwrap(),
        );
        assert!(!cg_v1.v2(), "Original cgroup should be v1");

        // Clone MUST preserve V1, not mutate to V2!
        let cloned_v1 = cg_v1.clone();
        assert!(
            !cloned_v1.v2(),
            "Cloned cgroup must remain v1 even with v2 topology"
        );
        assert!(std::sync::Arc::ptr_eq(
            &cg_v1.topology().unwrap(),
            &cloned_v1.topology().unwrap()
        ));
    }

    #[test]
    fn test_handles_share_non_clone_custom_hierarchy_until_last_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CustomHierarchy {
            drops: Arc<AtomicUsize>,
        }

        impl Drop for CustomHierarchy {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        impl Hierarchy for CustomHierarchy {
            fn subsystems(&self) -> Vec<Subsystem> {
                Vec::new()
            }

            fn root(&self) -> Result<PathBuf> {
                Err(Error::new(CgroupVersion))
            }

            fn v2(&self) -> bool {
                false
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let hierarchy: Arc<dyn Hierarchy> = Arc::new(CustomHierarchy {
            drops: drops.clone(),
        });
        let a = Cgroup::load(hierarchy.clone(), CgroupPath::new("a/child").unwrap());
        let b = Cgroup::builder(hierarchy.clone(), CgroupPath::new("b").unwrap()).load();
        let cloned = a.clone();
        let parent = a.parent().unwrap();
        let root = Cgroup::load(hierarchy.clone(), CgroupPath::root());
        for handle in [&a, &b, &cloned, &parent, &root] {
            assert!(Arc::ptr_eq(&hierarchy, &handle.hier));
        }
        assert_eq!(a.path().as_path(), Path::new("a/child"));
        assert_eq!(b.path().as_path(), Path::new("b"));
        assert_eq!(parent.path().as_path(), Path::new("a"));
        assert!(root.path().is_root());

        drop((hierarchy, a, cloned, parent, root));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(b.hier.root().unwrap_err().kind(), &CgroupVersion);
        drop(b);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_controller_selection_applies_to_root_and_child() {
        let legacy = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              44 33 0:39 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n",
            b"1:memory:/\n2:cpu:/\n",
            "",
        );
        let unified = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpu memory");
        for fixture in [&legacy, &unified] {
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            for selection in [
                ControllerSelection::default(),
                ControllerSelection::Only(vec!["memory".to_string()]),
                ControllerSelection::Only(Vec::new()),
            ] {
                let builder =
                    |path| Cgroup::builder(hierarchy.clone(), path).controllers(selection.clone());
                let child = builder(CgroupPath::new("child").unwrap()).load();
                let mut expected = match &selection {
                    ControllerSelection::Only(controllers) => controllers.clone(),
                    ControllerSelection::All if hierarchy.v2() => vec![
                        "cpu".to_string(),
                        "memory".to_string(),
                        "freezer".to_string(),
                    ],
                    ControllerSelection::All => vec!["cpu".to_string(), "memory".to_string()],
                };
                expected.sort();
                let subtree_control = fixture
                    .topology
                    .fixture_root()
                    .unwrap()
                    .join("cgroup.subtree_control");
                if hierarchy.v2() {
                    fs::write(&subtree_control, b"unchanged").unwrap();
                }
                let loaded_root = builder(CgroupPath::root()).load();
                if hierarchy.v2() {
                    assert_eq!(fs::read(&subtree_control).unwrap(), b"unchanged");
                }
                let mut handles = vec![loaded_root, child.parent().unwrap(), child];
                if matches!(&selection, ControllerSelection::Only(controllers) if controllers.is_empty())
                {
                    let error = builder(CgroupPath::root()).create().unwrap_err();
                    assert_eq!(
                        error.kind(),
                        &EmptyControllerSelection {
                            path: PathBuf::new()
                        }
                    );
                    if hierarchy.v2() {
                        assert_eq!(fs::read(&subtree_control).unwrap(), b"unchanged");
                    }
                } else {
                    handles.push(builder(CgroupPath::root()).create().unwrap());
                    if hierarchy.v2() {
                        assert_eq!(fs::read(&subtree_control).unwrap(), b"+memory");
                    }
                }
                for handle in handles {
                    let mut actual: Vec<_> = handle
                        .subsystems()
                        .iter()
                        .map(Subsystem::controller_name)
                        .collect();
                    actual.sort();
                    assert_eq!(actual, expected);
                    assert!(Arc::ptr_eq(&hierarchy, &handle.hier));
                }
            }
        }
    }

    #[test]
    fn test_creation_rejects_invalid_selections_without_mutation() {
        use crate::core::CgroupVersion;

        for version in [CgroupVersion::V1, CgroupVersion::V2] {
            let fixture = crate::tests::topology_fixture(version, "memory");
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            let root = fixture.topology.fixture_root().unwrap();
            let subtree_control = root.join("cgroup.subtree_control");
            fs::write(&subtree_control, b"unchanged").unwrap();
            for names in [
                Vec::new(),
                vec!["memory".to_string(), "missing".to_string()],
            ] {
                let path = CgroupPath::new("parent/child").unwrap();
                let handle = Cgroup::builder(hierarchy.clone(), path.clone())
                    .controllers(ControllerSelection::Only(names.clone()))
                    .load();
                // Exercise both public creation entrypoints; load remains non-mutating.
                for error in [
                    handle.create().unwrap_err(),
                    Cgroup::builder(hierarchy.clone(), path.clone())
                        .controllers(ControllerSelection::Only(names.clone()))
                        .create()
                        .unwrap_err(),
                ] {
                    let expected = if names.is_empty() {
                        EmptyControllerSelection {
                            path: path.as_path().to_path_buf(),
                        }
                    } else {
                        UnsupportedController {
                            controller: "missing".to_string(),
                            path: if version == CgroupVersion::V2 {
                                Some(root.join("cgroup.controllers"))
                            } else {
                                None
                            },
                        }
                    };
                    assert_eq!(error.kind(), &expected);
                }
                assert_eq!(fs::read(&subtree_control).unwrap(), b"unchanged");
                assert!(!root.join("parent").exists());
                assert!(!root.join("memory/parent").exists());
            }
        }
    }

    #[test]
    fn test_try_load_rejects_unreported_controller_names_without_cgroupfs() {
        let legacy = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n\
              44 33 0:39 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
            b"1:cpu:/\n2:memory:/\n",
            "",
        );
        let unified = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpu memory");
        for fixture in [&legacy, &unified] {
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            let root = fixture.topology.fixture_root().unwrap();
            // Loading uses the hierarchy's reported set even after its
            // control files disappear. It must not read or recreate them.
            fs::remove_dir_all(root).unwrap();
            for path in [CgroupPath::root(), CgroupPath::new("child").unwrap()] {
                let builder = || {
                    Cgroup::builder(hierarchy.clone(), path.clone()).controllers(
                        ControllerSelection::Only(vec!["cpu".to_string(), "mmeory".to_string()]),
                    )
                };
                let unchecked = builder().load();
                assert_eq!(unchecked.subsystems().len(), 1);
                assert!(unchecked
                    .controller_of::<crate::fs::cpu::CpuController>()
                    .is_some());
                assert!(unchecked
                    .controller_of::<crate::fs::memory::MemController>()
                    .is_none());

                let error = builder().try_load().unwrap_err();
                assert_eq!(
                    error.kind(),
                    &UnsupportedController {
                        controller: "mmeory".to_string(),
                        path: if hierarchy.v2() {
                            Some(root.join("cgroup.controllers"))
                        } else {
                            None
                        },
                    }
                );
                assert_eq!(unchecked.create().unwrap_err().kind(), error.kind());
                assert!(!root.exists());
            }
        }
    }

    #[test]
    fn test_try_load_preserves_valid_selections_and_v1_prefixes() {
        let legacy = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/blkio rw - cgroup cgroup rw,blkio\n",
            b"1:blkio:/\n",
            "",
        );
        let unified = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "io");
        for (fixture, name, wrong_name) in [(&legacy, "blkio", "io"), (&unified, "io", "blkio")] {
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            let root = fixture.topology.fixture_root().unwrap();
            fs::remove_dir_all(root).unwrap();
            for path in [CgroupPath::root(), CgroupPath::new("child").unwrap()] {
                for selection in [
                    ControllerSelection::All,
                    ControllerSelection::Only(vec![name.to_string()]),
                    ControllerSelection::Only(Vec::new()),
                ] {
                    let handle = Cgroup::builder(hierarchy.clone(), path.clone())
                        .controllers(selection.clone())
                        .v1_prefixes(HashMap::from([(
                            "blkio".to_string(),
                            CgroupPath::new("delegated").unwrap(),
                        )]))
                        .try_load()
                        .unwrap();
                    if matches!(selection, ControllerSelection::Only(names) if names.is_empty()) {
                        assert!(handle.subsystems().is_empty());
                        assert_eq!(
                            handle.create().unwrap_err().kind(),
                            &EmptyControllerSelection {
                                path: path.as_path().to_path_buf(),
                            }
                        );
                    } else {
                        let block_io: &crate::fs::blkio::BlkIoController =
                            handle.controller_of().unwrap();
                        let base = if hierarchy.v2() {
                            root.to_path_buf()
                        } else {
                            root.join("blkio/delegated")
                        };
                        assert_eq!(block_io.path(), base.join(path.as_path()));
                    }
                }
                let error = Cgroup::builder(hierarchy.clone(), path.clone())
                    .controllers(ControllerSelection::Only(vec![wrong_name.to_string()]))
                    .try_load()
                    .unwrap_err();
                assert!(
                    matches!(error.kind(), UnsupportedController { controller, .. } if controller == wrong_name)
                );
                if hierarchy.v2() {
                    let freezer = Cgroup::builder(hierarchy.clone(), path)
                        .controllers(ControllerSelection::Only(vec!["freezer".to_string()]))
                        .try_load()
                        .unwrap();
                    assert_eq!(freezer.subsystems().len(), 1);
                    assert!(freezer
                        .controller_of::<crate::fs::freezer::FreezerController>()
                        .is_some());
                }
            }
            assert!(!root.exists());
        }
    }

    #[test]
    fn test_v1_kill_reports_no_unified_root() {
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V1, "memory");
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let handle = Cgroup::load(hierarchy, CgroupPath::new("child").unwrap());
        assert_eq!(handle.kill().unwrap_err().kind(), &CgroupVersion);
        assert!(!fixture
            .topology
            .fixture_root()
            .unwrap()
            .join("child")
            .exists());
    }

    #[test]
    fn test_v2_operations_propagate_unified_root_errors() {
        use std::error::Error as _;

        #[derive(Debug)]
        struct UnavailableHierarchy;

        impl Hierarchy for UnavailableHierarchy {
            fn subsystems(&self) -> Vec<Subsystem> {
                Vec::new()
            }

            fn root(&self) -> Result<PathBuf> {
                Err(Error::with_cause(
                    ReadFailed("/custom/unified".to_string()),
                    std::io::Error::from_raw_os_error(libc::EACCES),
                ))
            }

            fn v2(&self) -> bool {
                true
            }
        }

        let handle = Cgroup::load(
            Arc::new(UnavailableHierarchy),
            CgroupPath::new("child").unwrap(),
        );
        for error in [
            handle.create().unwrap_err(),
            handle.delete().unwrap_err(),
            handle.kill().unwrap_err(),
        ] {
            assert_eq!(error.kind(), &ReadFailed("/custom/unified".to_string()));
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::EACCES)
            );
        }
    }

    #[test]
    fn test_v2_creation_with_no_resource_controllers() {
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "");
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let root = fixture.topology.fixture_root().unwrap();
        let subtree_control = root.join("cgroup.subtree_control");
        fs::write(&subtree_control, b"unchanged").unwrap();

        let all = Cgroup::builder(hierarchy.clone(), CgroupPath::new("all").unwrap())
            .create()
            .unwrap();
        assert_eq!(all.controllers, ControllerSelection::All);
        assert!(root.join("all").is_dir());
        assert!(all
            .controller_of::<crate::fs::freezer::FreezerController>()
            .is_some());

        let freezer = Cgroup::builder(hierarchy, CgroupPath::new("freezer/child").unwrap())
            .controllers(ControllerSelection::Only(vec!["freezer".to_string()]))
            .create()
            .unwrap();
        assert_eq!(freezer.subsystems().len(), 1);
        assert!(root.join("freezer/child").is_dir());
        assert_eq!(fs::read(&subtree_control).unwrap(), b"unchanged");
        assert!(!root.join("freezer/cgroup.subtree_control").exists());
    }

    #[test]
    fn test_custom_v2_hierarchy_can_create_without_a_snapshot() {
        #[derive(Debug)]
        struct CustomHierarchy(PathBuf);

        impl Hierarchy for CustomHierarchy {
            fn subsystems(&self) -> Vec<Subsystem> {
                vec![Subsystem::Cpu(crate::fs::cpu::CpuController::new(
                    self.0.clone(),
                    PathBuf::new(),
                    true,
                ))]
            }

            fn root(&self) -> Result<PathBuf> {
                Ok(self.0.clone())
            }

            fn v2(&self) -> bool {
                true
            }
        }

        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpu");
        let root = fixture.topology.fixture_root().unwrap();
        let hierarchy: Arc<dyn Hierarchy> = Arc::new(CustomHierarchy(root.to_path_buf()));
        seed_v2_directory(root, "child", "cpu", "");
        let handle = Cgroup::new(hierarchy.clone(), CgroupPath::new("child").unwrap()).unwrap();
        assert!(handle.topology().is_none());
        assert!(Arc::ptr_eq(&hierarchy, &handle.hier));
        assert!(root.join("child").is_dir());
        assert_eq!(
            fs::read(root.join("cgroup.subtree_control")).unwrap(),
            b"+cpu"
        );
    }

    #[test]
    fn test_block_io_selection_uses_kernel_names_for_each_hierarchy() {
        let legacy = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/blkio rw - cgroup cgroup rw,blkio\n",
            b"1:blkio:/\n",
            "",
        );
        let unified = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "io memory");
        for (fixture, name, wrong_name, relative_directory) in [
            (&legacy, "blkio", "io", "blkio/child"),
            (&unified, "io", "blkio", "child"),
        ] {
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            let root = fixture.topology.fixture_root().unwrap();
            if hierarchy.v2() {
                seed_v2_directory(root, "child", "io", "");
            }
            let handle = Cgroup::builder(hierarchy.clone(), CgroupPath::new("child").unwrap())
                .controllers(ControllerSelection::Only(vec![name.to_string()]))
                .create()
                .unwrap();
            assert_eq!(handle.subsystems().len(), 1);
            let blkio: &crate::fs::blkio::BlkIoController = handle.controller_of().unwrap();
            assert_eq!(blkio.path(), root.join(relative_directory));
            if hierarchy.v2() {
                assert_eq!(
                    fs::read(root.join("cgroup.subtree_control")).unwrap(),
                    b"+io"
                );
            }
            let cloned = handle.clone();
            let parent = handle.parent().unwrap();
            for related in [&cloned, &parent] {
                assert_eq!(related.controllers, handle.controllers);
                assert!(related
                    .controller_of::<crate::fs::blkio::BlkIoController>()
                    .is_some());
            }
            let error = Cgroup::builder(hierarchy, CgroupPath::new("other").unwrap())
                .controllers(ControllerSelection::Only(vec![wrong_name.to_string()]))
                .create()
                .unwrap_err();
            assert!(
                matches!(error.kind(), UnsupportedController { controller, .. } if controller == wrong_name)
            );
            assert!(!root.join("other").exists());
            assert!(!root.join("blkio/other").exists());
        }
    }

    #[test]
    fn test_v2_creation_rechecks_current_controller_availability() {
        use std::error::Error as _;

        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpu memory");
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let root = fixture.topology.fixture_root().unwrap();
        let controller_list = root.join("cgroup.controllers");
        let subtree_control = root.join("cgroup.subtree_control");
        let handle = Cgroup::builder(hierarchy.clone(), CgroupPath::new("child").unwrap())
            .controllers(ControllerSelection::Only(vec!["memory".to_string()]))
            .load();
        fs::write(&subtree_control, b"unchanged").unwrap();
        fs::write(&controller_list, b"cpu").unwrap();
        assert_eq!(
            handle.create().unwrap_err().kind(),
            &UnsupportedController {
                controller: "memory".to_string(),
                path: Some(controller_list.clone()),
            }
        );
        assert_eq!(fs::read(&subtree_control).unwrap(), b"unchanged");
        assert!(!root.join("child").exists());

        fs::remove_file(&controller_list).unwrap();
        let error = handle.create().unwrap_err();
        assert_eq!(
            error.kind(),
            &ReadFailed(controller_list.display().to_string())
        );
        let cause = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(cause.raw_os_error(), Some(libc::ENOENT));
        assert_eq!(fs::read(&subtree_control).unwrap(), b"unchanged");
        assert!(!root.join("child").exists());

        // All tolerates a smaller current set even at the hierarchy root.
        fs::write(&controller_list, b"cpu").unwrap();
        Cgroup::builder(hierarchy.clone(), CgroupPath::new("reduced").unwrap())
            .create()
            .unwrap();
        assert_eq!(fs::read(&subtree_control).unwrap(), b"+cpu");

        // All retains the snapshot's controller set rather than adopting a
        // controller that became available after discovery.
        fs::write(&controller_list, b"cpu memory io").unwrap();
        let all = Cgroup::builder(hierarchy, CgroupPath::new("all").unwrap())
            .create()
            .unwrap();
        assert!(all
            .controller_of::<crate::fs::blkio::BlkIoController>()
            .is_none());
        assert_eq!(fs::read(&subtree_control).unwrap(), b"+memory");
    }

    #[test]
    fn test_v2_controller_read_errors_preserve_context_and_stop_creation() {
        use std::error::Error as _;

        for selection in [
            ControllerSelection::All,
            ControllerSelection::Only(vec!["cpu".to_string()]),
        ] {
            for failed_directory in ["", "parent"] {
                let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpu");
                let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
                let root = fixture.topology.fixture_root().unwrap();
                let root_control = root.join("cgroup.subtree_control");
                fs::write(&root_control, b"unchanged").unwrap();
                let failed_file = root.join(failed_directory).join("cgroup.subtree_control");
                if failed_directory.is_empty() {
                    fs::remove_file(&failed_file).unwrap();
                }
                // A directory at the read target reliably produces EISDIR without root.
                fs::create_dir_all(&failed_file).unwrap();
                if !failed_directory.is_empty() {
                    fs::write(root.join("parent/cgroup.controllers"), b"cpu").unwrap();
                }
                let error = Cgroup::builder(hierarchy, CgroupPath::new("parent/child").unwrap())
                    .controllers(selection.clone())
                    .create()
                    .unwrap_err();
                assert_eq!(error.kind(), &ReadFailed(failed_file.display().to_string()));
                let cause = error
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap();
                assert_eq!(cause.raw_os_error(), Some(libc::EISDIR));
                assert!(!root.join("parent/child").exists());
                if failed_directory.is_empty() {
                    assert!(!root.join("parent").exists());
                } else {
                    // The successful ancestor write remains; creation has no rollback.
                    assert_eq!(fs::read(&root_control).unwrap(), b"+cpu");
                }
            }
        }
    }

    #[test]
    fn test_v2_creation_through_pre_enabled_ancestors() {
        use std::os::unix::fs::PermissionsExt;

        for selection in [
            ControllerSelection::Only(vec!["pids".to_string()]),
            ControllerSelection::All,
        ] {
            let fixture = crate::tests::topology_fixture(
                crate::core::CgroupVersion::V2,
                "cpuset memory pids rdma",
            );
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            let root = fixture.topology.fixture_root().unwrap();
            let mut ancestors = vec![(root.to_path_buf(), "cpuset memory pids rdma")];
            for path in [
                "user.slice",
                "user.slice/user-1000.slice",
                "user.slice/user-1000.slice/user@1000.service",
            ] {
                // Only pids was distributed into this branch. All must not
                // attempt to enable cpuset/memory/rdma from the root snapshot.
                ancestors.push((seed_v2_directory(root, path, "pids", "pids"), "pids"));
            }
            fs::write(root.join("cgroup.subtree_control"), ancestors[0].1).unwrap();
            for (ancestor, _) in &ancestors {
                fs::set_permissions(
                    ancestor.join("cgroup.subtree_control"),
                    fs::Permissions::from_mode(0o444),
                )
                .unwrap();
            }
            let parent_path = "user.slice/user-1000.slice/user@1000.service/app.slice";
            let parent = seed_v2_directory(root, parent_path, "pids", "");
            let target_path = format!("{}/x", parent_path);
            if matches!(selection, ControllerSelection::Only(_)) {
                // Seed the final observation for Only's postcondition. Plain
                // directories do not synthesize cgroup.controllers on mkdir.
                seed_v2_directory(root, &target_path, "pids", "");
            }
            let handle = Cgroup::builder(hierarchy, CgroupPath::new(&target_path).unwrap())
                .controllers(selection)
                .create()
                .unwrap();
            assert!(handle.exists());
            assert_eq!(
                fs::read(parent.join("cgroup.subtree_control")).unwrap(),
                b"+pids"
            );
            for (ancestor, enabled) in ancestors {
                // Also catches redundant writes when this test runs as root,
                // where mode bits alone cannot forbid them.
                assert_eq!(
                    fs::read_to_string(ancestor.join("cgroup.subtree_control")).unwrap(),
                    enabled
                );
            }
            if root
                .join(&target_path)
                .join("cgroup.subtree_control")
                .exists()
            {
                assert_eq!(
                    fs::read(root.join(&target_path).join("cgroup.subtree_control")).unwrap(),
                    b""
                );
            }
        }
    }

    #[test]
    fn test_v2_only_requires_controllers_in_ancestors_and_target() {
        for missing_at in ["parent", "parent/child"] {
            let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "pids");
            let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
            let root = fixture.topology.fixture_root().unwrap();
            fs::write(root.join("cgroup.subtree_control"), b"pids").unwrap();
            let parent = seed_v2_directory(root, "parent", "pids", "pids");
            let target = seed_v2_directory(root, "parent/child", "pids", "unchanged");
            fs::write(root.join(missing_at).join("cgroup.controllers"), b"").unwrap();
            let error = Cgroup::builder(hierarchy, CgroupPath::new("parent/child").unwrap())
                .controllers(ControllerSelection::Only(vec!["pids".to_string()]))
                .create()
                .unwrap_err();
            assert_eq!(
                error.kind(),
                &UnsupportedController {
                    controller: "pids".to_string(),
                    path: Some(root.join(missing_at).join("cgroup.controllers")),
                }
            );
            assert_eq!(
                fs::read(parent.join("cgroup.subtree_control")).unwrap(),
                b"pids"
            );
            assert_eq!(
                fs::read(target.join("cgroup.subtree_control")).unwrap(),
                b"unchanged"
            );
        }
    }

    #[test]
    fn test_v2_enable_writes_only_missing_controllers_and_preserves_errors() {
        use std::error::Error as _;

        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpu pids");
        let root = fixture.topology.fixture_root().unwrap();
        let file = root.join("cgroup.subtree_control");
        fs::write(&file, b"pids\n").unwrap();
        let selected = vec!["pids".to_string(), "cpu".to_string(), "cpu".to_string()];
        let selection = ControllerSelection::Only(selected.clone());
        let available = vec!["cpu".to_string(), "pids".to_string()];
        let mut writes = Vec::new();
        enable_controllers_with(&selection, &selected, &available, root, |path, body| {
            writes.push((path.to_path_buf(), body.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(writes, [(file.clone(), "+cpu".to_string())]);

        // Required writes must still fail, with their original errno. Inject
        // the write result so this test also works in a root library harness.
        for errno in [libc::EACCES, libc::EBUSY] {
            writes.clear();
            let error =
                enable_controllers_with(&selection, &selected, &available, root, |path, body| {
                    writes.push((path.to_path_buf(), body.to_string()));
                    Err(std::io::Error::from_raw_os_error(errno))
                })
                .unwrap_err();
            assert_eq!(writes, [(file.clone(), "+cpu".to_string())]);
            assert_eq!(
                error.kind(),
                &WriteFailed(file.display().to_string(), "+cpu".to_string())
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
        }
    }

    #[test]
    fn test_v2_all_skips_individual_ancestor_enable_failures() {
        let fixture =
            crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpuset cpu pids");
        let root = fixture.topology.fixture_root().unwrap();
        // user.slice offers cpuset without distributing it to the delegated
        // branch. Inject the error so this also works in a root test harness.
        let ancestor = seed_v2_directory(root, "user.slice", "cpuset cpu pids", "pids");
        let file = ancestor.join("cgroup.subtree_control");
        let controllers = vec!["cpuset".to_string(), "cpu".to_string(), "pids".to_string()];
        let available = supported_controllers_at(&ancestor).unwrap();
        let selection = ControllerSelection::default();

        for errno in [libc::EACCES, libc::EBUSY] {
            let mut writes = Vec::new();
            enable_controllers_with(
                &selection,
                &controllers,
                &available,
                &ancestor,
                |path, body| {
                    writes.push((path.to_path_buf(), body.to_string()));
                    if body == "+cpuset" {
                        Err(std::io::Error::from_raw_os_error(errno))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap();
            assert_eq!(
                writes,
                [
                    (file.clone(), "+cpuset".to_string()),
                    (file.clone(), "+cpu".to_string()),
                ]
            );
        }

        // The next level uses its own offered set; cpuset is unavailable.
        let delegated = seed_v2_directory(root, "user.slice/user-1000.slice", "cpu pids", "");
        let available = supported_controllers_at(&delegated).unwrap();
        let mut writes = Vec::new();
        enable_controllers_with(
            &selection,
            &controllers,
            &available,
            &delegated,
            |path, body| {
                writes.push((path.to_path_buf(), body.to_string()));
                Ok(())
            },
        )
        .unwrap();
        let file = delegated.join("cgroup.subtree_control");
        assert_eq!(
            writes,
            [
                (file.clone(), "+cpu".to_string()),
                (file, "+pids".to_string())
            ]
        );
    }

    #[test]
    fn test_root_operations_use_v1_prefixes_only_for_membership() {
        let fixture = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              44 33 0:39 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n\
              45 33 0:40 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n\
              46 33 0:41 / /sys/fs/cgroup/blkio rw - cgroup cgroup rw,blkio\n",
            b"1:memory:/\n2:cpu:/\n3:pids:/\n4:blkio:/\n",
            "",
        );
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let root = fixture.topology.fixture_root().unwrap();
        let names = ["cpu", "memory", "pids", "blkio"];
        let files = [
            ("tasks", "100"),
            ("cgroup.procs", "101"),
            ("release_agent", "/sbin/release"),
        ];
        let prefixes: HashMap<_, _> = names
            .iter()
            .map(|name| {
                (
                    name.to_string(),
                    CgroupPath::new(format!("delegated/{}", name)).unwrap(),
                )
            })
            .collect();

        for (selection, prefixes) in [
            (
                ControllerSelection::Only(vec!["cpu".to_string()]),
                prefixes.clone(),
            ),
            (ControllerSelection::Only(Vec::new()), prefixes.clone()),
            (ControllerSelection::All, prefixes.clone()),
            (ControllerSelection::All, HashMap::new()),
            (
                ControllerSelection::All,
                HashMap::from([("cpu".to_string(), prefixes["cpu"].clone())]),
            ),
        ] {
            // Seed both the true roots and prefixed paths with distinct state.
            // These ordinary files verify destinations, not kernel migration.
            for name in names {
                let prefix = prefixes
                    .get(name)
                    .map_or(Path::new(""), CgroupPath::as_path);
                for relative in [
                    PathBuf::new(),
                    prefix.to_path_buf(),
                    prefix.join("parent/child"),
                ] {
                    let directory = root.join(name).join(relative);
                    fs::create_dir_all(&directory).unwrap();
                    for (file, _) in files {
                        fs::write(directory.join(file), b"unchanged").unwrap();
                    }
                }
            }
            let child =
                Cgroup::builder(hierarchy.clone(), CgroupPath::new("parent/child").unwrap())
                    .controllers(selection.clone())
                    .v1_prefixes(prefixes.clone())
                    .load();
            child.remove_task(CgroupPid::from(100)).unwrap();
            child
                .clone()
                .remove_task_by_tgid(CgroupPid::from(101))
                .unwrap();
            child.set_release_agent("/sbin/release").unwrap();

            for name in names {
                let selected = match &selection {
                    ControllerSelection::All => true,
                    ControllerSelection::Only(names) => {
                        names.iter().any(|selected| selected == name)
                    }
                };
                let prefix = prefixes
                    .get(name)
                    .map_or(Path::new(""), CgroupPath::as_path);
                for (file, value) in files {
                    let target = if file == "release_agent" {
                        Path::new("")
                    } else {
                        prefix
                    };
                    for relative in [
                        PathBuf::new(),
                        prefix.to_path_buf(),
                        prefix.join("parent/child"),
                    ] {
                        assert_eq!(
                            fs::read_to_string(root.join(name).join(&relative).join(file)).unwrap(),
                            if selected && relative == target {
                                value
                            } else {
                                "unchanged"
                            },
                            "{name}/{relative:?}/{file} must respect {selection:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_root_operations_preserve_write_error_paths_and_sources() {
        use std::error::Error as _;

        let fixture = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              44 33 0:39 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n",
            b"1:memory:/\n2:cpu:/\n",
            "",
        );
        let root = fixture.topology.fixture_root().unwrap();
        for file in ["delegated/tasks", "delegated/cgroup.procs", "release_agent"] {
            // A directory at the write target fails even in a root harness.
            fs::create_dir_all(root.join("cpu").join(file)).unwrap();
        }
        let child = Cgroup::builder(
            crate::fs::hierarchies::from_topology(fixture.topology.clone()),
            CgroupPath::new("child").unwrap(),
        )
        .controllers(ControllerSelection::Only(vec!["cpu".to_string()]))
        .v1_prefixes(HashMap::from([(
            "cpu".to_string(),
            CgroupPath::new("delegated").unwrap(),
        )]))
        .load();
        for (file, error) in [
            (
                "delegated/tasks",
                child.remove_task(CgroupPid::from(100)).unwrap_err(),
            ),
            (
                "delegated/cgroup.procs",
                child.remove_task_by_tgid(CgroupPid::from(101)).unwrap_err(),
            ),
            (
                "release_agent",
                child.set_release_agent("/sbin/release").unwrap_err(),
            ),
        ] {
            assert!(
                matches!(error.kind(), WriteFailed(path, _) if path == &root.join("cpu").join(file).display().to_string())
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
        }
        assert!(!root.join("memory").exists());
        assert!(!root.join("cpu/delegated/child").exists());

        // A missing prefix must fail rather than fall back to a writable root.
        fs::remove_dir_all(root.join("cpu/delegated")).unwrap();
        for file in ["tasks", "cgroup.procs"] {
            fs::write(root.join("cpu").join(file), b"unchanged").unwrap();
        }
        for (file, error) in [
            (
                "tasks",
                child.remove_task(CgroupPid::from(100)).unwrap_err(),
            ),
            (
                "cgroup.procs",
                child.remove_task_by_tgid(CgroupPid::from(101)).unwrap_err(),
            ),
        ] {
            assert!(
                matches!(error.kind(), WriteFailed(path, _) if path == &root.join("cpu/delegated").join(file).display().to_string())
            );
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::ENOENT),
            );
            assert_eq!(fs::read(root.join("cpu").join(file)).unwrap(), b"unchanged");
        }
    }

    #[test]
    fn test_remove_task_ignores_v1_prefixes_on_v2() {
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "cpu");
        let root = fixture.topology.fixture_root().unwrap();
        // A regular file models thread mode for destination checks only.
        fs::write(root.join("cgroup.type"), CGROUP_MODE_DOMAIN_THREADED).unwrap();
        for relative in ["", "delegated", "child", "delegated/child"] {
            let directory = root.join(relative);
            fs::create_dir_all(&directory).unwrap();
            for file in ["cgroup.threads", "cgroup.procs"] {
                fs::write(directory.join(file), b"unchanged").unwrap();
            }
        }
        let child = Cgroup::builder(
            crate::fs::hierarchies::from_topology(fixture.topology.clone()),
            CgroupPath::new("child").unwrap(),
        )
        .controllers(ControllerSelection::Only(vec!["cpu".to_string()]))
        .v1_prefixes(HashMap::from([(
            "cpu".to_string(),
            CgroupPath::new("delegated").unwrap(),
        )]))
        .load();
        child.remove_task(CgroupPid::from(100)).unwrap();
        child.remove_task_by_tgid(CgroupPid::from(101)).unwrap();
        for (file, value) in [("cgroup.threads", "100"), ("cgroup.procs", "101")] {
            assert_eq!(fs::read_to_string(root.join(file)).unwrap(), value);
            for relative in ["delegated", "child", "delegated/child"] {
                assert_eq!(
                    fs::read(root.join(relative).join(file)).unwrap(),
                    b"unchanged"
                );
            }
        }
    }

    #[test]
    fn test_root_selection_limits_v1_creation_and_membership_writes() {
        let fixture = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              44 33 0:39 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n",
            b"1:memory:/\n2:cpu:/\n",
            "",
        );
        let root = fixture.topology.fixture_root().unwrap();
        let memory = root.join("memory/delegated");
        let cpu = root.join("cpu/delegated");
        let handle = Cgroup::builder(
            crate::fs::hierarchies::from_topology(fixture.topology.clone()),
            CgroupPath::root(),
        )
        .controllers(ControllerSelection::Only(vec!["memory".to_string()]))
        .v1_prefixes(HashMap::from([
            ("memory".to_string(), CgroupPath::new("delegated").unwrap()),
            ("cpu".to_string(), CgroupPath::new("delegated").unwrap()),
        ]))
        .create()
        .unwrap();
        assert!(memory.is_dir());
        assert!(!cpu.exists());

        // Ordinary files verify write destinations, not kernel migration.
        fs::create_dir_all(&cpu).unwrap();
        for directory in [&memory, &cpu] {
            fs::write(directory.join("tasks"), b"999").unwrap();
            fs::write(directory.join("cgroup.procs"), b"999").unwrap();
        }
        handle.add_task(CgroupPid::from(100)).unwrap();
        handle.add_task_by_tgid(CgroupPid::from(101)).unwrap();
        assert_eq!(fs::read(memory.join("tasks")).unwrap(), b"100");
        assert_eq!(fs::read(memory.join("cgroup.procs")).unwrap(), b"101");
        assert_eq!(fs::read(cpu.join("tasks")).unwrap(), b"999");
        assert_eq!(fs::read(cpu.join("cgroup.procs")).unwrap(), b"999");
    }

    #[test]
    fn test_handle_builder_maps_v1_paths_and_preserves_v2_paths() {
        let fixture = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              44 33 0:39 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n",
            b"1:memory:/\n2:cpu:/\n",
            "",
        );
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let v1_prefixes =
            HashMap::from([("memory".to_string(), CgroupPath::new("delegated").unwrap())]);
        let child = Cgroup::builder(hierarchy.clone(), CgroupPath::new("child").unwrap())
            .v1_prefixes(v1_prefixes.clone())
            .load();
        assert_eq!(child.path().as_path(), Path::new("child"));
        let memory: &crate::fs::memory::MemController = child.controller_of().unwrap();
        let cpu: &crate::fs::cpu::CpuController = child.controller_of().unwrap();
        let root = fixture.topology.fixture_root().unwrap();
        assert_eq!(memory.path(), root.join("memory/delegated/child"));
        assert_eq!(cpu.path(), root.join("cpu/child"));
        assert!(Arc::ptr_eq(&hierarchy, &child.hier));

        let selected = Cgroup::builder(hierarchy.clone(), CgroupPath::new("child").unwrap())
            .controllers(ControllerSelection::Only(vec!["memory".to_string()]))
            .v1_prefixes(v1_prefixes.clone())
            .load();
        assert_eq!(selected.subsystems().len(), 1);
        let memory: &crate::fs::memory::MemController = selected.controller_of().unwrap();
        assert_eq!(memory.path(), root.join("memory/delegated/child"));

        let root_handle = Cgroup::builder(hierarchy, CgroupPath::root())
            .controllers(ControllerSelection::Only(vec!["memory".to_string()]))
            .v1_prefixes(v1_prefixes.clone())
            .load();
        assert!(root_handle.path().is_root());
        assert_eq!(root_handle.subsystems().len(), 1);
        let memory: &crate::fs::memory::MemController = root_handle.controller_of().unwrap();
        assert_eq!(memory.path(), root.join("memory/delegated"));

        let unified = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "memory");
        let hierarchy = crate::fs::hierarchies::from_topology(unified.topology.clone());
        let child = Cgroup::builder(hierarchy, CgroupPath::new("child").unwrap())
            .v1_prefixes(v1_prefixes)
            .load();
        assert_eq!(child.path().as_path(), Path::new("child"));
        let memory: &crate::fs::memory::MemController = child.controller_of().unwrap();
        assert_eq!(
            memory.path(),
            unified.topology.fixture_root().unwrap().join("child")
        );
    }

    #[test]
    fn test_parent_retains_controller_selection_and_v1_prefixes() {
        let fixture = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              44 33 0:39 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n",
            b"1:memory:/\n2:cpu:/\n",
            "",
        );
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let selected = vec!["memory".to_string()];
        let child = Cgroup::builder(hierarchy.clone(), CgroupPath::new("a/b").unwrap())
            .controllers(ControllerSelection::Only(selected.clone()))
            .v1_prefixes(HashMap::from([(
                "memory".to_string(),
                CgroupPath::new("delegated").unwrap(),
            )]))
            .load();

        for parent in [child.parent().unwrap(), child.clone().parent().unwrap()] {
            assert_eq!(parent.path().as_path(), Path::new("a"));
            assert!(Arc::ptr_eq(&hierarchy, &parent.hier));
            assert_eq!(
                parent.controllers,
                ControllerSelection::Only(selected.clone())
            );
            assert_eq!(parent.subsystems().len(), 1);
            let memory: &crate::fs::memory::MemController = parent.controller_of().unwrap();
            assert_eq!(
                memory.path(),
                fixture
                    .topology
                    .fixture_root()
                    .unwrap()
                    .join("memory/delegated/a")
            );

            // The empty relative path stays at the configured v1 prefix and
            // retains the child's controller selection.
            let boundary = parent.parent().unwrap().clone();
            assert!(boundary.path().is_root());
            assert!(Arc::ptr_eq(&hierarchy, &boundary.hier));
            assert_eq!(
                boundary.controllers,
                ControllerSelection::Only(selected.clone())
            );
            assert_eq!(boundary.subsystems().len(), 1);
            let memory: &crate::fs::memory::MemController = boundary.controller_of().unwrap();
            assert_eq!(
                memory.path(),
                fixture
                    .topology
                    .fixture_root()
                    .unwrap()
                    .join("memory/delegated")
            );
            assert!(boundary.parent().is_err());
        }
    }

    #[test]
    fn test_v1_prefix_split_controls_parent_boundary_for_the_same_directory() {
        let fixture = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
            b"1:memory:/\n",
            "",
        );
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let handle = |prefix: &str, path: &str| {
            Cgroup::builder(hierarchy.clone(), CgroupPath::new(path).unwrap())
                .v1_prefixes(HashMap::from([(
                    "memory".to_string(),
                    CgroupPath::new(prefix).unwrap(),
                )]))
                .load()
        };
        let directory = |handle: &Cgroup| {
            let memory: &crate::fs::memory::MemController = handle.controller_of().unwrap();
            memory.path().to_path_buf()
        };

        let narrow = handle("kubepods/pod1", "ctr1");
        let broad = handle("kubepods", "pod1/ctr1");
        let mount = fixture.topology.fixture_root().unwrap().join("memory");
        assert_eq!(directory(&narrow), mount.join("kubepods/pod1/ctr1"));
        assert_eq!(directory(&narrow), directory(&broad));

        let narrow_parent = narrow.parent().unwrap();
        let broad_parent = broad.parent().unwrap();
        assert_eq!(directory(&narrow_parent), mount.join("kubepods/pod1"));
        assert_eq!(directory(&narrow_parent), directory(&broad_parent));
        assert!(narrow_parent.path().is_root());
        assert!(narrow_parent.parent().is_err());
        assert_eq!(broad_parent.path().as_path(), Path::new("pod1"));

        let broad_boundary = broad_parent.parent().unwrap();
        assert_eq!(directory(&broad_boundary), mount.join("kubepods"));
        assert!(broad_boundary.path().is_root());
        assert!(broad_boundary.parent().is_err());
    }

    #[test]
    fn test_parent_at_empty_path_preserves_distinct_v1_prefixes() {
        use std::error::Error as _;

        let fixture = crate::tests::TopologyFixture::new(
            b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n\
              44 33 0:39 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n\
              45 33 0:40 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n",
            b"1:memory:/\n2:cpu:/\n3:pids:/\n",
            "",
        );
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let prefixes = HashMap::from([
            (
                "memory".to_string(),
                CgroupPath::new(OsStr::from_bytes(b"delegated/\xff")).unwrap(),
            ),
            ("cpu".to_string(), CgroupPath::new("workloads/cpu").unwrap()),
        ]);
        let root = fixture.topology.fixture_root().unwrap();
        let memory_parent = root
            .join("memory")
            .join(OsStr::from_bytes(b"delegated/\xff"));
        let cpu_parent = root.join("cpu/workloads/cpu");
        let pids_parent = root.join("pids");

        for selection in [
            ControllerSelection::All,
            ControllerSelection::Only(vec!["memory".to_string(), "cpu".to_string()]),
            ControllerSelection::Only(Vec::new()),
        ] {
            let builder = Cgroup::builder(hierarchy.clone(), CgroupPath::new("child").unwrap())
                .v1_prefixes(prefixes.clone())
                .controllers(selection.clone());
            let root_builder = Cgroup::builder(hierarchy.clone(), CgroupPath::root())
                .v1_prefixes(prefixes.clone())
                .controllers(selection);
            let child = builder.load();
            for parent in [
                child.parent().unwrap(),
                child.clone().parent().unwrap(),
                root_builder.load(),
            ] {
                assert!(parent.path().is_root());
                assert!(Arc::ptr_eq(&hierarchy, &parent.hier));
                let expected: Vec<_> = child
                    .subsystems()
                    .iter()
                    .map(Subsystem::controller_name)
                    .collect();
                let actual: Vec<_> = parent
                    .subsystems()
                    .iter()
                    .map(Subsystem::controller_name)
                    .collect();
                assert_eq!(actual, expected);
                for subsystem in parent.subsystems() {
                    let expected_path = match subsystem.controller_name().as_str() {
                        "memory" => &memory_parent,
                        "cpu" => &cpu_parent,
                        "pids" => &pids_parent,
                        name => panic!("unexpected controller: {}", name),
                    };
                    assert_eq!(subsystem.to_controller().path(), expected_path);
                }
            }
        }

        // Ordinary files verify the migration methods' write destinations;
        // they do not exercise kernel process migration.
        for directory in [
            &memory_parent,
            &cpu_parent,
            &pids_parent,
            &root.join("memory"),
            &root.join("cpu"),
        ] {
            fs::create_dir_all(directory).unwrap();
            fs::write(directory.join("tasks"), b"999").unwrap();
            fs::write(directory.join("cgroup.procs"), b"999").unwrap();
        }
        let child = Cgroup::builder(hierarchy, CgroupPath::new("child").unwrap())
            .controllers(ControllerSelection::Only(vec![
                "memory".to_string(),
                "cpu".to_string(),
            ]))
            .v1_prefixes(prefixes)
            .load();
        child.move_task_to_parent(CgroupPid::from(100)).unwrap();
        child
            .clone()
            .move_task_to_parent_by_tgid(CgroupPid::from(101))
            .unwrap();
        for directory in [&memory_parent, &cpu_parent] {
            assert_eq!(fs::read(directory.join("tasks")).unwrap(), b"100");
            assert_eq!(fs::read(directory.join("cgroup.procs")).unwrap(), b"101");
        }
        for directory in [&pids_parent, &root.join("memory"), &root.join("cpu")] {
            assert_eq!(fs::read(directory.join("tasks")).unwrap(), b"999");
            assert_eq!(fs::read(directory.join("cgroup.procs")).unwrap(), b"999");
        }

        // A missing configured parent propagates the filesystem error rather
        // than falling back to the controller's hierarchy root.
        fs::remove_dir_all(&cpu_parent).unwrap();
        let error = child.move_task_to_parent(CgroupPid::from(102)).unwrap_err();
        assert!(matches!(
            error.kind(),
            WriteFailed(path, _) if path == &cpu_parent.join("tasks").display().to_string()
        ));
        let cause = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(cause.kind(), std::io::ErrorKind::NotFound);
        assert!(!cpu_parent.exists());
        assert_eq!(fs::read(root.join("cpu/tasks")).unwrap(), b"999");
    }

    #[test]
    fn test_load_does_not_create_and_new_preserves_creation_errors() {
        use std::error::Error as _;

        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "memory");
        let hierarchy = crate::fs::hierarchies::from_topology(fixture.topology.clone());
        let root = fixture.topology.fixture_root().unwrap();
        let handle = Cgroup::load(hierarchy.clone(), CgroupPath::new("missing").unwrap());
        assert!(!root.join("missing").exists());
        assert!(!handle.exists());

        fs::write(root.join("blocked"), b"not a directory").unwrap();
        let error = Cgroup::new(hierarchy, CgroupPath::new("blocked/child").unwrap()).unwrap_err();
        let cause = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        // Creation visits "blocked" first; its existing regular file causes
        // EEXIST before attempting to create the child directory.
        assert_eq!(cause.raw_os_error(), Some(libc::EEXIST));
    }

    #[test]
    fn test_membership_reads_fail_without_returning_partial_v1_results() {
        use std::error::Error as _;

        let (_fixture, cg) = apply_fixture();
        for subsystem in cg.subsystems() {
            for file in ["cgroup.procs", "tasks"] {
                fs::write(
                    subsystem.to_controller().path().join(file),
                    "200\n100\n100\n",
                )
                .unwrap();
            }
        }
        let last = cg.subsystems().last().unwrap().to_controller();
        for tasks in [false, true] {
            let path = last
                .path()
                .join(if tasks { "tasks" } else { "cgroup.procs" });
            fs::remove_file(&path).unwrap();
            let error = if tasks { cg.tasks() } else { cg.procs() }.unwrap_err();
            assert_eq!(error.kind(), &ReadFailed(path.display().to_string()));
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::NotFound
            );

            fs::write(&path, "100\ninvalid\n").unwrap();
            let error = if tasks { cg.tasks() } else { cg.procs() }.unwrap_err();
            assert_eq!(error.kind(), &ParseError);
            let context = error
                .source()
                .unwrap()
                .downcast_ref::<crate::fs::error::ParsePidFileError>()
                .unwrap();
            assert_eq!(context.path, path);
            assert_eq!(context.cause.line, 2);

            fs::write(&path, "200\n100\n100\n").unwrap();
            let pids = if tasks { cg.tasks() } else { cg.procs() }.unwrap();
            assert_eq!(pids, [CgroupPid::from(100), CgroupPid::from(200)]);
        }
    }

    #[test]
    fn test_tasks_v2_without_other_controllers() {
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "");
        let root = fixture.topology.fixture_root().unwrap();
        fs::write(root.join("cgroup.procs"), b"100\n200\n").unwrap();
        fs::write(root.join("cgroup.threads"), b"200\n101\n100\n101\n").unwrap();
        let cg = Cgroup::load(
            crate::fs::hierarchies::from_topology(fixture.topology.clone()),
            CgroupPath::root(),
        );

        // V2 exposes a synthetic freezer even when cgroup.controllers is empty.
        assert!(matches!(cg.subsystems(), [Subsystem::Freezer(_)]));
        assert_eq!(
            cg.procs().unwrap(),
            vec![CgroupPid::from(100), CgroupPid::from(200)]
        );
        assert_eq!(
            cg.tasks().unwrap(),
            vec![
                CgroupPid::from(100),
                CgroupPid::from(101),
                CgroupPid::from(200)
            ]
        );
    }

    #[test]
    fn test_cgroup_path_accessor() {
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V1, "");
        let topology = fixture.topology.clone();
        let hier = Arc::new(crate::fs::hierarchies::V1::from(topology));
        let cg = Cgroup::load(hier, CgroupPath::new("subgroup/child").unwrap());

        let path: &CgroupPath = cg.path();
        let path_ref: &Path = path.as_path();
        assert_eq!(path_ref, Path::new("subgroup/child"));
        assert_eq!(path_ref.to_str(), Some("subgroup/child"));

        // The typed borrow can also be passed directly to AsRef<Path> APIs.
        assert_eq!(
            Path::new("/mount").join(cg.path()),
            Path::new("/mount/subgroup/child")
        );
    }

    #[test]
    fn test_supported_controllers_at_propagates_error() {
        let non_existent = Path::new("/nonexistent/cgroupfs/root");
        let result = supported_controllers_at(non_existent);
        assert!(
            result.is_err(),
            "Must propagate error on unreadable cgroup.controllers"
        );
    }

    #[test]
    fn test_parent_and_move_task_fails_closed_on_root() {
        use crate::core::error::PathError;
        use std::error::Error as _;

        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "");
        let topology = fixture.topology.clone();
        let hier = crate::fs::hierarchies::from_topology(topology);
        let root = Cgroup::load(hier, CgroupPath::root());

        // Root cgroup has no parent and must fail closed rather than mutating root
        let error = root.parent().unwrap_err();
        let cause = error.source().unwrap().downcast_ref::<PathError>().unwrap();
        assert!(matches!(
            cause,
            PathError::RootPath { input, operation }
                if input.as_os_str().is_empty() && *operation == "Cgroup::parent"
        ));
        assert!(root.move_task_to_parent(CgroupPid::from(100)).is_err());
        assert!(root
            .move_task_to_parent_by_tgid(CgroupPid::from(100))
            .is_err());
    }

    #[test]
    fn test_parent_preserves_non_utf8_path() {
        let non_utf8_bytes = b"\xff\xfe/test_subgroup";
        let path = CgroupPath::new(Path::new(OsStr::from_bytes(non_utf8_bytes))).unwrap();
        let fixture = crate::tests::topology_fixture(crate::core::CgroupVersion::V2, "");
        let topology = fixture.topology.clone();
        let hier = crate::fs::hierarchies::from_topology(topology);
        let child = Cgroup::load(hier, path);

        let parent = child.parent().expect("parent resolution must succeed");
        assert_eq!(parent.path().as_path().as_os_str().as_bytes(), b"\xff\xfe");
    }

    #[test]
    fn test_custom_parent_preserves_hierarchy_controllers_and_path_bytes() {
        #[derive(Debug)]
        struct CustomHierarchy(PathBuf);

        impl Hierarchy for CustomHierarchy {
            fn subsystems(&self) -> Vec<Subsystem> {
                vec![
                    Subsystem::Mem(crate::fs::memory::MemController::new(
                        self.0.clone(),
                        self.0.clone(),
                        true,
                    )),
                    Subsystem::Cpu(crate::fs::cpu::CpuController::new(
                        self.0.clone(),
                        self.0.clone(),
                        true,
                    )),
                ]
            }

            fn root(&self) -> Result<PathBuf> {
                Ok(self.0.clone())
            }

            fn v2(&self) -> bool {
                true
            }
        }

        let hierarchy: Arc<dyn Hierarchy> = Arc::new(CustomHierarchy(PathBuf::from("/test")));
        let selected = vec!["memory".to_string()];
        let cases: &[(&[u8], &[u8])] = &[(b"a/b/c", b"a/b"), (b"\xff/b/c", b"\xff/b"), (b"a", b"")];
        for (path, expected_parent) in cases {
            let child = Cgroup::builder(
                hierarchy.clone(),
                CgroupPath::new(OsStr::from_bytes(path)).unwrap(),
            )
            .controllers(ControllerSelection::Only(selected.clone()))
            .load();
            let parent = child.parent().unwrap();
            assert_eq!(
                parent.path().as_path().as_os_str().as_bytes(),
                *expected_parent
            );
            assert!(Arc::ptr_eq(&hierarchy, &parent.hier));
            assert_eq!(
                parent.controllers,
                ControllerSelection::Only(selected.clone())
            );
            assert_eq!(parent.subsystems().len(), 1);
            let memory: &crate::fs::memory::MemController = parent.controller_of().unwrap();
            assert_eq!(
                memory.path(),
                hierarchy
                    .root()
                    .unwrap()
                    .join(OsStr::from_bytes(expected_parent))
            );
        }
    }
}
