// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module handles cgroup operations. Start here!

use crate::fs::error::ErrorKind::*;
use crate::fs::error::*;

use crate::fs::hierarchies::V1;
use crate::fs::{CgroupPid, ControllIdentifier, Controller, Hierarchy, Resources, Subsystem};
use crate::model::CgroupPath;

use std::collections::HashMap;
use std::convert::From;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::discovery::CgroupTopology;

pub const CGROUP_MODE_DOMAIN: &str = "domain";
pub const CGROUP_MODE_DOMAIN_THREADED: &str = "domain threaded";
pub const CGROUP_MODE_DOMAIN_INVALID: &str = "domain invalid";
pub const CGROUP_MODE_THREADED: &str = "threaded";

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
    path: CgroupPath,
    /// Pre-rendered lossy string representation of `path` to satisfy the
    /// legacy `fn path(&self) -> &str` borrow without per-call allocation.
    /// Slated for deprecation and removal in Phase 2 in favor of [`CgroupPath`].
    path_str: String,

    /// List of controllers specifically enabled in the control group.
    specified_controllers: Option<Vec<String>>,

    /// Topology snapshot from host discovery, if available.
    pub(crate) topology: Option<Arc<CgroupTopology>>,
}

/// Cloning preserves the hierarchy snapshot and the full selection
/// state: the underlying topology is shared through `Arc` instead of
/// re-discovered, and `specified_controllers` is carried over, so a
/// clone behaves identically to the original.
impl Clone for Cgroup {
    fn clone(&self) -> Self {
        Cgroup {
            subsystems: self.subsystems.clone(),
            hier: self.hier.clone(),
            path: self.path.clone(),
            path_str: self.path_str.clone(),
            specified_controllers: self.specified_controllers.clone(),
            topology: self.topology.clone(),
        }
    }
}

impl Default for Cgroup {
    fn default() -> Self {
        let hier: Arc<dyn Hierarchy> = crate::fs::hierarchies::auto().into();
        let topology = hier.topology();
        Cgroup {
            subsystems: Vec::new(),
            hier,
            path: CgroupPath::root().unwrap(),
            path_str: String::new(),
            specified_controllers: None,
            topology,
        }
    }
}

impl Cgroup {
    pub fn v2(&self) -> bool {
        self.hier.v2()
    }

    /// Return the topology snapshot held by this control group, if available.
    pub fn topology(&self) -> Option<Arc<CgroupTopology>> {
        self.topology.clone()
    }

    /// Return the path the cgroup is located at as a string slice.
    pub fn path(&self) -> &str {
        &self.path_str
    }

    /// Return the path the cgroup is located at as a `&Path`.
    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    /// Return the path as a string slice if it is valid UTF-8.
    pub fn path_str(&self) -> Option<&str> {
        self.path.as_path().to_str()
    }

    /// Return the validated [`CgroupPath`] for this control group.
    pub fn cgroup_path(&self) -> &CgroupPath {
        &self.path
    }

    /// Create this control group.
    pub fn create(&self) -> Result<()> {
        if self.hier.v2() {
            let hier_topo;
            let topo_ref = match self.topology.as_deref() {
                Some(t) => Some(t),
                None => {
                    hier_topo = self.hier.topology();
                    if hier_topo.is_none() {
                        log::warn!("cgroup hierarchy has no topology snapshot; falling back to dynamic controllers read");
                    }
                    hier_topo.as_deref()
                }
            };
            create_v2_cgroup(
                self.hier.root(),
                &self.path,
                &self.specified_controllers,
                topo_ref,
            )
        } else {
            self.subsystems
                .iter()
                .try_for_each(|subsystem| subsystem.to_controller().create())?;
            Ok(())
        }
    }

    /// Create a new control group in the hierarchy `hier`, with name `path`.
    ///
    /// Returns a handle to the control group that can be used to manipulate it.
    pub fn new<P: AsRef<Path>>(hier: Box<dyn Hierarchy>, path: P) -> Result<Cgroup> {
        let cpath = parse_cgroup_path(path).map_err(|e| Error::with_cause(InvalidPath, e))?;
        Self::new_validated(hier, cpath)
    }

    /// Create a new control group in the hierarchy `hier`, with name `path`.
    ///
    /// Returns a handle to the control group that can be used to manipulate it.
    pub fn new_with_specified_controllers<P: AsRef<Path>>(
        hier: Box<dyn Hierarchy>,
        path: P,
        specified_controllers: Option<Vec<String>>,
    ) -> Result<Cgroup> {
        let cpath = parse_cgroup_path(path).map_err(|e| Error::with_cause(InvalidPath, e))?;
        let cg = match specified_controllers {
            Some(sc) => Self::load_with_specified_controllers_validated(hier, cpath, sc),
            None => Self::load_validated(hier, cpath),
        };
        cg.create()?;
        Ok(cg)
    }

    /// Create a new control group in the hierarchy `hier`, with name `path` and `relative_paths`
    ///
    /// Returns a handle to the control group that can be used to manipulate it.
    ///
    /// Note that this method is only meaningful for cgroup v1, call it is equivalent to call `new` in the v2 mode.
    pub fn new_with_relative_paths<P: AsRef<Path>>(
        hier: Box<dyn Hierarchy>,
        path: P,
        relative_paths: HashMap<String, String>,
    ) -> Result<Cgroup> {
        let cpath = parse_cgroup_path(path).map_err(|e| Error::with_cause(InvalidPath, e))?;
        let mut validated_rel = HashMap::with_capacity(relative_paths.len());
        for (k, v) in relative_paths {
            let rp = cgroup_path_from_legacy_relative(&v)
                .map_err(|e| Error::with_cause(InvalidPath, e))?;
            validated_rel.insert(k, rp);
        }
        let cg = Self::load_with_relative_paths_validated(hier, cpath, validated_rel);
        cg.create()?;
        Ok(cg)
    }

    /// Create a handle for a control group in the hierarchy `hier`, with name `path`.
    ///
    /// Returns a handle to the control group (that possibly does not exist until `create()` has
    /// been called on the cgroup).
    #[deprecated(since = "0.5.0", note = "use Cgroup::load_validated instead")]
    pub fn load<P: AsRef<Path>>(hier: Box<dyn Hierarchy>, path: P) -> Cgroup {
        let cpath = parse_cgroup_path(path).expect(
            "Cgroup::load called with invalid cgroup path; use Cgroup::load_validated or Cgroup::new",
        );
        Self::load_validated(hier, cpath)
    }

    /// Create a handle for a specified control group in the hierarchy `hier`, with name `path`.
    ///
    /// Returns a handle to the control group (that possibly does not exist until `create()` has
    /// been called on the cgroup).
    #[deprecated(
        since = "0.5.0",
        note = "use Cgroup::load_with_specified_controllers_validated instead"
    )]
    pub fn load_with_specified_controllers<P: AsRef<Path>>(
        hier: Box<dyn Hierarchy>,
        path: P,
        specified_controllers: Vec<String>,
    ) -> Cgroup {
        let cpath = parse_cgroup_path(path).expect(
            "Cgroup::load_with_specified_controllers called with invalid cgroup path; use Cgroup::load_with_specified_controllers_validated",
        );
        Self::load_with_specified_controllers_validated(hier, cpath, specified_controllers)
    }

    /// Create a handle for a control group in the hierarchy `hier`, with name `path` and `relative_paths`
    ///
    /// Returns a handle to the control group (that possibly does not exist until `create()` has
    /// been called on the cgroup).
    ///
    /// Note that this method is only meaningful for cgroup v1, call it is equivalent to call `load` in the v2 mode
    #[deprecated(
        since = "0.5.0",
        note = "use Cgroup::load_with_relative_paths_validated instead"
    )]
    pub fn load_with_relative_paths<P: AsRef<Path>>(
        hier: Box<dyn Hierarchy>,
        path: P,
        relative_paths: HashMap<String, String>,
    ) -> Cgroup {
        let cpath = parse_cgroup_path(path).expect(
            "Cgroup::load_with_relative_paths called with invalid cgroup path; use Cgroup::load_with_relative_paths_validated",
        );
        let mut validated_rel = HashMap::with_capacity(relative_paths.len());
        for (k, v) in relative_paths {
            let rp = cgroup_path_from_legacy_relative(&v)
                .expect("Cgroup::load_with_relative_paths called with invalid relative path");
            validated_rel.insert(k, rp);
        }
        Self::load_with_relative_paths_validated(hier, cpath, validated_rel)
    }

    /// The list of subsystems that this control group supports.
    pub fn subsystems(&self) -> &Vec<Subsystem> {
        &self.subsystems
    }

    /// Internal shared constructor for validated cgroup handles.
    fn load_internal(
        hier: Box<dyn Hierarchy>,
        path: CgroupPath,
        specified_controllers: Option<Vec<String>>,
    ) -> Cgroup {
        let hier: Arc<dyn Hierarchy> = hier.into();
        let topology = hier.topology();
        if topology.is_none() {
            log::warn!(
                "cgroup loaded with hierarchy lacking topology snapshot; operations may fall back to host discovery"
            );
        }
        let rel = path.as_path();
        let path_str = rel.to_string_lossy().into_owned();
        let mut subsystems = hier.subsystems();
        if !rel.as_os_str().is_empty() {
            if let Some(ref sc) = specified_controllers {
                subsystems.retain(|x| sc.contains(&x.controller_name()));
            }
            subsystems = subsystems
                .into_iter()
                .map(|x| x.enter(rel))
                .collect::<Vec<_>>();
        }

        Cgroup {
            path,
            path_str,
            subsystems,
            hier,
            specified_controllers,
            topology,
        }
    }

    /// Create a handle for a control group from a validated
    /// [`CgroupPath`].
    ///
    /// The validated variant of [`Cgroup::load`]: the path is already
    /// checked (relative, no `..`/`.`/empty components), so entering
    /// subsystems cannot be redirected by an absolute or escaping path.
    /// The stored `path_str` is a lossy rendering for the legacy string API.
    pub fn load_validated(hier: Box<dyn Hierarchy>, path: CgroupPath) -> Cgroup {
        Self::load_internal(hier, path, None)
    }

    /// Create and apply a new control group from a validated
    /// [`CgroupPath`].
    ///
    /// The validated variant of [`Cgroup::new`]: the underlying
    /// `create()` may still fail, so this remains fallible.
    pub fn new_validated(hier: Box<dyn Hierarchy>, path: CgroupPath) -> Result<Cgroup> {
        let cg = Self::load_validated(hier, path);
        cg.create()?;
        Ok(cg)
    }

    /// Load with an explicit controller subset and a validated
    /// [`CgroupPath`].
    ///
    /// For compatibility with [`Cgroup::load_with_specified_controllers`],
    /// the subset is applied only to non-root paths. Root handles retain all
    /// subsystems.
    pub fn load_with_specified_controllers_validated(
        hier: Box<dyn Hierarchy>,
        path: CgroupPath,
        specified_controllers: Vec<String>,
    ) -> Cgroup {
        Self::load_internal(hier, path, Some(specified_controllers))
    }

    /// Load with per-controller relative paths, each a validated
    /// [`CgroupPath`].
    ///
    /// Only meaningful for cgroup v1; on v2 this delegates to
    /// [`Cgroup::load_validated`].
    pub fn load_with_relative_paths_validated(
        hier: Box<dyn Hierarchy>,
        path: CgroupPath,
        relative_paths: HashMap<String, CgroupPath>,
    ) -> Cgroup {
        // relative_paths only valid for cgroup v1
        if hier.v2() {
            return Self::load_validated(hier, path);
        }

        let hier: Arc<dyn Hierarchy> = hier.into();
        let topology = hier.topology();
        let rel = path.as_path();
        let path_str = rel.to_string_lossy().into_owned();
        let mut subsystems = hier.subsystems();
        if !rel.as_os_str().is_empty() {
            subsystems = subsystems
                .into_iter()
                .map(|x| {
                    let controller = x.controller_name();
                    match relative_paths.get(&controller) {
                        Some(relative) => {
                            let joined = relative.join(&path);
                            x.enter(joined.as_path())
                        }
                        None => x.enter(rel),
                    }
                })
                .collect::<Vec<_>>();
        }

        Cgroup {
            path,
            path_str,
            subsystems,
            hier,
            specified_controllers: None,
            topology,
        }
    }

    /// Create a control group handle from an already-discovered topology snapshot and a path.
    #[deprecated(
        since = "0.5.0",
        note = "use Cgroup::load_validated_with_topology instead"
    )]
    pub fn load_with_topology<P: AsRef<Path>>(topology: Arc<CgroupTopology>, path: P) -> Cgroup {
        let cpath = parse_cgroup_path(path).expect(
            "Cgroup::load_with_topology called with invalid cgroup path; use Cgroup::load_validated_with_topology",
        );
        Self::load_validated_with_topology(topology, cpath)
    }

    /// Create a control group handle from an already-discovered topology snapshot and a validated [`CgroupPath`].
    pub fn load_validated_with_topology(topology: Arc<CgroupTopology>, path: CgroupPath) -> Cgroup {
        Self::load_validated(crate::fs::hierarchies::auto_with_topology(topology), path)
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
                let p = self.hier.root().join(self.path.as_path());
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
    pub fn apply(&self, res: &Resources) -> Result<()> {
        self.subsystems
            .iter()
            .try_fold((), |_, e| e.to_controller().apply(res))
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
    /// Note that this means that the task will be moved back to the root control group in the
    /// hierarchy and any rules applied to that control group will _still_ apply to the proc.
    pub fn remove_task_by_tgid(&self, tgid: CgroupPid) -> Result<()> {
        self.hier.root_control_group().add_task_by_tgid(tgid)
    }

    /// Removes a task from the control group.
    ///
    /// Note that this means that the task will be moved back to the root control group in the
    /// hierarchy and any rules applied to that control group will _still_ apply to the task.
    pub fn remove_task(&self, tid: CgroupPid) -> Result<()> {
        self.hier.root_control_group().add_task(tid)
    }

    /// Return a handle to the parent control group in the hierarchy.
    ///
    /// Fails closed if this control group is the root control group (which has no parent)
    /// or if resolving the parent fails.
    pub fn parent(&self) -> Result<Cgroup> {
        if self.path.is_root() {
            return Err(Error::with_cause(
                ErrorKind::InvalidPath,
                crate::error::CoreError::InvalidPath {
                    input: self.path.as_path().to_path_buf(),
                    reason: crate::error::PathReason::Root,
                    operation: "Cgroup::parent",
                },
            ));
        }
        self.hier.parent_control_group_path(self.path.as_path())
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

    /// Return a handle to the parent control group in the hierarchy.
    ///
    /// # Panics
    ///
    /// Panics if this is the hierarchy root or if parent resolution fails.
    /// For fail-closed, fallible parent resolution, use [`Cgroup::parent`].
    pub fn parent_control_group(&self) -> Cgroup {
        self.parent()
            .expect("cannot resolve parent cgroup; use Cgroup::parent for fallible resolution")
    }

    /// Kill every process in the control group. Only supported for v2 cgroups and on
    /// kernels 5.14+. This will fail with InvalidOperation if the 'cgroup.kill' file does
    /// not exist.
    pub fn kill(&self) -> Result<()> {
        if !self.v2() {
            return Err(Error::new(CgroupVersion));
        }

        let val = "1";
        let file_name = "cgroup.kill";
        let p = self.hier.root().join(self.path.as_path()).join(file_name);

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

    /// Set release_agent
    pub fn set_release_agent(&self, path: &str) -> Result<()> {
        self.hier
            .root_control_group()
            .subsystems()
            .iter()
            .try_for_each(|sub| sub.to_controller().set_release_agent(path))
    }

    /// Returns an Iterator that can be used to iterate over the procs that are currently in the
    /// control group.
    pub fn procs(&self) -> Vec<CgroupPid> {
        // Collect the procs from all subsystems
        let mut v = if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                c.procs()
            } else {
                vec![]
            }
        } else {
            self.subsystems()
                .iter()
                .map(|x| x.to_controller().procs())
                .fold(vec![], |mut acc, mut x| {
                    acc.append(&mut x);
                    acc
                })
        };

        v.sort();
        v.dedup();
        v
    }

    /// Returns an Iterator that can be used to iterate over the tasks that are currently in the
    /// control group.
    pub fn tasks(&self) -> Vec<CgroupPid> {
        // Collect the tasks from all subsystems
        let mut v = if self.v2() {
            let subsystems = self.subsystems();
            if !subsystems.is_empty() {
                let c = subsystems[0].to_controller();
                c.tasks()
            } else {
                vec![]
            }
        } else {
            self.subsystems()
                .iter()
                .map(|x| x.to_controller().tasks())
                .fold(vec![], |mut acc, mut x| {
                    acc.append(&mut x);
                    acc
                })
        };

        v.sort();
        v.dedup();
        v
    }

    /// Checks if the cgroup exists.
    ///
    /// Returns true if at least one subsystem exists.
    pub fn exists(&self) -> bool {
        self.subsystems().iter().any(|e| e.to_controller().exists())
    }
}

/// Convert a path accepted by the legacy per-controller API into the
/// validated representation.
///
/// `/proc/<pid>/cgroup` paths have one leading slash, while callers have
/// historically also supplied already-relative paths. Accept both forms,
/// preserve `/` as the explicit cgroup root, and retain the strict component
/// checks for traversal and repeated separators.
fn cgroup_path_from_legacy_relative(path: &str) -> crate::error::CoreResult<CgroupPath> {
    if path.is_empty() {
        CgroupPath::root()
    } else if path.starts_with('/') {
        CgroupPath::from_proc_membership(path)
    } else {
        CgroupPath::new(path)
    }
}

/// Convert a general path-like input into a validated [`CgroupPath`].
///
/// Empty input represents the hierarchy root (`CgroupPath::root()`), while
/// non-empty input is validated as a relative cgroup path.
pub(crate) fn parse_cgroup_path<P: AsRef<Path>>(path: P) -> crate::error::CoreResult<CgroupPath> {
    CgroupPath::new(path)
}

pub const UNIFIED_MOUNTPOINT: &str = "/sys/fs/cgroup";

fn enable_controllers(controllers: &[String], path: &Path) {
    let f = path.join("cgroup.subtree_control");
    for c in controllers {
        let body = format!("+{}", c);
        let _rest = fs::write(f.as_path(), body.as_bytes());
    }
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
    specified_controllers: &Option<Vec<String>>,
    topology: Option<&CgroupTopology>,
) -> Result<()> {
    let available_controllers = if let Some(topo) = topology {
        topo.controllers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    } else {
        supported_controllers_at(&root)?
    };

    let controllers = match specified_controllers {
        Some(s_controllers) => {
            if !s_controllers
                .iter()
                .all(|c| available_controllers.contains(c))
            {
                return Err(Error::new(ErrorKind::SpecifiedControllers));
            }
            s_controllers.clone()
        }
        None => available_controllers,
    };

    let mut fp = root;

    // enable for root
    enable_controllers(&controllers, &fp);

    let components: Vec<_> = path.as_path().components().collect();
    let last_index = components.len().saturating_sub(1);
    for (i, comp) in components.iter().enumerate() {
        fp.push(comp.as_os_str());
        if let Err(e) = std::fs::create_dir_all(&fp) {
            return Err(Error::with_cause(ErrorKind::FsError, e));
        }

        if i < last_index {
            // enable controllers for subtree
            enable_controllers(&controllers, &fp);
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

pub fn get_cgroups_relative_paths() -> Result<HashMap<String, String>> {
    get_cgroups_relative_paths_with_host_paths(&crate::discovery::HostPaths::default())
}

pub fn get_cgroups_relative_paths_with_host_paths(
    host_paths: &crate::discovery::HostPaths,
) -> Result<HashMap<String, String>> {
    let path = host_paths.procfs.join("self/cgroup");
    get_cgroups_relative_paths_by_path(&path)
}

pub fn get_cgroups_relative_paths_by_pid(pid: u32) -> Result<HashMap<String, String>> {
    get_cgroups_relative_paths_by_pid_with_host_paths(pid, &crate::discovery::HostPaths::default())
}

pub fn get_cgroups_relative_paths_by_pid_with_host_paths(
    pid: u32,
    host_paths: &crate::discovery::HostPaths,
) -> Result<HashMap<String, String>> {
    let path = host_paths.procfs.join(format!("{}/cgroup", pid));
    get_cgroups_relative_paths_by_path(&path)
}

fn get_cgroup_destination(mut mount_root: String, pidpath: String) -> String {
    if mount_root == "/" {
        mount_root = String::from("");
    }
    pidpath.trim_start_matches(&mount_root).to_string()
}

pub fn existing_path(paths: HashMap<String, String>) -> Result<HashMap<String, String>> {
    existing_path_with_host_paths(paths, &crate::discovery::HostPaths::default())
}

pub fn existing_path_with_host_paths(
    paths: HashMap<String, String>,
    host_paths: &crate::discovery::HostPaths,
) -> Result<HashMap<String, String>> {
    let mount_roots_v1 =
        V1::with_host_paths(host_paths).map_err(|e| Error::with_cause(ErrorKind::FsError, e))?;
    let mut mount_roots_subsystems_map = HashMap::new();

    for s in mount_roots_v1.subsystems().iter() {
        let controller_name = s.controller_name();
        let path_from_cgroup = paths.get(&controller_name).ok_or_else(|| {
            Error::new(Common(format!(
                "controller {} found in mountinfo, but not found in cgroup.",
                controller_name
            )))
        })?;
        let path_from_mountinfo = s.to_controller().base().to_string_lossy().to_string();

        let des_path = get_cgroup_destination(path_from_mountinfo, path_from_cgroup.to_owned());
        mount_roots_subsystems_map.insert(controller_name, des_path);
    }
    Ok(mount_roots_subsystems_map)
}

fn get_cgroups_relative_paths_by_path<P: AsRef<Path>>(path: P) -> Result<HashMap<String, String>> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)
        .map_err(|e| Error::with_cause(ErrorKind::ReadFailed(path.display().to_string()), e))?;
    let membership = crate::discovery::parse_membership(&content)
        .map_err(|e| Error::with_cause(ErrorKind::InvalidPath, e))?;

    let mut m = HashMap::new();
    for record in membership.records() {
        let path_str = record.path.to_string_lossy().into_owned();
        if record.controllers.is_empty() {
            m.insert(String::new(), path_str);
        } else {
            for controller in &record.controllers {
                m.insert(controller.clone(), path_str.clone());
            }
        }
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn test_cgroup_preserves_non_utf8_path() {
        let non_utf8_bytes = b"\xff\xfe/test_subgroup";
        let path = CgroupPath::new(Path::new(OsStr::from_bytes(non_utf8_bytes))).unwrap();
        let hier = crate::fs::hierarchies::auto_with_topology(std::sync::Arc::new(
            crate::discovery::CgroupTopology {
                version: crate::discovery::CgroupVersion::V2,
                v2_available: true,
                mounts: crate::discovery::MountTable::default(),
                membership: crate::discovery::Membership::default(),
                controllers: crate::discovery::ControllerSet::default(),
                cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
                hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
            },
        ));

        let cg = Cgroup::load_validated(hier, path);
        assert_eq!(cg.as_path().as_os_str().as_bytes(), non_utf8_bytes);
        assert!(cg.path_str().is_none());
    }

    #[test]
    fn test_cgroup_threads_topology() {
        let topology = std::sync::Arc::new(crate::discovery::CgroupTopology {
            version: crate::discovery::CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/custom/cgroupfs"),
            hugepages: PathBuf::from("/custom/hugepages"),
        });

        let path = CgroupPath::new("a/b/c").unwrap();
        let cg = Cgroup::load_validated_with_topology(topology.clone(), path);

        // 1. Cgroup directly holds topology
        assert!(cg.topology().is_some());
        assert_eq!(
            cg.topology().unwrap().cgroupfs_root,
            PathBuf::from("/custom/cgroupfs")
        );

        // 2. Clone preserves the exact same Arc<CgroupTopology>
        let cloned = cg.clone();
        assert!(std::sync::Arc::ptr_eq(
            &cg.topology().unwrap(),
            &cloned.topology().unwrap()
        ));

        // 3. Parent control group threads the same topology
        let parent = cg.parent().unwrap();
        assert_eq!(parent.as_path(), Path::new("a/b"));
        assert!(parent.topology().is_some());
        assert!(std::sync::Arc::ptr_eq(
            &cg.topology().unwrap(),
            &parent.topology().unwrap()
        ));

        // 4. Root control group threads the same topology
        let root = parent.parent().unwrap().parent().unwrap();
        assert_eq!(root.as_path(), Path::new(""));
        assert!(root.topology().is_some());
        assert!(std::sync::Arc::ptr_eq(
            &cg.topology().unwrap(),
            &root.topology().unwrap()
        ));
    }

    #[test]
    fn test_cgroup_new_and_mutation_rejects_escaping_path() {
        let topology = std::sync::Arc::new(crate::discovery::CgroupTopology {
            version: crate::discovery::CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/custom/cgroupfs"),
            hugepages: PathBuf::from("/custom/hugepages"),
        });
        let hierarchy = || crate::fs::hierarchies::auto_with_topology(topology.clone());

        // 1. Cgroup::new rejects escaping paths
        assert!(Cgroup::new(hierarchy(), "../escape").is_err());
        assert!(Cgroup::new(hierarchy(), "/absolute").is_err());
        assert!(Cgroup::new(hierarchy(), "a/../b").is_err());

        // 2. Cgroup::load panics on escaping / absolute paths
        let res1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[allow(deprecated)]
            Cgroup::load(hierarchy(), "../escape");
        }));
        assert!(res1.is_err());

        let res2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[allow(deprecated)]
            Cgroup::load(hierarchy(), "/absolute");
        }));
        assert!(res2.is_err());
    }

    #[test]
    fn test_cgroup_clone_preserves_hierarchy_type() {
        // Create a topology with version == V2
        let topology = std::sync::Arc::new(crate::discovery::CgroupTopology {
            version: crate::discovery::CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/custom/cgroupfs"),
            hugepages: PathBuf::from("/custom/hugepages"),
        });

        // Explicitly create V1 with this topology
        let v1 = crate::fs::hierarchies::V1::with_topology(topology.clone());
        let cg_v1 = Cgroup::load_validated(
            Box::new(v1),
            crate::model::CgroupPath::new("test_v1").unwrap(),
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
    fn test_cgroup_clone_preserves_custom_hierarchy_object() {
        #[derive(Debug)]
        struct CustomHierarchy(PathBuf);

        impl Hierarchy for CustomHierarchy {
            fn subsystems(&self) -> Vec<Subsystem> {
                Vec::new()
            }

            fn root(&self) -> PathBuf {
                self.0.clone()
            }

            fn root_control_group(&self) -> Cgroup {
                panic!("not used by this test")
            }

            fn parent_control_group(&self, _path: &str) -> Cgroup {
                panic!("not used by this test")
            }

            fn v2(&self) -> bool {
                false
            }
        }

        let cg = Cgroup::load_validated(
            Box::new(CustomHierarchy(PathBuf::from("/custom/hierarchy"))),
            CgroupPath::new("child").unwrap(),
        );
        let cloned = cg.clone();

        assert!(Arc::ptr_eq(&cg.hier, &cloned.hier));
        assert_eq!(cloned.hier.root(), Path::new("/custom/hierarchy"));
    }

    #[test]
    fn test_legacy_relative_path_conversion() {
        assert_eq!(
            cgroup_path_from_legacy_relative("/parent/child")
                .unwrap()
                .as_path(),
            Path::new("parent/child")
        );
        assert_eq!(
            cgroup_path_from_legacy_relative("parent/child")
                .unwrap()
                .as_path(),
            Path::new("parent/child")
        );
        assert!(cgroup_path_from_legacy_relative("/").unwrap().is_root());
        assert!(cgroup_path_from_legacy_relative("").unwrap().is_root());
        assert!(cgroup_path_from_legacy_relative("/../escape").is_err());
        assert!(cgroup_path_from_legacy_relative("//escape").is_err());
    }

    #[test]
    fn test_specified_controllers_preserve_legacy_root_semantics() {
        let topology = Arc::new(crate::discovery::CgroupTopology {
            version: crate::discovery::CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: ["cpu".to_string(), "memory".to_string()]
                .iter()
                .cloned()
                .collect(),
            cgroupfs_root: PathBuf::from("/custom/cgroupfs"),
            hugepages: PathBuf::from("/custom/hugepages"),
        });
        let selected = vec!["memory".to_string()];

        let root = Cgroup::load_with_specified_controllers_validated(
            crate::fs::hierarchies::auto_with_topology(topology.clone()),
            CgroupPath::root().unwrap(),
            selected.clone(),
        );
        let root_names: Vec<_> = root
            .subsystems()
            .iter()
            .map(Subsystem::controller_name)
            .collect();
        assert!(root_names.contains(&"cpu".to_string()));
        assert!(root_names.contains(&"memory".to_string()));
        assert!(root_names.contains(&"freezer".to_string()));

        let child = Cgroup::load_with_specified_controllers_validated(
            crate::fs::hierarchies::auto_with_topology(topology),
            CgroupPath::new("child").unwrap(),
            selected,
        );
        let child_names: Vec<_> = child
            .subsystems()
            .iter()
            .map(Subsystem::controller_name)
            .collect();
        assert_eq!(child_names, vec!["memory".to_string()]);
    }

    #[test]
    fn test_cgroup_legacy_and_typed_path_api() {
        let topology = std::sync::Arc::new(crate::discovery::CgroupTopology {
            version: crate::discovery::CgroupVersion::V1,
            v2_available: false,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        });
        let hier = Box::new(crate::fs::hierarchies::V1::with_topology(topology));
        #[allow(deprecated)]
        let cg = Cgroup::load(hier, "subgroup/child");

        // Legacy path() returns &str
        let path_str: &str = cg.path();
        assert_eq!(path_str, "subgroup/child");

        // Typed as_path() returns &Path
        let path_ref: &Path = cg.as_path();
        assert_eq!(path_ref, Path::new("subgroup/child"));

        // Validated cgroup_path() returns &CgroupPath
        assert_eq!(cg.cgroup_path().as_path(), Path::new("subgroup/child"));
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
        let topology = Arc::new(crate::discovery::CgroupTopology {
            version: crate::discovery::CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        });
        let hier = crate::fs::hierarchies::auto_with_topology(topology);
        let root = Cgroup::load_validated(hier, CgroupPath::root().unwrap());

        // Root cgroup has no parent and must fail closed rather than mutating root
        assert!(root.parent().is_err());
        assert!(root.move_task_to_parent(CgroupPid::from(100)).is_err());
        assert!(root
            .move_task_to_parent_by_tgid(CgroupPid::from(100))
            .is_err());

        let legacy_parent =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.parent_control_group()));
        assert!(legacy_parent.is_err());
    }

    #[test]
    fn test_parent_preserves_non_utf8_path() {
        let non_utf8_bytes = b"\xff\xfe/test_subgroup";
        let path = CgroupPath::new(Path::new(OsStr::from_bytes(non_utf8_bytes))).unwrap();
        let topology = Arc::new(crate::discovery::CgroupTopology {
            version: crate::discovery::CgroupVersion::V2,
            v2_available: true,
            mounts: crate::discovery::MountTable::default(),
            membership: crate::discovery::Membership::default(),
            controllers: crate::discovery::ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        });
        let hier = crate::fs::hierarchies::auto_with_topology(topology);
        let child = Cgroup::load_validated(hier, path);

        let parent = child.parent().expect("parent resolution must succeed");
        assert_eq!(parent.as_path().as_os_str().as_bytes(), b"\xff\xfe");
    }

    #[test]
    fn test_existing_path_propagates_discovery_error() {
        let host_paths = crate::discovery::HostPaths {
            procfs: PathBuf::from("/nonexistent/proc"),
            cgroupfs_override: None,
            hugepages: PathBuf::from("/nonexistent/hugepages"),
        };
        let mut paths = HashMap::new();
        paths.insert("memory".to_string(), "/test".to_string());

        let result = existing_path_with_host_paths(paths, &host_paths);
        assert!(
            result.is_err(),
            "existing_path must return Err and not panic on discovery failure"
        );
    }

    #[test]
    fn test_get_cgroups_relative_paths_uses_membership_parser() {
        let temp_dir =
            std::env::temp_dir().join(format!("cgroups-rs-rel-path-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let valid_file = temp_dir.join("cgroup_valid");
        fs::write(
            &valid_file,
            "1:memory:/user.slice\n2:cpu,cpuacct:/test.slice:colon_path:scope\n0::/../sibling.slice\n",
        )
        .unwrap();
        let map = get_cgroups_relative_paths_by_path(&valid_file).unwrap();
        assert_eq!(map.get("memory").unwrap(), "/user.slice");
        assert_eq!(map.get("cpu").unwrap(), "/test.slice:colon_path:scope");
        assert_eq!(map.get("cpuacct").unwrap(), "/test.slice:colon_path:scope");
        assert_eq!(map.get("").unwrap(), "/../sibling.slice");

        let malformed_file = temp_dir.join("cgroup_malformed");
        fs::write(&malformed_file, "bad_line_without_colons\n").unwrap();
        let err = get_cgroups_relative_paths_by_path(&malformed_file);
        assert!(
            err.is_err(),
            "Must propagate parse error for malformed membership content"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_custom_hierarchy_legacy_parent_control_group_does_not_skip_generation() {
        #[derive(Debug)]
        struct LegacyCustomHierarchy(PathBuf);

        impl Hierarchy for LegacyCustomHierarchy {
            fn subsystems(&self) -> Vec<Subsystem> {
                vec![]
            }

            fn root(&self) -> PathBuf {
                self.0.clone()
            }

            fn root_control_group(&self) -> Cgroup {
                Cgroup::load_validated(
                    Box::new(LegacyCustomHierarchy(self.0.clone())),
                    CgroupPath::root().unwrap(),
                )
            }

            // Custom hierarchy only implements the legacy &str method
            fn parent_control_group(&self, path: &str) -> Cgroup {
                let parent = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
                let cpath = if parent.as_os_str().is_empty() {
                    CgroupPath::root().unwrap()
                } else {
                    CgroupPath::new(parent).unwrap()
                };
                Cgroup::load_validated(Box::new(LegacyCustomHierarchy(self.0.clone())), cpath)
            }

            fn v2(&self) -> bool {
                false
            }
        }

        let hier = Box::new(LegacyCustomHierarchy(PathBuf::from("/test")));
        let child = Cgroup::load_validated(hier, CgroupPath::new("a/b/c").unwrap());
        let parent = child.parent().expect("parent resolution must succeed");
        assert_eq!(
            parent.as_path(),
            Path::new("a/b"),
            "parent must be direct parent a/b, not grandparent a"
        );
    }
}
