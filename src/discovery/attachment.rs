// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Pure resolution of process and thread attachment destinations.
//!
//! This module resolves an [`AttachDestination`] and cgroup membership records
//! into a concrete [`AttachmentPlan`] describing where processes or threads
//! should be placed and whether leaf directories may be created.
//!
//! All calculations are pure: no pseudo-filesystems are read and no cgroups are
//! created or modified here.

#![cfg_attr(not(feature = "oci"), allow(dead_code))]

use std::collections::BTreeMap;
use std::path::{Component, Path};

use crate::discovery::membership::Membership;
use crate::discovery::topology::{CgroupTopology, CgroupVersion};
use crate::error::AttachmentError;
use crate::model::attachment::AttachDestination;
use crate::model::path::CgroupPath;
use crate::model::pid::ProcessId;

/// The target placement for process or thread attachment within cgroup hierarchies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placement {
    /// In cgroup v2, all controllers reside on a unified single hierarchy.
    /// The path is relative to the cgroupfs mountpoint.
    Unified(CgroupPath),
    /// In cgroup v1, controllers may reside on separate hierarchies
    /// with independent relative paths below their respective mountpoints.
    Legacy(BTreeMap<String, CgroupPath>),
}

/// Directory creation policy for the resolved attachment target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreationPolicy {
    /// The target is an explicit subgroup or managed cgroup and may be
    /// created as a leaf directory if it does not already exist.
    MayCreateLeaf,
    /// The target was resolved dynamically from a reference process
    /// (`SameCgroupAs`) and must already exist. If it has vanished,
    /// it must not be recreated.
    MustExist,
}

/// A fully resolved plan for attaching a process or thread to a cgroup hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachmentPlan {
    /// Target placement paths.
    pub placement: Placement,
    /// Leaf directory creation policy.
    pub creation: CreationPolicy,
}

impl AttachmentPlan {
    /// Return the unified target cgroup path if this is a unified plan.
    #[allow(dead_code)]
    pub(crate) fn unified_target(&self) -> Option<&CgroupPath> {
        match &self.placement {
            Placement::Unified(path) => Some(path),
            Placement::Legacy(_) => None,
        }
    }

    /// Return the subpath relative to `base` on a unified hierarchy.
    ///
    /// Returns an empty relative path ([`CgroupPath::root`]) if the target
    /// is `base` itself.
    #[allow(dead_code)]
    pub(crate) fn unified_subpath_below(
        &self,
        base: &CgroupPath,
    ) -> Result<CgroupPath, crate::error::CoreError> {
        match &self.placement {
            Placement::Unified(target) => {
                if target == base {
                    return CgroupPath::root();
                }
                let sub = target.as_path().strip_prefix(base.as_path()).map_err(|_| {
                    crate::error::CoreError::InvalidPath {
                        input: target.as_path().to_path_buf(),
                        reason: crate::error::PathReason::ContainmentViolation,
                        operation: "unified_subpath_below",
                    }
                })?;
                if sub.as_os_str().is_empty() {
                    CgroupPath::root()
                } else {
                    CgroupPath::new(sub)
                }
            }
            Placement::Legacy(_) => Err(crate::error::CoreError::InvalidPath {
                input: std::path::PathBuf::from("<legacy>"),
                reason: crate::error::PathReason::Root,
                operation: "unified subpath query on legacy placement",
            }),
        }
    }
}

/// Resolve an attachment destination into an execution plan without performing
/// any filesystem I/O or mutating any cgroup hierarchy.
///
/// # Arguments
/// - `topology`: immutable snapshot of the discovered host cgroup topology.
/// - `base`: the managed cgroup base path within the hierarchy.
/// - `subsystems`: list of controller names managed (used for v1 legacy resolution).
/// - `destination`: caller-specified [`AttachDestination`].
/// - `membership`: parsed membership records from `/proc/<pid>/cgroup` (required
///   when `destination` is [`AttachDestination::SameCgroupAs`]).
pub(crate) fn plan_attachment(
    topology: &CgroupTopology,
    base: &CgroupPath,
    subsystems: &[String],
    destination: &AttachDestination,
    membership: Option<&Membership>,
) -> Result<AttachmentPlan, AttachmentError> {
    // The public enum can be constructed directly, bypassing `subgroup()`.
    if matches!(destination, AttachDestination::Subgroup(path) if path.is_root()) {
        return Err(AttachmentError::InvalidDestination {
            source: crate::error::CoreError::InvalidPath {
                input: std::path::PathBuf::new(),
                reason: crate::error::PathReason::Root,
                operation: "plan_attachment",
            },
        });
    }
    if topology.version == CgroupVersion::V2 && topology.mounts.unified_mount().is_none() {
        return Err(AttachmentError::MissingHierarchyMount {
            hierarchy: "unified (0::)".to_string(),
            root: topology.cgroupfs_root.clone(),
        });
    }
    if topology.version == CgroupVersion::V1 {
        if subsystems.is_empty() {
            return Err(AttachmentError::Unsupported {
                backend: "cgroupfs",
                operation: "v1 attachment requires at least one visible managed hierarchy",
            });
        }
        // Validate every selected mount before constructing a plan, including
        // ManagedCgroup and Subgroup. Execution must never guess a mountpoint.
        for sub in subsystems {
            if topology.mounts.controller_mount(sub).is_none() {
                return Err(AttachmentError::MissingHierarchyMount {
                    hierarchy: sub.clone(),
                    root: topology.cgroupfs_root.clone(),
                });
            }
        }
    }
    match destination {
        AttachDestination::ManagedCgroup => {
            let placement = match topology.version {
                CgroupVersion::V2 => Placement::Unified(base.clone()),
                CgroupVersion::V1 => {
                    let mut map = BTreeMap::new();
                    for sub in subsystems {
                        map.insert(sub.clone(), base.clone());
                    }
                    Placement::Legacy(map)
                }
            };
            Ok(AttachmentPlan {
                placement,
                creation: CreationPolicy::MayCreateLeaf,
            })
        }
        AttachDestination::Subgroup(sub) => {
            let placement = match topology.version {
                CgroupVersion::V2 => Placement::Unified(base.join(sub)),
                CgroupVersion::V1 => {
                    let mut map = BTreeMap::new();
                    for sub_name in subsystems {
                        map.insert(sub_name.clone(), base.join(sub));
                    }
                    Placement::Legacy(map)
                }
            };
            Ok(AttachmentPlan {
                placement,
                creation: CreationPolicy::MayCreateLeaf,
            })
        }
        AttachDestination::SameCgroupAs(pid) => {
            let membership = membership.ok_or_else(|| AttachmentError::AmbiguousMembership {
                pid: *pid,
                detail: "membership records are required to resolve SameCgroupAs destination"
                    .to_string(),
            })?;

            match topology.version {
                CgroupVersion::V2 => {
                    let record = membership.unified().ok_or_else(|| {
                        AttachmentError::MissingHierarchyMembership {
                            pid: *pid,
                            hierarchy: "unified (0::)".to_string(),
                        }
                    })?;

                    let mount = topology.mounts.unified_mount().ok_or_else(|| {
                        AttachmentError::MissingHierarchyMount {
                            hierarchy: "unified (0::)".to_string(),
                            root: topology.cgroupfs_root.clone(),
                        }
                    })?;

                    let target =
                        resolve_single_hierarchy_path(*pid, base, &record.path, &mount.mount_root)?;

                    Ok(AttachmentPlan {
                        placement: Placement::Unified(target),
                        creation: CreationPolicy::MustExist,
                    })
                }
                CgroupVersion::V1 => {
                    let mut map = BTreeMap::new();
                    for sub in subsystems {
                        // Find membership record that binds this controller.
                        // Co-mounted controllers (e.g. cpu,cpuacct) share the same record.
                        let record = membership
                            .records()
                            .iter()
                            .find(|r| r.controllers.iter().any(|c| c == sub))
                            .ok_or_else(|| AttachmentError::MissingHierarchyMembership {
                                pid: *pid,
                                hierarchy: sub.clone(),
                            })?;

                        // Find mount that exposes this controller.
                        let mount = topology.mounts.controller_mount(sub).ok_or_else(|| {
                            AttachmentError::MissingHierarchyMount {
                                hierarchy: sub.clone(),
                                root: topology.cgroupfs_root.clone(),
                            }
                        })?;

                        let target = resolve_single_hierarchy_path(
                            *pid,
                            base,
                            &record.path,
                            &mount.mount_root,
                        )?;
                        map.insert(sub.clone(), target);
                    }

                    Ok(AttachmentPlan {
                        placement: Placement::Legacy(map),
                        creation: CreationPolicy::MustExist,
                    })
                }
            }
        }
    }
}

/// Resolve and validate a single hierarchy's observed path into a mutation-safe
/// [`CgroupPath`] below `base`.
fn resolve_single_hierarchy_path(
    pid: ProcessId,
    base: &CgroupPath,
    observed_path: &Path,
    mount_root: &Path,
) -> Result<CgroupPath, AttachmentError> {
    // 1. Observed path containing a parent component ('..') indicates the process
    // is outside the reader's cgroup namespace. Reject as outside immediately
    // without attempting normalization.
    if observed_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(AttachmentError::OutsideManagedCgroup {
            pid,
            observed: observed_path.to_path_buf(),
            managed: base.clone(),
        });
    }

    // 2. Map observed path through mount_root (mount namespace root translation).
    let rel_to_mount = match observed_path.strip_prefix(mount_root) {
        Ok(rel) => rel,
        Err(_) => {
            return Err(AttachmentError::OutsideManagedCgroup {
                pid,
                observed: observed_path.to_path_buf(),
                managed: base.clone(),
            });
        }
    };

    // 3. Containment check relative to base.
    // If base is root, any rel_to_mount path is within the hierarchy.
    // If base is non-root, rel_to_mount must have base components as a strict prefix.
    // Path::strip_prefix enforces component-aware matching, preventing prefix collisions
    // (e.g. "tenant/a" vs "tenant/ab/worker").
    if !base.is_root() && rel_to_mount.strip_prefix(base.as_path()).is_err() {
        return Err(AttachmentError::OutsideManagedCgroup {
            pid,
            observed: observed_path.to_path_buf(),
            managed: base.clone(),
        });
    }

    // 4. Convert validated mountpoint-relative path to a CgroupPath.
    if rel_to_mount.as_os_str().is_empty() {
        CgroupPath::root().map_err(|e| AttachmentError::ParseMembership { pid, source: e })
    } else {
        CgroupPath::new(rel_to_mount)
            .map_err(|e| AttachmentError::ParseMembership { pid, source: e })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::membership::parse_membership;
    use crate::discovery::mountinfo::parse_mountinfo;
    use crate::discovery::topology::ControllerSet;
    use std::path::PathBuf;

    fn make_v2_topology(mountinfo_text: &str) -> CgroupTopology {
        let mounts = parse_mountinfo(mountinfo_text).expect("valid mountinfo");
        CgroupTopology {
            version: CgroupVersion::V2,
            v2_available: true,
            mounts,
            membership: Membership::default(),
            controllers: ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        }
    }

    fn make_v1_topology(mountinfo_text: &str) -> CgroupTopology {
        let mounts = parse_mountinfo(mountinfo_text).expect("valid mountinfo");
        CgroupTopology {
            version: CgroupVersion::V1,
            v2_available: false,
            mounts,
            membership: Membership::default(),
            controllers: ControllerSet::default(),
            cgroupfs_root: PathBuf::from("/sys/fs/cgroup"),
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        }
    }

    const V2_MOUNTINFO: &str = "\
32 23 0:27 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n";

    #[test]
    fn test_v1_missing_mount_rejects_every_destination() {
        let topology =
            make_v1_topology("32 23 0:27 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n");
        let base = CgroupPath::new("app").unwrap();
        let membership = parse_membership("1:cpu:/app/leaf\n2:memory:/app/leaf\n").unwrap();
        for destination in [
            AttachDestination::ManagedCgroup,
            AttachDestination::subgroup("leaf").unwrap(),
            AttachDestination::same_cgroup_as(ProcessId::new(42).unwrap()),
        ] {
            assert!(
                matches!(plan_attachment(&topology, &base, &["cpu".to_string(), "memory".to_string()],
                &destination, Some(&membership)),
                Err(AttachmentError::MissingHierarchyMount { hierarchy, .. }) if hierarchy == "cpu")
            );
        }
    }

    #[test]
    fn test_v2_managed_cgroup_plan() {
        let topo = make_v2_topology(V2_MOUNTINFO);
        let base = CgroupPath::new("workload/app").unwrap();
        let plan =
            plan_attachment(&topo, &base, &[], &AttachDestination::ManagedCgroup, None).unwrap();

        assert_eq!(plan.creation, CreationPolicy::MayCreateLeaf);
        assert_eq!(plan.placement, Placement::Unified(base.clone()));
        assert_eq!(
            plan.unified_subpath_below(&base).unwrap(),
            CgroupPath::root().unwrap()
        );
    }

    #[test]
    fn test_v2_subgroup_plan() {
        let topo = make_v2_topology(V2_MOUNTINFO);
        let base = CgroupPath::new("workload/app").unwrap();
        let dest = AttachDestination::subgroup("leaf").unwrap();
        let plan = plan_attachment(&topo, &base, &[], &dest, None).unwrap();

        let expected_target = CgroupPath::new("workload/app/leaf").unwrap();
        assert_eq!(plan.creation, CreationPolicy::MayCreateLeaf);
        assert_eq!(plan.placement, Placement::Unified(expected_target));
        assert_eq!(
            plan.unified_subpath_below(&base).unwrap(),
            CgroupPath::new("leaf").unwrap()
        );
    }

    #[test]
    fn test_v2_same_cgroup_as_exact_base() {
        let topo = make_v2_topology(V2_MOUNTINFO);
        let base = CgroupPath::new("workload/app").unwrap();
        let pid = ProcessId::new(4242).unwrap();
        let membership = parse_membership("0::/workload/app\n").unwrap();

        let plan = plan_attachment(
            &topo,
            &base,
            &[],
            &AttachDestination::SameCgroupAs(pid),
            Some(&membership),
        )
        .unwrap();

        assert_eq!(plan.creation, CreationPolicy::MustExist);
        assert_eq!(plan.placement, Placement::Unified(base.clone()));
        assert_eq!(
            plan.unified_subpath_below(&base).unwrap(),
            CgroupPath::root().unwrap()
        );
    }

    #[test]
    fn test_v2_same_cgroup_as_descendant() {
        let topo = make_v2_topology(V2_MOUNTINFO);
        let base = CgroupPath::new("workload/app").unwrap();
        let pid = ProcessId::new(4242).unwrap();
        let membership = parse_membership("0::/workload/app/worker\n").unwrap();

        let plan = plan_attachment(
            &topo,
            &base,
            &[],
            &AttachDestination::SameCgroupAs(pid),
            Some(&membership),
        )
        .unwrap();

        let expected_target = CgroupPath::new("workload/app/worker").unwrap();
        assert_eq!(plan.creation, CreationPolicy::MustExist);
        assert_eq!(plan.placement, Placement::Unified(expected_target));
        assert_eq!(
            plan.unified_subpath_below(&base).unwrap(),
            CgroupPath::new("worker").unwrap()
        );
    }

    #[test]
    fn test_v2_same_cgroup_as_prefix_collision_rejected() {
        let topo = make_v2_topology(V2_MOUNTINFO);
        // Base is workload/a, observed is workload/ab/worker: not a child component!
        let base = CgroupPath::new("workload/a").unwrap();
        let pid = ProcessId::new(4242).unwrap();
        let membership = parse_membership("0::/workload/ab/worker\n").unwrap();

        let result = plan_attachment(
            &topo,
            &base,
            &[],
            &AttachDestination::SameCgroupAs(pid),
            Some(&membership),
        );

        assert!(matches!(
            result,
            Err(AttachmentError::OutsideManagedCgroup { .. })
        ));
    }

    #[test]
    fn test_v2_same_cgroup_as_escaping_parent_dir_rejected() {
        let topo = make_v2_topology(V2_MOUNTINFO);
        let base = CgroupPath::new("workload/app").unwrap();
        let pid = ProcessId::new(4242).unwrap();
        let membership = parse_membership("0::/../sibling\n").unwrap();

        let result = plan_attachment(
            &topo,
            &base,
            &[],
            &AttachDestination::SameCgroupAs(pid),
            Some(&membership),
        );

        assert!(matches!(
            result,
            Err(AttachmentError::OutsideManagedCgroup { .. })
        ));
    }

    #[test]
    fn test_v2_namespaced_mount_root_offset() {
        // Mountpoint /sys/fs/cgroup was mounted from filesystem subpath /tenant
        let namespaced_mountinfo = "\
32 23 0:27 /tenant /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw\n";
        let topo = make_v2_topology(namespaced_mountinfo);
        let base = CgroupPath::new("worker").unwrap();
        let pid = ProcessId::new(4242).unwrap();
        // Observed membership path inside namespace starts at /tenant/worker/task
        let membership = parse_membership("0::/tenant/worker/task\n").unwrap();

        let plan = plan_attachment(
            &topo,
            &base,
            &[],
            &AttachDestination::SameCgroupAs(pid),
            Some(&membership),
        )
        .unwrap();

        let expected_target = CgroupPath::new("worker/task").unwrap();
        assert_eq!(plan.placement, Placement::Unified(expected_target));
        assert_eq!(
            plan.unified_subpath_below(&base).unwrap(),
            CgroupPath::new("task").unwrap()
        );
    }

    const V1_MOUNTINFO: &str = "\
35 23 0:30 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:12 - cgroup cgroup rw,cpu,cpuacct\n\
36 23 0:31 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:13 - cgroup cgroup rw,memory\n";

    #[test]
    fn test_v1_co_mounted_and_split_controllers() {
        let topo = make_v1_topology(V1_MOUNTINFO);
        let base = CgroupPath::new("tenant/app").unwrap();
        let pid = ProcessId::new(1001).unwrap();
        // cpu,cpuacct is co-mounted on one hierarchy, memory is separate
        let membership = parse_membership(
            "2:cpu,cpuacct:/tenant/app/cpu_leaf\n\
             3:memory:/tenant/app/mem_leaf\n",
        )
        .unwrap();

        let subsystems = vec![
            "cpu".to_string(),
            "cpuacct".to_string(),
            "memory".to_string(),
        ];
        let plan = plan_attachment(
            &topo,
            &base,
            &subsystems,
            &AttachDestination::SameCgroupAs(pid),
            Some(&membership),
        )
        .unwrap();

        assert_eq!(plan.creation, CreationPolicy::MustExist);
        match plan.placement {
            Placement::Legacy(map) => {
                assert_eq!(
                    map.get("cpu").unwrap(),
                    &CgroupPath::new("tenant/app/cpu_leaf").unwrap()
                );
                assert_eq!(
                    map.get("cpuacct").unwrap(),
                    &CgroupPath::new("tenant/app/cpu_leaf").unwrap()
                );
                assert_eq!(
                    map.get("memory").unwrap(),
                    &CgroupPath::new("tenant/app/mem_leaf").unwrap()
                );
            }
            Placement::Unified(_) => panic!("expected legacy placement"),
        }
    }

    #[test]
    fn test_v1_missing_controller_fails_whole_plan() {
        let topo = make_v1_topology(V1_MOUNTINFO);
        let base = CgroupPath::new("tenant/app").unwrap();
        let pid = ProcessId::new(1001).unwrap();
        // Membership only contains memory, missing cpu
        let membership = parse_membership("3:memory:/tenant/app/mem_leaf\n").unwrap();

        let subsystems = vec!["cpu".to_string(), "memory".to_string()];
        let result = plan_attachment(
            &topo,
            &base,
            &subsystems,
            &AttachDestination::SameCgroupAs(pid),
            Some(&membership),
        );

        assert!(matches!(
            result,
            Err(AttachmentError::MissingHierarchyMembership { hierarchy, .. }) if hierarchy == "cpu"
        ));
    }
}
