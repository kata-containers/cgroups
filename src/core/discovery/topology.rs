// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Host topology: the immutable snapshot assembled from the pure
//! discovery parsers.
//!
//! [`discover`] is the only place in this module that performs I/O: it
//! reads `<procfs>/self/mountinfo` and `<procfs>/self/cgroup`, parses
//! them with the pure parsers, and hands the results to
//! `assemble_topology`, which resolves the version verdict and the
//! cgroupfs root. Managers and cgroup handles share the resulting
//! snapshot through `Arc` instead of re-discovering per operation.
//!
//! Testing does not require privileges or a live cgroup layout: point a
//! [`HostPaths`] at a temporary directory containing fixture `mountinfo`
//! and `cgroup` files and run [`discover`] end to end.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::iter::FromIterator;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use super::membership::{parse_membership_bytes, CgroupMembership};
use super::mountinfo::{parse_mountinfo_bytes, CgroupMountTable, MountRecord};
use crate::core::error::{CoreError, CoreResult, LayoutError};

/// Host paths used to build a topology snapshot.
///
/// `procfs` supplies the discovery records, and `hugepages` records the
/// sysfs metadata root for huge-page size discovery. With the `fixtures`
/// feature, `cgroupfs_fixture_root` supplies an ordinary-filesystem tree
/// for unprivileged tests while retaining the mountinfo-derived roots.
///
/// Construct with [`HostPaths::new`] or [`HostPaths::default`], then update
/// individual fields as needed. Struct literals, including functional update
/// syntax, are unavailable outside this crate so construction remains stable
/// when Cargo unifies features from other dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostPaths {
    /// procfs root (e.g. `/proc`).
    pub procfs: PathBuf,
    /// Root of a fixture cgroup tree on an ordinary filesystem.
    ///
    /// Requires the `fixtures` feature. When set, discovery still derives
    /// the natural root from `mountinfo` so
    /// [`CgroupTopology::resolve_mount_point`] knows which prefix to strip,
    /// but reports this directory as [`CgroupTopology::cgroupfs_root`] and
    /// skips the cgroup2 statfs check. Mount points under the natural root
    /// are re-rooted here, allowing tests to use filesystem-backed cgroup
    /// operations without privileges.
    ///
    /// Nothing is auto-populated and no kernel cgroup semantics apply:
    /// tests must seed any file they expect to read. This field does not
    /// configure a bind-mounted cgroup filesystem or enforce resource limits.
    /// Downstream tests can enable `fixtures` on their `cgroups-rs`
    /// dev-dependency and use Cargo resolver 2 to keep those test features
    /// out of normal builds. The feature is off by default; explicitly
    /// enabling it also exposes this field in release builds.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::fs;
    /// use std::path::Path;
    /// use cgroups_rs::core::{discover, HostPaths};
    ///
    /// // Synthetic procfs records describe a v1 memory mount.
    /// let fixture = Path::new("/tmp/fixture");
    /// fs::create_dir_all(fixture.join("proc/self")).unwrap();
    /// fs::write(
    ///     fixture.join("proc/self/mountinfo"),
    ///     "30 26 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
    /// ).unwrap();
    /// fs::write(fixture.join("proc/self/cgroup"), "1:memory:/\n").unwrap();
    ///
    /// // The fixture tree starts as an empty directory owned by the test.
    /// let tree = fixture.join("cgroup");
    /// fs::create_dir_all(&tree).unwrap();
    /// let host_paths = HostPaths::new(
    ///     fixture.join("proc"),
    ///     fixture.join("hugepages"),
    /// ).with_fixture_root(tree.clone());
    /// let topology = discover(&host_paths).unwrap();
    ///
    /// assert_eq!(topology.cgroupfs_root(), tree);
    /// assert_eq!(
    ///     topology.resolve_mount_point(Path::new("/sys/fs/cgroup/memory")),
    ///     tree.join("memory"),
    /// );
    /// ```
    #[cfg(feature = "fixtures")]
    pub cgroupfs_fixture_root: Option<PathBuf>,
    /// Sysfs root for discovering supported huge-page sizes.
    pub hugepages: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self::new(
            PathBuf::from("/proc"),
            PathBuf::from("/sys/kernel/mm/hugepages"),
        )
    }
}

impl HostPaths {
    /// Configure the procfs and huge-page metadata roots without performing I/O.
    ///
    /// This constructor is available with every feature combination. Fixture
    /// redirection is initially disabled, even when `fixtures` is enabled.
    ///
    /// ```
    /// use cgroups_rs::core::HostPaths;
    ///
    /// let host_paths = HostPaths::new(
    ///     "/tmp/fixture/proc".into(),
    ///     "/tmp/fixture/hugepages".into(),
    /// );
    /// ```
    pub fn new(procfs: PathBuf, hugepages: PathBuf) -> Self {
        Self {
            procfs,
            #[cfg(feature = "fixtures")]
            cgroupfs_fixture_root: None,
            hugepages,
        }
    }

    /// Redirect cgroupfs operations to an ordinary-filesystem fixture tree.
    ///
    /// Requires the `fixtures` feature. See [`Self::cgroupfs_fixture_root`] for
    /// the discovery and statfs semantics; this method only records the path.
    #[cfg(feature = "fixtures")]
    pub fn with_fixture_root(mut self, root: PathBuf) -> Self {
        self.cgroupfs_fixture_root = Some(root);
        self
    }

    /// The configured fixture tree root, or constant `None` without `fixtures`.
    ///
    /// With the feature disabled, discovery uses the natural root and
    /// verifies every selected cgroup2 candidate with statfs.
    #[inline]
    pub(crate) fn fixture_root(&self) -> Option<&Path> {
        #[cfg(feature = "fixtures")]
        {
            self.cgroupfs_fixture_root.as_deref()
        }
        #[cfg(not(feature = "fixtures"))]
        {
            None
        }
    }
}

/// The cgroup version a host operates in.
///
/// Hosts with resource controllers on visible v1 mounts report
/// [`CgroupVersion::V1`]; an additionally available v2 hierarchy is recorded
/// as [`CgroupTopology::v2_available`] rather than a third variant.
/// Controller-less named v1 hierarchies do not displace a visible v2
/// hierarchy; without a visible cgroup2 mount, v1 mounts still select `V1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CgroupVersion {
    /// cgroup v1, possibly with a v2 hierarchy also mounted (hybrid).
    V1,
    /// Unified cgroup v2.
    V2,
}

/// The set of controller names visible on the primary hierarchy.
///
/// Minimal stringly carrier for Phase 1; a typed controller vocabulary
/// belongs to the Phase 3 manager API, not to topology.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControllerSet(BTreeSet<String>);

impl ControllerSet {
    /// Whether `name` is in the set.
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains(name)
    }

    /// Iterate over the controller names in sorted order.
    ///
    /// ```
    /// use cgroups_rs::core::{ControllerIter, ControllerSet};
    ///
    /// let controllers: ControllerSet = ["memory", "cpu", "memory"]
    ///     .iter()
    ///     .map(|name| name.to_string())
    ///     .collect();
    /// let iter: ControllerIter<'_> = controllers.iter();
    /// let names: Vec<&str> = iter.collect();
    /// assert_eq!(names, ["cpu", "memory"]);
    ///
    /// let mut names_from_loop: Vec<&str> = Vec::new();
    /// for name in &controllers {
    ///     names_from_loop.push(name);
    /// }
    /// assert_eq!(names_from_loop, names);
    /// assert!(controllers.contains("memory"));
    /// ```
    pub fn iter(&self) -> ControllerIter<'_> {
        self.into_iter()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of controllers in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Borrowed controller names in sorted order.
///
/// Created by [`ControllerSet::iter`] or by iterating over a borrowed
/// [`ControllerSet`].
#[derive(Debug, Clone)]
pub struct ControllerIter<'a> {
    inner: std::collections::btree_set::Iter<'a, String>,
}

impl<'a> Iterator for ControllerIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(String::as_str)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> IntoIterator for &'a ControllerSet {
    type Item = &'a str;
    type IntoIter = ControllerIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ControllerIter {
            inner: self.0.iter(),
        }
    }
}

impl FromIterator<String> for ControllerSet {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        ControllerSet(iter.into_iter().collect())
    }
}

/// An immutable snapshot of the host's cgroup layout.
///
/// Constructed once by [`discover`] and shared through `Arc`; cloning a
/// cgroup handle must clone the `Arc`, never re-run discovery.
///
/// # Immutability Contract
/// All fields are immutable once created by discovery and reflect a consistent
/// host snapshot. They must not be modified after construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupTopology {
    /// The primary cgroup version driving representation choices.
    version: CgroupVersion,
    /// Whether a cgroup v2 hierarchy is also available. Hybrid hosts
    /// (controller-bearing v1 mounts plus a qualifying cgroup2 mount)
    /// report `V1` here with this flag set.
    v2_available: bool,
    /// All parsed mounts, not only cgroup mounts.
    mounts: CgroupMountTable,
    /// The process's membership records.
    membership: CgroupMembership,
    /// Controller names visible on the primary hierarchy.
    controllers: ControllerSet,
    /// The directory used for cgroup filesystem operations: the fixture
    /// root when set with the `fixtures` feature, otherwise the natural
    /// root derived from the parsed mounts.
    cgroupfs_root: PathBuf,
    /// The natural root shared by visible v1 mounts when v1 is primary.
    ///
    /// Equals `cgroupfs_root` unless a fixture root is configured. Retained
    /// separately so fixture mapping can strip the natural mount prefix.
    /// Named v1 mounts on a v2 host remain in `mounts` without setting this
    /// prefix or changing the unified root.
    v1_mount_root: Option<PathBuf>,
    /// The selected cgroup2 mount point from `mountinfo`, if available.
    ///
    /// Selection considers only roots containing the unified membership
    /// path, preferring the fewest leading `..` components, then the fewest
    /// total path components in `mount_root`.
    unified_mount_point: Option<PathBuf>,
    /// Huge-page size discovery root copied from HostPaths.
    hugepages: PathBuf,
}

impl CgroupTopology {
    /// The primary cgroup version driving representation choices.
    pub fn version(&self) -> CgroupVersion {
        self.version
    }

    /// Whether a qualifying v2 hierarchy is also available.
    pub fn v2_available(&self) -> bool {
        self.v2_available
    }

    /// All parsed mount records on the host.
    pub fn mounts(&self) -> &CgroupMountTable {
        &self.mounts
    }

    /// The process's cgroup membership records.
    pub fn membership(&self) -> &CgroupMembership {
        &self.membership
    }

    /// Controllers visible on the primary hierarchy.
    pub fn controllers(&self) -> &ControllerSet {
        &self.controllers
    }

    /// The natural root derived from mountinfo, or the fixture tree root
    /// when configured with the `fixtures` feature.
    pub fn cgroupfs_root(&self) -> &Path {
        &self.cgroupfs_root
    }

    /// Sysfs root for discovering supported huge-page sizes.
    pub fn hugepages(&self) -> &Path {
        &self.hugepages
    }

    /// Map a mount point under the selected natural root to `cgroupfs_root`.
    ///
    /// A configured fixture root changes the destination while the natural
    /// root remains the prefix to strip. Paths outside that prefix are
    /// returned unchanged.
    ///
    /// V1-primary layouts, including hybrid hosts, use only the v1 root
    /// prefix. V2-primary layouts use the selected unified mount prefix.
    /// On hybrid hosts, the unified prefix is not tried after a v1 mismatch.
    ///
    /// Without the `fixtures` feature, or with no fixture root configured,
    /// every mount point maps to itself.
    pub fn resolve_mount_point(&self, original: &Path) -> PathBuf {
        if let Some(natural_root) = &self.v1_mount_root {
            if original == natural_root {
                return self.cgroupfs_root.clone();
            }
            if let Ok(rel) = original.strip_prefix(natural_root) {
                return self.cgroupfs_root.join(rel);
            }
        } else if let Some(selected) = &self.unified_mount_point {
            if original == selected.as_path() {
                return self.cgroupfs_root.clone();
            }
            if let Ok(rel) = original.strip_prefix(selected) {
                return self.cgroupfs_root.join(rel);
            }
        }
        original.to_path_buf()
    }
}

/// Discover the host topology once.
///
/// Reads `<procfs>/self/mountinfo` and `<procfs>/self/cgroup`, parses
/// them with the pure discovery parsers, and assembles the snapshot.
/// I/O failures return a typed [`CoreError`] identifying the operation,
/// path, and underlying cause; malformed content returns a line-numbered
/// parser error. Layout failures (see `assemble_topology`) return
/// [`CoreError::Layout`] rather than silently defaulting to v1, and a
/// candidate root on the wrong filesystem returns [`CoreError::NotCgroup2`].
pub fn discover(host_paths: &HostPaths) -> CoreResult<Arc<CgroupTopology>> {
    let mountinfo_path = host_paths.procfs.join("self/mountinfo");
    let membership_path = host_paths.procfs.join("self/cgroup");

    let mountinfo_bytes = fs::read(&mountinfo_path).map_err(|cause| CoreError::ReadProcFile {
        path: mountinfo_path.clone(),
        cause,
    })?;
    let membership_bytes = fs::read(&membership_path).map_err(|cause| CoreError::ReadProcFile {
        path: membership_path.clone(),
        cause,
    })?;

    let mounts =
        parse_mountinfo_bytes(&mountinfo_bytes).map_err(|cause| CoreError::ParseMountInFile {
            path: mountinfo_path.clone(),
            cause,
        })?;
    let membership = parse_membership_bytes(&membership_bytes).map_err(|cause| {
        CoreError::ParseMembershipInFile {
            path: membership_path.clone(),
            cause,
        }
    })?;
    let topology = assemble_topology(
        mounts,
        membership,
        host_paths,
        &mountinfo_path,
        &membership_path,
    )?;

    Ok(Arc::new(topology))
}

/// Determine the natural root of a non-empty set of cgroup v1 mounts.
///
/// Infer a root for each mount: a mount point whose final component consists
/// of controller names on that hierarchy (including a `name=foo` hierarchy)
/// uses its parent; other mounts use their own mount point. All inferred
/// roots must agree so one root can describe the layout and map its mounts
/// into one fixture tree.
///
/// Only parsed mounts are inspected; the caller attaches the procfs source
/// path to any layout error.
///
/// The caller must supply at least one mount; `assemble_topology` checks
/// this before selecting v1 as the primary hierarchy.
fn determine_v1_natural_root(v1_mounts: &[&MountRecord]) -> Result<PathBuf, LayoutError> {
    let roots = v1_mounts
        .iter()
        .map(|mount| v1_mount_natural_root(mount).to_path_buf())
        .collect::<BTreeSet<_>>();

    if roots.len() > 1 {
        Err(LayoutError::AmbiguousV1Roots { roots })
    } else {
        Ok(roots
            .into_iter()
            .next()
            .expect("v1 root inference requires at least one mount"))
    }
}

/// Infer the filesystem root represented by one parsed v1 mount.
///
/// A controller-named mount directory uses its parent; other mount points
/// represent their own root. This uses filesystem coordinates, independently
/// of the mount's cgroup-relative `mount_root`, and performs no I/O.
pub(crate) fn v1_mount_natural_root(mount: &MountRecord) -> &Path {
    let mount_name = mount
        .mount_point
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let is_subsystem_dir = !mount_name.is_empty()
        && mount_name.split(',').all(|name| {
            mount.super_opts.iter().any(|opt| {
                opt.as_slice() == name.as_bytes()
                    || opt.strip_prefix(b"name=") == Some(name.as_bytes())
            })
        });
    if is_subsystem_dir {
        mount.mount_point.parent().unwrap_or(&mount.mount_point)
    } else {
        &mount.mount_point
    }
}

/// Whether a cgroup mount contains a namespace-relative membership path.
///
/// Kernfs represents both paths relative to the reader's cgroup namespace:
/// leading `..` components reach ancestors of that namespace root, then
/// ordinary components name descendants. A pure ancestor such as `/..`
/// contains `/work`, while `/../sibling` does not. Compare components without
/// resolving these virtual paths against the host filesystem.
fn cgroup_mount_contains(mount_root: &Path, membership_path: &Path) -> bool {
    let mut root = mount_root.components().peekable();
    let mut membership = membership_path.components().peekable();
    if root.next() != Some(Component::RootDir) || membership.next() != Some(Component::RootDir) {
        return false;
    }

    let mut root_parents = 0usize;
    while root.peek() == Some(&Component::ParentDir) {
        root.next();
        root_parents += 1;
    }
    let mut membership_parents = 0usize;
    while membership.peek() == Some(&Component::ParentDir) {
        membership.next();
        membership_parents += 1;
    }

    // Kernfs emits parent components only at the start. Do not interpret
    // other traversals as canonical cgroup paths.
    if root
        .clone()
        .any(|component| component == Component::ParentDir)
        || membership
            .clone()
            .any(|component| component == Component::ParentDir)
    {
        return false;
    }

    if root_parents == membership_parents {
        root.all(|component| membership.next() == Some(component))
    } else {
        root_parents > membership_parents && root.next().is_none()
    }
}

/// Assemble the topology snapshot from the parsed inputs.
///
/// # Contract
///
/// - Version: a cgroup2 mount is a candidate only when its `mount_root`
///   contains the unified membership path in the cgroup namespace's hierarchy.
///   Prefer the matching root with the fewest leading `..` components, then
///   the fewest total path components; candidates tied on both counts retain
///   mountinfo order. Mapping through an ancestor root requires knowing the
///   namespace root's name, so prefer a subtree with fewer leading `..` even
///   when it is deeper. Visible cgroup2 mounts without a matching root leave
///   optional v2 unavailable on a v1-primary host and cause a layout error on
///   a v2-primary host. Namespace-relative ancestor roots such as `/..` can
///   contain the process even without a textual prefix; sibling subtrees cannot.
///   Without a fixture root, a statfs recheck on the chosen root guards
///   against stale or forged mountinfo. A fixture root (available with the
///   `fixtures` feature) uses an ordinary filesystem tree and skips the recheck.
///   With `fixtures` disabled, selected cgroup2 candidates always undergo statfs
///   verification in both hybrid and v2-primary layouts.
///   A failed recheck of an optional cgroup2 mount on a v1 host leaves v2
///   unavailable; a v2-primary host returns the error even when named v1
///   hierarchies are also visible.
/// - Hybrid: with a visible cgroup2 mount (typically at
///   `/sys/fs/cgroup/unified`), selecting primary `V1` requires at least one
///   resource controller to appear in both the membership records and the
///   visible v1 mount options. `v2_available = true` only when the cgroup2
///   mount qualifies; `name=...` entries identify hierarchies, not resource
///   controllers.
///   Named-only v1 mounts alongside cgroup2 select `V2` and remain in `mounts`
///   without contributing to its root or controller set. Without a visible
///   cgroup2 mount, named-only v1 mounts still select `V1`.
/// - `cgroupfs_root`: the configured fixture root when set, else the unified
///   mount point (v2) or the common inferred root of the v1 cgroup mounts.
///   When v1 is primary, each v1 mount uses its parent when it looks like a
///   controller directory, otherwise its own mount point. Different inferred
///   roots cause a discovery error because one root cannot represent the
///   layout or map its mounts into a fixture tree.
/// - Cross-check visible unified mounts against `membership.unified()`
///   (the `0::` record): a visible cgroup2 mount without that record leaves
///   optional v2 unavailable on a v1-primary host and is an error on a
///   v2-primary host. The reverse does not hold: `0::` may be present when
///   cgroup2 is mounted elsewhere on the host but hidden from this mount
///   namespace. Empty membership is always an error, checked before version
///   selection. Unified layout checks precede filesystem verification; their
///   failure is logged when v1 remains usable.
/// - `controllers`: v1 — the process's membership controller names that
///   also appear as byte-exact options on visible v1 mounts, including
///   `name=...` hierarchies; v2 — the names published by
///   `<cgroupfs_root>/cgroup.controllers`; a
///   missing file on a genuine v2 host is an error, not an empty set.
/// - Every failure carries context; nothing defaults silently to v1.
fn assemble_topology(
    mounts: CgroupMountTable,
    membership: CgroupMembership,
    host_paths: &HostPaths,
    mountinfo_path: &Path,
    membership_path: &Path,
) -> CoreResult<CgroupTopology> {
    if membership.records().is_empty() {
        return Err(CoreError::Layout {
            path: membership_path.to_path_buf(),
            cause: LayoutError::NoMembershipRecords,
        });
    }

    let v1_mounts = mounts.cgroup_mounts();
    let unified_mounts = mounts.unified_mounts();
    let fixture_root = host_paths.fixture_root();

    // Select without rejecting the layout yet: optional v2 failures must
    // not hide usable v1. A `0::` record alone does not imply a visible
    // mount here because cgrp_dfl_visible is global across mount namespaces.
    let unified_candidate = membership.unified().and_then(|unified_membership| {
        unified_mounts
            .iter()
            .filter(|mount| cgroup_mount_contains(&mount.mount_root, &unified_membership.path))
            .min_by_key(|mount| {
                let parents = mount
                    .mount_root
                    .components()
                    .skip(1)
                    .take_while(|component| *component == Component::ParentDir)
                    .count();
                (parents, mount.mount_root.components().count())
            })
    });
    let unified_layout_error = || match membership.unified() {
        Some(unified_membership) => CoreError::Layout {
            path: mountinfo_path.to_path_buf(),
            cause: LayoutError::NoMatchingUnifiedMount {
                membership: unified_membership.path.clone(),
                roots: unified_mounts
                    .iter()
                    .map(|mount| mount.mount_root.clone())
                    .collect(),
            },
        },
        None => CoreError::Layout {
            path: membership_path.to_path_buf(),
            cause: LayoutError::MissingUnifiedMembership,
        },
    };

    // Superblock options also contain flags such as `rw` and `xattr`.
    // Membership supplies controller names; visible mounts confirm their
    // availability without a hard-coded controller vocabulary.
    let v1_controllers = membership
        .records()
        .iter()
        .flat_map(|record| record.controllers.iter())
        .filter(|controller| {
            v1_mounts.iter().any(|mount| {
                mount
                    .super_opts
                    .iter()
                    .any(|option| option.as_slice() == controller.as_bytes())
            })
        })
        .cloned()
        .collect::<ControllerSet>();
    let v1_primary = !v1_mounts.is_empty()
        && (v1_controllers
            .iter()
            .any(|controller| !controller.starts_with("name="))
            || unified_mounts.is_empty());

    let v1_mount_root = if v1_primary {
        Some(
            determine_v1_natural_root(&v1_mounts).map_err(|cause| CoreError::Layout {
                path: mountinfo_path.to_path_buf(),
                cause,
            })?,
        )
    } else {
        None
    };

    let (version, v2_available, cgroupfs_root, unified_mount_point) =
        if let Some(natural_root) = &v1_mount_root {
            let cgroupfs_root = match fixture_root {
                Some(root) => root.to_path_buf(),
                None => natural_root.clone(),
            };

            // The matching cgroup2 mount may expose a delegated subtree with
            // a non-root mount_root in this cgroup namespace.
            // Failure to verify this optional mount must not hide usable v1.
            let (v2_available, unified_mp) = match unified_candidate {
                Some(candidate) => match fixture_root {
                    Some(_) => (true, Some(candidate.mount_point.clone())),
                    None => match verify_cgroup2_mount(&candidate.mount_point) {
                        Ok(()) => (true, Some(candidate.mount_point.clone())),
                        Err(error) => {
                            log::warn!("optional cgroup2 mount is unavailable: {}", error);
                            (false, None)
                        }
                    },
                },
                None => {
                    if !unified_mounts.is_empty() {
                        log::warn!(
                            "optional cgroup2 mount is unavailable: {}",
                            unified_layout_error(),
                        );
                    }
                    (false, None)
                }
            };

            (CgroupVersion::V1, v2_available, cgroupfs_root, unified_mp)
        } else if !unified_mounts.is_empty() {
            let candidate = unified_candidate.ok_or_else(unified_layout_error)?;
            let cgroupfs_root = match fixture_root {
                Some(root) => root.to_path_buf(),
                None => {
                    verify_cgroup2_mount(&candidate.mount_point)?;
                    candidate.mount_point.clone()
                }
            };
            (
                CgroupVersion::V2,
                true,
                cgroupfs_root,
                Some(candidate.mount_point.clone()),
            )
        } else {
            return Err(CoreError::Layout {
                path: mountinfo_path.to_path_buf(),
                cause: LayoutError::NoCgroupMounts,
            });
        };

    let controllers = match version {
        CgroupVersion::V1 => v1_controllers,
        CgroupVersion::V2 => read_controller_names(&cgroupfs_root)?,
    };

    Ok(CgroupTopology {
        version,
        v2_available,
        mounts,
        membership,
        controllers,
        cgroupfs_root,
        v1_mount_root,
        unified_mount_point,
        hugepages: host_paths.hugepages.clone(),
    })
}

/// statfs recheck: confirm that a cgroup2 mount point really is a
/// cgroup2 filesystem, guarding against stale or forged mountinfo.
fn verify_cgroup2_mount(path: &Path) -> CoreResult<()> {
    use nix::sys::statfs;

    match statfs::statfs(path) {
        Ok(stat) if stat.filesystem_type() == statfs::CGROUP2_SUPER_MAGIC => Ok(()),
        Ok(_) => Err(CoreError::NotCgroup2 {
            path: path.to_path_buf(),
        }),
        Err(errno) => Err(CoreError::StatfsCgroupRoot {
            path: path.to_path_buf(),
            cause: io::Error::from_raw_os_error(errno as i32),
        }),
    }
}

/// Read the controller names published by a unified cgroupfs root.
fn read_controller_names(cgroupfs_root: &Path) -> CoreResult<ControllerSet> {
    let path = cgroupfs_root.join("cgroup.controllers");
    let contents = fs::read_to_string(&path).map_err(|cause| CoreError::ReadControllers {
        path: path.clone(),
        cause,
    })?;
    Ok(contents.split_whitespace().map(str::to_string).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;
    use std::os::unix::ffi::OsStrExt;

    const V1_MOUNTINFO: &str = "\
43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory
48 33 0:43 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:25 - cgroup cgroup rw,cpu,cpuacct
35 33 0:30 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd
36 35 98:0 / /mnt rw,relatime - ext3 /dev/root rw";

    const V1_MEMBERSHIP: &str = "\
7:memory:/user.slice
12:cpu,cpuacct:/user.slice
1:name=systemd:/user.slice";

    const V2_MOUNTINFO: &str =
        "47 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw";

    const V2_MEMBERSHIP: &str = "0::/user.slice/session-1.scope";

    const NAMED_V1_MOUNT: &str = "50 44 0:50 / /run/openrc rw - cgroup cgroup rw,name=openrc";

    const NAMED_V1_MEMBERSHIP: &str = "1:name=openrc:/\n0::/user.slice";

    const HYBRID_EXTRA_MOUNT: &str =
        "34 33 0:29 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate";

    const HYBRID_MEMBERSHIP: &str = "\
7:memory:/user.slice
12:cpu,cpuacct:/user.slice
1:name=systemd:/user.slice
0::/user.slice";

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    /// Create a scratch procfs root containing `self/mountinfo` and
    /// `self/cgroup` with the given fixture contents.
    fn fixture_host(tag: &str, mountinfo: &str, cgroup: &str) -> (TempDir, HostPaths) {
        let root = std::env::temp_dir().join(format!(
            "cgroups-rs-topology-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let self_dir = root.join("self");
        fs::create_dir_all(&self_dir).unwrap();
        fs::write(self_dir.join("mountinfo"), mountinfo).unwrap();
        fs::write(self_dir.join("cgroup"), cgroup).unwrap();

        let host_paths = HostPaths::new(root.clone(), PathBuf::from("/nonexistent"));
        (TempDir(root), host_paths)
    }

    #[test]
    fn test_discover_v1() {
        let (_root, host_paths) = fixture_host("v1", V1_MOUNTINFO, V1_MEMBERSHIP);

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert!(!topology.v2_available);
        assert_eq!(topology.cgroupfs_root, PathBuf::from("/sys/fs/cgroup"));
        assert!(topology.controllers.contains("memory"));
        assert!(topology.controllers.contains("cpu"));
        assert!(topology.controllers.contains("cpuacct"));
        assert!(topology.controllers.contains("name=systemd"));
        assert_eq!(topology.mounts.cgroup_mounts().len(), 3);
    }

    #[test]
    fn test_discover_v1_excludes_membership_without_visible_mount() {
        const MEMORY_ONLY_MOUNT: &str =
            "43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory";
        const MEMBERSHIP: &str = "7:memory:/work\n12:cpu,cpuacct:/work";
        let (_root, host_paths) =
            fixture_host("v1-visible-memory-only", MEMORY_ONLY_MOUNT, MEMBERSHIP);

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version(), CgroupVersion::V1);
        assert_eq!(topology.mounts().cgroup_mounts().len(), 1);
        assert_eq!(topology.membership().records().len(), 2);
        assert!(topology.controllers().contains("memory"));
        assert!(!topology.controllers().contains("cpu"));
        assert!(!topology.controllers().contains("cpuacct"));
        assert_eq!(topology.controllers().len(), 1);
    }

    #[test]
    fn test_discover_preserves_non_utf8_membership_path() {
        let (root, host_paths) = fixture_host("non-utf8", V1_MOUNTINFO, V1_MEMBERSHIP);
        fs::write(
            root.join("self/cgroup"),
            b"7:memory:/non-utf8-\xff\n12:cpu,cpuacct:/user.slice\n1:name=systemd:/user.slice",
        )
        .unwrap();

        let topology = discover(&host_paths).unwrap();
        assert_eq!(
            topology.membership.records()[0].path.as_os_str().as_bytes(),
            b"/non-utf8-\xff"
        );
    }

    #[test]
    fn test_discover_v2_with_fixture_root() {
        // The fixture root is an ordinary directory, so discovery skips
        // statfs there and uses the test's seeded controller file.
        let (root, host_paths) = fixture_host("v2", V2_MOUNTINFO, V2_MEMBERSHIP);
        let cgroupfs = root.join("cgroupfs");
        fs::create_dir_all(&cgroupfs).unwrap();
        fs::write(
            cgroupfs.join("cgroup.controllers"),
            "cpuset cpu io memory pids\n",
        )
        .unwrap();

        let host_paths = host_paths.with_fixture_root(cgroupfs.clone());
        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V2);
        assert!(topology.v2_available);
        assert_eq!(topology.cgroupfs_root, cgroupfs);
        assert_eq!(topology.controllers.len(), 5);
        assert!(topology.controllers.contains("memory"));
        assert!(topology.controllers.contains("io"));
    }

    #[test]
    fn test_discover_v2_with_named_v1_hierarchies() {
        const OTHER_NAMED_MOUNT: &str =
            "51 44 0:51 / /opt/legacy/systemd rw - cgroup cgroup rw,xattr,release_agent=/bin/cleanup,name=systemd";

        for (tag, named_mounts, membership, named_count) in [
            ("single", NAMED_V1_MOUNT.to_string(), NAMED_V1_MEMBERSHIP, 1),
            (
                "disjoint",
                format!("{}\n{}", NAMED_V1_MOUNT, OTHER_NAMED_MOUNT),
                "1:name=openrc:/\n2:name=systemd:/\n0::/user.slice",
                2,
            ),
            (
                "hidden-controller",
                NAMED_V1_MOUNT.to_string(),
                "1:name=openrc:/\n7:memory:/work\n0::/user.slice",
                1,
            ),
        ] {
            let mountinfo = format!("{}\n{}", V2_MOUNTINFO, named_mounts);
            for (order, mountinfo) in [
                mountinfo.clone(),
                mountinfo.lines().rev().collect::<Vec<_>>().join("\n"),
            ]
            .iter()
            .enumerate()
            {
                let (root, host_paths) = fixture_host(
                    &format!("v2-named-{}-{}", tag, order),
                    mountinfo,
                    membership,
                );
                let cgroupfs = root.join("cgroupfs");
                fs::create_dir_all(&cgroupfs).unwrap();
                fs::write(cgroupfs.join("cgroup.controllers"), "cpu io memory pids\n").unwrap();
                let host_paths = host_paths.with_fixture_root(cgroupfs.clone());

                let topology = discover(&host_paths).unwrap();
                assert_eq!(topology.version(), CgroupVersion::V2);
                assert!(topology.v2_available());
                assert_eq!(topology.cgroupfs_root(), cgroupfs);
                assert_eq!(topology.mounts().cgroup_mounts().len(), named_count);
                assert!(topology.membership().records().iter().any(|record| record
                    .controllers
                    .iter()
                    .any(|controller| controller == "name=openrc")));
                assert!(topology.v1_mount_root.is_none());
                assert_eq!(
                    topology.controllers(),
                    &["cpu", "io", "memory", "pids"]
                        .iter()
                        .map(|name| name.to_string())
                        .collect::<ControllerSet>(),
                );
                assert_eq!(
                    topology.resolve_mount_point(Path::new("/sys/fs/cgroup")),
                    cgroupfs,
                );
                assert_eq!(
                    topology.resolve_mount_point(Path::new("/sys/fs/cgroup/work")),
                    cgroupfs.join("work"),
                );
                for mount in topology.mounts().cgroup_mounts() {
                    assert_eq!(
                        topology.resolve_mount_point(&mount.mount_point),
                        mount.mount_point,
                    );
                }
            }
        }
    }

    #[test]
    fn test_discover_named_v1_keeps_v2_errors_fatal() {
        let (root, host_paths) = fixture_host(
            "v2-named-errors",
            &format!("{}\n{}", V2_MOUNTINFO, NAMED_V1_MOUNT),
            "1:name=openrc:/",
        );
        let cgroupfs = root.join("cgroupfs");
        fs::create_dir_all(&cgroupfs).unwrap();

        for with_fixture_root in [false, true] {
            let host_paths = if with_fixture_root {
                host_paths.clone().with_fixture_root(cgroupfs.clone())
            } else {
                host_paths.clone()
            };
            let error = discover(&host_paths).unwrap_err();
            assert_eq!(
                error.source().unwrap().downcast_ref::<LayoutError>(),
                Some(&LayoutError::MissingUnifiedMembership),
            );
            match error {
                CoreError::Layout {
                    path,
                    cause: LayoutError::MissingUnifiedMembership,
                } => assert_eq!(path, root.join("self/cgroup")),
                other => panic!("expected missing unified membership, got `{:?}`", other),
            }
        }

        let host_paths = host_paths.with_fixture_root(cgroupfs.clone());
        fs::write(root.join("self/cgroup"), NAMED_V1_MEMBERSHIP).unwrap();
        let error = discover(&host_paths).unwrap_err();
        let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
        assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
        match error {
            CoreError::ReadControllers { path, cause } => {
                assert_eq!(path, cgroupfs.join("cgroup.controllers"));
                assert_eq!(cause.raw_os_error(), Some(libc::ENOENT));
            }
            other => panic!("expected a ReadControllers error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_discover_v1_with_fixture_root() {
        let (root, host_paths) = fixture_host("v1-fixture-root", V1_MOUNTINFO, V1_MEMBERSHIP);
        let custom_cgroupfs = root.join("custom_cgroupfs");
        let custom_hugepages = root.join("custom_hugepages");
        fs::create_dir_all(&custom_cgroupfs).unwrap();
        fs::create_dir_all(&custom_hugepages).unwrap();

        let host_paths = HostPaths::new(host_paths.procfs, custom_hugepages.clone())
            .with_fixture_root(custom_cgroupfs.clone());

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert_eq!(topology.cgroupfs_root, custom_cgroupfs);
        assert_eq!(topology.hugepages, custom_hugepages);
        assert_eq!(
            topology.v1_mount_root.as_deref(),
            Some(Path::new("/sys/fs/cgroup")),
        );
        assert_eq!(fs::read_dir(&custom_cgroupfs).unwrap().count(), 0);

        // Verify resolve_mount_point re-roots the V1 mountpoint
        let orig_mem_mount = Path::new("/sys/fs/cgroup/memory");
        let resolved = topology.resolve_mount_point(orig_mem_mount);
        assert_eq!(resolved, custom_cgroupfs.join("memory"));
    }

    #[test]
    fn test_discover_hybrid() {
        let (root, host_paths) = fixture_host(
            "hybrid",
            &format!("{}\n{}", V1_MOUNTINFO, HYBRID_EXTRA_MOUNT),
            HYBRID_MEMBERSHIP,
        );
        let host_paths = host_paths.with_fixture_root(root.join("cgroupfs"));

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert!(topology.v2_available);
        assert_eq!(topology.cgroupfs_root, root.join("cgroupfs"));
        // Primary-hierarchy controllers only.
        assert!(!topology.controllers.contains("io"));
    }

    #[test]
    fn test_discover_hybrid_with_controller_bearing_named_v1() {
        // A named hierarchy may also carry resource controllers, including
        // names unknown to this crate; those still make v1 primary.
        for controller in ["memory", "future_controller"] {
            let mountinfo = format!(
                "50 44 0:50 / /sys/fs/cgroup/legacy rw - cgroup cgroup rw,{},name=legacy\n{}",
                controller, V2_MOUNTINFO,
            );
            let membership = format!("1:{},name=legacy:/work\n0::/user.slice", controller);
            let (root, host_paths) = fixture_host(
                &format!("hybrid-named-{}", controller),
                &mountinfo,
                &membership,
            );
            let cgroupfs = root.join("cgroupfs");
            let host_paths = host_paths.with_fixture_root(cgroupfs.clone());

            let topology = discover(&host_paths).unwrap();
            assert_eq!(topology.version(), CgroupVersion::V1);
            assert!(topology.v2_available());
            assert_eq!(topology.cgroupfs_root(), cgroupfs);
            assert_eq!(
                topology.v1_mount_root.as_deref(),
                Some(Path::new("/sys/fs/cgroup")),
            );
            assert_eq!(topology.controllers().len(), 2);
            assert!(topology.controllers().contains(controller));
            assert!(topology.controllers().contains("name=legacy"));
            assert_eq!(
                topology.resolve_mount_point(Path::new("/sys/fs/cgroup/legacy")),
                cgroupfs.join("legacy"),
            );
        }
    }

    #[test]
    fn test_discover_hybrid_downgrades_failed_optional_v2_recheck() {
        for (tag, create_mount_point) in [("wrong-fs", true), ("missing-mount", false)] {
            let (root, host_paths) = fixture_host(tag, V1_MOUNTINFO, HYBRID_MEMBERSHIP);
            let candidate = root.join("unified");
            if create_mount_point {
                fs::create_dir_all(&candidate).unwrap();
            }
            let cgroup2_mount = format!(
                "34 33 0:29 / {} rw - cgroup2 cgroup2 rw",
                candidate.display()
            );
            fs::write(
                root.join("self/mountinfo"),
                format!("{}\n{}", V1_MOUNTINFO, cgroup2_mount),
            )
            .unwrap();

            let topology = discover(&host_paths).unwrap();
            assert_eq!(topology.version(), CgroupVersion::V1);
            assert!(!topology.v2_available());
            assert!(topology.unified_mount_point.is_none());
            assert_eq!(topology.mounts().unified_mounts().len(), 1);
            assert!(topology.membership().unified().is_some());
            assert!(topology.controllers().contains("memory"));

            // The same failed recheck remains fatal when v2 is primary,
            // even with a controller-less named v1 hierarchy alongside it.
            for (v1_mount, membership) in
                [("", V2_MEMBERSHIP), (NAMED_V1_MOUNT, NAMED_V1_MEMBERSHIP)]
            {
                fs::write(
                    root.join("self/mountinfo"),
                    format!("{}\n{}", cgroup2_mount, v1_mount),
                )
                .unwrap();
                fs::write(root.join("self/cgroup"), membership).unwrap();
                let error = discover(&host_paths).unwrap_err();
                if create_mount_point {
                    assert!(error.source().is_none());
                } else {
                    let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
                    assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
                }
                match (create_mount_point, error) {
                    (true, CoreError::NotCgroup2 { path }) => {
                        assert_eq!(path, candidate);
                    }
                    (false, CoreError::StatfsCgroupRoot { path, cause }) => {
                        assert_eq!(path, candidate);
                        assert_eq!(cause.raw_os_error(), Some(libc::ENOENT));
                    }
                    other => panic!(
                        "expected a filesystem verification error, got `{:?}`",
                        other
                    ),
                }
            }
        }
    }

    #[test]
    fn test_discover_hybrid_downgrades_missing_unified_membership() {
        for (tag, create_mount_point) in [("missing", false), ("wrong-fs", true)] {
            let (root, host_paths) = fixture_host(
                &format!("hybrid-missing-0-{}", tag),
                V1_MOUNTINFO,
                V1_MEMBERSHIP,
            );
            let candidate = root.join("unified");
            if create_mount_point {
                fs::create_dir_all(&candidate).unwrap();
            }
            fs::write(
                root.join("self/mountinfo"),
                format!(
                    "{}\n34 33 0:29 / {} rw - cgroup2 cgroup2 rw",
                    V1_MOUNTINFO,
                    candidate.display(),
                ),
            )
            .unwrap();

            for with_fixture_root in [false, true] {
                let host_paths = if with_fixture_root {
                    host_paths.clone().with_fixture_root(root.join("cgroupfs"))
                } else {
                    host_paths.clone()
                };
                let topology = discover(&host_paths).unwrap();
                assert_eq!(topology.version(), CgroupVersion::V1);
                assert!(!topology.v2_available());
                assert!(topology.unified_mount_point.is_none());
                assert_eq!(topology.mounts().unified_mounts().len(), 1);
                assert!(topology.membership().unified().is_none());
                assert!(topology.controllers().contains("memory"));
                assert_eq!(
                    topology.cgroupfs_root(),
                    if with_fixture_root {
                        root.join("cgroupfs")
                    } else {
                        PathBuf::from("/sys/fs/cgroup")
                    },
                );
            }
        }
    }

    #[test]
    fn test_discover_no_cgroup_mounts() {
        let (root, host_paths) = fixture_host(
            "none",
            "36 35 98:0 / /mnt rw,relatime - ext3 /dev/root rw",
            V1_MEMBERSHIP,
        );

        match discover(&host_paths) {
            Err(CoreError::Layout {
                path,
                cause: LayoutError::NoCgroupMounts,
            }) => {
                assert_eq!(path, root.join("self/mountinfo"));
            }
            other => panic!("expected no cgroup mounts, got `{:?}`", other),
        }
    }

    #[test]
    fn test_discover_contradictory_membership() {
        // A parsed unified mount without `0::` is a layout contradiction,
        // independent of the candidate's filesystem or fixture redirection.
        for (tag, create_mount_point) in [("missing", false), ("wrong-fs", true)] {
            let (root, host_paths) = fixture_host(&format!("contra-{}", tag), "", V1_MEMBERSHIP);
            let candidate = root.join("unified");
            if create_mount_point {
                fs::create_dir_all(&candidate).unwrap();
            }
            fs::write(
                root.join("self/mountinfo"),
                format!(
                    "47 44 0:30 / {} rw - cgroup2 cgroup2 rw",
                    candidate.display()
                ),
            )
            .unwrap();

            for with_fixture_root in [false, true] {
                let host_paths = if with_fixture_root {
                    host_paths.clone().with_fixture_root(root.join("cgroupfs"))
                } else {
                    host_paths.clone()
                };
                let error = discover(&host_paths).unwrap_err();
                assert_eq!(
                    error.source().unwrap().downcast_ref::<LayoutError>(),
                    Some(&LayoutError::MissingUnifiedMembership),
                );
                match error {
                    CoreError::Layout {
                        path,
                        cause: LayoutError::MissingUnifiedMembership,
                    } => assert_eq!(path, root.join("self/cgroup")),
                    other => panic!("expected missing unified membership, got `{:?}`", other),
                }
            }
        }
    }

    #[test]
    fn test_discover_v1_with_unified_membership_but_no_v2_mount() {
        // cgroup2 is mounted elsewhere on the host, so procfs includes
        // `0::`, but this mount namespace exposes only v1 hierarchies.
        let (_root, host_paths) = fixture_host(
            "v1-hidden-v2",
            V1_MOUNTINFO,
            &format!("{}\n0::/", V1_MEMBERSHIP),
        );

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version(), CgroupVersion::V1);
        assert!(!topology.v2_available());
        assert!(topology.membership().unified().is_some());
        assert_eq!(topology.cgroupfs_root(), Path::new("/sys/fs/cgroup"));
        assert!(topology.controllers().contains("memory"));
    }

    #[test]
    fn test_discover_v1_root_co_mount_with_named_child() {
        const CO_MOUNT: &str = "30 26 0:26 / /sys/fs/cgroup rw - cgroup cgroup rw,cpu,memory";
        const NAMED_MOUNT: &str =
            "31 30 0:27 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd";
        const MEMBERSHIP: &str = "1:cpu,memory:/work\n2:name=systemd:/work";
        let layouts = [
            format!("{}\n{}", CO_MOUNT, NAMED_MOUNT),
            format!("{}\n{}", NAMED_MOUNT, CO_MOUNT),
        ];

        for (order, mountinfo) in layouts.iter().enumerate() {
            for with_fixture_root in [false, true] {
                let (root, host_paths) = fixture_host(
                    &format!("root-co-named-{}-{}", order, with_fixture_root),
                    mountinfo,
                    MEMBERSHIP,
                );
                let fixture_root = root.join("cgroupfs");
                fs::create_dir_all(&fixture_root).unwrap();
                let host_paths = if with_fixture_root {
                    host_paths.with_fixture_root(fixture_root.clone())
                } else {
                    host_paths
                };
                let expected_root = if with_fixture_root {
                    fixture_root
                } else {
                    PathBuf::from("/sys/fs/cgroup")
                };

                let topology = discover(&host_paths).unwrap();
                assert_eq!(topology.version(), CgroupVersion::V1);
                assert_eq!(topology.cgroupfs_root(), expected_root);
                assert_eq!(
                    topology.v1_mount_root.as_deref(),
                    Some(Path::new("/sys/fs/cgroup")),
                );
                assert_eq!(
                    topology.resolve_mount_point(Path::new("/sys/fs/cgroup")),
                    expected_root,
                );
                assert_eq!(
                    topology.resolve_mount_point(Path::new("/sys/fs/cgroup/systemd")),
                    expected_root.join("systemd"),
                );
                assert!(topology.controllers().contains("cpu"));
                assert!(topology.controllers().contains("memory"));
                assert!(topology.controllers().contains("name=systemd"));
            }
        }
    }

    #[test]
    fn test_discover_v1_mounts_with_different_roots_are_ambiguous() {
        const EXTERNAL_MOUNT: &str =
            "50 33 0:50 / /run/lxcfs/custom rw - cgroup cgroup rw,name=custom";
        let layouts = [
            format!("{}\n{}", V1_MOUNTINFO, EXTERNAL_MOUNT),
            format!("{}\n{}", EXTERNAL_MOUNT, V1_MOUNTINFO),
        ];
        let membership = format!("{}\n2:name=custom:/user.slice", V1_MEMBERSHIP);
        let expected_roots =
            BTreeSet::from([PathBuf::from("/sys/fs/cgroup"), PathBuf::from("/run/lxcfs")]);

        for (order, mountinfo) in layouts.iter().enumerate() {
            for with_fixture_root in [false, true] {
                let (root, host_paths) = fixture_host(
                    &format!("mixed-v1-roots-{}-{}", order, with_fixture_root),
                    mountinfo,
                    &membership,
                );
                let host_paths = if with_fixture_root {
                    host_paths.with_fixture_root(root.join("cgroupfs"))
                } else {
                    host_paths
                };

                match discover(&host_paths) {
                    Err(CoreError::Layout {
                        path,
                        cause: LayoutError::AmbiguousV1Roots { roots },
                    }) => {
                        assert_eq!(path, root.join("self/mountinfo"));
                        assert_eq!(roots, expected_roots);
                    }
                    other => panic!("expected ambiguous v1 roots, got `{:?}`", other),
                }
            }
        }
    }

    #[test]
    fn test_discover_missing_proc_file_preserves_path_and_source() {
        for relative in ["self/mountinfo", "self/cgroup"] {
            let (root, host_paths) = fixture_host(
                &format!("missing-{}", relative.replace('/', "-")),
                V1_MOUNTINFO,
                V1_MEMBERSHIP,
            );
            let missing_path = root.join(relative);
            fs::remove_file(&missing_path).unwrap();

            let error = discover(&host_paths).unwrap_err();
            let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
            assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
            match error {
                CoreError::ReadProcFile { path, cause } => {
                    assert_eq!(path, missing_path);
                    assert_eq!(cause.raw_os_error(), Some(libc::ENOENT));
                }
                other => panic!("expected a ReadProcFile error, got `{:?}`", other),
            }
        }
    }

    #[test]
    fn test_discover_empty_membership_preserves_layout_source() {
        for (layout, v1_mountinfo, has_unified_mount) in [
            ("v1", V1_MOUNTINFO, false),
            ("v2", "", true),
            ("hybrid", V1_MOUNTINFO, true),
        ] {
            for (state, create_mount_point) in [("missing", false), ("wrong-fs", true)] {
                let (root, host_paths) = fixture_host(
                    &format!("empty-membership-{}-{}", layout, state),
                    v1_mountinfo,
                    "",
                );
                let candidate = root.join("unified");
                if has_unified_mount {
                    if create_mount_point {
                        fs::create_dir_all(&candidate).unwrap();
                    }
                    let unified_mount = format!(
                        "47 44 0:30 / {} rw - cgroup2 cgroup2 rw",
                        candidate.display(),
                    );
                    let mountinfo = if v1_mountinfo.is_empty() {
                        unified_mount
                    } else {
                        format!("{}\n{}", v1_mountinfo, unified_mount)
                    };
                    fs::write(root.join("self/mountinfo"), mountinfo).unwrap();
                }

                for with_fixture_root in [false, true] {
                    let host_paths = if with_fixture_root {
                        host_paths.clone().with_fixture_root(root.join("cgroupfs"))
                    } else {
                        host_paths.clone()
                    };
                    let error = discover(&host_paths).unwrap_err();
                    assert_eq!(
                        error.source().unwrap().downcast_ref::<LayoutError>(),
                        Some(&LayoutError::NoMembershipRecords),
                    );
                    match error {
                        CoreError::Layout {
                            path,
                            cause: LayoutError::NoMembershipRecords,
                        } => assert_eq!(path, root.join("self/cgroup")),
                        other => panic!("expected no membership records, got `{:?}`", other),
                    }
                }
            }
        }
    }

    #[test]
    fn test_determine_v1_root_rejects_distinct_roots_with_shared_parent() {
        const MOUNTINFO: &[u8] = b"\
30 26 0:26 / /run/cgroups/primary rw - cgroup cgroup rw,cpu,memory
31 26 0:27 / /run/cgroups/systemd rw - cgroup cgroup rw,name=systemd";
        let table = parse_mountinfo_bytes(MOUNTINFO).unwrap();
        let mounts = table.cgroup_mounts();
        let expected = LayoutError::AmbiguousV1Roots {
            roots: BTreeSet::from([
                PathBuf::from("/run/cgroups/primary"),
                PathBuf::from("/run/cgroups"),
            ]),
        };

        assert_eq!(determine_v1_natural_root(&mounts), Err(expected.clone()));
        let reversed = mounts.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(determine_v1_natural_root(&reversed), Err(expected));
    }

    #[test]
    fn test_discover_controller_read_errors_preserve_path_and_source() {
        for (tag, contents, expected_kind, expected_errno) in [
            ("missing", None, io::ErrorKind::NotFound, Some(libc::ENOENT)),
            (
                "invalid-utf8",
                Some(&b"memory \xff"[..]),
                io::ErrorKind::InvalidData,
                None,
            ),
        ] {
            let (root, host_paths) = fixture_host(tag, V2_MOUNTINFO, V2_MEMBERSHIP);
            let cgroupfs = root.join("cgroupfs");
            fs::create_dir_all(&cgroupfs).unwrap();
            let controllers_path = cgroupfs.join("cgroup.controllers");
            if let Some(contents) = contents {
                fs::write(&controllers_path, contents).unwrap();
            }
            let host_paths = host_paths.with_fixture_root(cgroupfs);

            let error = discover(&host_paths).unwrap_err();
            let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
            assert_eq!(source.kind(), expected_kind);
            assert_eq!(source.raw_os_error(), expected_errno);
            match error {
                CoreError::ReadControllers { path, cause } => {
                    assert_eq!(path, controllers_path);
                    assert_eq!(cause.kind(), expected_kind);
                    assert_eq!(cause.raw_os_error(), expected_errno);
                }
                other => panic!("expected a ReadControllers error, got `{:?}`", other),
            }
        }
    }

    #[test]
    fn test_discover_propagates_parse_error_with_path() {
        let (_root, host_paths) = fixture_host(
            "parse",
            &format!("{}\nnot a mountinfo line", V1_MOUNTINFO),
            V1_MEMBERSHIP,
        );

        match discover(&host_paths) {
            Err(CoreError::ParseMountInFile { path, cause }) => {
                assert_eq!(cause.line(), 5);
                assert!(
                    path.ends_with("self/mountinfo"),
                    "expected path to end with self/mountinfo, got {:?}",
                    path
                );
            }
            other => panic!("expected a ParseMountInFile error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_resolve_mount_point_single_co_mount_fixture_root() {
        const SINGLE_CO_MOUNT: &str =
            "30 26 0:26 / /sys/fs/cgroup rw - cgroup cgroup rw,cpu,cpuacct,memory";
        const SINGLE_MEMBERSHIP: &str = "1:cpu,cpuacct,memory:/user.slice";

        let (root, host_paths) = fixture_host("single-co", SINGLE_CO_MOUNT, SINGLE_MEMBERSHIP);
        let custom_cgroupfs = root.join("custom_cgroupfs");
        fs::create_dir_all(&custom_cgroupfs).unwrap();

        let host_paths = host_paths.with_fixture_root(custom_cgroupfs.clone());

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert_eq!(topology.cgroupfs_root, custom_cgroupfs);

        // Single co-mount must resolve directly to custom_cgroupfs, NOT custom_cgroupfs/cgroup
        let resolved = topology.resolve_mount_point(Path::new("/sys/fs/cgroup"));
        assert_eq!(resolved, custom_cgroupfs);
    }

    #[test]
    fn test_resolve_mount_point_single_controller_directory_fixture_root() {
        const CASES: &[(&str, &str)] = &[
            (
                "30 26 0:26 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct",
                "cpu,cpuacct",
            ),
            (
                "30 26 0:26 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,xattr,name=systemd",
                "systemd",
            ),
        ];

        for (index, (mountinfo, directory)) in CASES.iter().enumerate() {
            let membership = if *directory == "systemd" {
                "1:name=systemd:/user.slice"
            } else {
                "1:cpu,cpuacct:/user.slice"
            };
            let (root, host_paths) = fixture_host(
                &format!("single-controller-{}", index),
                mountinfo,
                membership,
            );
            let custom_cgroupfs = root.join("custom_cgroupfs");
            fs::create_dir_all(&custom_cgroupfs).unwrap();
            let host_paths = host_paths.with_fixture_root(custom_cgroupfs.clone());

            let topology = discover(&host_paths).unwrap();
            assert_eq!(topology.version(), CgroupVersion::V1);
            assert!(!topology.v2_available());
            let original = Path::new("/sys/fs/cgroup").join(directory);
            assert_eq!(
                topology.resolve_mount_point(&original),
                custom_cgroupfs.join(directory)
            );
        }
    }

    #[test]
    fn test_discover_hybrid_accepts_namespaced_cgroup2_mount() {
        const DELEGATED_CGROUP2: &str =
            "34 33 0:29 /.. /sys/fs/cgroup/unified rw shared:10 - cgroup2 cgroup2 rw";
        let (root, host_paths) = fixture_host(
            "hybrid-delegated",
            &format!("{}\n{}", V1_MOUNTINFO, DELEGATED_CGROUP2),
            HYBRID_MEMBERSHIP,
        );
        let host_paths = host_paths.with_fixture_root(root.join("cgroupfs"));

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert!(topology.v2_available);
    }

    #[test]
    fn test_cgroup_mount_contains_namespace_membership() {
        for (root, membership, expected) in [
            ("/", "/", true),
            ("/", "/work", true),
            ("/delegation-a", "/delegation-b/work", false),
            ("/delegation-b", "/delegation-b", true),
            ("/delegation-b", "/delegation-b/work", true),
            ("/delegation-b", "/delegation-b-sibling/work", false),
            ("/..", "/work", true),
            ("/../..", "/work", true),
            ("/..", "/..", true),
            ("/..", "/../sibling/work", true),
            ("/..", "/../../work", false),
            ("/", "/../sibling/work", false),
            ("/../sibling", "/../sibling/work", true),
            ("/../sibling", "/work", false),
            ("/../../sibling", "/../work", false),
            ("/../sibling", "/../../sibling/work", false),
            ("relative-root", "/work", false),
            ("/delegation-b/../delegation-a", "/delegation-a/work", false),
        ] {
            assert_eq!(
                cgroup_mount_contains(Path::new(root), Path::new(membership)),
                expected,
                "mount root {:?}, membership {:?}",
                root,
                membership,
            );
        }

        let root = Path::new(std::ffi::OsStr::from_bytes(b"/delegation-\xff"));
        let membership = Path::new(std::ffi::OsStr::from_bytes(b"/delegation-\xff/work"));
        assert!(cgroup_mount_contains(root, membership));
    }

    #[test]
    fn test_discover_selects_namespace_ancestor_outside_root() {
        const MOUNTINFO: &str = "\
47 44 0:30 / /sys/fs/cgroup/root rw - cgroup2 cgroup2 rw
48 44 0:30 /.. /sys/fs/cgroup/ancestor rw - cgroup2 cgroup2 rw";
        let (root, host_paths) = fixture_host(
            "unified-namespace-ancestor",
            MOUNTINFO,
            "0::/../sibling/work",
        );
        let cgroupfs = root.join("cgroupfs");
        fs::create_dir_all(&cgroupfs).unwrap();
        fs::write(cgroupfs.join("cgroup.controllers"), "memory\n").unwrap();
        let host_paths = host_paths.with_fixture_root(cgroupfs);

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version(), CgroupVersion::V2);
        assert_eq!(
            topology.unified_mount_point.as_deref(),
            Some(Path::new("/sys/fs/cgroup/ancestor")),
        );
    }

    #[test]
    fn test_discover_selects_unified_mount_containing_membership() {
        const SUBTREES: [&str; 2] = [
            "47 44 0:30 /delegation-a /sys/fs/cgroup/a rw - cgroup2 cgroup2 rw",
            "48 44 0:30 /delegation-b /sys/fs/cgroup/b rw - cgroup2 cgroup2 rw",
        ];

        for (layout, v1_mountinfo, v1_membership, version) in [
            ("v2", "", "", CgroupVersion::V2),
            ("hybrid", V1_MOUNTINFO, V1_MEMBERSHIP, CgroupVersion::V1),
        ] {
            for reverse in [false, true] {
                let subtrees = if reverse {
                    [SUBTREES[1], SUBTREES[0]]
                } else {
                    SUBTREES
                };
                let mountinfo = [v1_mountinfo, subtrees[0], subtrees[1]]
                    .iter()
                    .filter(|record| !record.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                let membership = [v1_membership, "0::/delegation-b/work"]
                    .iter()
                    .filter(|record| !record.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                let (root, host_paths) = fixture_host(
                    &format!("unified-match-{}-{}", layout, reverse),
                    &mountinfo,
                    &membership,
                );
                let cgroupfs = root.join("cgroupfs");
                fs::create_dir_all(&cgroupfs).unwrap();
                fs::write(cgroupfs.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
                let host_paths = host_paths.with_fixture_root(cgroupfs.clone());

                let topology = discover(&host_paths).unwrap();
                assert_eq!(topology.version(), version);
                assert!(topology.v2_available());
                assert_eq!(
                    topology.unified_mount_point.as_deref(),
                    Some(Path::new("/sys/fs/cgroup/b")),
                );
                assert_eq!(topology.mounts().unified_mounts().len(), 2);
                if version == CgroupVersion::V2 {
                    assert_eq!(
                        topology.resolve_mount_point(Path::new("/sys/fs/cgroup/b/work")),
                        cgroupfs.join("work"),
                    );
                    assert_eq!(
                        topology.resolve_mount_point(Path::new("/sys/fs/cgroup/a")),
                        PathBuf::from("/sys/fs/cgroup/a"),
                    );
                }
            }
        }
    }

    #[test]
    fn test_discover_prefers_shallower_unified_subtree() {
        // Both subtrees contain the process. Prefer the parent subtree
        // regardless of which bind mount appears first in mountinfo.
        const SUBTREES: [&str; 2] = [
            "47 44 0:30 /docker/abc /sys/fs/cgroup rw - cgroup2 cgroup2 rw",
            "48 44 0:30 /docker/abc/nested /sys/fs/cgroup/nested rw - cgroup2 cgroup2 rw",
        ];

        for reverse in [false, true] {
            let subtrees = if reverse {
                [SUBTREES[1], SUBTREES[0]]
            } else {
                SUBTREES
            };
            let (root, host_paths) = fixture_host(
                &format!("unified-nested-subtrees-{}", reverse),
                &subtrees.join("\n"),
                "0::/docker/abc/nested/work",
            );
            let cgroupfs = root.join("cgroupfs");
            fs::create_dir_all(&cgroupfs).unwrap();
            fs::write(cgroupfs.join("cgroup.controllers"), "memory\n").unwrap();
            let host_paths = host_paths.with_fixture_root(cgroupfs.clone());

            let topology = discover(&host_paths).unwrap();
            assert_eq!(topology.version(), CgroupVersion::V2);
            assert!(topology.v2_available());
            assert_eq!(
                topology.unified_mount_point.as_deref(),
                Some(Path::new("/sys/fs/cgroup")),
            );
            assert_eq!(
                topology.resolve_mount_point(Path::new("/sys/fs/cgroup/nested/work")),
                cgroupfs.join("nested/work"),
            );
        }
    }

    #[test]
    fn test_discover_prefers_namespace_subtree_over_ancestor() {
        const ANCESTOR: &str = "47 44 0:30 /.. /sys/fs/cgroup/host rw - cgroup2 cgroup2 rw";

        // Prefer a subtree even when it has more components than the ancestor:
        // mapping through the ancestor would require the namespace root's name.
        for (tag, subtree_root, membership) in [
            ("one-level", "/a", "0::/a/work"),
            ("nested", "/a/nested", "0::/a/nested/work"),
        ] {
            let subtree = format!(
                "48 44 0:30 {} /sys/fs/cgroup/a rw - cgroup2 cgroup2 rw",
                subtree_root,
            );
            for reverse in [false, true] {
                let mounts = if reverse {
                    [subtree.as_str(), ANCESTOR]
                } else {
                    [ANCESTOR, subtree.as_str()]
                };
                let (root, host_paths) = fixture_host(
                    &format!("unified-subtree-over-ancestor-{}-{}", tag, reverse),
                    &mounts.join("\n"),
                    membership,
                );
                let cgroupfs = root.join("cgroupfs");
                fs::create_dir_all(&cgroupfs).unwrap();
                fs::write(cgroupfs.join("cgroup.controllers"), "memory\n").unwrap();
                let host_paths = host_paths.with_fixture_root(cgroupfs.clone());

                let topology = discover(&host_paths).unwrap();
                assert_eq!(topology.version(), CgroupVersion::V2);
                assert!(topology.v2_available());
                assert_eq!(
                    topology.unified_mount_point.as_deref(),
                    Some(Path::new("/sys/fs/cgroup/a")),
                );
                assert_eq!(
                    topology.resolve_mount_point(Path::new("/sys/fs/cgroup/a/work")),
                    cgroupfs.join("work"),
                );
            }
        }
    }

    #[test]
    fn test_discover_unified_mounts_outside_membership() {
        for (layout, v1_mountinfo, v1_membership, v1_primary) in [
            ("v2", "", "", false),
            ("named-v1", NAMED_V1_MOUNT, "1:name=openrc:/", false),
            ("hybrid", V1_MOUNTINFO, V1_MEMBERSHIP, true),
        ] {
            for (tag, unified_path) in [
                ("outside", "/outside/work"),
                ("prefix-sibling", "/delegation-b-sibling/work"),
            ] {
                let membership = if v1_membership.is_empty() {
                    format!("0::{}", unified_path)
                } else {
                    format!("{}\n0::{}", v1_membership, unified_path)
                };
                let (root, host_paths) = fixture_host(
                    &format!("unified-no-match-{}-{}", layout, tag),
                    "",
                    &membership,
                );
                // Missing ordinary paths make any premature statfs probe fail,
                // without inspecting the host's live cgroup filesystem.
                let subtrees = [
                    format!(
                        "47 44 0:30 /delegation-a {} rw - cgroup2 cgroup2 rw",
                        root.join("a").display(),
                    ),
                    format!(
                        "48 44 0:30 /delegation-b {} rw - cgroup2 cgroup2 rw",
                        root.join("b").display(),
                    ),
                ];
                let expected = LayoutError::NoMatchingUnifiedMount {
                    membership: PathBuf::from(unified_path),
                    roots: BTreeSet::from([
                        PathBuf::from("/delegation-a"),
                        PathBuf::from("/delegation-b"),
                    ]),
                };
                for reverse in [false, true] {
                    let ordered = if reverse {
                        [&subtrees[1], &subtrees[0]]
                    } else {
                        [&subtrees[0], &subtrees[1]]
                    };
                    let mountinfo = [v1_mountinfo, ordered[0].as_str(), ordered[1].as_str()]
                        .iter()
                        .filter(|record| !record.is_empty())
                        .copied()
                        .collect::<Vec<_>>()
                        .join("\n");
                    fs::write(root.join("self/mountinfo"), mountinfo).unwrap();

                    for with_fixture_root in [false, true] {
                        let host_paths = if with_fixture_root {
                            host_paths.clone().with_fixture_root(root.join("cgroupfs"))
                        } else {
                            host_paths.clone()
                        };
                        if v1_primary {
                            let topology = discover(&host_paths).unwrap();
                            assert_eq!(topology.version(), CgroupVersion::V1);
                            assert!(!topology.v2_available());
                            assert!(topology.unified_mount_point.is_none());
                            assert_eq!(topology.mounts().unified_mounts().len(), 2);
                            assert_eq!(
                                topology.membership().unified().unwrap().path,
                                Path::new(unified_path),
                            );
                            assert!(topology.controllers().contains("memory"));
                            assert_eq!(
                                topology.cgroupfs_root(),
                                if with_fixture_root {
                                    root.join("cgroupfs")
                                } else {
                                    PathBuf::from("/sys/fs/cgroup")
                                },
                            );
                            continue;
                        }
                        let error = discover(&host_paths).unwrap_err();
                        assert_eq!(
                            error.source().unwrap().downcast_ref::<LayoutError>(),
                            Some(&expected),
                        );
                        match error {
                            CoreError::Layout { path, cause } => {
                                assert_eq!(path, root.join("self/mountinfo"));
                                assert_eq!(cause, expected);
                            }
                            other => {
                                panic!("expected no matching unified mount, got `{:?}`", other)
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_resolve_mount_point_v2_delegated_before_root() {
        // Both mounts contain membership; the root mount must win even
        // though the delegated subtree mount appears first.
        const DELEGATED_FIRST: &str = "\
47 44 0:30 /sub /sys/fs/cgroup/delegated rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw
48 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:8 - cgroup2 cgroup2 rw";

        let (root, host_paths) =
            fixture_host("v2-delegated-first", DELEGATED_FIRST, "0::/sub/work");
        let custom_cgroupfs = root.join("custom_cgroupfs");
        fs::create_dir_all(&custom_cgroupfs).unwrap();
        fs::write(
            custom_cgroupfs.join("cgroup.controllers"),
            "cpu memory io\n",
        )
        .unwrap();

        let host_paths = host_paths.with_fixture_root(custom_cgroupfs.clone());

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V2);
        // The root mount at /sys/fs/cgroup (mount_root == "/") must be
        // selected, not the delegated subtree at /sys/fs/cgroup/delegated.
        assert_eq!(topology.cgroupfs_root, custom_cgroupfs);

        // resolve_mount_point must relocate the *root* mount's
        // mount_point even though the delegated mount appeared first
        // in the mountinfo list.
        let resolved = topology.resolve_mount_point(Path::new("/sys/fs/cgroup"));
        assert_eq!(
            resolved, custom_cgroupfs,
            "root mount_point should resolve to cgroupfs_fixture_root"
        );

        // A child under the root mount should also be relocated.
        let resolved_child = topology.resolve_mount_point(Path::new("/sys/fs/cgroup/user.slice"));
        assert_eq!(
            resolved_child,
            custom_cgroupfs.join("user.slice"),
            "child of root mount should resolve under cgroupfs_fixture_root"
        );
    }

    #[test]
    fn test_discover_propagates_membership_parse_error_with_path() {
        let (_root, host_paths) = fixture_host(
            "membership-parse",
            V1_MOUNTINFO,
            // Malformed: only one colon-separated field.
            "bad-membership-line",
        );

        match discover(&host_paths) {
            Err(CoreError::ParseMembershipInFile { path, cause }) => {
                assert_eq!(cause.line(), 1);
                assert!(
                    path.ends_with("self/cgroup"),
                    "expected path to end with self/cgroup, got {:?}",
                    path
                );
            }
            other => panic!("expected a ParseMembershipInFile error, got `{:?}`", other),
        }
    }
}
