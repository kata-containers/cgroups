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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::discovery::membership::{parse_membership, Membership};
use crate::discovery::mountinfo::{parse_mountinfo, MountTable};
use crate::error::{CoreError, CoreResult};

/// Where discovery reads the host from.
///
/// Every host path the library touches is derived from this struct, so
/// tests can point it at fixtures and callers can override the cgroupfs
/// root instead of relying on the default `/sys/fs/cgroup` mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    /// procfs root (e.g. `/proc`).
    pub procfs: PathBuf,
    /// Explicit cgroupfs root; when set it replaces every defaulted
    /// `/sys/fs/cgroup` constant.
    pub cgroupfs_override: Option<PathBuf>,
    /// hugetlbfs mount root.
    pub hugepages: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        HostPaths {
            procfs: PathBuf::from("/proc"),
            cgroupfs_override: None,
            hugepages: PathBuf::from("/sys/kernel/mm/hugepages"),
        }
    }
}

/// The cgroup version a host operates in.
///
/// Hybrid hosts report [`CgroupVersion::V1`] as their primary version;
/// the additionally available v2 hierarchy is recorded as
/// [`CgroupTopology::v2_available`] rather than a third variant, so
/// exactly one version drives representation choices.
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
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.0.iter()
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
    pub version: CgroupVersion,
    /// Whether a cgroup v2 hierarchy is also available. Hybrid hosts
    /// (v1 mounts plus a qualifying cgroup2 mount) report `V1` here with
    /// this flag set; they are never silently collapsed to one side.
    pub v2_available: bool,
    /// All parsed mounts, not only cgroup mounts.
    pub mounts: MountTable,
    /// The process's membership records.
    pub membership: Membership,
    /// Controller names visible on the primary hierarchy.
    pub controllers: ControllerSet,
    /// The resolved cgroupfs root: `cgroupfs_override` when set, else the
    /// root derived from the parsed mounts. This is the value that
    /// replaces the hard-coded `/sys/fs/cgroup` constants across the
    /// crate.
    pub cgroupfs_root: PathBuf,
    /// hugetlbfs mount root derived from HostPaths.
    pub hugepages: PathBuf,
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
    pub fn mounts(&self) -> &MountTable {
        &self.mounts
    }

    /// The process's cgroup membership records.
    pub fn membership(&self) -> &Membership {
        &self.membership
    }

    /// Controllers visible on the primary hierarchy.
    pub fn controllers(&self) -> &ControllerSet {
        &self.controllers
    }

    /// The resolved cgroupfs root directory.
    pub fn cgroupfs_root(&self) -> &Path {
        &self.cgroupfs_root
    }

    /// hugetlbfs root directory.
    pub fn hugepages(&self) -> &Path {
        &self.hugepages
    }

    /// Adjust a mountpoint from mountinfo according to `cgroupfs_root`.
    pub fn resolve_mount_point(&self, original: &Path) -> PathBuf {
        let v1_mounts = self.mounts.cgroup_mounts();
        if !v1_mounts.is_empty() {
            let natural_root = determine_v1_natural_root(&v1_mounts);
            if original == natural_root {
                return self.cgroupfs_root.clone();
            }
            if let Ok(rel) = original.strip_prefix(&natural_root) {
                return self.cgroupfs_root.join(rel);
            }
        } else if let Some(candidate) = self.mounts.unified_mount() {
            if original == candidate.mount_point {
                return self.cgroupfs_root.clone();
            }
            if let Ok(rel) = original.strip_prefix(&candidate.mount_point) {
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
/// I/O failures return [`CoreError::Discovery`] naming the step and the
/// path; malformed content returns [`CoreError::ParseError`]; a
/// self-contradictory layout (see `assemble_topology`) returns a
/// discovery error rather than silently defaulting to v1.
pub fn discover(host_paths: &HostPaths) -> CoreResult<Arc<CgroupTopology>> {
    let mountinfo_text = read_proc_file(host_paths, "self/mountinfo", "read mountinfo")?;
    let membership_text = read_proc_file(host_paths, "self/cgroup", "read membership")?;

    let mounts = parse_mountinfo(&mountinfo_text)?;
    let membership = parse_membership(&membership_text)?;
    let topology = assemble_topology(mounts, membership, host_paths)?;

    Ok(Arc::new(topology))
}

/// Read one file beneath the procfs root, mapping I/O failures to
/// [`CoreError::Discovery`] with the step name and the full path.
fn read_proc_file(
    host_paths: &HostPaths,
    relative: &str,
    step: &'static str,
) -> CoreResult<String> {
    let path = host_paths.procfs.join(relative);
    fs::read_to_string(&path).map_err(|cause| CoreError::Discovery { step, path, cause })
}

/// Determine the natural root of cgroup v1 mounts.
///
/// If a single mount point is named after all controllers on that hierarchy
/// (including a `name=foo` hierarchy), its parent is the natural root. A
/// single mount directly at the common cgroup root remains its own natural
/// root. If there are multiple mounts sharing a parent directory, that parent
/// directory is the root.
fn determine_v1_natural_root(v1_mounts: &[&crate::discovery::mountinfo::MountRecord]) -> PathBuf {
    if v1_mounts.is_empty() {
        return PathBuf::from("/sys/fs/cgroup");
    }
    if v1_mounts.len() == 1 {
        let mount = v1_mounts[0];
        let mount_name = mount
            .mount_point
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let is_subsystem_dir = !mount_name.is_empty()
            && mount_name.split(',').all(|name| {
                mount
                    .super_opts
                    .iter()
                    .any(|opt| opt == name || opt.strip_prefix("name=") == Some(name))
            });
        if is_subsystem_dir {
            mount
                .mount_point
                .parent()
                .unwrap_or(&mount.mount_point)
                .to_path_buf()
        } else {
            mount.mount_point.clone()
        }
    } else {
        let parent = v1_mounts[0]
            .mount_point
            .parent()
            .unwrap_or(&v1_mounts[0].mount_point);
        let all_share_parent = v1_mounts
            .iter()
            .all(|m| m.mount_point.parent() == Some(parent));
        if all_share_parent {
            parent.to_path_buf()
        } else {
            v1_mounts[0].mount_point.clone()
        }
    }
}

/// Assemble the topology snapshot from the parsed inputs.
///
/// # Contract
///
/// - Version: any cgroup2 mount is a unified-hierarchy candidate; the
///   candidate with `mount_root == "/"` is preferred. A delegated or
///   namespaced cgroup2 subtree (`mount_root != "/"`) is equally valid
///   for the process that sees it — inside a delegated cgroup namespace
///   the subtree mount IS the unified hierarchy — so requiring an
///   absolute mount root would break exactly the namespaced layouts
///   this crate must support. On default host paths a statfs recheck
///   on the chosen root guards against stale or forged mountinfo; an
///   explicit `cgroupfs_override` is trusted as-is and skips the
///   recheck.
/// - Hybrid: v1 `cgroup` mounts coexist with a cgroup2 mount
///   (typically at `/sys/fs/cgroup/unified`) → primary `V1` with
///   `v2_available = true`.
/// - `cgroupfs_root`: `cgroupfs_override` when set, else the unified
///   mount point (v2) or the parent of the first v1 cgroup mount point
///   (v1); the derived root always comes from the parsed mounts.
/// - Cross-check the mount-based verdict against `membership.unified()`
///   (the `0::` record): unified mounts without a `0::` record, a `0::`
///   record without any cgroup2 mount, or no membership records at all
///   are errors, never a silent side-pick.
/// - `controllers`: v1 — the controller names bound to the process's v1
///   hierarchies (the same source the legacy subsystem map used); v2 —
///   the names published by `<cgroupfs_root>/cgroup.controllers`; a
///   missing file on a genuine v2 host is an error, not an empty set.
/// - Every failure carries context; nothing defaults silently to v1
///   (plan.md: "return discovery errors rather than interpreting errors
///   as cgroup v1").
fn assemble_topology(
    mounts: MountTable,
    membership: Membership,
    host_paths: &HostPaths,
) -> CoreResult<CgroupTopology> {
    let v1_mounts = mounts.cgroup_mounts();
    let unified_candidate = mounts.unified_mount();

    let (version, v2_available, cgroupfs_root) = if !v1_mounts.is_empty() {
        let natural_root = determine_v1_natural_root(&v1_mounts);
        let cgroupfs_root = match &host_paths.cgroupfs_override {
            Some(root) => root.clone(),
            None => natural_root,
        };

        // A cgroup namespace may expose a delegated cgroup2 subtree with a
        // non-root mount_root. It is still the visible unified hierarchy and
        // is subject to the same statfs verification as a pure-v2 layout.
        let v2_available = match unified_candidate {
            Some(candidate) => match &host_paths.cgroupfs_override {
                Some(_) => true,
                None => {
                    verify_cgroup2_mount(&candidate.mount_point)?;
                    true
                }
            },
            None => false,
        };

        (CgroupVersion::V1, v2_available, cgroupfs_root)
    } else if let Some(candidate) = unified_candidate {
        let cgroupfs_root = match &host_paths.cgroupfs_override {
            Some(root) => root.clone(),
            None => {
                verify_cgroup2_mount(&candidate.mount_point)?;
                candidate.mount_point.clone()
            }
        };
        (CgroupVersion::V2, true, cgroupfs_root)
    } else {
        return Err(CoreError::Discovery {
            step: "resolve cgroup layout",
            path: host_paths.procfs.join("self/mountinfo"),
            cause: io::Error::new(io::ErrorKind::NotFound, "no cgroup or cgroup2 mounts found"),
        });
    };

    // Cross-check the mount-based verdict against process membership.
    let unified_membership = membership.unified();
    if v2_available && unified_membership.is_none() {
        return Err(layout_error(
            "cross-check membership",
            host_paths.procfs.join("self/cgroup"),
            "unified mounts but the process has no `0::` membership record",
        ));
    }
    if !v2_available && unified_membership.is_some() {
        return Err(layout_error(
            "cross-check membership",
            host_paths.procfs.join("self/cgroup"),
            "`0::` membership record but no qualifying cgroup2 mount is visible",
        ));
    }
    if membership.records().is_empty() {
        return Err(layout_error(
            "cross-check membership",
            host_paths.procfs.join("self/cgroup"),
            "no membership records at all",
        ));
    }

    let controllers = match version {
        CgroupVersion::V1 => membership
            .records()
            .iter()
            .flat_map(|record| record.controllers.iter().cloned())
            .collect::<ControllerSet>(),
        CgroupVersion::V2 => read_controller_names(&cgroupfs_root)?,
    };

    Ok(CgroupTopology {
        version,
        v2_available,
        mounts,
        membership,
        controllers,
        cgroupfs_root,
        hugepages: host_paths.hugepages.clone(),
    })
}

/// statfs recheck: confirm that a cgroup2 mount point really is a
/// cgroup2 filesystem, guarding against stale or forged mountinfo.
fn verify_cgroup2_mount(path: &Path) -> CoreResult<()> {
    use nix::sys::statfs;

    match statfs::statfs(path) {
        Ok(stat) if stat.filesystem_type() == statfs::CGROUP2_SUPER_MAGIC => Ok(()),
        Ok(_) => Err(CoreError::Discovery {
            step: "statfs cgroupfs root",
            path: path.to_path_buf(),
            cause: io::Error::new(
                io::ErrorKind::InvalidData,
                "the cgroup2 mount point is not a cgroup2 filesystem",
            ),
        }),
        Err(errno) => Err(CoreError::Discovery {
            step: "statfs cgroupfs root",
            path: path.to_path_buf(),
            cause: io::Error::other(format!("statfs failed: {}", errno)),
        }),
    }
}

/// Read the controller names published by a unified cgroupfs root.
fn read_controller_names(cgroupfs_root: &Path) -> CoreResult<ControllerSet> {
    let path = cgroupfs_root.join("cgroup.controllers");
    let contents = fs::read_to_string(&path).map_err(|cause| CoreError::Discovery {
        step: "read cgroup.controllers",
        path: path.clone(),
        cause,
    })?;
    Ok(contents.split_whitespace().map(str::to_string).collect())
}

/// Build a discovery error for a self-contradictory host layout.
fn layout_error(step: &'static str, path: PathBuf, message: &str) -> CoreError {
    CoreError::Discovery {
        step,
        path,
        cause: io::Error::new(io::ErrorKind::InvalidData, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let host_paths = HostPaths {
            procfs: root.clone(),
            cgroupfs_override: None,
            hugepages: PathBuf::from("/nonexistent"),
        };
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
    fn test_discover_v2_with_override() {
        // The override both relocates the cgroupfs root and skips the
        // statfs recheck, so a plain directory stands in for cgroupfs.
        let (root, host_paths) = fixture_host("v2", V2_MOUNTINFO, V2_MEMBERSHIP);
        let cgroupfs = root.join("cgroupfs");
        fs::create_dir_all(&cgroupfs).unwrap();
        fs::write(
            cgroupfs.join("cgroup.controllers"),
            "cpuset cpu io memory pids\n",
        )
        .unwrap();

        let host_paths = HostPaths {
            cgroupfs_override: Some(cgroupfs.clone()),
            ..host_paths
        };
        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V2);
        assert!(topology.v2_available);
        assert_eq!(topology.cgroupfs_root, cgroupfs);
        assert_eq!(topology.controllers.len(), 5);
        assert!(topology.controllers.contains("memory"));
        assert!(topology.controllers.contains("io"));
    }

    #[test]
    fn test_discover_v1_with_override() {
        let (root, host_paths) = fixture_host("v1-override", V1_MOUNTINFO, V1_MEMBERSHIP);
        let custom_cgroupfs = root.join("custom_cgroupfs");
        let custom_hugepages = root.join("custom_hugepages");
        fs::create_dir_all(&custom_cgroupfs).unwrap();
        fs::create_dir_all(&custom_hugepages).unwrap();

        let host_paths = HostPaths {
            cgroupfs_override: Some(custom_cgroupfs.clone()),
            hugepages: custom_hugepages.clone(),
            ..host_paths
        };

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert_eq!(topology.cgroupfs_root, custom_cgroupfs);
        assert_eq!(topology.hugepages, custom_hugepages);

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
        let host_paths = HostPaths {
            cgroupfs_override: Some(root.join("cgroupfs")),
            ..host_paths
        };

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert!(topology.v2_available);
        assert_eq!(topology.cgroupfs_root, root.join("cgroupfs"));
        // Primary-hierarchy controllers only.
        assert!(!topology.controllers.contains("io"));
    }

    #[test]
    fn test_discover_hybrid_missing_unified_membership() {
        let (root, host_paths) = fixture_host(
            "hybrid-missing-0",
            &format!("{}\n{}", V1_MOUNTINFO, HYBRID_EXTRA_MOUNT),
            V1_MEMBERSHIP,
        );
        let host_paths = HostPaths {
            cgroupfs_override: Some(root.join("cgroupfs")),
            ..host_paths
        };

        match discover(&host_paths) {
            Err(CoreError::Discovery { step, cause, .. }) => {
                assert_eq!(step, "cross-check membership");
                assert!(cause
                    .to_string()
                    .contains("unified mounts but the process has no `0::` membership record"));
            }
            other => panic!("expected a Discovery error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_discover_no_cgroup_mounts() {
        let (_root, host_paths) = fixture_host(
            "none",
            "36 35 98:0 / /mnt rw,relatime - ext3 /dev/root rw",
            V1_MEMBERSHIP,
        );

        match discover(&host_paths) {
            Err(CoreError::Discovery { step, path, .. }) => {
                assert_eq!(step, "resolve cgroup layout");
                assert!(path.ends_with("self/mountinfo"));
            }
            other => panic!("expected a Discovery error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_discover_contradictory_membership() {
        // Unified mounts but the process has no `0::` record. The
        // override skips the statfs recheck so the contradiction is
        // reached deterministically.
        let (root, host_paths) = fixture_host("contra", V2_MOUNTINFO, V1_MEMBERSHIP);
        let host_paths = HostPaths {
            cgroupfs_override: Some(root.join("cgroupfs")),
            ..host_paths
        };

        match discover(&host_paths) {
            Err(CoreError::Discovery { step, .. }) => {
                assert_eq!(step, "cross-check membership");
            }
            other => panic!("expected a Discovery error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_discover_missing_membership_record_without_v2_mount() {
        // `0::` membership but no cgroup2 mount on a v1 host.
        let (_root, host_paths) =
            fixture_host("contra2", V1_MOUNTINFO, &format!("{}\n0::/", V1_MEMBERSHIP));

        match discover(&host_paths) {
            Err(CoreError::Discovery { step, .. }) => {
                assert_eq!(step, "cross-check membership");
            }
            other => panic!("expected a Discovery error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_discover_missing_file() {
        let root = std::env::temp_dir().join(format!(
            "cgroups-rs-topology-missing-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _temp = TempDir(root.clone());
        fs::create_dir_all(root.join("self")).unwrap();
        // Only the membership file exists.
        fs::write(root.join("self/cgroup"), V1_MEMBERSHIP).unwrap();

        let host_paths = HostPaths {
            procfs: root.clone(),
            cgroupfs_override: None,
            hugepages: PathBuf::from("/nonexistent"),
        };
        match discover(&host_paths) {
            Err(CoreError::Discovery { step, path, .. }) => {
                assert_eq!(step, "read mountinfo");
                assert!(path.ends_with("self/mountinfo"));
            }
            other => panic!("expected a Discovery error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_discover_propagates_parse_error() {
        let (_root, host_paths) = fixture_host(
            "parse",
            &format!("{}\nnot a mountinfo line", V1_MOUNTINFO),
            V1_MEMBERSHIP,
        );

        match discover(&host_paths) {
            Err(CoreError::ParseError { kind, line, .. }) => {
                assert_eq!(kind, crate::error::ParseSource::Mountinfo);
                assert_eq!(line, 5);
            }
            other => panic!("expected a ParseError, got `{:?}`", other),
        }
    }

    #[test]
    fn test_resolve_mount_point_single_co_mount_override() {
        const SINGLE_CO_MOUNT: &str =
            "30 26 0:26 / /sys/fs/cgroup rw - cgroup cgroup rw,cpu,cpuacct,memory";
        const SINGLE_MEMBERSHIP: &str = "1:cpu,cpuacct,memory:/user.slice";

        let (root, host_paths) = fixture_host("single-co", SINGLE_CO_MOUNT, SINGLE_MEMBERSHIP);
        let custom_cgroupfs = root.join("custom_cgroupfs");
        fs::create_dir_all(&custom_cgroupfs).unwrap();

        let host_paths = HostPaths {
            cgroupfs_override: Some(custom_cgroupfs.clone()),
            ..host_paths
        };

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert_eq!(topology.cgroupfs_root, custom_cgroupfs);

        // Single co-mount must resolve directly to custom_cgroupfs, NOT custom_cgroupfs/cgroup
        let resolved = topology.resolve_mount_point(Path::new("/sys/fs/cgroup"));
        assert_eq!(resolved, custom_cgroupfs);
    }

    #[test]
    fn test_resolve_mount_point_single_controller_directory_override() {
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
            let host_paths = HostPaths {
                cgroupfs_override: Some(custom_cgroupfs.clone()),
                ..host_paths
            };

            let topology = discover(&host_paths).unwrap();
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
        let host_paths = HostPaths {
            cgroupfs_override: Some(root.join("cgroupfs")),
            ..host_paths
        };

        let topology = discover(&host_paths).unwrap();
        assert_eq!(topology.version, CgroupVersion::V1);
        assert!(topology.v2_available);
    }
}
