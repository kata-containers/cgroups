// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module represents the various control group hierarchies the Linux kernel supports.

use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::discovery::{discover, CgroupTopology, CgroupVersion, HostPaths};
use crate::core::error::{CoreError, CoreResult};
#[cfg(test)]
use crate::core::CgroupPath;
use crate::fs::blkio::BlkIoController;
use crate::fs::cpu::CpuController;
use crate::fs::cpuacct::CpuAcctController;
use crate::fs::cpuset::CpuSetController;
use crate::fs::devices::DevicesController;
use crate::fs::error::{Error, ErrorKind, Result};
use crate::fs::freezer::FreezerController;
use crate::fs::hugetlb::HugeTlbController;
use crate::fs::memory::MemController;
use crate::fs::net_cls::NetClsController;
use crate::fs::net_prio::NetPrioController;
use crate::fs::perf_event::PerfEventController;
use crate::fs::pid::PidController;
use crate::fs::rdma::RdmaController;
use crate::fs::systemd::SystemdController;
use crate::fs::{Controllers, Hierarchy, Subsystem};

#[cfg(test)]
use crate::fs::cgroup::Cgroup;

/// The standard, original cgroup implementation. Often referred to as "cgroupv1".
///
/// On a v2-primary topology, this view still exposes visible named v1
/// hierarchies. Each controller retains its own mount point; there is no
/// single v1 root. [`Hierarchy::root`] returns [`ErrorKind::CgroupVersion`],
/// including when this view has no v1 mounts.
#[derive(Debug, Clone)]
pub struct V1 {
    topology: Arc<CgroupTopology>,
}

/// A cgroup v2 hierarchy.
///
/// Use fallible discovery and checked conversion, which
/// preserve discovery errors and reject v1-primary hosts, including hybrid:
///
/// ```no_run
/// use std::convert::TryFrom;
/// use cgroups_rs::core::{discover, HostPaths};
/// use cgroups_rs::fs::hierarchies::V2;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let topology = discover(&HostPaths::default())?;
/// let hierarchy = V2::try_from(topology)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct V2 {
    topology: Arc<CgroupTopology>,
}

impl Hierarchy for V1 {
    fn v2(&self) -> bool {
        false
    }

    fn subsystems(&self) -> Vec<Subsystem> {
        let mut subs = vec![];

        // The cgroup writeback feature requires cooperation between memcgs and blkcgs
        // To avoid exceptions, we should add_task for blkcg before memcg(push BlkIo before Mem)
        // For more Information: https://www.alibabacloud.com/help/doc-detail/155509.htm
        if let Some((point, root)) = self.get_mount_point(Controllers::BlkIo) {
            subs.push(Subsystem::BlkIo(BlkIoController::new(point, root, false)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::Mem) {
            subs.push(Subsystem::Mem(MemController::new(point, root, false)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::Pids) {
            subs.push(Subsystem::Pid(PidController::new(point, root, false)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::CpuSet) {
            subs.push(Subsystem::CpuSet(CpuSetController::new(point, root, false)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::CpuAcct) {
            subs.push(Subsystem::CpuAcct(CpuAcctController::new(point, root)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::Cpu) {
            subs.push(Subsystem::Cpu(CpuController::new(point, root, false)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::Devices) {
            subs.push(Subsystem::Devices(DevicesController::new(point, root)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::Freezer) {
            subs.push(Subsystem::Freezer(FreezerController::new(
                point, root, false,
            )));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::NetCls) {
            subs.push(Subsystem::NetCls(NetClsController::new(point, root)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::PerfEvent) {
            subs.push(Subsystem::PerfEvent(PerfEventController::new(point, root)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::NetPrio) {
            subs.push(Subsystem::NetPrio(NetPrioController::new(point, root)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::HugeTlb) {
            subs.push(Subsystem::HugeTlb(HugeTlbController::new_with_hugepages(
                point,
                root,
                false,
                self.hugepages(),
            )));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::Rdma) {
            subs.push(Subsystem::Rdma(RdmaController::new(point, root)));
        }
        if let Some((point, root)) = self.get_mount_point(Controllers::Systemd) {
            subs.push(Subsystem::Systemd(SystemdController::new(
                point, root, false,
            )));
        }

        subs
    }

    fn root(&self) -> Result<PathBuf> {
        Err(Error::new(ErrorKind::CgroupVersion))
    }

    fn topology(&self) -> Option<Arc<CgroupTopology>> {
        Some(self.topology.clone())
    }
}

impl Hierarchy for V2 {
    fn v2(&self) -> bool {
        true
    }

    fn subsystems(&self) -> Vec<Subsystem> {
        let mut subs = vec![];
        let root = self.topology.cgroupfs_root();

        let mut controller_list: Vec<&str> = self.topology.controllers().iter().collect();

        // The freezer functionality is present in V2, but not as a controller,
        // but apparently as a core functionality. FreezerController supports
        // that, but we must explicitly fake the controller here.
        controller_list.push("freezer");

        for s in controller_list {
            match s {
                "cpu" => {
                    subs.push(Subsystem::Cpu(CpuController::new(
                        root.to_path_buf(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "io" => {
                    subs.push(Subsystem::BlkIo(BlkIoController::new(
                        root.to_path_buf(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "cpuset" => {
                    subs.push(Subsystem::CpuSet(CpuSetController::new(
                        root.to_path_buf(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "memory" => {
                    subs.push(Subsystem::Mem(MemController::new(
                        root.to_path_buf(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "pids" => {
                    subs.push(Subsystem::Pid(PidController::new(
                        root.to_path_buf(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "freezer" => {
                    subs.push(Subsystem::Freezer(FreezerController::new(
                        root.to_path_buf(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "hugetlb" => {
                    subs.push(Subsystem::HugeTlb(HugeTlbController::new_with_hugepages(
                        root.to_path_buf(),
                        PathBuf::from(""),
                        true,
                        self.hugepages(),
                    )));
                }
                _ => {}
            }
        }

        subs
    }

    fn root(&self) -> Result<PathBuf> {
        Ok(self.topology.cgroupfs_root().to_path_buf())
    }

    fn topology(&self) -> Option<Arc<CgroupTopology>> {
        Some(self.topology.clone())
    }
}

impl From<Arc<CgroupTopology>> for V1 {
    /// Build a cgroup v1 view of an already-discovered topology.
    ///
    /// The v1 view is valid on any topology. It exposes only visible v1
    /// mounts, including named hierarchies on a v2-primary host. Without v1
    /// mounts it has no subsystems. Construction performs no I/O.
    fn from(topology: Arc<CgroupTopology>) -> V1 {
        V1 { topology }
    }
}

impl V1 {
    fn hugepages(&self) -> &Path {
        self.topology.hugepages()
    }

    /// Return the visible mount point and mount root for a v1 controller.
    pub fn get_mount_point(&self, controller: Controllers) -> Option<(PathBuf, PathBuf)> {
        let controller_name = controller.to_string();
        self.topology
            .mounts()
            .cgroup_mounts()
            .iter()
            .find_map(|mount| {
                if mount
                    .super_opts
                    .iter()
                    .any(|opt| opt.as_slice() == controller_name.as_bytes())
                {
                    Some((
                        self.topology.resolve_mount_point(&mount.mount_point),
                        mount.mount_root.clone(),
                    ))
                } else {
                    None
                }
            })
    }
}

impl TryFrom<Arc<CgroupTopology>> for V2 {
    type Error = CoreError;

    /// Build a cgroup v2 view of an already-discovered topology.
    ///
    /// Returns a [`CoreError::VersionMismatch`] error before constructing the
    /// hierarchy if `topology` has a v1 primary version, including hybrid hosts.
    /// This prevents v2 creation logic from treating a v1 cgroupfs root as a
    /// unified hierarchy.
    fn try_from(topology: Arc<CgroupTopology>) -> CoreResult<V2> {
        if topology.version() != CgroupVersion::V2 {
            return Err(CoreError::VersionMismatch {
                path: topology.cgroupfs_root().to_path_buf(),
                requested: CgroupVersion::V2,
                found: topology.version(),
            });
        }
        Ok(V2 { topology })
    }
}

impl V2 {
    fn hugepages(&self) -> &Path {
        self.topology.hugepages()
    }
}

pub const UNIFIED_MOUNTPOINT: &str = "/sys/fs/cgroup";

/// Whether the host operates in unified cgroup v2 mode.
///
/// Uses strict discovery on the default host paths. Hybrid hosts report
/// `Ok(false)` because their primary hierarchy is v1; discovery failures
/// remain errors instead of being interpreted as a v1 host.
pub fn is_cgroup2_unified_mode() -> CoreResult<bool> {
    auto().map(|hierarchy| hierarchy.v2())
}

/// Discover the current host and build a hierarchy sharing its topology.
///
/// Required procfs read, parse, and layout failures, including empty membership
/// and ambiguous v1 roots, propagate as structured [`CoreError`] values.
/// A v2-primary host also requires a readable `cgroup.controllers`.
/// No fallback hierarchy is constructed on failure.
///
/// Every built-in hierarchy has a snapshot. To choose host paths explicitly,
/// use [`discover`] followed by [`from_topology`].
pub fn auto() -> CoreResult<Arc<dyn Hierarchy>> {
    auto_with_host_paths(&HostPaths::default())
}

fn auto_with_host_paths(host_paths: &HostPaths) -> CoreResult<Arc<dyn Hierarchy>> {
    discover(host_paths).map(from_topology)
}

/// Build the hierarchy for an already-discovered topology without further I/O.
///
/// Discover from any [`HostPaths`] first, then reuse the snapshot across
/// hierarchies and control group handles.
pub fn from_topology(topology: Arc<CgroupTopology>) -> Arc<dyn Hierarchy> {
    match topology.version() {
        CgroupVersion::V1 => Arc::new(V1::from(topology)),
        CgroupVersion::V2 => Arc::new(V2 { topology }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::{LayoutError, ParseMembershipError, ParseMountError};
    use crate::fs::Controller;
    use std::error::Error as _;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    struct Fixture {
        root: PathBuf,
        paths: HostPaths,
    }

    impl Fixture {
        fn new(mountinfo: &str, membership: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "hierarchy-strict-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let proc_self = root.join("proc/self");
            let cgroupfs = root.join("cgroupfs");
            fs::create_dir_all(&proc_self).unwrap();
            fs::create_dir_all(&cgroupfs).unwrap();
            fs::write(proc_self.join("mountinfo"), mountinfo).unwrap();
            fs::write(proc_self.join("cgroup"), membership).unwrap();
            fs::write(cgroupfs.join("cgroup.controllers"), "cpu memory\n").unwrap();
            let paths = HostPaths::new(root.join("proc"), root.join("hugepages"))
                .with_fixture_root(cgroupfs);
            Self { root, paths }
        }

        fn strict_error(&self) -> CoreError {
            auto_with_host_paths(&self.paths).unwrap_err()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    const V1_MOUNT: &str = "43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
    const V2_MOUNT: &str = "47 44 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";

    #[test]
    fn test_auto_preserves_shared_topology() {
        let hybrid_mounts = format!("{V1_MOUNT}{V2_MOUNT}");
        for (mountinfo, membership, version) in [
            (V1_MOUNT, "1:memory:/\n", CgroupVersion::V1),
            (V2_MOUNT, "0::/\n", CgroupVersion::V2),
            (
                hybrid_mounts.as_str(),
                "1:memory:/\n0::/\n",
                CgroupVersion::V1,
            ),
        ] {
            let fixture = Fixture::new(mountinfo, membership);
            assert_eq!(
                auto_with_host_paths(&fixture.paths).unwrap().v2(),
                version == CgroupVersion::V2,
            );
            let hierarchy = auto_with_host_paths(&fixture.paths).unwrap();
            let topology = hierarchy.topology().unwrap();
            assert_eq!(topology.version(), version);
            if version == CgroupVersion::V2 {
                assert_eq!(hierarchy.root().unwrap(), fixture.root.join("cgroupfs"));
            } else {
                assert_eq!(
                    hierarchy.root().unwrap_err().kind(),
                    &ErrorKind::CgroupVersion
                );
            }

            // Related handles keep the snapshot even if discovery files vanish.
            fs::remove_dir_all(fixture.paths.procfs.join("self")).unwrap();
            let selected = from_topology(topology.clone());
            assert!(Arc::ptr_eq(&topology, &selected.topology().unwrap()));
            let v1 = V1::from(topology.clone());
            assert!(Arc::ptr_eq(&topology, &v1.topology().unwrap()));
            match V2::try_from(topology.clone()) {
                Ok(v2) => {
                    assert_eq!(version, CgroupVersion::V2);
                    assert!(Arc::ptr_eq(&topology, &v2.topology().unwrap()));
                }
                Err(CoreError::VersionMismatch {
                    requested, found, ..
                }) => {
                    assert_eq!(version, CgroupVersion::V1);
                    assert_eq!(requested, CgroupVersion::V2);
                    assert_eq!(found, version);
                }
                Err(error) => panic!("unexpected conversion error: {:?}", error),
            }
            let root = Cgroup::load(hierarchy.clone(), CgroupPath::root());
            assert!(Arc::ptr_eq(&topology, &root.topology().unwrap()));
            let child = Cgroup::load(hierarchy, CgroupPath::new("child").unwrap());
            assert!(Arc::ptr_eq(
                &topology,
                &child.parent().unwrap().topology().unwrap(),
            ));
        }
    }

    #[test]
    fn test_auto_rejects_empty_or_malformed_membership() {
        let fixture = Fixture::new(V1_MOUNT, "");
        let error = fixture.strict_error();
        assert!(matches!(
            &error,
            CoreError::Layout { path, cause: LayoutError::NoMembershipRecords }
                if path == &fixture.paths.procfs.join("self/cgroup")
        ));
        assert_eq!(
            error.source().unwrap().downcast_ref::<LayoutError>(),
            Some(&LayoutError::NoMembershipRecords)
        );
        fs::write(
            fixture.paths.procfs.join("self/cgroup"),
            b"bad membership\n",
        )
        .unwrap();
        let error = fixture.strict_error();
        match &error {
            CoreError::ParseMembershipInFile { path, cause } => {
                assert_eq!(path, &fixture.paths.procfs.join("self/cgroup"));
                assert_eq!(cause.line(), 1);
            }
            other => panic!("expected a membership parse error, got {:?}", other),
        }
        assert!(error
            .source()
            .unwrap()
            .downcast_ref::<ParseMembershipError>()
            .is_some());
    }

    #[test]
    fn test_auto_rejects_malformed_mountinfo_after_a_valid_record() {
        let fixture = Fixture::new(&format!("{V1_MOUNT}bad mountinfo\n"), "1:memory:/\n");
        let error = fixture.strict_error();
        match &error {
            CoreError::ParseMountInFile { path, cause } => {
                assert_eq!(path, &fixture.paths.procfs.join("self/mountinfo"));
                assert_eq!(cause.line(), 2);
            }
            other => panic!("expected a mountinfo parse error, got {:?}", other),
        }
        assert!(error
            .source()
            .unwrap()
            .downcast_ref::<ParseMountError>()
            .is_some());
    }

    #[test]
    fn test_auto_rejects_ambiguous_v1_roots() {
        let fixture = Fixture::new(
            &format!("{V1_MOUNT}44 33 0:39 / /other/cgroups/cpu rw - cgroup cgroup rw,cpu\n"),
            "1:memory:/\n2:cpu:/\n",
        );
        let error = fixture.strict_error();
        match &error {
            CoreError::Layout {
                path,
                cause: LayoutError::AmbiguousV1Roots { roots },
            } => {
                assert_eq!(path, &fixture.paths.procfs.join("self/mountinfo"));
                assert_eq!(
                    roots,
                    &std::collections::BTreeSet::from([
                        PathBuf::from("/sys/fs/cgroup"),
                        PathBuf::from("/other/cgroups"),
                    ])
                );
            }
            other => panic!("expected ambiguous v1 roots, got {:?}", other),
        }
        assert!(error
            .source()
            .unwrap()
            .downcast_ref::<LayoutError>()
            .is_some());
    }

    #[test]
    fn test_auto_preserves_required_read_errors() {
        for relative in [
            "proc/self/mountinfo",
            "proc/self/cgroup",
            "cgroupfs/cgroup.controllers",
        ] {
            let fixture = Fixture::new(V2_MOUNT, "0::/\n");
            let missing_path = fixture.root.join(relative);
            fs::remove_file(&missing_path).unwrap();
            let error = fixture.strict_error();
            match &error {
                CoreError::ReadProcFile { path, .. } | CoreError::ReadControllers { path, .. } => {
                    assert_eq!(path, &missing_path)
                }
                other => panic!("expected a required read error, got {:?}", other),
            }
            let source = error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap();
            assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
        }
    }

    #[test]
    fn test_v1_view_uses_named_mounts_without_a_unified_root() {
        for mount_point in ["/opt/legacy/systemd", "/srv/legacy-tree"] {
            let mounts = format!(
                "{V2_MOUNT}51 44 0:51 /delegated {mount_point} rw - cgroup cgroup rw,name=systemd\n"
            );
            let fixture = Fixture::new(&mounts, "0::/\n1:name=systemd:/delegated/work\n");
            let topology = discover(&fixture.paths).unwrap();
            assert_eq!(topology.version(), CgroupVersion::V2);
            assert_eq!(topology.cgroupfs_root(), fixture.root.join("cgroupfs"));
            // Converting the snapshot and querying the view need no live procfs.
            fs::remove_dir_all(fixture.paths.procfs.join("self")).unwrap();
            let v1 = V1::from(topology.clone());
            assert_eq!(v1.root().unwrap_err().kind(), &ErrorKind::CgroupVersion);
            assert_eq!(
                v1.clone().root().unwrap_err().kind(),
                &ErrorKind::CgroupVersion
            );
            assert!(Arc::ptr_eq(&topology, &v1.topology().unwrap()));
            assert_eq!(
                v1.get_mount_point(Controllers::Systemd),
                Some((PathBuf::from(mount_point), PathBuf::from("/delegated"))),
            );
            let handle = Cgroup::load(Arc::new(v1), CgroupPath::new("child").unwrap());
            let systemd: &SystemdController = handle.controller_of().unwrap();
            assert_eq!(systemd.path(), Path::new(mount_point).join("child"));
        }
    }

    #[test]
    fn test_v1_view_with_separate_named_mounts_has_no_unified_root() {
        let systemd_mount = "51 44 0:51 / /opt/legacy/systemd rw - cgroup cgroup rw,name=systemd\n";
        let openrc_mount = "52 44 0:52 / /run/openrc rw - cgroup cgroup rw,name=openrc\n";
        for named_mounts in [
            format!("{systemd_mount}{openrc_mount}"),
            format!("{openrc_mount}{systemd_mount}"),
        ] {
            let fixture = Fixture::new(
                &format!("{V2_MOUNT}{named_mounts}"),
                "0::/\n1:name=systemd:/\n2:name=openrc:/\n",
            );
            let topology = discover(&fixture.paths).unwrap();
            assert_eq!(topology.version(), CgroupVersion::V2);
            let v1 = V1::from(topology);
            assert_eq!(v1.root().unwrap_err().kind(), &ErrorKind::CgroupVersion);
            assert_eq!(
                v1.get_mount_point(Controllers::Systemd),
                Some((PathBuf::from("/opt/legacy/systemd"), PathBuf::from("/"))),
            );
        }
    }

    #[test]
    fn test_v1_view_preserves_non_utf8_named_mount_point() {
        let fixture = crate::tests::TopologyFixture::new(
            b"47 44 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n\
              51 44 0:51 / /opt/legacy-\xff/systemd rw - cgroup cgroup rw,name=systemd\n",
            b"0::/\n1:name=systemd:/\n",
            "cpu memory",
        );
        assert_eq!(fixture.topology.version(), CgroupVersion::V2);
        let v1 = V1::from(fixture.topology.clone());
        assert_eq!(v1.root().unwrap_err().kind(), &ErrorKind::CgroupVersion);
        let (mount_point, mount_root) = v1.get_mount_point(Controllers::Systemd).unwrap();
        assert_eq!(
            mount_point.as_os_str().as_bytes(),
            b"/opt/legacy-\xff/systemd"
        );
        assert_eq!(mount_root, Path::new("/"));
    }

    #[test]
    fn test_v1_view_without_v1_mounts_keeps_the_snapshot() {
        let fixture = Fixture::new(V2_MOUNT, "0::/\n");
        let v1 = V1::from(discover(&fixture.paths).unwrap());
        assert_eq!(v1.root().unwrap_err().kind(), &ErrorKind::CgroupVersion);
        assert!(v1.subsystems().is_empty());
        assert!(v1.topology().is_some());
    }

    #[test]
    fn test_v1_controller_match_with_non_utf8_super_option() {
        let input = b"43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory,release_agent=/tmp/agent-\xff\n";
        let fixture = crate::tests::TopologyFixture::new(input, b"1:memory:/\n", "");
        assert_eq!(
            fixture.topology.mounts().cgroup_mounts()[0].super_opts[2],
            b"release_agent=/tmp/agent-\xff"
        );
        let hierarchy = V1::from(fixture.topology.clone());
        assert_eq!(
            hierarchy.get_mount_point(Controllers::Mem),
            Some((
                fixture.topology.cgroupfs_root().join("memory"),
                PathBuf::from("/")
            ))
        );
    }

    #[test]
    fn test_v1_hierarchy_mountpoint_and_hugetlb_override() {
        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let temp_dir = std::env::temp_dir().join(format!("v1-hier-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _guard = TempGuard(temp_dir.clone());
        let custom_cgroupfs = temp_dir.join("cgroupfs");
        let custom_hugepages = temp_dir.join("hugepages");
        std::fs::create_dir_all(&custom_cgroupfs).unwrap();
        std::fs::create_dir_all(custom_hugepages.join("hugepages-2048kB")).unwrap();

        let mountinfo = "\
43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory
44 33 0:39 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,hugetlb";
        let proc_self = temp_dir.join("proc/self");
        std::fs::create_dir_all(&proc_self).unwrap();
        std::fs::write(proc_self.join("mountinfo"), mountinfo).unwrap();
        std::fs::write(proc_self.join("cgroup"), "1:memory:/\n2:hugetlb:/\n").unwrap();
        let host_paths = HostPaths::new(temp_dir.join("proc"), custom_hugepages)
            .with_fixture_root(custom_cgroupfs.clone());
        let topology = discover(&host_paths).unwrap();

        let v1 = V1::from(topology);
        let mem_point = v1.get_mount_point(Controllers::Mem).unwrap();
        assert_eq!(mem_point.0, custom_cgroupfs.join("memory"));

        let subs = v1.subsystems();
        let hugetlb_sub = subs
            .iter()
            .find(|s| s.controller_name() == "hugetlb")
            .unwrap();
        match hugetlb_sub {
            Subsystem::HugeTlb(c) => {
                assert!(c.size_supported("2MB"));
            }
            _ => panic!("expected HugeTlb controller"),
        }
    }

    #[test]
    fn test_strict_detection_is_scoped_to_host_paths() {
        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn write_proc(root: &Path, mountinfo: &str, membership: &str) {
            let proc_self = root.join("proc/self");
            std::fs::create_dir_all(&proc_self).unwrap();
            std::fs::write(proc_self.join("mountinfo"), mountinfo).unwrap();
            std::fs::write(proc_self.join("cgroup"), membership).unwrap();
        }

        let temp_dir = std::env::temp_dir().join(format!("hier-mode-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _guard = TempGuard(temp_dir.clone());

        let v1_root = temp_dir.join("v1");
        write_proc(
            &v1_root,
            "43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory",
            "1:memory:/",
        );
        let v1_paths = HostPaths::new(v1_root.join("proc"), v1_root.join("hugepages"))
            .with_fixture_root(v1_root.join("cgroupfs"));

        let v2_root = temp_dir.join("v2");
        write_proc(
            &v2_root,
            "47 44 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw",
            "0::/",
        );
        let v2_cgroupfs = v2_root.join("cgroupfs");
        std::fs::create_dir_all(&v2_cgroupfs).unwrap();
        std::fs::write(v2_cgroupfs.join("cgroup.controllers"), "cpu memory\n").unwrap();
        let v2_paths = HostPaths::new(v2_root.join("proc"), v2_root.join("hugepages"))
            .with_fixture_root(v2_cgroupfs);

        assert_eq!(discover(&v1_paths).unwrap().version(), CgroupVersion::V1);
        assert_eq!(discover(&v2_paths).unwrap().version(), CgroupVersion::V2);
        assert_eq!(discover(&v1_paths).unwrap().version(), CgroupVersion::V1);
    }

    #[test]
    fn test_v2_constructors_reject_v1_topology_before_mutation() {
        struct TempGuard(PathBuf);
        impl Drop for TempGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let temp_dir =
            std::env::temp_dir().join(format!("v2-hier-reject-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _guard = TempGuard(temp_dir.clone());

        let proc_self = temp_dir.join("proc/self");
        std::fs::create_dir_all(&proc_self).unwrap();
        std::fs::write(
            proc_self.join("mountinfo"),
            "43 33 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory",
        )
        .unwrap();
        std::fs::write(proc_self.join("cgroup"), "1:memory:/").unwrap();

        let cgroupfs_root = temp_dir.join("cgroupfs");
        let v1_paths = HostPaths::new(temp_dir.join("proc"), temp_dir.join("hugepages"))
            .with_fixture_root(cgroupfs_root.clone());
        std::fs::create_dir_all(&cgroupfs_root).unwrap();

        // Discover first, then reject v1 in the pure hierarchy conversion.
        let topology = discover(&v1_paths).unwrap();
        let target = cgroupfs_root.join("must-not-be-created");
        match V2::try_from(topology) {
            Err(CoreError::VersionMismatch {
                path,
                requested,
                found,
            }) => {
                assert_eq!(path, cgroupfs_root);
                assert_eq!(requested, CgroupVersion::V2);
                assert_eq!(found, CgroupVersion::V1);
            }
            Ok(v2) => {
                // If the version check regresses, exercise the dangerous path:
                // Cgroup::create would otherwise create this directory using
                // v2 semantics under a v1 root and report success.
                let cgroup = Cgroup::load(
                    Arc::new(v2),
                    CgroupPath::new("must-not-be-created").unwrap(),
                );
                cgroup.create().unwrap();
            }
            Err(other) => panic!("unexpected error: {}", other),
        }
        assert!(
            !target.exists(),
            "rejecting a v1 topology must happen before cgroupfs mutation"
        );
    }
}
